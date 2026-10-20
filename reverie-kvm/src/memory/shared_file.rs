/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

// AUTONOMOUS-BOT-IMPLEMENTED: Retain ordinary shared files in the stable KVM arena.
// TODO-HUMAN-REVIEW(PR-911): Review publication, fault containment and retirement.
use super::*;

/// An allocation owner also defers terminal notifications until its real mutex
/// has been released. The monotonically distinct owner prevents an old Drop
/// from clearing a successor that acquired the allocator between the unlock
/// and the deferred-record check.
pub(crate) struct AllocationGuard<'a> {
    memory: &'a GuestMemory,
    guard: Option<MutexGuard<'a, ()>>,
    id: u128,
}

struct ClosedSnapshot<'a> {
    allocation: Option<AllocationGuard<'a>>,
    closed: Option<Closed>,
}

impl Drop for ClosedSnapshot<'_> {
    fn drop(&mut self) {
        drop(self.allocation.take());
        drop(self.closed.take());
    }
}

#[derive(Default)]
pub(super) struct DeferredFailures {
    next: u128,
    active: Option<u128>,
    scopes: usize,
    causes: Vec<(EntryOrigin, Arc<Error>)>,
    notifications: Vec<crate::entry::CopyRetirement>,
}

impl std::fmt::Debug for DeferredFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeferredFailures")
            .field("active", &self.active)
            .field("scopes", &self.scopes)
            .field("queued", &self.causes.len())
            .finish()
    }
}

impl Drop for AllocationGuard<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        let (causes, notifications) = {
            let mut deferred = self.memory.mapping.deferred.lock().unwrap();
            if deferred.active != Some(self.id) {
                // A successor owns the mutex and will publish after its own
                // unlock. Never notify while pretending that owner is gone.
                return;
            }
            deferred.active = None;
            if deferred.scopes != 0 {
                return;
            }
            (
                std::mem::take(&mut deferred.causes),
                std::mem::take(&mut deferred.notifications),
            )
        };
        self.memory.deliver_deferred(causes, notifications);
    }
}

/// A synchronous, nestable notification fence for caller-owned locks such as
/// the executor's shared file table. Hold this outside those lock guards and
/// drop it after them. It never owns a lock, waits, or spans an async callback.
pub(crate) struct DeferredNotifications<'a> {
    memory: &'a GuestMemory,
}

impl Drop for DeferredNotifications<'_> {
    fn drop(&mut self) {
        let (causes, notifications) = {
            let mut deferred = self.memory.mapping.deferred.lock().unwrap();
            deferred.scopes = deferred
                .scopes
                .checked_sub(1)
                .expect("notification scope retired twice");
            if deferred.scopes != 0 || deferred.active.is_some() {
                return;
            }
            (
                std::mem::take(&mut deferred.causes),
                std::mem::take(&mut deferred.notifications),
            )
        };
        self.memory.deliver_deferred(causes, notifications);
    }
}

pub(super) struct MemoryCopyAccess<'a> {
    memory: &'a GuestMemory,
    copy: Option<CopyAccess>,
}

impl<'a> MemoryCopyAccess<'a> {
    pub(super) fn new(memory: &'a GuestMemory, copy: CopyAccess) -> Self {
        Self {
            memory,
            copy: Some(copy),
        }
    }
}

impl std::ops::Deref for MemoryCopyAccess<'_> {
    type Target = CopyAccess;
    fn deref(&self) -> &CopyAccess {
        self.copy.as_ref().unwrap()
    }
}

impl Drop for MemoryCopyAccess<'_> {
    fn drop(&mut self) {
        let notification = self.copy.take().unwrap().retire_deferred();
        {
            let mut deferred = self.memory.mapping.deferred.lock().unwrap();
            if deferred.active.is_some() || deferred.scopes != 0 {
                deferred.notifications.push(notification);
                return;
            }
        }
        notification.notify();
    }
}

pub(crate) struct SharedFileRangePlan {
    pub(crate) address: u64,
    pub(crate) length: usize,
    pub(crate) file: OwnedFd,
    pub(crate) offset: u64,
    pub(crate) readable: bool,
    pub(crate) writable: bool,
    pub(crate) max_writable: bool,
    pub(crate) cursors: Option<AllocationCursors>,
}

pub(crate) struct PrivateRangePlan<'a> {
    pub(crate) address: u64,
    pub(crate) length: usize,
    pub(crate) contents: Option<&'a [u8]>,
    /// None retires user access; it does not zero the outgoing file.
    pub(crate) permissions: Option<(bool, bool)>,
    pub(crate) cursors: Option<AllocationCursors>,
}

impl GuestMemory {
    pub(crate) fn defer_notifications(&self) -> DeferredNotifications<'_> {
        let mut deferred = self.mapping.deferred.lock().unwrap();
        deferred.scopes = deferred
            .scopes
            .checked_add(1)
            .expect("notification scope count exhausted");
        DeferredNotifications { memory: self }
    }

    fn deliver_deferred(
        &self,
        causes: Vec<(EntryOrigin, Arc<Error>)>,
        notifications: Vec<crate::entry::CopyRetirement>,
    ) {
        // The caller transferred these queues after releasing all its guards.
        // A newly entering transaction gets its own record/queues and cannot
        // be cleared by this older delivery.
        for (origin, cause) in causes {
            self.entry_gate()
                .poison(origin, Error::SharedFailure(cause));
        }
        for notification in notifications {
            notification.notify();
        }
    }

    pub(crate) fn allocation_guard(&self) -> AllocationGuard<'_> {
        let guard = self
            .mapping
            .allocation
            .lock()
            .expect("KVM allocation transaction lock poisoned");
        let id = {
            let mut deferred = self.mapping.deferred.lock().unwrap();
            deferred.next = deferred
                .next
                .checked_add(1)
                .expect("allocation owner generation exhausted");
            let id = deferred.next;
            deferred.active = Some(id);
            id
        };
        AllocationGuard {
            memory: self,
            guard: Some(guard),
            id,
        }
    }

    /// Capture only after the caller's own address/backing/copy guards retire.
    /// An enclosing layout transaction queues the same Arc until its allocator
    /// unlock; trait adapters still return EIO rather than fabricate EFAULT.
    pub(crate) fn capture_shared_file_error(&self, error: Error) -> Error {
        // SharedFailure is an ownership wrapper used by unrelated failures
        // too. Only an actual shared-file primary belongs to this terminal
        // path; preserve the caller's wrappers and cleanup evidence below.
        if !matches!(
            error.primary(),
            Error::SharedFileCapability { .. } | Error::SharedFileCopy { .. }
        ) {
            return error;
        }
        let origin = self.entry_origin();
        let cause = match error {
            Error::SharedFailure(cause) => cause,
            error => Arc::new(error),
        };
        {
            let mut deferred = self.mapping.deferred.lock().unwrap();
            if deferred.active.is_some() || deferred.scopes != 0 {
                if !deferred
                    .causes
                    .iter()
                    .any(|(_, old)| Arc::ptr_eq(old, &cause))
                {
                    deferred.causes.push((origin, cause.clone()));
                }
                return self.entry_gate().pending_failure().map_or_else(
                    || Error::SharedFailure(deferred.causes[0].1.clone()),
                    |failure| failure.error(),
                );
            }
        }
        self.entry_gate()
            .poison(origin, Error::SharedFailure(cause))
            .error()
    }

    pub(crate) fn contains_shared_file(&self) -> bool {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .values()
            .any(|page| matches!(page._slice.backing.kind, BackingKind::OrdinaryFile { .. }))
    }

    pub(crate) fn range_contains_shared_file(&self, address: u64, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        let last = address.saturating_add(length as u64 - 1) / PAGE_SIZE as u64;
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .range(address / PAGE_SIZE as u64..=last)
            .any(|(_, page)| matches!(page._slice.backing.kind, BackingKind::OrdinaryFile { .. }))
    }

    pub(crate) fn file_write_permitted(&self, address: u64, length: usize) -> bool {
        if length == 0 {
            return true;
        }
        let last = address.saturating_add(length as u64 - 1) / PAGE_SIZE as u64;
        !self
            .mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .range(address / PAGE_SIZE as u64..=last)
            .any(|(_, page)| {
                matches!(
                    page._slice.backing.kind,
                    BackingKind::OrdinaryFile {
                        max_writable: false
                    }
                )
            })
    }

    /// The executor supplies an independently owned descriptor retained while
    /// its ordinary-file classification is still protected by the file table.
    pub(crate) fn publish_shared_file_range<'a>(
        &'a self,
        allocation: AllocationGuard<'a>,
        plan: SharedFileRangePlan,
    ) -> Result<()> {
        let flags = unsafe { libc::fcntl(plan.file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::MemoryMapping(io::Error::last_os_error()));
        }
        if flags & libc::O_PATH != 0
            || !matches!(flags & libc::O_ACCMODE, libc::O_RDONLY | libc::O_RDWR)
        {
            return Err(Error::MemoryMapping(io::Error::from_raw_os_error(
                libc::EACCES,
            )));
        }
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(plan.file.as_raw_fd(), metadata.as_mut_ptr()) } != 0 {
            return Err(Error::MemoryMapping(io::Error::last_os_error()));
        }
        if unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(Error::MemoryMapping(io::Error::from_raw_os_error(
                libc::ENODEV,
            )));
        }
        let seals = unsafe { libc::fcntl(plan.file.as_raw_fd(), libc::F_GET_SEALS) };
        let seals = if seals < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINVAL) {
                return Err(Error::MemoryMapping(error));
            }
            0
        } else {
            seals
        };
        let write_sealed = seals & (libc::F_SEAL_WRITE | libc::F_SEAL_FUTURE_WRITE) != 0;
        if plan.writable && write_sealed {
            return Err(Error::MemoryMapping(io::Error::from_raw_os_error(
                libc::EPERM,
            )));
        }
        let max_writable = flags & libc::O_ACCMODE == libc::O_RDWR && !write_sealed;
        if plan.max_writable != max_writable || (plan.writable && !max_writable) {
            return Err(Error::MemoryMapping(io::Error::from_raw_os_error(
                libc::EACCES,
            )));
        }
        let offset = usize::try_from(plan.offset).map_err(|_| Error::InvalidMemoryLayout {
            guest_base: plan.address,
            size: plan.length,
        })?;
        let end = offset
            .checked_add(plan.length)
            .filter(|end| libc::off_t::try_from(*end).is_ok())
            .ok_or(Error::InvalidMemoryLayout {
                guest_base: plan.address,
                size: plan.length,
            })?;
        let backing = Arc::new(Backing {
            fd: plan.file,
            // This is a geometry bound, NOT an assertion about mutable st_size.
            length: end,
            host_access: Mutex::new(()),
            kind: BackingKind::OrdinaryFile { max_writable },
        });
        let slice =
            BackingSlice::new(backing, offset, plan.length).map_err(Error::MemoryMapping)?;
        self.publish_range(
            allocation,
            plan.address,
            slice,
            Some((plan.readable, plan.writable)),
            plan.cursors,
        )
    }

    pub(crate) fn publish_private_range<'a>(
        &'a self,
        allocation: AllocationGuard<'a>,
        plan: PrivateRangePlan<'_>,
    ) -> Result<()> {
        let backing = Arc::new(Backing::new(plan.length).map_err(Error::MemoryMapping)?);
        if let Some(contents) = plan.contents {
            if contents.len() > plan.length {
                return Err(Error::InvalidMemoryLayout {
                    guest_base: plan.address,
                    size: contents.len(),
                });
            }
            write_backing(&backing, contents).map_err(Error::MemoryMapping)?;
        }
        let slice = BackingSlice::new(backing, 0, plan.length).map_err(Error::MemoryMapping)?;
        self.publish_range(
            allocation,
            plan.address,
            slice,
            plan.permissions,
            plan.cursors,
        )
    }

    fn publish_range<'a>(
        &'a self,
        allocation: AllocationGuard<'a>,
        address: u64,
        slice: BackingSlice,
        permissions: Option<(bool, bool)>,
        cursors: Option<AllocationCursors>,
    ) -> Result<()> {
        self.publish_range_from(allocation, address, slice, permissions, cursors, None)
    }

    // Only snapshot_with_shared_files may supply a source VMA. Its parent
    // allocation and Closed token retain that exact installed source until
    // this operation returns. Normal mmap continues to validate new VMA rights.
    fn publish_range_from<'a>(
        &'a self,
        allocation: AllocationGuard<'a>,
        address: u64,
        slice: BackingSlice,
        permissions: Option<(bool, bool)>,
        cursors: Option<AllocationCursors>,
        inherited: Option<NonNull<u8>>,
    ) -> Result<()> {
        self.check_copy_failure()?;
        if self.mapping.sync_mmu.lock().unwrap().as_ref() == Some(&false) {
            return Err(Error::SynchronousMmuUnsupported);
        }
        if !std::ptr::eq(allocation.memory, self) {
            // Comparing handles would reject an equivalent clone; the actual
            // mapping identity is what binds its allocator to this image.
            if !Arc::ptr_eq(&allocation.memory.mapping, &self.mapping) {
                return Err(Error::MappingPublicationGateMismatch);
            }
        }
        if !address.is_multiple_of(PAGE_SIZE as u64) {
            return Err(Error::InvalidMemoryLayout {
                guest_base: address,
                size: slice.length,
            });
        }
        let offset = self.checked_offset(address, slice.length)?;
        let reservation = if permissions.is_some() {
            Some(self.reserve_region(address, slice.length as u64, RegionKind::Mmap)?)
        } else {
            None
        };
        let gate = self.entry_gate();
        let expected = gate.generation().map_err(|failure| failure.error())?;
        // All BTreeMap nodes and terminal ownership storage are prepared before
        // the first destructive mmap. The publication closure only updates
        // existing nodes and swaps complete images.
        let mut prepared = self.mapping.address_space.lock().unwrap().clone();
        let first = address / PAGE_SIZE as u64;
        let pages = slice.length / PAGE_SIZE;
        for i in 0..pages {
            let page = first + i as u64;
            prepared.backing_pages.insert(
                page,
                InstalledBackingPage {
                    _generation: expected,
                    _slice: BackingSlice {
                        backing: slice.backing.clone(),
                        offset: slice.offset + i * PAGE_SIZE,
                        length: PAGE_SIZE,
                    },
                    mapping: self.mapping.original_pages[offset / PAGE_SIZE + i],
                },
            );
            match permissions {
                Some((readable, writable)) => {
                    prepared.pages.insert(
                        page,
                        if readable {
                            UserPageState::Accessible { writable }
                        } else {
                            UserPageState::NoAccess
                        },
                    );
                }
                None => {
                    prepared.pages.remove(&page);
                    if !prepared
                        .reservations
                        .get(&page)
                        .is_some_and(|kind| kind.permanent())
                    {
                        prepared.reservations.remove(&page);
                    }
                }
            }
        }
        if let Some(cursors) = cursors {
            prepared.cursors = Some(cursors);
        }
        let domain = prepared
            .backing_pages
            .values()
            .any(|page| matches!(page._slice.backing.kind, BackingKind::OrdinaryFile { .. }));
        let ledger = self.prepare_mapping_retirement(&prepared);
        let mut closed = match gate
            .try_close_quiescent_single()
            .map_err(|failure| failure.error())?
        {
            Some(closed) => {
                // Check the hardware requirement while no HVA has changed.
                // Error paths explicitly release allocation before reopening.
                let recorded = *self.mapping.sync_mmu.lock().unwrap();
                let supported = match recorded {
                    Some(supported) => Ok(supported),
                    None => Kvm::new().map(|kvm| kvm.check_extension(Cap::SyncMmu)),
                };
                if !matches!(supported, Ok(true)) {
                    drop(reservation);
                    drop(allocation);
                    drop(closed);
                    return match supported {
                        Ok(false) => Err(Error::SynchronousMmuUnsupported),
                        Err(error) => Err(error.into()),
                        Ok(true) => unreachable!(),
                    };
                }
                closed
            }
            None => match gate
                .try_close_quiescent_unattached()
                .map_err(|failure| failure.error())?
            {
                Some(closed) => closed,
                None => {
                    return Err(Error::SharedFileCapability {
                        operation: "mapping publication",
                        reason: "requires one stopped vCPU (or unattached memory), no host copies and no retained operands",
                    });
                }
            },
        };
        if let Err(failure) = closed.set_single_member_domain(domain) {
            drop(reservation);
            drop(allocation);
            drop(closed);
            return Err(failure.error());
        }
        let mapping = &self.mapping;
        let result = closed
            .publish(self.entry_origin(), expected, move |generation| {
                let outcome = (|| {
                    // Keep the ledger before mmap; after failure it excludes the
                    // uncertain target even if a foreign allocator fills the gap.
                    let mut ownership = mapping.retirement.lock().unwrap();
                    *ownership = Some(ledger);
                    let target = mapping.base_address + offset;
                    let protection = match slice.backing.kind {
                        BackingKind::Fixed | BackingKind::OrdinaryFile { max_writable: true } => {
                            libc::PROT_READ | libc::PROT_WRITE
                        }
                        BackingKind::OrdinaryFile {
                            max_writable: false,
                        } => libc::PROT_READ,
                    };
                    ownership
                        .as_mut()
                        .unwrap()
                        .lose_fixed_target(offset, slice.length, None);
                    let installed = match inherited {
                        Some(source) => self.duplicate_shared_image(source, target, slice.length),
                        None => self.map_shared_image(target, &slice, protection),
                    };
                    let installed = match installed {
                        Ok(installed) => installed,
                        Err(error) => {
                            ownership.as_mut().unwrap().mapping_errno = error.raw_os_error();
                            return Err(Error::MemoryMapping(error));
                        }
                    };
                    if installed.expose_provenance() != target {
                        ownership
                            .as_mut()
                            .unwrap()
                            .note_unexpected_address(installed.expose_provenance(), slice.length);
                        return Err(Error::MemoryMapping(io::Error::other(
                            "shared-file MAP_FIXED returned an unexpected address",
                        )));
                    }
                    let owner = ownership.as_mut().unwrap();
                    owner.ambiguous = None;
                    owner.owned = [
                        Some(WriteAliasRange {
                            address: mapping.base_address,
                            length: mapping.slice.length,
                        }),
                        None,
                        None,
                    ];
                    let installed =
                        NonNull::new(installed.cast::<u8>()).expect("nonzero fixed arena address");
                    for i in 0..pages {
                        let page = prepared.backing_pages.get_mut(&(first + i as u64)).unwrap();
                        page._generation = generation;
                        // Pointer arithmetic remains within this mmap's returned
                        // range; no Rust access dereferences ordinary-file pages.
                        page.mapping = unsafe {
                            NonNull::new_unchecked(installed.as_ptr().add(i * PAGE_SIZE))
                        };
                    }
                    *mapping.address_space.lock().unwrap() = prepared;
                    if let Some(reservation) = reservation {
                        reservation.commit();
                    }
                    Ok(InstalledMapping::new(generation))
                })();
                drop(allocation);
                outcome
            })
            .map_err(|failure| failure.error());
        drop(closed);
        result.map(|_| ())
    }

    /// Fork into a distinct address space, preserving retained shared VMAs.
    /// This is not CLONE_VM: private bytes, permissions, gate and HVA ownership
    /// all belong to the new child. Anonymous MAP_SHARED has no such metadata
    /// yet and retains its pre-existing behavior outside this bounded repair.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-919): Review shared-file fork ownership and copies.
    pub(super) fn snapshot_with_shared_files(
        &self,
        allocation: AllocationGuard<'_>,
    ) -> Result<Self> {
        if !Arc::ptr_eq(&allocation.memory.mapping, &self.mapping) {
            return Err(Error::MappingPublicationGateMismatch);
        }
        let gate = self.entry_gate();
        let closed = match gate.try_close_quiescent_single().map_err(|e| e.error())? {
            Some(closed) => closed,
            None => gate.try_close_quiescent_unattached().map_err(|e| e.error())?
                .ok_or(Error::SharedFileCapability {
                    operation: "shared-file fork snapshot",
                    reason: "requires one stopped vCPU (or unattached memory), no copies and no retained operands",
                })?,
        };
        // Drop releases allocation BEFORE Closed, including during unwinding.
        // Opening admission may synchronously notify a caller-owned observer.
        let authority = ClosedSnapshot {
            allocation: Some(allocation),
            closed: Some(closed),
        };
        let parent_state = self.mapping.address_space.lock().unwrap().clone();
        let child = Self::new(self.guest_base(), self.len())?;
        #[cfg(test)]
        let child = {
            let mut child = child;
            child.test_shared_map = self.test_shared_map.clone();
            child
        };
        let mut buffer = vec![0; (1024 * 1024).min(self.len())];
        let mut cursor = self.guest_base();
        let mut inherited = Vec::new();
        for (&page, installed) in &parent_state.backing_pages {
            if !matches!(
                installed._slice.backing.kind,
                BackingKind::OrdinaryFile { .. }
            ) {
                continue;
            }
            let address = page * PAGE_SIZE as u64;
            self.copy_private_snapshot_interval(
                authority.closed.as_ref().unwrap(),
                &child,
                cursor,
                address,
                &mut buffer,
            )?;
            inherited.push((page, installed.clone()));
            cursor = address + PAGE_SIZE as u64;
        }
        self.copy_private_snapshot_interval(
            authority.closed.as_ref().unwrap(),
            &child,
            cursor,
            self.guest_end(),
            &mut buffer,
        )?;
        let mut child_state = parent_state.clone();
        // All private extents now belong to the child's base backing. Shared
        // installed pointers are recreated only from actual child syscall results.
        child_state.backing_pages.clear();
        *child.mapping.address_space.lock().unwrap() = child_state;
        for (page, installed) in inherited {
            let permissions = match parent_state.pages.get(&page) {
                Some(UserPageState::Accessible { writable }) => Some((true, *writable)),
                Some(UserPageState::NoAccess) => Some((false, false)),
                None => None,
            };
            // A page is always contained in one existing host VMA. Do not
            // merge numerically adjacent publications into an unproved VMA.
            child.publish_range_from(
                child.allocation_guard(),
                page * PAGE_SIZE as u64,
                installed._slice,
                permissions,
                None,
                Some(installed.mapping),
            )?;
        }
        self.check_copy_failure()?;
        child.check_copy_failure()?;
        drop(authority);
        Ok(child)
    }

    #[cfg(test)]
    pub(crate) fn fail_shared_snapshot_duplication_for_test(&mut self) {
        self.test_shared_map = Some(Arc::new(|_, _| {
            Some(Err(io::Error::from_raw_os_error(libc::ENOMEM)))
        }));
    }

    fn copy_private_snapshot_interval(
        &self,
        closed: &Closed,
        child: &GuestMemory,
        mut address: u64,
        end: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        if !closed.belongs_to(&self.entry_gate()) {
            return Err(Error::MappingPublicationGateMismatch);
        }
        while address < end {
            let length = usize::try_from(end - address).unwrap().min(buffer.len());
            let offset = self.checked_offset(address, length)?;
            let chunks = self.mapping.host_chunks(offset, length);
            if chunks
                .iter()
                .any(|chunk| chunk.backing.kind != BackingKind::Fixed)
            {
                return Err(Error::SharedFileCapability {
                    operation: "shared-file fork private copy",
                    reason: "a retained file extent must be inherited without reading its bytes",
                });
            }
            // The exact Closed token excludes guest entry and every ordinary
            // host copy; allocation excludes publication. Taking CopyAccess
            // here would wait for our own close. No file pointer is dereferenced.
            self.read_host_chunks(&chunks, address, &mut buffer[..length])?;
            child.write_raw(address, &buffer[..length])?;
            address += length as u64;
        }
        Ok(())
    }

    pub(crate) fn retire_shared_files_for_exec(&self) -> Result<()> {
        loop {
            let allocation = self.allocation_guard();
            let range = {
                let state = self.mapping.address_space.lock().unwrap();
                let mut pages = state.backing_pages.iter().filter(|(_, page)| {
                    matches!(page._slice.backing.kind, BackingKind::OrdinaryFile { .. })
                });
                pages.next().map(|(&first, _)| {
                    let mut end = first + 1;
                    for (&page, _) in pages {
                        if page != end {
                            break;
                        }
                        end += 1;
                    }
                    (first * PAGE_SIZE as u64, (end - first) as usize * PAGE_SIZE)
                })
            };
            let Some((address, length)) = range else {
                return Ok(());
            };
            self.publish_private_range(
                allocation,
                PrivateRangePlan {
                    address,
                    length,
                    contents: None,
                    permissions: None,
                    cursors: None,
                },
            )?;
        }
    }
}

impl GuestMemory {
    /// Synchronize mapped file spans in address order. Holes are remembered
    /// while later mapped spans are visited, as Linux msync does. No address,
    /// allocation or backing mutex spans the potentially blocking host call.
    pub(crate) fn sync_shared_file_range(
        &self,
        address: u64,
        length: usize,
        flags: i32,
    ) -> Result<i64> {
        self.check_copy_failure()?;
        if !address.is_multiple_of(PAGE_SIZE as u64)
            || flags & !(libc::MS_SYNC | libc::MS_ASYNC | libc::MS_INVALIDATE) != 0
            || flags & libc::MS_SYNC != 0 && flags & libc::MS_ASYNC != 0
        {
            return Ok(-(libc::EINVAL as i64));
        }
        if length == 0 {
            return Ok(0);
        }
        // Match Linux mm/msync.c's unsigned page rounding: a length that
        // wraps to zero succeeds, while a nonzero interval may still overflow.
        let rounded = length.wrapping_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if rounded == 0 {
            return Ok(0);
        }
        let Some(end) = address.checked_add(rounded as u64) else {
            return Ok(-(libc::ENOMEM as i64));
        };
        let copy = self.copy_access()?;
        let retained = self
            .entry_gate()
            .retain_operand(&copy)
            .map_err(|failure| failure.error())?;
        let (spans, hole) = {
            let state = self.mapping.address_space.lock().unwrap();
            let mut spans: Vec<(usize, usize, Arc<Backing>, usize)> = Vec::new();
            let mut hole = address < self.guest_base() || end > self.guest_end();
            let scan_start = if flags == libc::MS_ASYNC && address < self.guest_base() {
                end
            } else {
                address.max(self.guest_base())
            };
            let scan_end = end.min(self.guest_end());
            for page in scan_start / PAGE_SIZE as u64..scan_end / PAGE_SIZE as u64 {
                if (page * PAGE_SIZE as u64) < self.guest_base()
                    || (page * PAGE_SIZE as u64) >= self.guest_end()
                    || !state.pages.contains_key(&page)
                {
                    hole = true;
                    if flags == libc::MS_ASYNC {
                        break;
                    }
                    continue;
                }
                let Some(installed) = state.backing_pages.get(&page) else {
                    continue;
                };
                if !matches!(
                    installed._slice.backing.kind,
                    BackingKind::OrdinaryFile { .. }
                ) {
                    continue;
                }
                let host = self.mapping.base_address
                    + (page * PAGE_SIZE as u64 - self.guest_base()) as usize;
                if let Some(last) = spans.last_mut()
                    && last.0 + last.1 == host
                    && Arc::ptr_eq(&last.2, &installed._slice.backing)
                    && last.3 + last.1 == installed._slice.offset
                {
                    last.1 += PAGE_SIZE;
                } else {
                    spans.push((
                        host,
                        PAGE_SIZE,
                        installed._slice.backing.clone(),
                        installed._slice.offset,
                    ));
                }
            }
            (spans, hole)
        };
        drop(copy);
        let mut result = if hole { -(libc::ENOMEM as i64) } else { 0 };
        for (host, length, _backing, _offset) in spans {
            // The retained operand prevents replacement, and each span retains
            // its file description. Linux owns writeback and errno; no retry.
            #[cfg(test)]
            if let Some(errno) = self
                .test_shared_sync
                .as_ref()
                .and_then(|hook| hook(host, length, flags))
            {
                result = -(errno as i64);
                break;
            }
            let rc = unsafe {
                libc::msync(
                    std::ptr::with_exposed_provenance_mut::<libc::c_void>(host),
                    length,
                    flags,
                )
            };
            if rc != 0 {
                result = -(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO) as i64);
                break;
            }
        }
        drop(retained);
        self.check_copy_failure()?;
        Ok(result)
    }

    pub(super) fn copy_file_chunk(
        &self,
        chunk: &HostChunk,
        local: *mut u8,
        write: bool,
        address: u64,
        requested: usize,
        transferred: usize,
    ) -> Result<()> {
        let local_iov = libc::iovec {
            iov_base: local.cast(),
            iov_len: chunk.length,
        };
        let remote_iov = libc::iovec {
            iov_base: chunk.mapping.as_ptr().cast(),
            iov_len: chunk.length,
        };
        // Both iovec structures and the local bytes are owned host storage.
        // Only the remote numeric address names a truncate-capable file page;
        // no Rust reference or raw memcpy touches that page. The actual host
        // PID is required, not the virtual process identity from the executor.
        let pid = unsafe { libc::getpid() };
        let copied = unsafe {
            if write {
                libc::process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0)
            } else {
                libc::process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0)
            }
        };
        if copied == chunk.length as isize {
            return Ok(());
        }
        let (actual, source) = if copied < 0 {
            (0, io::Error::last_os_error())
        } else {
            (
                copied as usize,
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short fault-contained shared-file copy",
                ),
            )
        };
        Err(Error::SharedFileCopy {
            operation: if write { "write" } else { "read" },
            address,
            requested,
            transferred: transferred + actual,
            prior_transferred: 0,
            source,
        })
    }

    pub(super) fn read_host_chunks(
        &self,
        chunks: &[HostChunk],
        address: u64,
        destination: &mut [u8],
    ) -> Result<()> {
        let _guard = self
            .mapping
            .slice
            .backing
            .host_access
            .lock()
            .expect("guest memory lock poisoned");
        let mut copied = 0;
        for chunk in chunks {
            let target = unsafe { destination.as_mut_ptr().add(copied) };
            match chunk.backing.kind {
                BackingKind::OrdinaryFile { .. } => {
                    self.copy_file_chunk(chunk, target, false, address, destination.len(), copied)?
                }
                BackingKind::Fixed => unsafe {
                    std::ptr::copy_nonoverlapping(chunk.mapping.as_ptr(), target, chunk.length);
                },
            }
            copied += chunk.length;
        }
        debug_assert_eq!(copied, destination.len());
        Ok(())
    }

    pub(super) fn deferred_failure(&self) -> Option<Arc<Error>> {
        self.mapping
            .deferred
            .lock()
            .unwrap()
            .causes
            .first()
            .map(|(_, cause)| cause.clone())
    }
}

impl GuestMemory {
    /// Called before KVM slot/vCPU registration. Serializing this record with
    /// publication closes the unattached-memory race without holding an
    /// allocator across entry registration or its callbacks.
    pub(crate) fn record_kvm_sync_mmu(&self, supported: bool) -> Result<()> {
        let _allocation = self.allocation_guard();
        self.check_copy_failure()?;
        if !supported && self.contains_shared_file() {
            return Err(Error::SynchronousMmuUnsupported);
        }
        let mut record = self.mapping.sync_mmu.lock().unwrap();
        *record = Some(record.is_none_or(|old| old) && supported);
        Ok(())
    }
}

impl UserMemory {
    /// Check scalar copyout before a syscall consumes its own state. The
    /// eventual scalar store repeats this check; preflight does not promise
    /// rollback of arbitrary intervening syscall effects.
    pub(crate) fn preflight_atomic_store(&self, address: u64, length: usize) -> Result<()> {
        self.memory.with_copy(|copy| {
            self.translate_admitted(address, length, copy)?;
            if self.user_writable_prefix_admitted(address, length, copy)? != length {
                return Err(Error::GuestMemoryAccessDenied { address, length });
            }
            if self.memory.range_contains_shared_file(address, length) {
                return Err(Error::SharedFileCapability { operation: "atomic scalar store", reason: "truncate-capable file backing has no proven fault-contained atomic store" });
            }
            Ok(())
        })
    }
}

impl GuestMemory {
    pub(super) fn prepare_mapping_retirement(
        &self,
        prepared: &AddressSpaceState,
    ) -> Box<WriteAliasMapping> {
        let old = self.mapping.address_space.lock().unwrap();
        let mut extents =
            Vec::with_capacity(prepared.backing_pages.len() + old.backing_pages.len() + 1);
        extents.push(WriteAliasExtent {
            offset: 0,
            slice: self.mapping.slice.clone(),
        });
        for image in [prepared, &*old] {
            for (&page, installed) in &image.backing_pages {
                extents.push(WriteAliasExtent {
                    offset: (page * PAGE_SIZE as u64 - self.guest_base()) as usize,
                    slice: installed._slice.clone(),
                });
            }
        }
        Box::new(WriteAliasMapping {
            address: self.mapping.base_address,
            length: self.len(),
            ambiguous: None,
            mapping_errno: None,
            unexpected: None,
            unexpected_bounds_valid: false,
            owned: [
                Some(WriteAliasRange {
                    address: self.mapping.base_address,
                    length: self.len(),
                }),
                None,
                None,
            ],
            cleanup: [None; 3],
            _extents: extents,
            next: None,
        })
    }
}

impl GuestMemory {
    fn duplicate_shared_image(
        &self,
        source: NonNull<u8>,
        target: usize,
        length: usize,
    ) -> io::Result<*mut libc::c_void> {
        #[cfg(test)]
        if let Some(result) = self
            .test_shared_map
            .as_ref()
            .and_then(|hook| hook(target, length))
        {
            return result.map(std::ptr::with_exposed_provenance_mut::<libc::c_void>);
        }
        // Linux mremap(old_size=0) duplicates an existing shareable VMA,
        // retaining its vm_file, vm_pgoff and flags. Unlike a fresh mmap, it
        // preserves an existing writable view after F_SEAL_FUTURE_WRITE.
        // https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/mm/mremap.c#L1683
        // SAFETY: parent Closed+allocation retain this exact one-page source;
        // target belongs to the child's preallocated ownership ledger. FIXED
        // can unmap target before a later failure, so the caller marked it
        // ambiguous before entering this syscall and never retries that hole.
        let result = unsafe {
            libc::mremap(
                source.as_ptr().cast::<libc::c_void>(),
                0,
                length,
                libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
                std::ptr::with_exposed_provenance_mut::<libc::c_void>(target),
            )
        };
        if result == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    pub(super) fn map_shared_image(
        &self,
        target: usize,
        slice: &BackingSlice,
        protection: i32,
    ) -> io::Result<*mut libc::c_void> {
        #[cfg(test)]
        if let Some(result) = self
            .test_shared_map
            .as_ref()
            .and_then(|hook| hook(target, slice.length))
        {
            return result.map(std::ptr::with_exposed_provenance_mut::<libc::c_void>);
        }
        // Exact numeric target belongs to our retained ownership ledger. Only
        // the returned mmap pointer is used for subsequent pointer arithmetic.
        let result = unsafe {
            libc::mmap(
                std::ptr::with_exposed_provenance_mut::<libc::c_void>(target),
                slice.length,
                protection,
                libc::MAP_SHARED | libc::MAP_FIXED,
                slice.backing.fd.as_raw_fd(),
                slice.offset as libc::off_t,
            )
        };
        if result == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
}

/// Vector adapters keep the bytes from earlier elements even when a later
/// file-backed element faults. Do not fold that separate extent into the
/// current element's address/length or convert the terminal result to EFAULT.
pub(super) fn vector_copy_error(mut error: Error, prior: usize) -> Error {
    if let Error::SharedFileCopy {
        prior_transferred, ..
    } = &mut error
    {
        *prior_transferred = prior;
    }
    error
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::future::Future;
    use std::io::IoSlice;
    use std::io::IoSliceMut;
    use std::os::unix::fs::FileExt;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Context;
    use std::task::Wake;
    use std::task::Waker;

    use reverie::syscalls::Addr;
    use reverie::syscalls::AddrMut;
    use reverie::syscalls::AddrSlice;
    use reverie::syscalls::AddrSliceMut;

    use super::*;

    const BASE: u64 = 0x10000;
    const P: u64 = PAGE_SIZE as u64;

    fn file(pages: usize) -> File {
        let mut name = b"/tmp/reverie-shared-file-XXXXXX\0".to_vec();
        let fd = unsafe { libc::mkstemp(name.as_mut_ptr().cast()) };
        assert!(fd >= 0, "mkstemp: {}", io::Error::last_os_error());
        assert_eq!(unsafe { libc::unlink(name.as_ptr().cast()) }, 0);
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len((pages * PAGE_SIZE) as u64).unwrap();
        for page in 0..pages {
            file.write_all_at(&vec![(page as u8 + 1) * 0x11; PAGE_SIZE], page as u64 * P)
                .unwrap();
        }
        file
    }

    fn fixture(pages: usize) -> GuestMemory {
        let memory = GuestMemory::new(BASE, pages * PAGE_SIZE).unwrap();
        memory.enable_user_access();
        memory
            .map_user_range(BASE, pages as u64 * P, false)
            .unwrap();
        memory
    }

    fn install(memory: &GuestMemory, file: &File, address: u64, pages: usize, offset: u64) {
        memory
            .publish_shared_file_range(
                memory.allocation_guard(),
                SharedFileRangePlan {
                    address,
                    length: pages * PAGE_SIZE,
                    file: file.try_clone().unwrap().into(),
                    offset,
                    readable: true,
                    writable: true,
                    max_writable: true,
                    cursors: None,
                },
            )
            .unwrap();
    }

    fn replace(
        memory: &GuestMemory,
        address: u64,
        pages: usize,
        contents: Option<&[u8]>,
        mapped: bool,
    ) {
        memory
            .publish_private_range(
                memory.allocation_guard(),
                PrivateRangePlan {
                    address,
                    length: pages * PAGE_SIZE,
                    contents,
                    permissions: mapped.then_some((true, true)),
                    cursors: None,
                },
            )
            .unwrap();
    }

    fn bytes(file: &File, offset: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        file.read_exact_at(&mut bytes, offset).unwrap();
        bytes
    }

    fn read(memory: &GuestMemory, address: u64, length: usize) -> Vec<u8> {
        let mut bytes = vec![0; length];
        memory.read_raw(address, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn unrelated_shared_failure_keeps_its_wrapper_without_poisoning_memory() {
        for deferred in [false, true] {
            for file_cleanup in [false, true] {
                let memory = fixture(1);
                let gate = memory.entry_gate();
                let generation = gate.generation().unwrap();
                let original = Arc::new(Error::GuestWorkerPanic);
                let wrapped = if file_cleanup {
                    // A secondary file error must not replace the unrelated
                    // primary as the reason to poison this memory domain.
                    Arc::new(Error::WithCleanup {
                        primary: original.clone(),
                        cleanup: vec![Arc::new(Error::SharedFileCapability {
                            operation: "cleanup control",
                            reason: "secondary is not the primary",
                        })],
                    })
                } else {
                    original.clone()
                };
                let notifications = deferred.then(|| memory.defer_notifications());
                let returned =
                    memory.capture_shared_file_error(Error::SharedFailure(wrapped.clone()));
                let Error::SharedFailure(actual) = returned else {
                    panic!("unrelated failure ownership wrapper changed");
                };
                assert!(Arc::ptr_eq(&actual, &wrapped));
                assert!(matches!(actual.primary(), Error::GuestWorkerPanic));
                assert!(memory.deferred_failure().is_none());
                assert!(gate.pending_failure().is_none());
                drop(notifications);
                assert!(memory.deferred_failure().is_none());
                assert!(gate.pending_failure().is_none());
                assert_eq!(gate.generation().unwrap(), generation);
                assert_eq!(read(&memory, BASE, 4), [0; 4]);
            }
        }
    }

    #[test]
    fn wrapped_shared_file_primaries_preserve_identity_and_cleanup() {
        fn assert_cleanup(error: &Error, cause: &Arc<Error>, cleanup_cause: &Arc<Error>) {
            match error {
                Error::SharedFailure(inner) => assert_cleanup(inner, cause, cleanup_cause),
                Error::WithCleanup { primary, cleanup } => {
                    assert!(Arc::ptr_eq(primary, cause));
                    assert_eq!(cleanup.len(), 1);
                    assert!(Arc::ptr_eq(&cleanup[0], cleanup_cause));
                }
                _ => panic!("shared-file capture lost the cleanup wrapper"),
            }
        }

        for deferred in [false, true] {
            for file_copy in [false, true] {
                for wrapper in 0..3 {
                    let memory = fixture(1);
                    let gate = memory.entry_gate();
                    let cause = Arc::new(if file_copy {
                        Error::SharedFileCopy {
                            operation: "write",
                            address: BASE,
                            requested: 8,
                            transferred: 2,
                            prior_transferred: 4,
                            source: io::Error::from_raw_os_error(libc::EFAULT),
                        }
                    } else {
                        Error::SharedFileCapability {
                            operation: "atomic scalar store",
                            reason: "capture identity control",
                        }
                    });
                    let cleanup = Arc::new(Error::GuestWorkerPanic);
                    let make_aggregate = || Error::WithCleanup {
                        primary: cause.clone(),
                        cleanup: vec![cleanup.clone()],
                    };
                    let shared_wrapper = Arc::new(make_aggregate());
                    let error = match wrapper {
                        0 => Error::SharedFailure(cause.clone()),
                        1 => Error::SharedFailure(shared_wrapper.clone()),
                        2 => make_aggregate(),
                        _ => unreachable!(),
                    };
                    let notifications = deferred.then(|| memory.defer_notifications());
                    let returned = memory.capture_shared_file_error(error);
                    assert!(returned.retains_primary(&cause));
                    if wrapper == 1 {
                        assert!(returned.retains_primary(&shared_wrapper));
                    }
                    if wrapper != 0 {
                        assert_cleanup(&returned, &cause, &cleanup);
                    }
                    assert_eq!(gate.pending_failure().is_none(), deferred);
                    drop(notifications);
                    let pending = gate
                        .pending_failure()
                        .expect("file primary was not captured");
                    let terminal = pending.error();
                    assert!(terminal.retains_primary(&cause));
                    if wrapper == 1 {
                        assert!(terminal.retains_primary(&shared_wrapper));
                    }
                    if wrapper != 0 {
                        assert_cleanup(&terminal, &cause, &cleanup);
                    }
                    assert_eq!(pending.causes().len(), 1);
                    assert!(memory.deferred_failure().is_none());
                }
            }
        }
    }

    #[test]
    fn shared_file_is_live_across_fd_writes_overlap_and_repeated_msync() {
        let memory = fixture(4);
        let file = file(3);
        install(&memory, &file, BASE, 2, P);
        install(&memory, &file, BASE + 2 * P, 1, P);
        assert_eq!(read(&memory, BASE, 4), [0x22; 4]);
        memory.write_raw(BASE + 9, b"map!").unwrap();
        // Both descriptors and overlapping VMAs see changes before msync.
        assert_eq!(bytes(&file, P + 9, 4), b"map!");
        assert_eq!(read(&memory, BASE + 2 * P + 9, 4), b"map!");
        file.write_all_at(b"fd!!", P + 13).unwrap();
        assert_eq!(read(&memory, BASE + 13, 4), b"fd!!");
        assert_eq!(read(&memory, BASE + 2 * P + 13, 4), b"fd!!");
        for _ in 0..3 {
            assert_eq!(
                memory
                    .sync_shared_file_range(BASE, 3 * PAGE_SIZE, libc::MS_SYNC)
                    .unwrap(),
                0
            );
            assert_eq!(bytes(&file, P + 9, 8), b"map!fd!!");
        }
        assert_eq!(bytes(&file, 0, PAGE_SIZE), vec![0x11; PAGE_SIZE]);
        // This tests live page-cache coherence, not crash/power-loss durability.
    }

    #[test]
    fn shared_file_retains_description_after_fd_reuse() {
        let memory = fixture(1);
        let original = file(1);
        let observer = original.try_clone().unwrap();
        install(&memory, &original, BASE, 1, 0);
        let replacement = file(1);
        replacement.write_all_at(b"other", 0).unwrap();
        // dup2 atomically replaces our still-owned fd; there is no close/open
        // race with another test's host descriptor allocator.
        assert_eq!(
            unsafe { libc::dup2(replacement.as_raw_fd(), original.as_raw_fd()) },
            original.as_raw_fd()
        );
        drop(original);
        memory.write_raw(BASE, b"owned").unwrap();
        assert_eq!(
            memory
                .sync_shared_file_range(BASE, PAGE_SIZE, libc::MS_SYNC)
                .unwrap(),
            0
        );
        assert_eq!(bytes(&observer, 0, 5), b"owned");
        assert_eq!(bytes(&replacement, 0, 5), b"other");
    }

    #[test]
    fn private_replacement_and_partial_retirement_preserve_outgoing_file() {
        let memory = fixture(3);
        let original = file(3);
        let replacement = file(1);
        let original_bytes = bytes(&original, 0, 3 * PAGE_SIZE);
        install(&memory, &original, BASE, 3, 0);
        replace(&memory, BASE + P, 1, None, false);
        assert!(memory.contains_shared_file());
        assert!(memory.entry_gate().single_member_domain_active());
        assert!(!memory.user_range_is_mapped(BASE + P, P));
        assert_eq!(read(&memory, BASE, 8), [0x11; 8]);
        assert_eq!(read(&memory, BASE + 2 * P, 8), [0x33; 8]);
        assert_eq!(bytes(&original, 0, 3 * PAGE_SIZE), original_bytes);
        replacement.write_all_at(b"new-file", 0).unwrap();
        install(&memory, &replacement, BASE, 1, 0);
        assert_eq!(read(&memory, BASE, 8), b"new-file");
        replace(&memory, BASE, 1, Some(b"private!"), true);
        assert_eq!(read(&memory, BASE, 8), b"private!");
        assert_eq!(bytes(&replacement, 0, 8), b"new-file");
        assert!(memory.contains_shared_file());
        memory.retire_shared_files_for_exec().unwrap();
        assert!(!memory.contains_shared_file());
        assert!(!memory.entry_gate().single_member_domain_active());
        assert_eq!(bytes(&original, 0, 3 * PAGE_SIZE), original_bytes);
        let child = memory.snapshot().unwrap();
        child.write_raw(BASE, b"child!!!").unwrap();
        assert_eq!(read(&memory, BASE, 8), b"private!");
    }

    #[test]
    fn readonly_and_sealed_file_maximum_is_enforced_before_publication() {
        let file = file(1);
        let path = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(raw >= 0);
        let readonly = unsafe { OwnedFd::from_raw_fd(raw) };
        let memory = fixture(1);
        memory
            .publish_shared_file_range(
                memory.allocation_guard(),
                SharedFileRangePlan {
                    address: BASE,
                    length: PAGE_SIZE,
                    file: readonly,
                    offset: 0,
                    readable: true,
                    writable: false,
                    max_writable: false,
                    cursors: None,
                },
            )
            .unwrap();
        assert_eq!(read(&memory, BASE, 4), [0x11; 4]);
        assert!(!memory.file_write_permitted(BASE, PAGE_SIZE));
        assert!(matches!(
            memory.map_user_permissions(BASE, P, true, true),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
        assert!(matches!(
            memory.user().put_user_i32(BASE, 7),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
        assert!(memory.entry_gate().pending_failure().is_none());
        assert_eq!(bytes(&file, 0, 4), [0x11; 4]);

        for seal in [libc::F_SEAL_WRITE, libc::F_SEAL_FUTURE_WRITE] {
            let raw = unsafe {
                libc::memfd_create(
                    c"shared-file-seal-test".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                )
            };
            assert!(raw >= 0);
            let sealed = unsafe { File::from_raw_fd(raw) };
            sealed.set_len(P).unwrap();
            sealed.write_all_at(b"sealed", 0).unwrap();
            assert_eq!(
                unsafe { libc::fcntl(sealed.as_raw_fd(), libc::F_ADD_SEALS, seal,) },
                0
            );
            let memory = fixture(1);
            memory.write_raw(BASE, b"before").unwrap();
            let plan = |writable| SharedFileRangePlan {
                address: BASE,
                length: PAGE_SIZE,
                file: sealed.try_clone().unwrap().into(),
                offset: 0,
                readable: true,
                writable,
                max_writable: false,
                cursors: None,
            };
            let error = memory
                .publish_shared_file_range(memory.allocation_guard(), plan(true))
                .unwrap_err();
            assert!(
                matches!(error, Error::MemoryMapping(ref e) if e.raw_os_error() == Some(libc::EPERM))
            );
            assert_eq!(read(&memory, BASE, 6), b"before");
            assert!(!memory.contains_shared_file());
            memory
                .publish_shared_file_range(memory.allocation_guard(), plan(false))
                .unwrap();
            assert_eq!(read(&memory, BASE, 6), b"sealed");
            assert!(!memory.file_write_permitted(BASE, PAGE_SIZE));
        }
    }

    #[test]
    fn truncate_copy_keeps_exact_prefix_and_errno() {
        for write in [false, true] {
            let memory = fixture(2);
            let file = file(2);
            install(&memory, &file, BASE, 2, 0);
            file.set_len(P).unwrap();
            let mut destination = vec![0x55; 2 * PAGE_SIZE];
            let result = if write {
                memory.user().copy_to_user(BASE, &vec![0x77; 2 * PAGE_SIZE])
            } else {
                memory.read_raw(BASE, &mut destination)
            };
            let error = result.unwrap_err();
            assert!(matches!(error.primary(), Error::SharedFileCopy {
                operation, address: BASE, requested, transferred, prior_transferred: 0, source,
            } if *operation == if write { "write" } else { "read" }
                && *requested == 2 * PAGE_SIZE && *transferred == PAGE_SIZE
                && source.raw_os_error() == Some(libc::EFAULT)));
            assert_eq!(memory.entry_gate().test_state().copies, 0);
            assert!(memory.entry_gate().pending_failure().is_some());
            if write {
                assert_eq!(bytes(&file, 0, PAGE_SIZE), vec![0x77; PAGE_SIZE]);
            } else {
                assert_eq!(&destination[..PAGE_SIZE], vec![0x11; PAGE_SIZE]);
                assert_eq!(&destination[PAGE_SIZE..], vec![0x55; PAGE_SIZE]);
            }
            assert_eq!(file.metadata().unwrap().len(), P);
        }
    }

    #[test]
    fn atomic_store_refuses_before_private_prefix_and_permission_fault_wins() {
        for width in [2, 4] {
            for writable in [false, true] {
                let memory = fixture(2);
                memory.write_raw(BASE, &vec![0x44; 2 * PAGE_SIZE]).unwrap();
                // A separate original-backing view can inspect private prefix
                // bytes even after the tested Mapping is terminally poisoned.
                let observer =
                    GuestMemory::from_backing_slice(BASE, memory.mapping.slice.clone()).unwrap();
                let file = file(1);
                install(&memory, &file, BASE + P, 1, 0);
                memory
                    .map_user_permissions(BASE + P, P, true, writable)
                    .unwrap();
                let address = BASE + P - 1;
                let result = if width == 2 {
                    memory.user().put_user_i16(address, 0x1234)
                } else {
                    memory.user().put_user_i32(address, 0x12345678)
                };
                let error = result.unwrap_err();
                if writable {
                    assert!(matches!(
                        error.primary(),
                        Error::SharedFileCapability {
                            operation: "atomic scalar store",
                            ..
                        }
                    ));
                    assert!(memory.entry_gate().pending_failure().is_some());
                } else {
                    assert!(matches!(error, Error::GuestMemoryAccessDenied { .. }));
                    assert!(memory.entry_gate().pending_failure().is_none());
                }
                assert_eq!(read(&observer, BASE + P - 4, 4), [0x44; 4]);
                assert_eq!(bytes(&file, 0, 8), [0x11; 8]);
            }
        }
        let memory = fixture(2);
        let file = file(1);
        install(&memory, &file, BASE + P, 1, 0);
        let error = memory
            .user()
            .preflight_atomic_store(BASE + P - 1, 4)
            .unwrap_err();
        assert!(matches!(
            error.primary(),
            Error::SharedFileCapability {
                operation: "atomic scalar store",
                ..
            }
        ));
        assert_eq!(bytes(&file, 0, 4), [0x11; 4]);
    }

    fn vector_transfer<M: MemoryAccess>(
        mut adapter: M,
        write: bool,
        output: &mut [u8],
    ) -> std::result::Result<usize, Errno> {
        if write {
            let mut first = unsafe {
                AddrSliceMut::from_raw_parts(AddrMut::from_raw(BASE as usize).unwrap(), 4)
            };
            let mut second = unsafe {
                AddrSliceMut::from_raw_parts(AddrMut::from_raw((BASE + P) as usize).unwrap(), 4)
            };
            adapter.write_vectored(
                &[IoSlice::new(b"donefail")],
                &mut [unsafe { first.as_ioslice_mut() }, unsafe {
                    second.as_ioslice_mut()
                }],
            )
        } else {
            let first =
                unsafe { AddrSlice::from_raw_parts(Addr::from_raw(BASE as usize).unwrap(), 4) };
            let second = unsafe {
                AddrSlice::from_raw_parts(Addr::from_raw((BASE + P) as usize).unwrap(), 4)
            };
            adapter.read_vectored(
                &[unsafe { first.as_ioslice() }, unsafe {
                    second.as_ioslice()
                }],
                &mut [IoSliceMut::new(output)],
            )
        }
    }

    #[test]
    fn vector_copy_failure_preserves_prior_element_count() {
        for write in [false, true] {
            for user in [false, true] {
                let memory = fixture(2);
                memory.write_raw(BASE, b"head").unwrap();
                let file = file(1);
                install(&memory, &file, BASE + P, 1, 0);
                file.set_len(0).unwrap();
                let observer =
                    GuestMemory::from_backing_slice(BASE, memory.mapping.slice.clone()).unwrap();
                let mut output = [0x55; 8];
                let result = if user {
                    vector_transfer(memory.user(), write, &mut output)
                } else {
                    vector_transfer(memory.clone(), write, &mut output)
                };
                assert_eq!(result, Err(Errno::EIO));
                let failure = memory.entry_gate().pending_failure().unwrap().error();
                assert!(matches!(failure.primary(), Error::SharedFileCopy {
                    address, requested: 4, transferred: 0, prior_transferred: 4, source, ..
                } if *address == BASE + P && source.raw_os_error() == Some(libc::EFAULT)));
                if write {
                    assert_eq!(read(&observer, BASE, 4), b"done");
                } else {
                    assert_eq!(output, *b"headUUUU");
                }
                assert_eq!(memory.entry_gate().test_state().copies, 0);
            }
        }
    }

    #[test]
    fn snapshot_shares_file_offsets_and_keeps_private_memory_independent() {
        let memory = fixture(5);
        let original = file(3);
        install(&memory, &original, BASE + P, 2, P);
        install(&memory, &original, BASE + 3 * P, 1, P);
        memory.write_raw(BASE, b"private-parent").unwrap();
        let participant = memory.entry_gate().register().unwrap();
        let child = memory.snapshot().unwrap();
        assert!(!Arc::ptr_eq(&memory.mapping, &child.mapping));
        assert!(!Arc::ptr_eq(&memory.entry_gate(), &child.entry_gate()));
        assert_ne!(memory.host_address(), child.host_address());
        assert!(memory.entry_gate().single_member_domain_active());
        assert!(child.entry_gate().single_member_domain_active());
        assert_eq!(child.separately_backed_pages(), 3);
        child.write_raw(BASE, b"private-child!").unwrap();
        assert_eq!(read(&memory, BASE, 14), b"private-parent");
        assert_eq!(read(&child, BASE, 14), b"private-child!");
        child.write_raw(BASE + P + 9, b"child").unwrap();
        assert_eq!(read(&memory, BASE + P + 9, 5), b"child");
        assert_eq!(read(&memory, BASE + 3 * P + 9, 5), b"child");
        assert_eq!(bytes(&original, P + 9, 5), b"child");
        original.write_all_at(b"file!", 2 * P + 13).unwrap();
        assert_eq!(read(&child, BASE + 2 * P + 13, 5), b"file!");
        assert_eq!(bytes(&original, 0, PAGE_SIZE), vec![0x11; PAGE_SIZE]);
        // Permission metadata belongs to the child, not its source process.
        child
            .map_user_permissions(BASE + P, P, true, false)
            .unwrap();
        assert!(child.user().copy_to_user(BASE + P, b"x").is_err());
        memory.user().copy_to_user(BASE + P, b"p").unwrap();
        assert_eq!(read(&child, BASE + P, 1), b"p");
        let second = memory.snapshot().unwrap();
        second.write_raw(BASE + P + 20, b"second").unwrap();
        assert_eq!(read(&child, BASE + P + 20, 6), b"second");
        drop(participant);
        drop(memory);
        child.write_raw(BASE + 2 * P, b"alive").unwrap();
        assert_eq!(read(&second, BASE + 2 * P, 5), b"alive");
        assert_eq!(bytes(&original, 2 * P, 5), b"alive");
    }

    #[test]
    fn snapshot_keeps_shared_storage_after_fd_reuse_and_parent_retirement() {
        let memory = fixture(3);
        let original = file(2);
        let observer = original.try_clone().unwrap();
        install(&memory, &original, BASE, 2, 0);
        let unrelated = file(1);
        unrelated.write_all_at(b"other", 0).unwrap();
        assert_eq!(
            unsafe { libc::dup2(unrelated.as_raw_fd(), original.as_raw_fd()) },
            original.as_raw_fd()
        );
        drop(original);
        let child = memory.snapshot().unwrap();
        replace(&memory, BASE, 1, Some(b"new-private"), true);
        memory.retire_shared_files_for_exec().unwrap();
        assert!(!memory.contains_shared_file());
        assert!(child.contains_shared_file());
        child.write_raw(BASE + P, b"child").unwrap();
        assert_eq!(bytes(&observer, P, 5), b"child");
        assert_eq!(bytes(&observer, 0, 5), vec![0x11; 5]);
        assert_eq!(bytes(&unrelated, 0, 5), b"other");
        assert_eq!(read(&memory, BASE, 11), b"new-private");
        assert_eq!(
            child
                .sync_shared_file_range(BASE, 2 * PAGE_SIZE, libc::MS_SYNC)
                .unwrap(),
            0
        );
    }

    #[test]
    fn snapshot_preserves_preexisting_memfd_vma_after_future_write_seal() {
        let fd = unsafe {
            libc::memfd_create(
                c"fork-inherited-view".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(fd >= 0, "memfd setup: {}", io::Error::last_os_error());
        let file = unsafe { File::from_raw_fd(fd) };
        file.set_len(2 * P).unwrap();
        file.write_all_at(b"before", P).unwrap();
        let memory = fixture(2);
        install(&memory, &file, BASE, 1, P);
        assert_eq!(
            unsafe {
                libc::fcntl(
                    file.as_raw_fd(),
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_FUTURE_WRITE,
                )
            },
            0
        );
        let fresh = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                P as libc::off_t,
            )
        };
        assert_eq!(
            fresh,
            libc::MAP_FAILED,
            "a fresh writable VMA must not impersonate inheritance"
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        let child = memory.snapshot().unwrap();
        assert!(child.file_write_permitted(BASE, PAGE_SIZE));
        child.write_raw(BASE, b"after!").unwrap();
        assert_eq!(read(&memory, BASE, 6), b"after!");
        assert_eq!(bytes(&file, P, 6), b"after!");
        assert_eq!(bytes(&file, 0, PAGE_SIZE), vec![0; PAGE_SIZE]);
    }

    #[test]
    fn snapshot_readonly_file_preserves_maximum_and_protection() {
        let memory = fixture(2);
        let original = file(1);
        let readonly = File::open(format!("/proc/self/fd/{}", original.as_raw_fd())).unwrap();
        memory
            .publish_shared_file_range(
                memory.allocation_guard(),
                SharedFileRangePlan {
                    address: BASE,
                    length: PAGE_SIZE,
                    file: readonly.into(),
                    offset: 0,
                    readable: true,
                    writable: false,
                    max_writable: false,
                    cursors: None,
                },
            )
            .unwrap();
        let child = memory.snapshot().unwrap();
        assert_eq!(read(&child, BASE, PAGE_SIZE), vec![0x11; PAGE_SIZE]);
        assert!(!child.file_write_permitted(BASE, PAGE_SIZE));
        assert!(matches!(
            child.map_user_permissions(BASE, P, true, true),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
        assert!(child.user().copy_to_user(BASE, b"x").is_err());
        assert!(child.entry_gate().pending_failure().is_none());
        original.write_all_at(b"host", 0).unwrap();
        assert_eq!(read(&child, BASE, 4), b"host");
        assert_eq!(read(&memory, BASE, 4), b"host");
    }

    #[test]
    fn snapshot_never_reads_truncated_shared_pages() {
        let memory = fixture(3);
        let original = file(1);
        install(&memory, &original, BASE + P, 1, 0);
        memory.write_raw(BASE, b"private").unwrap();
        original.set_len(0).unwrap();
        let child = memory.snapshot().unwrap();
        assert_eq!(read(&child, BASE, 7), b"private");
        assert!(memory.entry_gate().pending_failure().is_none());
        assert!(child.entry_gate().pending_failure().is_none());
        let mut output = [0x7b; 4];
        let failure = child.read_raw(BASE + P, &mut output).unwrap_err();
        assert!(matches!(failure.primary(), Error::SharedFileCopy {
            address, requested: 4, transferred: 0, source, ..
        } if *address == BASE + P && source.raw_os_error() == Some(libc::EFAULT)));
        assert_eq!(output, [0x7b; 4]);
        assert!(child.entry_gate().pending_failure().is_some());
        assert!(
            memory.entry_gate().pending_failure().is_none(),
            "child cancellation owns its gate only"
        );
    }

    #[test]
    fn snapshot_requires_quiescence_and_notifies_after_parent_unlock() {
        let memory = fixture(2);
        let original = file(1);
        install(&memory, &original, BASE, 1, 0);
        let participant = memory.entry_gate().register().unwrap();
        let gate = memory.entry_gate();
        let copy = gate.try_copy(None).unwrap().unwrap();
        assert!(matches!(
            memory.snapshot().unwrap_err(),
            Error::SharedFileCapability { .. }
        ));
        let retained = gate.retain_operand(&copy).unwrap();
        drop(copy);
        assert!(matches!(
            memory.snapshot().unwrap_err(),
            Error::SharedFileCapability { .. }
        ));
        assert!(gate.pending_failure().is_none());
        drop(retained);
        let observation = observations(&memory);
        let mut change = Box::pin(gate.subscribe());
        assert!(
            change
                .as_mut()
                .poll(&mut Context::from_waker(&Waker::from(observation.clone())))
                .is_pending()
        );
        let child = memory.snapshot().unwrap();
        assert!(child.contains_shared_file());
        let rows = observation.rows.lock().unwrap();
        assert!(!rows.is_empty());
        assert!(
            rows.iter().all(|row| *row == (true, true, true, 0)),
            "notifications must follow every parent guard release: {rows:?}"
        );
        drop(rows);
        assert_eq!(gate.test_state().copies, 0);
        drop(participant);
    }

    #[test]
    fn snapshot_failed_duplication_preserves_parent_and_foreign_destination() {
        let mut memory = fixture(3);
        let original = file(2);
        install(&memory, &original, BASE, 2, 0);
        let before = bytes(&original, 0, 2 * PAGE_SIZE);
        let foreign = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let target_record = foreign.clone();
        let call_record = calls.clone();
        memory.test_shared_map = Some(Arc::new(move |target, length| {
            if call_record.fetch_add(1, Ordering::SeqCst) == 0 {
                return None;
            }
            assert_eq!(length, PAGE_SIZE);
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::with_exposed_provenance_mut(target),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_eq!(ptr.addr(), target);
            unsafe { std::ptr::write_bytes(ptr.cast::<u8>(), 0xa7, length) };
            target_record.store(target, Ordering::SeqCst);
            Some(Err(io::Error::from_raw_os_error(libc::ENOMEM)))
        }));
        assert!(
            matches!(memory.snapshot().unwrap_err().primary(), Error::MemoryMapping(e) if e.raw_os_error() == Some(libc::ENOMEM))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(memory.entry_gate().pending_failure().is_none());
        assert_eq!(read(&memory, BASE, 2 * PAGE_SIZE), before);
        assert_eq!(bytes(&original, 0, 2 * PAGE_SIZE), before);
        let target = foreign.load(Ordering::SeqCst);
        assert_ne!(target, 0);
        let mut resident = 0;
        assert_eq!(
            unsafe {
                libc::mincore(
                    std::ptr::with_exposed_provenance_mut(target),
                    PAGE_SIZE,
                    &mut resident,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                std::slice::from_raw_parts(
                    std::ptr::with_exposed_provenance::<u8>(target),
                    PAGE_SIZE,
                )
            },
            vec![0xa7; PAGE_SIZE]
        );
        // Only this test owns the planted foreign mapping; production cleanup
        // must have excluded it, even after a preceding child VMA succeeded.
        assert_eq!(
            unsafe { libc::munmap(std::ptr::with_exposed_provenance_mut(target), PAGE_SIZE) },
            0
        );
    }

    #[test]
    fn discard_and_metadata_remap_still_refuse_shared_history() {
        // Fork is now a real inherited view. These other unsupported layout
        // operations retain their no-effect capability boundaries unchanged.
        for operation in 0..3 {
            let memory = fixture(2);
            let file = file(1);
            install(&memory, &file, BASE, 1, 0);
            let before = bytes(&file, 0, PAGE_SIZE);
            let result = match operation {
                0 => memory.discard_pages(BASE, 2 * PAGE_SIZE),
                1 => memory.remap_user_range(BASE, P, BASE + P, P),
                2 => memory.unmap_user_range(BASE, P),
                _ => unreachable!(),
            };
            assert!(matches!(
                result.unwrap_err().primary(),
                Error::SharedFileCapability { .. }
            ));
            assert!(memory.contains_shared_file());
            assert!(memory.user_range_is_mapped(BASE, P));
            assert_eq!(bytes(&file, 0, PAGE_SIZE), before);
        }
    }

    #[test]
    fn failed_fixed_publication_never_unmaps_foreign_target() {
        for target_page in [0, 1, 2] {
            let mut memory = fixture(3);
            let file = file(3);
            install(&memory, &file, BASE, 3, 0);
            let base = memory.mapping.base_address;
            let foreign = base + target_page * PAGE_SIZE;
            memory.test_shared_map = Some(Arc::new(move |target, length| {
                assert_eq!((target, length), (foreign, PAGE_SIZE));
                let ptr = unsafe {
                    libc::mmap(
                        std::ptr::with_exposed_provenance_mut(target),
                        length,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                assert_eq!(ptr.addr(), target);
                unsafe { std::ptr::write_bytes(ptr.cast::<u8>(), 0xa7, length) };
                // Model Linux's failed MAP_FIXED gap being filled by another
                // allocator. The file publisher never owns this replacement.
                Some(Err(io::Error::from_raw_os_error(libc::ENOMEM)))
            }));
            let result = memory.publish_private_range(
                memory.allocation_guard(),
                PrivateRangePlan {
                    address: BASE + target_page as u64 * P,
                    length: PAGE_SIZE,
                    contents: None,
                    permissions: Some((true, true)),
                    cursors: None,
                },
            );
            assert!(
                matches!(result.unwrap_err().primary(), Error::MemoryMapping(e) if e.raw_os_error() == Some(libc::ENOMEM))
            );
            assert!(memory.entry_gate().pending_failure().is_some());
            drop(memory);
            let mut resident = 0_u8;
            assert_eq!(
                unsafe {
                    libc::mincore(
                        std::ptr::with_exposed_provenance_mut(foreign),
                        PAGE_SIZE,
                        &mut resident,
                    )
                },
                0
            );
            assert_eq!(
                unsafe {
                    std::slice::from_raw_parts(
                        std::ptr::with_exposed_provenance::<u8>(foreign),
                        PAGE_SIZE,
                    )
                },
                vec![0xa7; PAGE_SIZE]
            );
            let retained = retained_write_aliases_for_test()
                .into_iter()
                .find(|row| row.address == base && row.ambiguous == Some((foreign, PAGE_SIZE)))
                .unwrap();
            assert!(retained.owned_ranges.iter().all(Option::is_none));
            assert!(retained.backing_count >= 4);
            // Explicitly retire only the test-owned foreign mapping. The
            // terminal ledger must never retry that ambiguous address.
            assert_eq!(
                unsafe { libc::munmap(std::ptr::with_exposed_provenance_mut(foreign), PAGE_SIZE) },
                0
            );
            assert_eq!(
                bytes(&file, target_page as u64 * P, 4),
                vec![(target_page as u8 + 1) * 0x11; 4]
            );
        }
    }

    #[test]
    fn cleanup_refusal_retains_exact_extents_without_gate_or_retry() {
        // Exercise the exact retirement engine used by Mapping::drop, with a
        // planted kernel refusal and a real test-owned reservation. The
        // separate foreign-target test exercises Mapping::drop itself.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let address = ptr.expose_provenance();
        let backing = Arc::new(Backing::new(PAGE_SIZE).unwrap());
        let weak = Arc::downgrade(&backing);
        let ledger = Box::new(WriteAliasMapping {
            address,
            length: PAGE_SIZE,
            ambiguous: None,
            mapping_errno: None,
            unexpected: None,
            unexpected_bounds_valid: false,
            owned: [
                Some(WriteAliasRange {
                    address,
                    length: PAGE_SIZE,
                }),
                None,
                None,
            ],
            cleanup: [None; 3],
            _extents: vec![WriteAliasExtent {
                offset: 0,
                slice: BackingSlice::new(backing, 0, PAGE_SIZE).unwrap(),
            }],
            next: None,
        });
        let mut calls = Vec::new();
        let retired = ledger.retire_with(|range| {
            calls.push((range.address, range.length));
            Err(libc::EBUSY)
        });
        assert_eq!(calls, [(address, PAGE_SIZE)]);
        assert_ne!(retired.retention_id, 0);
        let row = retained_write_aliases_for_test()
            .into_iter()
            .find(|row| row.retention_id == retired.retention_id)
            .unwrap();
        assert_eq!(row.owned_ranges, [Some((address, PAGE_SIZE)), None, None]);
        assert_eq!(
            row.cleanup_errors,
            [Some((address, PAGE_SIZE, libc::EBUSY)), None, None]
        );
        assert_eq!(row.ambiguous, None);
        assert_eq!(row.backing_count, 1);
        assert!(weak.upgrade().is_some());
        assert!(retired.error(None).is_some());
        let mut resident = 0;
        assert_eq!(unsafe { libc::mincore(ptr, PAGE_SIZE, &mut resident) }, 0);
        // The test alone owns this planted refusal's reservation. No production
        // retry or global ledger sweep is performed by this cleanup.
        assert_eq!(unsafe { libc::munmap(ptr, PAGE_SIZE) }, 0);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn native_msync_preserves_order_errors_and_releases_locks() {
        let mut memory = fixture(4);
        let file = file(2);
        install(&memory, &file, BASE, 1, 0);
        install(&memory, &file, BASE + 2 * P, 1, P);
        memory.unmap_user_range(BASE + P, P).unwrap();
        let base = memory.mapping.base_address;
        let weak = Arc::downgrade(&memory.mapping);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        memory.test_shared_sync = Some(Arc::new(move |host, length, flags| {
            let mapping = weak.upgrade().unwrap();
            assert!(mapping.allocation.try_lock().is_ok());
            assert!(mapping.address_space.try_lock().is_ok());
            assert!(mapping.slice.backing.host_access.try_lock().is_ok());
            let state = mapping.entry_gate.test_state();
            assert_eq!(state.copies, 0);
            assert_eq!(state.retained_operands, 1);
            observed.lock().unwrap().push((host - base, length, flags));
            None // Observe, then execute the real host msync.
        }));
        assert_eq!(
            memory
                .sync_shared_file_range(BASE, 3 * PAGE_SIZE, libc::MS_SYNC)
                .unwrap(),
            -(libc::ENOMEM as i64)
        );
        assert_eq!(
            *calls.lock().unwrap(),
            [
                (0, PAGE_SIZE, libc::MS_SYNC),
                (2 * PAGE_SIZE, PAGE_SIZE, libc::MS_SYNC)
            ]
        );
        calls.lock().unwrap().clear();
        assert_eq!(
            memory
                .sync_shared_file_range(BASE, 3 * PAGE_SIZE, libc::MS_ASYNC)
                .unwrap(),
            -(libc::ENOMEM as i64)
        );
        assert_eq!(*calls.lock().unwrap(), [(0, PAGE_SIZE, libc::MS_ASYNC)]);
        calls.lock().unwrap().clear();
        assert_eq!(
            memory
                .sync_shared_file_range(BASE - P, 2 * PAGE_SIZE, libc::MS_ASYNC)
                .unwrap(),
            -(libc::ENOMEM as i64)
        );
        assert!(calls.lock().unwrap().is_empty());
        let injected = Arc::new(AtomicUsize::new(0));
        let count = injected.clone();
        memory.test_shared_sync = Some(Arc::new(move |_, _, _| {
            count.fetch_add(1, Ordering::SeqCst);
            Some(libc::EIO)
        }));
        assert_eq!(
            memory
                .sync_shared_file_range(BASE, PAGE_SIZE, libc::MS_SYNC)
                .unwrap(),
            -(libc::EIO as i64)
        );
        assert_eq!(injected.load(Ordering::SeqCst), 1);
        for (address, length, flags, errno) in [
            (BASE + 1, PAGE_SIZE, libc::MS_SYNC, libc::EINVAL),
            (
                BASE,
                PAGE_SIZE,
                libc::MS_SYNC | libc::MS_ASYNC,
                libc::EINVAL,
            ),
            (BASE, usize::MAX, libc::MS_SYNC, 0),
            (BASE, usize::MAX - (PAGE_SIZE - 2), libc::MS_SYNC, 0),
            (
                BASE,
                usize::MAX - (PAGE_SIZE - 1),
                libc::MS_SYNC,
                libc::ENOMEM,
            ),
        ] {
            assert_eq!(
                memory
                    .sync_shared_file_range(address, length, flags)
                    .unwrap(),
                -(errno as i64)
            );
        }
        assert_eq!(injected.load(Ordering::SeqCst), 1);
        assert_eq!(memory.entry_gate().test_state().retained_operands, 0);

        // A native VM_LOCKED error proves that the real libc call remains in
        // the successful wrapper route: hook counts alone cannot catch a
        // substituted `0` because shared page-cache bytes are already coherent.
        memory.test_shared_sync = None;
        let locked_address = std::ptr::with_exposed_provenance_mut::<libc::c_void>(base);
        let rc = unsafe { libc::mlock(locked_address, PAGE_SIZE) };
        assert_eq!(rc, 0, "native mlock setup: {}", io::Error::last_os_error());
        struct Unlock(*mut libc::c_void);
        impl Drop for Unlock {
            fn drop(&mut self) {
                assert_eq!(unsafe { libc::munlock(self.0, PAGE_SIZE) }, 0);
            }
        }
        let _locked = Unlock(locked_address);
        let flags = libc::MS_SYNC | libc::MS_INVALIDATE;
        let rc = unsafe { libc::msync(locked_address, PAGE_SIZE, flags) };
        let errno = io::Error::last_os_error().raw_os_error();
        assert_eq!((rc, errno), (-1, Some(libc::EBUSY)));
        let before = bytes(&file, 0, PAGE_SIZE);
        assert_eq!(
            memory
                .sync_shared_file_range(BASE, PAGE_SIZE, flags)
                .unwrap(),
            -(libc::EBUSY as i64)
        );
        assert_eq!(bytes(&file, 0, PAGE_SIZE), before);
        assert!(memory.mapping.allocation.try_lock().is_ok());
        assert!(memory.mapping.address_space.try_lock().is_ok());
        assert!(memory.mapping.slice.backing.host_access.try_lock().is_ok());
        assert_eq!(memory.entry_gate().test_state().retained_operands, 0);
    }

    #[derive(Default)]
    struct Observations {
        rows: Mutex<Vec<(bool, bool, bool, usize)>>,
        mapping: Mutex<Option<std::sync::Weak<Mapping>>>,
    }
    impl Wake for Observations {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let mapping = self
                .mapping
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap();
            let row = (
                mapping.allocation.try_lock().is_ok(),
                mapping.address_space.try_lock().is_ok(),
                mapping.slice.backing.host_access.try_lock().is_ok(),
                mapping.entry_gate.test_state().copies,
            );
            self.rows.lock().unwrap().push(row);
        }
    }
    fn observations(memory: &GuestMemory) -> Arc<Observations> {
        Arc::new(Observations {
            rows: Mutex::new(Vec::new()),
            mapping: Mutex::new(Some(Arc::downgrade(&memory.mapping))),
        })
    }

    #[test]
    fn deferred_copy_failure_preserves_identity_and_notifies_after_allocation() {
        let memory = fixture(1);
        let file = file(1);
        install(&memory, &file, BASE, 1, 0);
        file.set_len(0).unwrap();
        let gate = memory.entry_gate();
        let observation = observations(&memory);
        let mut change = Box::pin(gate.subscribe());
        assert!(
            change
                .as_mut()
                .poll(&mut Context::from_waker(&Waker::from(observation.clone())))
                .is_pending()
        );
        let allocation = memory.allocation_guard();
        let first = memory.read_raw(BASE, &mut [0; 1]).unwrap_err();
        let Error::SharedFailure(first_cause) = first else {
            panic!("lost shared cause")
        };
        assert!(matches!(
            first_cause.primary(),
            Error::SharedFileCopy { transferred: 0, .. }
        ));
        assert!(gate.pending_failure().is_none());
        assert_eq!(gate.test_state().copies, 0);
        assert!(observation.rows.lock().unwrap().is_empty());
        let second = memory.user().put_user_i32(BASE, 0).unwrap_err();
        assert!(second.retains_primary(&first_cause));
        assert!(
            memory
                .check_copy_failure()
                .unwrap_err()
                .retains_primary(&first_cause)
        );
        drop(allocation);
        assert!(
            gate.pending_failure()
                .unwrap()
                .error()
                .retains_primary(&first_cause)
        );
        let rows = observation.rows.lock().unwrap();
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|row| *row == (true, true, true, 0)));
    }

    #[test]
    fn copy_early_exits_defer_notifications_under_allocation() {
        for path in 0..9 {
            let memory = fixture(1);
            let gate = memory.entry_gate();
            let observation = observations(&memory);
            let mut change = Box::pin(gate.subscribe());
            assert!(
                change
                    .as_mut()
                    .poll(&mut Context::from_waker(&Waker::from(observation.clone())))
                    .is_pending()
            );
            let allocation = memory.allocation_guard();
            match path {
                0 => {
                    assert!(memory.read_raw(BASE - 1, &mut [0]).is_err());
                }
                1 => {
                    assert!(memory.try_write_raw(BASE - 1, &[0]).is_err());
                }
                2 => {
                    assert!(
                        memory
                            .try_read_with(|access| access.read_raw(BASE - 1, &mut [0]))
                            .is_err()
                    );
                }
                3 => {
                    assert!(memory.user().copy_to_user(BASE - 1, &[0]).is_err());
                }
                4 => {
                    let mut user = memory.user();
                    assert_eq!(
                        user.write_with_user_access(
                            AddrMut::from_raw((BASE - 1) as usize).unwrap(),
                            &[0]
                        ),
                        Err(Errno::EFAULT)
                    );
                }
                5 | 6 => {
                    let source = unsafe {
                        AddrSlice::from_raw_parts(Addr::from_raw((BASE - 1) as usize).unwrap(), 1)
                    };
                    let mut target = [0];
                    let mut output = [IoSliceMut::new(&mut target)];
                    let result = if path == 5 {
                        memory.read_vectored(&[unsafe { source.as_ioslice() }], &mut output)
                    } else {
                        memory
                            .user()
                            .read_vectored(&[unsafe { source.as_ioslice() }], &mut output)
                    };
                    assert_eq!(result, Err(Errno::EFAULT));
                }
                7 | 8 => {
                    let mut destination = unsafe {
                        AddrSliceMut::from_raw_parts(
                            AddrMut::from_raw((BASE - 1) as usize).unwrap(),
                            1,
                        )
                    };
                    let mut output = [unsafe { destination.as_ioslice_mut() }];
                    let source = [IoSlice::new(b"x")];
                    let result = if path == 7 {
                        memory.clone().write_vectored(&source, &mut output)
                    } else {
                        memory.user().write_vectored(&source, &mut output)
                    };
                    assert_eq!(result, Err(Errno::EFAULT));
                }
                _ => unreachable!(),
            }
            assert_eq!(gate.test_state().copies, 0);
            assert!(gate.pending_failure().is_none());
            assert!(observation.rows.lock().unwrap().is_empty());
            drop(allocation);
            let rows = observation.rows.lock().unwrap();
            assert!(!rows.is_empty(), "path {path} lost retirement notification");
            assert!(rows.iter().all(|row| *row == (true, true, true, 0)));
        }
    }

    #[test]
    fn nested_notification_scopes_wait_for_caller_locks_and_allocation() {
        struct ScopeWake {
            memory: GuestMemory,
            external: Arc<Mutex<()>>,
            rows: Mutex<Vec<(bool, bool, usize)>>,
        }
        impl Wake for ScopeWake {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                let row = (
                    self.external.try_lock().is_ok(),
                    self.memory.mapping.allocation.try_lock().is_ok(),
                    self.memory.entry_gate().test_state().copies,
                );
                self.rows.lock().unwrap().push(row);
            }
        }
        for allocation_last in [false, true] {
            let memory = fixture(1);
            let file = file(1);
            install(&memory, &file, BASE, 1, 0);
            file.set_len(0).unwrap();
            let external = Arc::new(Mutex::new(()));
            let wake = Arc::new(ScopeWake {
                memory: memory.clone(),
                external: external.clone(),
                rows: Mutex::new(Vec::new()),
            });
            let gate = memory.entry_gate();
            let mut change = Box::pin(gate.subscribe());
            assert!(
                change
                    .as_mut()
                    .poll(&mut Context::from_waker(&Waker::from(wake.clone())))
                    .is_pending()
            );
            let outer = memory.defer_notifications();
            let external_guard = external.lock().unwrap();
            let allocation = memory.allocation_guard();
            let inner = memory.defer_notifications();
            let failure = memory.read_raw(BASE, &mut [0]).unwrap_err();
            let Error::SharedFailure(cause) = failure else {
                panic!("typed cause missing")
            };
            assert!(
                memory
                    .check_copy_failure()
                    .unwrap_err()
                    .retains_primary(&cause)
            );
            drop(inner);
            assert!(gate.pending_failure().is_none());
            assert!(wake.rows.lock().unwrap().is_empty());
            drop(external_guard);
            if allocation_last {
                drop(outer);
                assert!(wake.rows.lock().unwrap().is_empty());
                drop(allocation);
            } else {
                drop(allocation);
                assert!(wake.rows.lock().unwrap().is_empty());
                drop(outer);
            }
            assert!(
                gate.pending_failure()
                    .unwrap()
                    .error()
                    .retains_primary(&cause)
            );
            let rows = wake.rows.lock().unwrap();
            assert!(!rows.is_empty());
            assert!(rows.iter().all(|row| *row == (true, true, 0)));
        }
    }

    #[test]
    fn allocation_generation_handoff_does_not_clear_successor() {
        let memory = fixture(1);
        let file = file(1);
        install(&memory, &file, BASE, 1, 0);
        file.set_len(0).unwrap();
        let gate = memory.entry_gate();
        let observation = observations(&memory);
        let mut change = Box::pin(gate.subscribe());
        assert!(
            change
                .as_mut()
                .poll(&mut Context::from_waker(&Waker::from(observation.clone())))
                .is_pending()
        );
        let mut first = memory.allocation_guard();
        let failure = memory.read_raw(BASE, &mut [0]).unwrap_err();
        let Error::SharedFailure(cause) = failure else {
            panic!("typed cause missing")
        };
        // Pause the old Drop exactly after its real unlock, without a timing
        // race or sleep; a successor then acquires and installs its generation.
        drop(first.guard.take());
        let successor = memory.allocation_guard();
        assert_ne!(first.id, successor.id);
        drop(first);
        assert_eq!(
            memory.mapping.deferred.lock().unwrap().active,
            Some(successor.id)
        );
        assert!(gate.pending_failure().is_none());
        assert!(observation.rows.lock().unwrap().is_empty());
        drop(successor);
        assert!(
            gate.pending_failure()
                .unwrap()
                .error()
                .retains_primary(&cause)
        );
        let rows = observation.rows.lock().unwrap();
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|row| *row == (true, true, true, 0)));
    }

    #[test]
    fn busy_copy_refuses_publication_without_reservation_or_byte_effect() {
        let memory = fixture(1);
        memory.write_raw(BASE, b"private").unwrap();
        let file = file(1);
        let gate = memory.entry_gate();
        let generation = gate.generation().unwrap();
        let reservation = memory.reservation_kind(BASE);
        let copy = gate.copy_blocking(None).unwrap();
        let result = memory.publish_shared_file_range(
            memory.allocation_guard(),
            SharedFileRangePlan {
                address: BASE,
                length: PAGE_SIZE,
                file: file.try_clone().unwrap().into(),
                offset: 0,
                readable: true,
                writable: true,
                max_writable: true,
                cursors: None,
            },
        );
        assert!(matches!(
            result,
            Err(Error::SharedFileCapability {
                operation: "mapping publication",
                ..
            })
        ));
        assert_eq!(gate.generation().unwrap(), generation);
        assert_eq!(memory.reservation_kind(BASE), reservation);
        assert!(!gate.single_member_domain_active());
        assert!(!memory.contains_shared_file());
        drop(copy);
        assert_eq!(read(&memory, BASE, 7), b"private");
        assert_eq!(bytes(&file, 0, 7), [0x11; 7]);
    }

    #[test]
    fn sync_mmu_attachment_record_closes_unattached_race() {
        let file = file(1);
        let memory = fixture(1);
        memory.record_kvm_sync_mmu(false).unwrap();
        let result = memory.publish_shared_file_range(
            memory.allocation_guard(),
            SharedFileRangePlan {
                address: BASE,
                length: PAGE_SIZE,
                file: file.try_clone().unwrap().into(),
                offset: 0,
                readable: true,
                writable: true,
                max_writable: true,
                cursors: None,
            },
        );
        assert!(matches!(result, Err(Error::SynchronousMmuUnsupported)));
        assert!(!memory.contains_shared_file());
        assert!(!memory.entry_gate().single_member_domain_active());
        let memory = fixture(1);
        install(&memory, &file, BASE, 1, 0);
        assert!(matches!(
            memory.record_kvm_sync_mmu(false),
            Err(Error::SynchronousMmuUnsupported)
        ));
        memory.record_kvm_sync_mmu(true).unwrap();
        let member = memory.entry_gate().register().unwrap();
        // The recorded capability allows a stopped real member without opening
        // /dev/kvm in this native unit. It does not claim a VM execution result.
        replace(&memory, BASE, 1, None, false);
        assert!(!memory.contains_shared_file());
        assert!(!memory.entry_gate().single_member_domain_active());
        drop(member);
    }
}
