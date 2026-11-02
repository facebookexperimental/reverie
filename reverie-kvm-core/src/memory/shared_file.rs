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
pub struct AllocationGuard<'a> {
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

/// How long a mapping publication waits for the address space's other vCPUs
/// and host copies to stop ([`PUBLICATION_STOP_FAILURE`] after it), and for
/// a host operation using the memory it replaces to return (a refusal by
/// name after it). A vCPU interrupted with the reserved signal stops within
/// microseconds, and a copy is short; the bound is for a thread that never
/// stops, which would otherwise hang the run.
const PUBLICATION_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Why a publication ends when the address space's other vCPUs or host
/// copies did not stop within [`PUBLICATION_STOP_TIMEOUT`]. Nothing a
/// program does keeps them running that long, so this is the backend's own
/// failure ([`Error::SharedFileCapability`]), not a refusal by name.
const PUBLICATION_STOP_FAILURE: &str = "the address space's other vCPUs or host copies did not \
     stop within the publication's bound; this is a defect of the backend to report, not a \
     refusal of the program";

/// What a fork's snapshot of an address space that holds shared views needs.
const FORK_SNAPSHOT_REQUIREMENT: &str =
    "requires one stopped vCPU (or unattached memory), no copies and no retained operands";

#[cfg(test)]
thread_local! {
    /// A unit test's bound in place of `PUBLICATION_STOP_TIMEOUT`, for the
    /// publications its own thread makes.
    static PUBLICATION_STOP_TIMEOUT_FOR_TEST: std::cell::Cell<Option<std::time::Duration>> =
        const { std::cell::Cell::new(None) };
}

fn publication_stop_timeout() -> std::time::Duration {
    #[cfg(test)]
    if let Some(timeout) = PUBLICATION_STOP_TIMEOUT_FOR_TEST.with(std::cell::Cell::get) {
        return timeout;
    }
    PUBLICATION_STOP_TIMEOUT
}

/// What a publication's operation owns while it installs the new image: the
/// held address-space lock, the region reservation and the allocation
/// transaction. They are released in that order however the operation ends,
/// run or dropped unrun: a reservation's rollback takes the address-space
/// lock, and the allocation transaction's release delivers deferred
/// notifications, whose wakers may read memory.
struct PublicationHold<'a> {
    space: Option<MutexGuard<'a, AddressSpaceState>>,
    reservation: Option<PendingReservation>,
    allocation: Option<AllocationGuard<'a>>,
}

impl Drop for PublicationHold<'_> {
    fn drop(&mut self) {
        drop(self.space.take());
        drop(self.reservation.take());
        drop(self.allocation.take());
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
            self.memory
                .mapping
                .deferred_queued
                .store(false, std::sync::atomic::Ordering::Release);
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
pub struct DeferredNotifications<'a> {
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
            self.memory
                .mapping
                .deferred_queued
                .store(false, std::sync::atomic::Ordering::Release);
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
        let memory = self.memory;
        let mut notification = self
            .copy
            .take()
            .unwrap()
            .retire_deferred_with(|| memory.entry_origin());
        {
            let mut deferred = self.memory.mapping.deferred.lock().unwrap();
            if deferred.active.is_some() || deferred.scopes != 0 {
                // Queued past this borrow: keep the issuing context alive
                // until delivery, as a stored origin would.
                notification.keep_issuer(|| memory.entry_origin());
                deferred.notifications.push(notification);
                return;
            }
        }
        notification.notify();
    }
}

pub struct SharedFileRangePlan {
    pub address: u64,
    pub length: usize,
    pub file: OwnedFd,
    pub offset: u64,
    pub readable: bool,
    pub writable: bool,
    pub max_writable: bool,
    pub cursors: Option<AllocationCursors>,
}

/// Where a publication's new HVA view comes from.
#[derive(Clone, Copy)]
enum InstallSource {
    /// A new shared view of the slice's backing.
    Fresh,
    /// A new shared view of the slice's backing, after first copying the
    /// target range's current bytes into that backing.
    CurrentContents,
    /// A duplicate of this exact installed source VMA (fork only).
    Inherited(NonNull<u8>),
}

pub struct PrivateRangePlan<'a> {
    pub address: u64,
    pub length: usize,
    pub contents: Option<&'a [u8]>,
    /// None retires user access; it does not zero the outgoing file.
    pub permissions: Option<(bool, bool)>,
    pub cursors: Option<AllocationCursors>,
}

impl GuestMemory {
    pub fn defer_notifications(&self) -> DeferredNotifications<'_> {
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

    pub fn allocation_guard(&self) -> AllocationGuard<'_> {
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
    pub fn capture_shared_file_error(&self, error: Error) -> Error {
        // SharedFailure is an ownership wrapper used by unrelated failures
        // too. Only an actual shared-file primary belongs to this terminal
        // path; preserve the caller's wrappers and cleanup evidence below.
        if !matches!(
            error.primary(),
            Error::SharedFileCapability { .. }
                | Error::UnsupportedSharedFile { .. }
                | Error::SharedFileCopy { .. }
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
                    self.mapping
                        .deferred_queued
                        .store(true, std::sync::atomic::Ordering::Release);
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

    pub fn contains_shared_file(&self) -> bool {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .values()
            .any(|page| matches!(page._slice.backing.kind, BackingKind::OrdinaryFile { .. }))
    }

    /// Whether any page is a retained shared view: an ordinary file, or
    /// shared anonymous memory that a fork has made reachable from another
    /// address space. Such a page can only be replaced by a publication.
    pub fn contains_retained_shared(&self) -> bool {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .values()
            .any(|page| page._slice.backing.kind.retained_shared())
    }

    pub fn range_contains_retained_shared(&self, address: u64, length: usize) -> bool {
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
            .any(|(_, page)| page._slice.backing.kind.retained_shared())
    }

    pub fn range_contains_shared_file(&self, address: u64, length: usize) -> bool {
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

    pub fn file_write_permitted(&self, address: u64, length: usize) -> bool {
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
    pub fn publish_shared_file_range<'a>(
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

    pub fn publish_private_range<'a>(
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
        self.publish_range_from(
            allocation,
            address,
            slice,
            permissions,
            cursors,
            InstallSource::Fresh,
        )
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
        source: InstallSource,
    ) -> Result<()> {
        self.check_copy_failure()?;
        // A vfork child's copy may not change its shared views: on Linux the
        // change would reach its parent's address space too. Only a guest's
        // own mapping change is a Fresh publication; a fork's inheritance and
        // the sharing of anonymous memory before a fork change no mapping the
        // guest can see. The allocation guard excludes a concurrent change.
        if matches!(source, InstallSource::Fresh)
            && self.shares_parent_address_space()
            && (slice.backing.kind.retained_shared()
                || self.range_contains_retained_shared(address, slice.length))
        {
            return Err(Self::vfork_shared_view_change(
                "mapping change in a vfork child",
            ));
        }
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
        let replaced = offset..offset + slice.length;
        // A close with no participant serves an arena no vCPU has entered yet
        // (a fork's child before it runs); every other has a vCPU to protect.
        let (mut closed, attached) = match gate
            .try_close_quiescent_single()
            .map_err(|failure| failure.error())?
        {
            Some(closed) => (closed, true),
            None => match gate
                .try_close_quiescent_unattached()
                .map_err(|failure| failure.error())?
            {
                Some(closed) => (closed, false),
                // Other vCPUs share the address space, or a host copy or a
                // retained operand is live: a guest's own mapping change
                // closes admission for every vCPU, on this thread, holding
                // its allocation transaction, which no stopping vCPU and no
                // admitted copy needs.
                None if matches!(source, InstallSource::Fresh) => {
                    match gate
                        .close_blocking(publication_stop_timeout())
                        .map_err(|failure| failure.error())?
                    {
                        Some(closed) => (closed, true),
                        // The backend's own vCPUs or copies failed to stop:
                        // its failure, not a refusal of what the program did.
                        None => {
                            drop(reservation);
                            drop(allocation);
                            return Err(Error::SharedFileCapability {
                                operation: "mapping publication",
                                reason: PUBLICATION_STOP_FAILURE,
                            });
                        }
                    }
                }
                None => {
                    drop(reservation);
                    drop(allocation);
                    return Err(Error::SharedFileCapability {
                        operation: "mapping publication",
                        reason: "requires one stopped vCPU (or unattached memory), no host copies and no retained operands",
                    });
                }
            },
        };
        if attached {
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
        }
        // A host operation still using memory the publication replaces would
        // read or write the old mapping, or the new one, at a host-timed
        // point: wait, bounded, for it to return, and refuse by name if it
        // does not. One waiting on another guest thread (a host futex wait)
        // may not return while this close holds every vCPU outside the guest.
        // That is the program's doing (a mapping over memory another of its
        // threads is blocked on), so the refusal is a named one.
        let quiet = closed
            .wait_for_operands_outside(&replaced, publication_stop_timeout())
            .map_err(|failure| failure.error());
        if !matches!(quiet, Ok(true)) {
            drop(reservation);
            drop(allocation);
            drop(closed);
            return match quiet {
                Ok(_) => Err(Error::UnsupportedSharedFile {
                    operation: "mapping publication",
                    reason: "a host operation still uses memory in the replaced range",
                }),
                Err(error) => Err(error),
            };
        }
        if matches!(source, InstallSource::CurrentContents)
            && let Err(error) = self.copy_current_contents(&closed, address, &slice)
        {
            drop(reservation);
            drop(allocation);
            drop(closed);
            return Err(error);
        }
        // The new image is prepared from the current one, under one hold of
        // the address-space lock that lasts until it is installed: with
        // several vCPUs, another thread's call (a Tool callback's scratch
        // exposure, for one) may change the page map at any other time, and
        // installing an image prepared earlier would undo that change. All
        // BTreeMap nodes and terminal ownership storage are prepared before
        // the first destructive mmap. The publication closure only updates
        // existing nodes and swaps complete images.
        let space = self.mapping.address_space.lock().unwrap();
        let mut prepared = space.clone();
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
                    prepared
                        .pages
                        .insert(page, UserPageState::undeclared(readable, writable));
                }
                None => {
                    prepared.pages.remove(&page);
                    prepared.file_pages.edit().remove(&page);
                    prepared.shared_anonymous_pages.edit().remove(&page);
                    prepared.set_mapping_incarnation(page, None);
                    if !prepared
                        .reservations
                        .get(&page)
                        .is_some_and(|kind| kind.permanent())
                    {
                        prepared.reservations.edit().remove(&page);
                    }
                }
            }
        }
        if let Some(cursors) = cursors {
            prepared.cursors = Some(cursors);
        }
        let ledger = self.prepare_mapping_retirement(&prepared, &space);
        // The operation owns the held lock, the reservation and the
        // allocation transaction, and releases them in that order however it
        // ends, run or dropped unrun (`PublicationHold`).
        let mut hold = PublicationHold {
            space: Some(space),
            reservation,
            allocation: Some(allocation),
        };
        let mapping = &self.mapping;
        let result = closed
            .publish(self.entry_origin(), expected, replaced, move |generation| {
                let outcome = (|| {
                    // Keep the ledger before mmap; after failure it excludes the
                    // uncertain target even if a foreign allocator fills the gap.
                    let mut ownership = mapping.retirement.lock().unwrap();
                    *ownership = Some(ledger);
                    let target = mapping.base_address + offset;
                    let protection = match slice.backing.kind {
                        BackingKind::Fixed
                        | BackingKind::SharedAnonymous
                        | BackingKind::OrdinaryFile { max_writable: true } => {
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
                    let installed = match source {
                        InstallSource::Inherited(source) => {
                            self.duplicate_shared_image(source, target, slice.length)
                        }
                        InstallSource::Fresh | InstallSource::CurrentContents => {
                            self.map_shared_image(target, &slice, protection)
                        }
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
                    **hold.space.as_mut().expect("the address space is held") = prepared;
                    if let Some(reservation) = hold.reservation.take() {
                        reservation.commit();
                    }
                    Ok(InstalledMapping::new(generation))
                })();
                // Nothing held may outlive the operation: the gate notifies
                // its waiters after it returns.
                drop(hold);
                outcome
            })
            .map_err(|failure| failure.error());
        drop(closed);
        result.map(|_| ())
    }

    /// Fill a new backing with the bytes the target range holds now. The exact
    /// Closed token excludes guest entry and every ordinary host copy, so no
    /// store can land in the old page after it is read.
    fn copy_current_contents(
        &self,
        closed: &Closed,
        address: u64,
        slice: &BackingSlice,
    ) -> Result<()> {
        if !closed.belongs_to(&self.entry_gate()) {
            return Err(Error::MappingPublicationGateMismatch);
        }
        let mut buffer = vec![0; (1024 * 1024).min(slice.length)];
        let mut copied = 0;
        while copied < slice.length {
            let length = buffer.len().min(slice.length - copied);
            let current = address + copied as u64;
            let offset = self.checked_offset(current, length)?;
            let chunks = self.mapping.host_chunks(offset, length);
            if chunks
                .iter()
                .any(|chunk| chunk.backing.kind.retained_shared())
            {
                return Err(Error::SharedFileCapability {
                    operation: "shared anonymous fork sharing",
                    reason: "the source page is already a retained shared view",
                });
            }
            self.read_host_chunks(&chunks, current, &mut buffer[..length])?;
            write_backing_at(&slice.backing, slice.offset + copied, &buffer[..length])
                .map_err(Error::MemoryMapping)?;
            copied += length;
        }
        Ok(())
    }

    /// Before a fork, move every `MAP_SHARED | MAP_ANONYMOUS` page that still
    /// lives in private backing into its own shmem object, keeping its bytes
    /// and permissions, so the child inherits the object instead of a copy.
    /// Linux creates that object at mmap time; doing it at the first fork is
    /// unobservable to the guest and leaves single-process use, including
    /// threads, on the unchanged private path. Returns the allocation guard
    /// once no such page remains.
    pub(super) fn share_anonymous_memory_for_fork(&self) -> Result<AllocationGuard<'_>> {
        loop {
            let allocation = self.allocation_guard();
            let run = {
                let state = self.mapping.address_space.lock().unwrap();
                let pending = |page: u64| {
                    let shared = state.backing_pages.get(&page).is_some_and(|installed| {
                        installed._slice.backing.kind == BackingKind::SharedAnonymous
                    });
                    (!shared).then(|| state.pages.get(&page).copied()).flatten()
                };
                let mut run: Option<(u64, u64, UserPageState)> = None;
                for &page in &state.shared_anonymous_pages {
                    let Some(permission) = pending(page) else {
                        if run.is_some() {
                            break;
                        }
                        continue;
                    };
                    match &mut run {
                        None => run = Some((page, 1, permission)),
                        Some((first, count, current))
                            if *first + *count == page && *current == permission =>
                        {
                            *count += 1;
                        }
                        Some(_) => break,
                    }
                }
                run
            };
            let Some((first, count, permission)) = run else {
                return Ok(allocation);
            };
            let length = usize::try_from(count)
                .ok()
                .and_then(|count| count.checked_mul(PAGE_SIZE))
                .ok_or(Error::InvalidMemoryLayout {
                    guest_base: first * PAGE_SIZE as u64,
                    size: usize::MAX,
                })?;
            let backing =
                Arc::new(Backing::new_shared_anonymous(length).map_err(Error::MemoryMapping)?);
            let slice = BackingSlice::new(backing, 0, length).map_err(Error::MemoryMapping)?;
            let permissions = match permission {
                UserPageState::Accessible { writable, .. } => (true, writable),
                UserPageState::NoAccess { .. } => (false, false),
            };
            match self.publish_range_from(
                allocation,
                first * PAGE_SIZE as u64,
                slice,
                Some(permissions),
                None,
                InstallSource::CurrentContents,
            ) {
                Ok(()) => {}
                Err(Error::SharedFileCapability {
                    operation: "mapping publication",
                    ..
                }) => {
                    // Copying the object instead would silently give the child
                    // private memory where Linux shares it.
                    return Err(Error::SharedFileCapability {
                        operation: "fork with shared anonymous memory",
                        reason: "sharing MAP_SHARED|MAP_ANONYMOUS memory with a child requires one stopped vCPU (no other live thread), no host copies and no retained operands",
                    });
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Fork into a distinct address space, preserving retained shared VMAs.
    /// This is not CLONE_VM: private bytes, permissions, gate and HVA ownership
    /// all belong to the new child. Ordinary-file views and fork-shared
    /// anonymous memory (see `share_anonymous_memory_for_fork`) are inherited
    /// as the same object; everything else is copied.
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-919): Review shared-file fork ownership and copies.
    pub(super) fn snapshot_with_shared_files(
        &self,
        allocation: AllocationGuard<'_>,
        share_record: bool,
    ) -> Result<Self> {
        if !Arc::ptr_eq(&allocation.memory.mapping, &self.mapping) {
            return Err(Error::MappingPublicationGateMismatch);
        }
        let gate = self.entry_gate();
        let closed = match gate.try_close_quiescent_single().map_err(|e| e.error())? {
            Some(closed) => closed,
            None => match gate
                .try_close_quiescent_unattached()
                .map_err(|e| e.error())?
            {
                Some(closed) => closed,
                // Another vCPU of the address space lives: the program forked
                // a process that holds views while another of its threads
                // runs, which this backend does not implement, so the refusal
                // is a named one. Anything else (a host copy or a retained
                // operand beside the one vCPU) is the backend's own state.
                None if gate.member_count().map_err(|e| e.error())? > 1 => {
                    return Err(Error::UnsupportedSharedFile {
                        operation: "shared-file fork snapshot",
                        reason: FORK_SNAPSHOT_REQUIREMENT,
                    });
                }
                None => {
                    return Err(Error::SharedFileCapability {
                        operation: "shared-file fork snapshot",
                        reason: FORK_SNAPSHOT_REQUIREMENT,
                    });
                }
            },
        };
        // Drop releases allocation BEFORE Closed, including during unwinding.
        // Opening admission may synchronously notify a caller-owned observer.
        let authority = ClosedSnapshot {
            allocation: Some(allocation),
            closed: Some(closed),
        };
        let parent_state = self.mapping.address_space.lock().unwrap().clone();
        let child = Self::new(self.guest_base(), self.len())?;
        #[cfg(any(test, feature = "test-support"))]
        let child = {
            let mut child = child;
            child.test_shared_map = self.test_shared_map.clone();
            child
        };
        let mut buffer = vec![0; (1024 * 1024).min(self.len())];
        let mut cursor = self.guest_base();
        let mut inherited = Vec::new();
        for (&page, installed) in &parent_state.backing_pages {
            if !installed._slice.backing.kind.retained_shared() {
                continue;
            }
            let address = page * PAGE_SIZE as u64;
            self.copy_private_snapshot_interval(
                authority.closed.as_ref().unwrap(),
                &child,
                &parent_state.backing_pages,
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
            &parent_state.backing_pages,
            cursor,
            self.guest_end(),
            &mut buffer,
        )?;
        let mut child_state = parent_state.clone();
        // A fork's child is another address space: it starts with the
        // parent's stack-window record, and the two record their own changes,
        // those the publications below make in the child included.
        if !share_record {
            child_state.pages.detach_watch();
        }
        // All private extents now belong to the child's base backing. Shared
        // installed pointers are recreated only from actual child syscall results.
        child_state.backing_pages.clear();
        *child.mapping.address_space.lock().unwrap() = child_state;
        let permissions = |page: u64| match parent_state.pages.get(&page) {
            Some(UserPageState::Accessible { writable, .. }) => Some((true, *writable)),
            Some(UserPageState::NoAccess { .. }) => Some((false, false)),
            None => None,
        };
        let mut inherited = inherited.into_iter().peekable();
        while let Some((page, installed)) = inherited.next() {
            if installed._slice.backing.kind == BackingKind::SharedAnonymous {
                // The backend owns this memfd and never seals it, so a fresh
                // shared view of the same pages is the same object. Map a run
                // of consecutive pages of one object with one publication.
                let mut slice = installed._slice;
                let mut pages = 1;
                while let Some((next, following)) = inherited.peek()
                    && *next == page + pages
                    && Arc::ptr_eq(&following._slice.backing, &slice.backing)
                    && following._slice.offset == slice.offset + slice.length
                    && permissions(*next) == permissions(page)
                {
                    slice.length += following._slice.length;
                    pages += 1;
                    inherited.next();
                }
                child.publish_range_from(
                    child.allocation_guard(),
                    page * PAGE_SIZE as u64,
                    slice,
                    permissions(page),
                    None,
                    InstallSource::Fresh,
                )?;
                continue;
            }
            // A page is always contained in one existing host VMA. Do not
            // merge numerically adjacent publications into an unproved VMA.
            child.publish_range_from(
                child.allocation_guard(),
                page * PAGE_SIZE as u64,
                installed._slice,
                permissions(page),
                None,
                InstallSource::Inherited(installed.mapping),
            )?;
        }
        self.check_copy_failure()?;
        child.check_copy_failure()?;
        drop(authority);
        // Only now, after the inherited views above are published: a vfork
        // child's copy refuses later changes to them until its exec.
        child.mark_shares_parent_address_space(share_record);
        Ok(child)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn fail_shared_snapshot_duplication_for_test(&mut self) {
        self.test_shared_map = Some(Arc::new(|_, _| {
            Some(Err(io::Error::from_raw_os_error(libc::ENOMEM)))
        }));
    }

    /// Copies the private bytes of `[address, end)`, which holds no retained
    /// shared page, into `child`, a new arena of the same size and base. The
    /// child's base backing is new, so it holds no data, and only data
    /// extents are copied: of each run of pages that live in this arena's base
    /// backing (`copy_base_snapshot_run`), and of each page with a private
    /// backing of its own, from that backing's descriptor
    /// (`GuestMemory::copy_sparse_separate_run`). So a page the guest never
    /// wrote costs the child nothing and is not read, which would commit it.
    /// A run or page the sparse copy cannot finish is copied byte for byte,
    /// which overwrites whatever part of it the sparse copy wrote.
    fn copy_private_snapshot_interval(
        &self,
        closed: &Closed,
        child: &GuestMemory,
        backing_pages: &BTreeMap<u64, InstalledBackingPage>,
        address: u64,
        end: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        if !closed.belongs_to(&self.entry_gate()) {
            return Err(Error::MappingPublicationGateMismatch);
        }
        let page_size = PAGE_SIZE as u64;
        let mut cursor = address;
        if address < end {
            for (&page, installed) in
                backing_pages.range(address / page_size..end.div_ceil(page_size))
            {
                let separate = page * page_size;
                self.copy_base_snapshot_run(child, cursor, separate, buffer)?;
                let copied = self.copy_sparse_separate_run(child, separate, installed, 1);
                #[cfg(test)]
                let copied = copied.and_then(|()| tests::injected_sparse_copy_failure());
                if copied.is_err() {
                    self.copy_private_snapshot_bytes(
                        child,
                        separate,
                        separate + page_size,
                        buffer,
                    )?;
                }
                cursor = separate + page_size;
            }
        }
        self.copy_base_snapshot_run(child, cursor, end, buffer)
    }

    /// Copies `[start, end)`, pages of this arena's base backing, into the
    /// same range of `child`'s new base backing: its data extents only, or, if
    /// that cannot finish, every byte.
    fn copy_base_snapshot_run(
        &self,
        child: &GuestMemory,
        start: u64,
        end: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        if start >= end {
            return Ok(());
        }
        let length = usize::try_from(end - start).expect("guest range must fit usize");
        self.checked_offset(start, length)?;
        child.checked_offset(start, length)?;
        let sparse = self.copy_sparse_base_run(child, start, end);
        #[cfg(test)]
        let sparse = sparse.and_then(|()| tests::injected_sparse_copy_failure());
        match sparse {
            Ok(()) => Ok(()),
            Err(_) => self.copy_private_snapshot_bytes(child, start, end, buffer),
        }
    }

    /// Copies every byte of `[address, end)`, which holds no retained shared
    /// page, into `child`.
    fn copy_private_snapshot_bytes(
        &self,
        child: &GuestMemory,
        mut address: u64,
        end: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
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

    pub fn retire_shared_files_for_exec(&self) -> Result<()> {
        // The new image is a new address space: a vfork child that execs no
        // longer shares its parent's (its changes to private memory went back
        // first, `return_vfork_changes`, and none of the new image's may),
        // and its outgoing views retire below.
        self.mark_shares_parent_address_space(false);
        self.mapping.vfork_parent.lock().unwrap().take();
        self.mapping
            .exec_count
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        loop {
            let allocation = self.allocation_guard();
            let range = {
                let state = self.mapping.address_space.lock().unwrap();
                // Shared anonymous views retire too: discarding the outgoing
                // image would otherwise zero the object for its other holders.
                let mut pages = state
                    .backing_pages
                    .iter()
                    .filter(|(_, page)| page._slice.backing.kind.retained_shared());
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
    pub fn sync_shared_file_range(&self, address: u64, length: usize, flags: i32) -> Result<i64> {
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
        // The range the call names, within the arena: the host msync below
        // touches file views inside it alone.
        let retained = self
            .entry_gate()
            .retain_operand_with(&copy, self.arena_range(address, rounded), || {
                self.entry_origin()
            })
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
            #[cfg(any(test, feature = "test-support"))]
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
                BackingKind::Fixed | BackingKind::SharedAnonymous => unsafe {
                    std::ptr::copy_nonoverlapping(chunk.mapping.as_ptr(), target, chunk.length);
                },
            }
            copied += chunk.length;
        }
        debug_assert_eq!(copied, destination.len());
        Ok(())
    }

    pub(super) fn deferred_failure(&self) -> Option<Arc<Error>> {
        if !self
            .mapping
            .deferred_queued
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
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
    pub fn record_kvm_sync_mmu(&self, supported: bool) -> Result<()> {
        let _allocation = self.allocation_guard();
        self.check_copy_failure()?;
        if !supported && self.contains_retained_shared() {
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
    pub fn preflight_atomic_store(&self, address: u64, length: usize) -> Result<()> {
        self.memory.with_copy(|copy| {
            let physical = self.translate_admitted(address, length, copy)?;
            if self.user_writable_prefix_admitted(address, length, copy)? != length {
                return Err(Error::GuestMemoryAccessDenied { address, length });
            }
            // Shared-file metadata is by physical address.
            if self.memory.range_contains_shared_file(physical, length) {
                return Err(Error::SharedFileCapability { operation: "atomic scalar store", reason: "truncate-capable file backing has no proven fault-contained atomic store" });
            }
            Ok(())
        })
    }
}

impl GuestMemory {
    /// The retirement ledger for installing `prepared` over `old`, the image
    /// installed now, which the caller holds locked.
    pub(super) fn prepare_mapping_retirement(
        &self,
        prepared: &AddressSpaceState,
        old: &AddressSpaceState,
    ) -> Box<WriteAliasMapping> {
        let mut extents =
            Vec::with_capacity(prepared.backing_pages.len() + old.backing_pages.len() + 1);
        extents.push(WriteAliasExtent {
            offset: 0,
            slice: self.mapping.slice.clone(),
        });
        for image in [prepared, old] {
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
        #[cfg(any(test, feature = "test-support"))]
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
        #[cfg(any(test, feature = "test-support"))]
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
    use crate::error_ext::ErrorExt;

    thread_local! {
        /// Makes this thread's shared-file snapshot copies report a failure
        /// after their sparse copy, so a test sees the byte-for-byte fallback.
        static FAIL_SPARSE_COPY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    pub(super) fn injected_sparse_copy_failure() -> io::Result<()> {
        if FAIL_SPARSE_COPY.with(std::cell::Cell::get) {
            Err(io::Error::other("injected sparse copy failure"))
        } else {
            Ok(())
        }
    }

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

    type AccessMaps = (
        std::collections::BTreeMap<u64, UserPageState>,
        std::collections::BTreeMap<u64, RegionKind>,
        std::collections::BTreeMap<u64, u64>,
        std::collections::BTreeSet<u64>,
    );

    fn access_maps(memory: &GuestMemory) -> AccessMaps {
        let access = memory.mapping.address_space.lock().unwrap();
        (
            access.pages.to_map(),
            (*access.reservations).clone(),
            (*access.file_pages).clone(),
            (*access.shared_anonymous_pages).clone(),
        )
    }

    /// The composition the Tool-scratch fast paths replace.
    fn composed_expose(memory: &GuestMemory, address: u64, length: u64) -> Result<()> {
        let reservation = memory.reserve_region(address, length, RegionKind::ToolScratch)?;
        memory.map_user_range(address, length, false)?;
        reservation.commit();
        Ok(())
    }

    fn outcome(result: Result<()>) -> String {
        match result {
            Ok(()) => "ok".to_owned(),
            Err(error) => format!("{error:?}"),
        }
    }

    fn readonly_file_page(memory: &GuestMemory, file: &File) {
        let path = std::ffi::CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(raw >= 0);
        memory
            .publish_shared_file_range(
                memory.allocation_guard(),
                SharedFileRangePlan {
                    address: BASE + P,
                    length: PAGE_SIZE,
                    file: unsafe { OwnedFd::from_raw_fd(raw) },
                    offset: 0,
                    readable: true,
                    writable: false,
                    max_writable: false,
                    cursors: None,
                },
            )
            .unwrap();
    }

    #[test]
    fn tool_scratch_fast_paths_match_the_composed_mapping_calls() {
        let file = file(1);
        // (setup, address, length)
        let cases: Vec<(&str, u64, u64)> = vec![
            ("plain", BASE, P),
            ("plain", BASE + 2 * P, 2 * P),
            ("plain", BASE, 0),
            ("plain", BASE + 4 * P, P),
            ("plain", BASE + 3 * P + 1, P),
            ("readonly-file", BASE + P, P),
            ("readonly-file", BASE, 2 * P),
            ("shared-file", BASE + P, P),
            ("shared-file", BASE, 3 * P),
        ];
        for (setup, address, length) in cases {
            let prepare = || {
                let memory = fixture(4);
                memory.unmap_user_range(BASE, 4 * P).unwrap();
                match setup {
                    "plain" => {}
                    "readonly-file" => readonly_file_page(&memory, &file),
                    "shared-file" => install(&memory, &file, BASE + P, 1, 0),
                    _ => unreachable!(),
                }
                memory
            };
            let fast = prepare();
            let composed = prepare();
            assert_eq!(access_maps(&fast), access_maps(&composed));
            for round in 0..2 {
                let label = format!("{setup} {address:#x}+{length:#x} round {round}");
                assert_eq!(
                    outcome(fast.expose_tool_scratch(address, length)),
                    outcome(composed_expose(&composed, address, length)),
                    "expose {label}"
                );
                assert_eq!(access_maps(&fast), access_maps(&composed), "expose {label}");
                assert_eq!(
                    outcome(fast.hide_tool_scratch(address, length)),
                    outcome(composed.unmap_user_range(address, length)),
                    "hide {label}"
                );
                assert_eq!(access_maps(&fast), access_maps(&composed), "hide {label}");
            }
        }
    }

    fn scratch_cache_holds(memory: &GuestMemory, address: u64) -> bool {
        memory
            .mapping
            .address_space
            .lock()
            .unwrap()
            .scratch_cache_holds(address / P)
    }

    /// Repeated expose/hide cycles over two scratch pages, with every kind of
    /// page edit in between, leave the same maps and results as the composed
    /// calls; the cache serves the steady state and never survives an edit.
    #[test]
    fn tool_scratch_cache_matches_the_composed_calls_and_drops_on_any_page_edit() {
        let (a, b) = (BASE, BASE + 2 * P);
        let prepare = || {
            let memory = fixture(4);
            memory.unmap_user_range(BASE, 4 * P).unwrap();
            memory
        };
        let fast = prepare();
        let composed = prepare();
        type Edit = fn(&GuestMemory);
        fn file_a(m: &GuestMemory) {
            m.record_file_pages(BASE, P, Some(0));
        }
        fn shared_b(m: &GuestMemory) {
            m.record_page_backing(BASE + 2 * P, P, None, true);
        }
        fn read_only_a(m: &GuestMemory) {
            m.map_user_permissions(BASE, P, true, false).unwrap();
        }
        fn no_access_a(m: &GuestMemory) {
            m.map_user_range(BASE, P, true).unwrap();
        }
        fn file_b(m: &GuestMemory) {
            m.record_file_pages(BASE + 2 * P, P, Some(P));
        }
        fn unmap_a(m: &GuestMemory) {
            m.unmap_user_range(BASE, P).unwrap();
        }
        // (label, edit applied to both memories, whether the edit lands
        // while the pages are exposed rather than before the cycle)
        let edits: [(&str, Option<Edit>, bool); 12] = [
            ("warm", None, false),
            ("steady", None, false),
            ("file offset while hidden", Some(file_a), false),
            ("steady after file", None, false),
            ("shared anonymous while hidden", Some(shared_b), false),
            ("steady after shared", None, false),
            ("mapped read-only while hidden", Some(read_only_a), false),
            ("steady after map", None, false),
            ("mapped no-access while exposed", Some(no_access_a), true),
            ("file offset while exposed", Some(file_b), true),
            ("unmapped while exposed", Some(unmap_a), true),
            ("steady at the end", None, false),
        ];
        for (label, edit, while_exposed) in edits {
            if let (Some(edit), false) = (edit, while_exposed) {
                edit(&fast);
                edit(&composed);
                assert!(
                    !scratch_cache_holds(&fast, a),
                    "{label}: edit kept the cache"
                );
            }
            // An edit made before the cycle drops the cache; one made while
            // exposed has not happened yet.
            let steady = (edit.is_none() || while_exposed) && label != "warm";
            assert_eq!(scratch_cache_holds(&fast, a), steady, "{label}: page a");
            for page in [a, b] {
                assert_eq!(
                    outcome(fast.expose_tool_scratch(page, P)),
                    outcome(composed_expose(&composed, page, P)),
                    "expose {label} {page:#x}"
                );
                assert_eq!(access_maps(&fast), access_maps(&composed), "expose {label}");
            }
            if let (Some(edit), true) = (edit, while_exposed) {
                edit(&fast);
                edit(&composed);
                assert!(
                    !scratch_cache_holds(&fast, a),
                    "{label}: edit kept the cache"
                );
                assert_eq!(access_maps(&fast), access_maps(&composed), "edit {label}");
            }
            // Hide in the other order, as two Tool threads may.
            for page in [b, a] {
                assert_eq!(
                    outcome(fast.hide_tool_scratch(page, P)),
                    outcome(composed.unmap_user_range(page, P)),
                    "hide {label} {page:#x}"
                );
                assert_eq!(access_maps(&fast), access_maps(&composed), "hide {label}");
            }
            assert!(
                scratch_cache_holds(&fast, a) && scratch_cache_holds(&fast, b),
                "{label}"
            );
        }
        // A cloned state (a fork snapshot) carries the same facts, and an
        // edit to the clone does not leave the original's cache stale.
        let snapshot = fast.mapping.address_space.lock().unwrap().clone();
        assert!(snapshot.scratch_cache_holds(a / P));
        let mut edited = snapshot.clone();
        edited.reservations.edit().insert(a / P, RegionKind::Mmap);
        assert!(!edited.scratch_cache_holds(a / P));
        assert!(snapshot.scratch_cache_holds(a / P));
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
            // A capability guard, a file copy, and a named refusal.
            for kind in 0..3 {
                for wrapper in 0..3 {
                    let memory = fixture(1);
                    let gate = memory.entry_gate();
                    let cause = Arc::new(match kind {
                        0 => Error::SharedFileCapability {
                            operation: "atomic scalar store",
                            reason: "capture identity control",
                        },
                        1 => Error::SharedFileCopy {
                            operation: "write",
                            address: BASE,
                            requested: 8,
                            transferred: 2,
                            prior_transferred: 4,
                            source: io::Error::from_raw_os_error(libc::EFAULT),
                        },
                        _ => Error::UnsupportedSharedFile {
                            operation: "mmap",
                            reason: "capture identity control",
                        },
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
                    // Only the named refusal reads as one, through every wrapper.
                    assert_eq!(terminal.is_named_refusal(), kind == 2);
                    assert_eq!(returned.is_named_refusal(), kind == 2);
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

    /// A Tool's compare-and-exchange of a word on a shared file page answers
    /// the missing capability (`ENOSYS`) with nothing stored and records no
    /// failure, so the mapping stays usable; the provider's exchange of the
    /// same word keeps its terminal shared-file refusal.
    #[test]
    fn a_tool_exchange_on_file_backing_is_a_missing_capability_not_a_failure() {
        let memory = fixture(2);
        let file = file(1);
        install(&memory, &file, BASE + P, 1, 0);
        memory
            .map_user_permissions(BASE + P, P, true, true)
            .unwrap();
        let mut user = memory.user();
        let word = AddrMut::<u32>::from_raw((BASE + P) as usize).unwrap();
        assert_eq!(
            MemoryAccess::compare_exchange_u32(&mut user, word, 0x1111_1111, 7),
            Err(Errno::ENOSYS)
        );
        assert_eq!(bytes(&file, 0, 4), [0x11; 4]);
        assert!(memory.entry_gate().pending_failure().is_none());
        // A private word next to it still exchanges.
        let private = AddrMut::<u32>::from_raw(BASE as usize).unwrap();
        assert_eq!(
            MemoryAccess::compare_exchange_u32(&mut user, private, 0, 9),
            Ok(0)
        );
        assert_eq!(read(&memory, BASE, 4), 9_u32.to_ne_bytes());
        let error = memory
            .user()
            .compare_exchange_u32(BASE + P, 0x1111_1111, 7)
            .unwrap_err();
        assert!(matches!(
            error.primary(),
            Error::SharedFileCapability {
                operation: "atomic compare-exchange",
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

    /// A memory of six pages whose top three are a stack window, the top two
    /// reachable and mapped read-write as one mapping, watched; and the
    /// window's user start.
    fn watched_window_fixture() -> (GuestMemory, u64) {
        let memory = fixture(6);
        let window = memory.establish_user_stack_window(3 * P).unwrap();
        memory
            .reserve_region(BASE + 3 * P, 3 * P, RegionKind::Stack)
            .unwrap()
            .commit();
        memory
            .map_user_protection(
                BASE + 3 * P,
                3 * P,
                (libc::PROT_READ | libc::PROT_WRITE) as u8,
            )
            .unwrap();
        memory.watch_user_stack_window();
        (memory, window)
    }

    /// The stack window's pages as extents of equal declared mapping.
    type WindowList = Option<Vec<(u64, u64, DeclaredMapping)>>;

    /// `memory`'s stack window pages as extents of equal declared mapping,
    /// `(user start, user end, declared)`; `None` while its record is not
    /// certain. Every page of these fixtures is declared.
    fn window_list(memory: &GuestMemory) -> WindowList {
        let mut extents: Vec<(u64, u64, DeclaredMapping)> = Vec::new();
        for page in memory.user_stack_window_pages()? {
            let declared = page.declared.unwrap();
            match extents.last_mut() {
                Some((_, end, last)) if *end == page.user_address && *last == declared => *end += P,
                _ => extents.push((page.user_address, page.user_address + P, declared)),
            }
        }
        Some(extents)
    }

    /// The window's one mapping, and its two once its top page is read-only.
    fn window_lists(window: u64) -> (WindowList, WindowList) {
        let mapping = |prot: libc::c_int| DeclaredMapping {
            prot: prot as u8,
            flags: 0,
            lineage: 0,
        };
        let read_write = mapping(libc::PROT_READ | libc::PROT_WRITE);
        (
            Some(vec![(window, USER_STACK_TOP, read_write)]),
            Some(vec![
                (window, window + P, read_write),
                (window + P, USER_STACK_TOP, mapping(libc::PROT_READ)),
            ]),
        )
    }

    /// A fork's copy of a memory that holds a shared file view is another
    /// address space: it starts with the stack window's pages and keeps a
    /// record of its own, so a change either side makes afterwards shows in
    /// its own list only.
    #[test]
    fn a_shared_file_snapshot_keeps_its_own_stack_window_record() {
        for child_changes in [true, false] {
            let (memory, window) = watched_window_fixture();
            let (whole, split) = window_lists(window);
            install(&memory, &file(1), BASE + P, 1, 0);
            assert_eq!(window_list(&memory), whole);
            let child = memory.snapshot().unwrap();
            assert!(child.contains_shared_file());
            assert_eq!(window_list(&child), whole);
            let (changing, other) = if child_changes {
                (&child, &memory)
            } else {
                (&memory, &child)
            };
            changing
                .protect_user_range(BASE + 4 * P, P, libc::PROT_READ as u8)
                .unwrap();
            assert_eq!(window_list(changing), split);
            assert_eq!(window_list(other), whole, "child changes: {child_changes}");
        }
    }

    /// A fork's copy of a memory that holds a shared file view keeps the
    /// lineages its source's window pages were given, as any copy does.
    #[test]
    fn a_shared_file_snapshot_keeps_the_lineages_it_is_given() {
        let (memory, window) = watched_window_fixture();
        install(&memory, &file(1), BASE + P, 1, 0);
        memory.set_user_stack_window_lineage(window + P, P, 3);
        let child = memory.snapshot().unwrap();
        assert!(child.contains_shared_file());
        let read_write = DeclaredMapping {
            prot: (libc::PROT_READ | libc::PROT_WRITE) as u8,
            flags: 0,
            lineage: 0,
        };
        let given = Some(vec![
            (window, window + P, read_write),
            (
                window + P,
                USER_STACK_TOP,
                DeclaredMapping {
                    lineage: 3,
                    ..read_write
                },
            ),
        ]);
        assert_eq!(window_list(&memory), given);
        assert_eq!(window_list(&child), given);
    }

    /// A copy of a memory that holds a shared file view, for a child that
    /// shares the address space (`snapshot_sharing_address_space`), shares
    /// the stack window's record as the copy of any other memory does: a
    /// change either side makes afterwards leaves the other's list unknown.
    #[test]
    fn a_shared_file_sharing_snapshot_shares_the_stack_window_record() {
        for copy_changes in [true, false] {
            let (memory, window) = watched_window_fixture();
            let (whole, split) = window_lists(window);
            install(&memory, &file(1), BASE + P, 1, 0);
            let copy = memory.snapshot_sharing_address_space().unwrap();
            assert!(copy.contains_shared_file());
            assert_eq!(window_list(&copy), whole);
            let (changing, other) = if copy_changes {
                (&copy, &memory)
            } else {
                (&memory, &copy)
            };
            changing
                .protect_user_range(BASE + 4 * P, P, libc::PROT_READ as u8)
                .unwrap();
            assert_eq!(window_list(changing), split);
            assert_eq!(window_list(other), None, "copy changes: {copy_changes}");
        }
    }

    /// A copy that shares the stack window's record with its source, as a
    /// vfork child's does, keeps sharing it across a publication, which
    /// installs a prepared copy of the address-space state in place of the
    /// old one: a change either side makes afterwards still leaves the
    /// other's list unknown.
    #[test]
    fn a_publication_keeps_a_shared_stack_window_record() {
        for copy_publishes in [true, false] {
            let (memory, window) = watched_window_fixture();
            let (whole, split) = window_lists(window);
            let copy = memory.snapshot_sharing_address_space().unwrap();
            let (publisher, other) = if copy_publishes {
                (&copy, &memory)
            } else {
                (&memory, &copy)
            };
            replace(publisher, BASE, 1, Some(b"published"), true);
            assert_eq!(
                window_list(other),
                whole,
                "copy publishes: {copy_publishes}"
            );
            publisher
                .protect_user_range(BASE + 4 * P, P, libc::PROT_READ as u8)
                .unwrap();
            assert_eq!(window_list(publisher), split);
            assert_eq!(window_list(other), None, "copy publishes: {copy_publishes}");
        }
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
        let retained = gate.retain_operand(&copy, 0..8).unwrap();
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

    /// `zero_lazily` refuses a range that holds a retained shared view, in
    /// every build, before the poisoning discard is reached: the file is
    /// unchanged, the entry gate stays clear, and memory stays usable
    /// (https://github.com/rrnewton/reverie/issues/1058).
    #[test]
    fn zero_lazily_refuses_a_retained_shared_view_before_discarding() {
        let memory = fixture(2);
        let file = file(1);
        install(&memory, &file, BASE, 1, 0);
        let before = bytes(&file, 0, PAGE_SIZE);
        assert!(matches!(
            memory.zero_lazily(BASE, 2 * PAGE_SIZE),
            Err(Error::SharedFileCapability { .. })
        ));
        assert!(memory.entry_gate().pending_failure().is_none());
        assert_eq!(bytes(&file, 0, PAGE_SIZE), before);
        memory.zero_raw(BASE + P, PAGE_SIZE).unwrap();
    }

    /// The same refusal at 2 MiB, where zero_lazily would otherwise discard:
    /// one ordinary-file page inside a 2 MiB range is refused, unchanged and
    /// unpoisoned, in debug and release builds
    /// (https://github.com/rrnewton/reverie/issues/1058).
    #[test]
    fn zero_lazily_refuses_a_retained_shared_view_at_lazy_size() {
        let pages = crate::memory::LAZY_ZERO_MIN_BYTES / PAGE_SIZE + 4;
        let memory = fixture(pages);
        let file = file(1);
        install(&memory, &file, BASE + 4 * P, 1, 0);
        let before = bytes(&file, 0, PAGE_SIZE);
        assert!(matches!(
            memory.zero_lazily(BASE, crate::memory::LAZY_ZERO_MIN_BYTES),
            Err(Error::SharedFileCapability {
                operation: "zero lazily",
                ..
            })
        ));
        assert!(memory.entry_gate().pending_failure().is_none());
        assert_eq!(bytes(&file, 0, PAGE_SIZE), before);
        memory.zero_raw(BASE, PAGE_SIZE).unwrap();
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

    /// A host copy that does not retire within the publication's bound (here
    /// the test's own, which it holds through the call) refuses the
    /// publication by name, with no reservation or byte effect; the close is
    /// abandoned, so admission reopens and nothing is poisoned.
    #[test]
    fn busy_copy_refuses_publication_without_reservation_or_byte_effect() {
        let memory = fixture(1);
        memory.write_raw(BASE, b"private").unwrap();
        let file = file(1);
        let gate = memory.entry_gate();
        let generation = gate.generation().unwrap();
        let reservation = memory.reservation_kind(BASE);
        let copy = gate.copy_blocking(None).unwrap();
        PUBLICATION_STOP_TIMEOUT_FOR_TEST
            .with(|bound| bound.set(Some(std::time::Duration::from_millis(50))));
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
        PUBLICATION_STOP_TIMEOUT_FOR_TEST.with(|bound| bound.set(None));
        // The backend's own failure, which names itself a defect to report,
        // not a refusal by name.
        assert!(
            matches!(
                &result,
                Err(error @ Error::SharedFileCapability {
                    operation: "mapping publication",
                    reason: PUBLICATION_STOP_FAILURE,
                }) if !error.is_named_refusal()
                    && error.to_string().contains("a defect of the backend to report")
            ),
            "{result:?}"
        );
        assert_eq!(gate.generation().unwrap(), generation);
        assert_eq!(memory.reservation_kind(BASE), reservation);
        assert!(gate.admission_open().unwrap());
        assert!(gate.pending_failure().is_none());
        assert!(!memory.contains_shared_file());
        drop(copy);
        assert_eq!(read(&memory, BASE, 7), b"private");
        assert_eq!(bytes(&file, 0, 7), [0x11; 7]);
    }

    /// A publication over memory that a retained host operand (here a
    /// futex-style operand of four bytes) still covers waits, bounded, for it
    /// to retire, and refuses by name when it does not, with no reservation,
    /// mapping or generation effect and no failure recorded. A publication
    /// beside the operand goes on while it lives, and the operand retires
    /// afterwards across the new generation.
    #[test]
    fn publication_over_a_retained_operand_waits_then_refuses_by_name() {
        let memory = fixture(2);
        memory.record_kvm_sync_mmu(true).unwrap();
        memory.write_raw(BASE, b"operand!").unwrap();
        let file = file(1);
        let gate = memory.entry_gate();
        let generation = gate.generation().unwrap();
        let reservation = memory.reservation_kind(BASE);
        let operand = memory.user().host_operand(BASE, 4).unwrap();
        let plan = |address| SharedFileRangePlan {
            address,
            length: PAGE_SIZE,
            file: file.try_clone().unwrap().into(),
            offset: 0,
            readable: true,
            writable: true,
            max_writable: true,
            cursors: None,
        };
        PUBLICATION_STOP_TIMEOUT_FOR_TEST
            .with(|bound| bound.set(Some(std::time::Duration::from_millis(50))));
        let refused = memory.publish_shared_file_range(memory.allocation_guard(), plan(BASE));
        PUBLICATION_STOP_TIMEOUT_FOR_TEST.with(|bound| bound.set(None));
        assert!(
            matches!(
                &refused,
                Err(error @ Error::UnsupportedSharedFile {
                    operation: "mapping publication",
                    reason: "a host operation still uses memory in the replaced range",
                }) if error.is_named_refusal()
            ),
            "{refused:?}"
        );
        assert_eq!(gate.generation().unwrap(), generation);
        assert_eq!(memory.reservation_kind(BASE), reservation);
        assert!(gate.admission_open().unwrap());
        assert!(gate.pending_failure().is_none());
        assert!(!memory.contains_shared_file());
        assert_eq!(read(&memory, BASE, 8), b"operand!");

        memory
            .publish_shared_file_range(memory.allocation_guard(), plan(BASE + P))
            .unwrap();
        assert!(memory.contains_shared_file());
        assert_eq!(gate.generation().unwrap().get(), generation.get() + 1);
        assert_eq!(read(&memory, BASE + P, 4), [0x11; 4]);
        assert_eq!(gate.test_state().retained_operands, 1);
        drop(operand);
        assert_eq!(gate.test_state().retained_operands, 0);
        assert!(gate.pending_failure().is_none());
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
        drop(member);
    }

    fn vfork_refusal(result: Result<()>) {
        match result {
            Err(Error::SharedFileCapability { operation, reason }) => {
                assert_eq!(operation, "mapping change in a vfork child");
                assert!(reason.starts_with("a vfork child shares its parent's address space"));
            }
            other => panic!("expected the vfork child's shared-view refusal, got {other:?}"),
        }
    }

    /// A vfork child's copy of a memory that holds shared views has an arena
    /// and an entry gate of its own, so the parent's gate keeps its one
    /// stopped participant. The copy inherits the views, so a store through
    /// one reaches the other side and the file at once, and copies private
    /// memory, whose changes reach the parent when the child's window ends,
    /// a nested vfork's through its own parent. It is marked until its exec;
    /// a fork of it is another address space and is not, and a vfork of it
    /// is.
    #[test]
    fn vfork_copy_inherits_shared_views_on_a_gate_of_its_own() {
        let memory = fixture(4);
        let original = file(2);
        install(&memory, &original, BASE + P, 2, 0);
        memory.write_raw(BASE, b"parent").unwrap();
        let participant = memory.entry_gate().register().unwrap();
        let child = memory.snapshot_sharing_address_space().unwrap();
        assert!(child.shares_parent_address_space());
        assert!(!memory.shares_parent_address_space());
        assert!(!Arc::ptr_eq(&memory.mapping, &child.mapping));
        assert!(!Arc::ptr_eq(&memory.entry_gate(), &child.entry_gate()));
        assert_eq!(memory.entry_gate().test_state().members.len(), 1);
        assert!(child.entry_gate().test_state().members.is_empty());
        assert_eq!(child.separately_backed_pages(), 2);
        child.write_raw(BASE + P + 3, b"child").unwrap();
        assert_eq!(read(&memory, BASE + P + 3, 5), b"child");
        assert_eq!(bytes(&original, 3, 5), b"child");
        memory.write_raw(BASE + 2 * P + 5, b"parent").unwrap();
        assert_eq!(read(&child, BASE + 2 * P + 5, 6), b"parent");
        child.write_raw(BASE, b"child!").unwrap();
        // The parent waits in its call while the child runs; the child's
        // private stores are the parent's once the window ends, as on Linux,
        // where the two share one address space.
        assert_eq!(read(&memory, BASE, 6), b"parent");
        assert!(!child.snapshot().unwrap().shares_parent_address_space());
        let grandchild = child.snapshot_sharing_address_space().unwrap();
        assert!(grandchild.shares_parent_address_space());
        assert!(child.shares_parent_address_space());
        grandchild.write_raw(BASE + P, b"grand").unwrap();
        assert_eq!(read(&memory, BASE + P, 5), b"grand");
        grandchild.write_raw(BASE + 3 * P, b"grandchild").unwrap();
        grandchild.return_vfork_changes(BASE).unwrap();
        assert_eq!(read(&child, BASE + 3 * P, 10), b"grandchild");
        assert_eq!(read(&memory, BASE + 3 * P, 10), [0; 10]);
        let returned = child.return_vfork_changes(BASE).unwrap().unwrap();
        assert_eq!(read(&memory, BASE, 6), b"child!");
        assert_eq!(read(&memory, BASE + 3 * P, 10), b"grandchild");
        // Pages 0 and 3; the views are the same object and are not written.
        assert_eq!(returned.bytes_written, 2 * PAGE_SIZE);
        assert!(memory.entry_gate().pending_failure().is_none());
        drop(participant);
    }

    /// Every vfork copy is marked, whether or not its source holds a view,
    /// and no fork copy is.
    #[test]
    fn vfork_copies_are_marked_and_fork_copies_are_not() {
        let memory = fixture(2);
        assert!(!memory.shares_parent_address_space());
        assert!(
            memory
                .snapshot_sharing_address_space()
                .unwrap()
                .shares_parent_address_space()
        );
        assert!(!memory.snapshot().unwrap().shares_parent_address_space());
    }

    /// Until its exec, a vfork child's copy refuses every change to a shared
    /// view before it changes anything: withdrawing part of an inherited
    /// view, a private mapping over part of one, and a new view elsewhere.
    /// A private publication that touches no view goes ahead. The exec ends
    /// the window: the copy's views retire, the new image may map files, and
    /// the parent's views and file are unchanged throughout.
    #[test]
    fn vfork_copy_refuses_shared_view_changes_until_exec() {
        let memory = fixture(5);
        let original = file(2);
        install(&memory, &original, BASE + P, 2, 0);
        let participant = memory.entry_gate().register().unwrap();
        let child = memory.snapshot_sharing_address_space().unwrap();
        let before = (access_maps(&child), child.separately_backed_pages());
        let parent_before = (access_maps(&memory), memory.separately_backed_pages());
        let other = file(1);
        vfork_refusal(child.publish_private_range(
            child.allocation_guard(),
            PrivateRangePlan {
                address: BASE + P,
                length: PAGE_SIZE,
                contents: None,
                permissions: None,
                cursors: None,
            },
        ));
        vfork_refusal(child.publish_private_range(
            child.allocation_guard(),
            PrivateRangePlan {
                address: BASE + 2 * P,
                length: PAGE_SIZE,
                contents: Some(b"private"),
                permissions: Some((true, true)),
                cursors: None,
            },
        ));
        vfork_refusal(child.publish_shared_file_range(
            child.allocation_guard(),
            SharedFileRangePlan {
                address: BASE + 3 * P,
                length: PAGE_SIZE,
                file: other.try_clone().unwrap().into(),
                offset: 0,
                readable: true,
                writable: true,
                max_writable: true,
                cursors: None,
            },
        ));
        assert_eq!(
            (access_maps(&child), child.separately_backed_pages()),
            before
        );
        assert!(child.entry_gate().pending_failure().is_none());
        // A private publication over private memory changes no view.
        replace(&child, BASE + 4 * P, 1, Some(b"private"), true);
        assert_eq!(read(&child, BASE + 4 * P, 7), b"private");
        assert!(child.range_contains_shared_file(BASE + P, 2 * PAGE_SIZE));
        // The exec: the new image is another address space.
        child.retire_shared_files_for_exec().unwrap();
        assert!(!child.shares_parent_address_space());
        assert!(!child.contains_shared_file());
        install(&child, &other, BASE + 3 * P, 1, 0);
        assert!(child.range_contains_shared_file(BASE + 3 * P, PAGE_SIZE));
        assert_eq!(
            (access_maps(&memory), memory.separately_backed_pages()),
            parent_before
        );
        memory.write_raw(BASE + P, b"parent").unwrap();
        assert_eq!(bytes(&original, 0, 6), b"parent");
        assert!(memory.entry_gate().pending_failure().is_none());
        drop(participant);
    }

    /// A vfork child's copy of shared views needs what a fork's does: the
    /// source's one participant stopped and no host copy in flight. A copy
    /// in flight beside the one participant is the backend's own state, so
    /// the snapshot fails (SharedFileCapability); a second participant is
    /// another thread of the program, which a view's address space may now
    /// hold, so the snapshot is refused by name (UnsupportedSharedFile).
    #[test]
    fn vfork_copy_needs_the_sources_one_participant_quiescent() {
        let memory = fixture(2);
        let original = file(1);
        install(&memory, &original, BASE, 1, 0);
        let participant = memory.entry_gate().register().unwrap();
        let gate = memory.entry_gate();
        let copy = gate.try_copy(None).unwrap().unwrap();
        let busy = memory.snapshot_sharing_address_space().unwrap_err();
        assert!(
            matches!(
                &busy,
                Error::SharedFileCapability {
                    operation: "shared-file fork snapshot",
                    ..
                }
            ) && !busy.is_named_refusal(),
            "{busy}"
        );
        drop(copy);
        assert!(
            memory
                .snapshot_sharing_address_space()
                .unwrap()
                .shares_parent_address_space()
        );
        assert!(gate.pending_failure().is_none());
        // A second vCPU joins the view's address space, but a vfork-style
        // child of the two is refused by name, as a fork of them is.
        let joined = fixture(2);
        install(&joined, &original, BASE, 1, 0);
        let first = joined.entry_gate().register().unwrap();
        let second = joined.entry_gate().register().unwrap();
        let two_threads = joined.snapshot_sharing_address_space().unwrap_err();
        assert!(
            matches!(
                &two_threads,
                Error::UnsupportedSharedFile {
                    operation: "shared-file fork snapshot",
                    ..
                }
            ) && two_threads.is_named_refusal(),
            "{two_threads}"
        );
        assert!(joined.entry_gate().pending_failure().is_none());
        drop((first, second));
        // Two stopped vCPUs take a view: the publication closes for both.
        // The recorded capability spares this native unit /dev/kvm.
        let threaded = fixture(2);
        threaded.record_kvm_sync_mmu(true).unwrap();
        let one = threaded.entry_gate().register().unwrap();
        let two = threaded.entry_gate().register().unwrap();
        threaded
            .publish_shared_file_range(
                threaded.allocation_guard(),
                SharedFileRangePlan {
                    address: BASE,
                    length: PAGE_SIZE,
                    file: original.try_clone().unwrap().into(),
                    offset: 0,
                    readable: true,
                    writable: false,
                    max_writable: true,
                    cursors: None,
                },
            )
            .unwrap();
        assert!(threaded.contains_shared_file());
        assert_eq!(threaded.entry_gate().generation().unwrap().get(), 1);
        assert!(threaded.entry_gate().admission_open().unwrap());
        drop((one, two, participant));
    }

    /// The bytes the host has allocated for the base backing of `memory`.
    fn allocated_bytes(memory: &GuestMemory) -> u64 {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the descriptor is live and metadata is valid for a stat.
        let rc = unsafe {
            libc::fstat(
                memory.mapping.slice.backing.fd.as_raw_fd(),
                metadata.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "{}", io::Error::last_os_error());
        // SAFETY: fstat succeeded.
        unsafe { metadata.assume_init() }.st_blocks as u64 * 512
    }

    /// 16 MiB, eight 2 MiB regions: a host that backs shared memory with
    /// huge pages allocates a written region whole.
    const SPARSE_PAGES: usize = 4096;

    /// A memory of `SPARSE_PAGES` pages that holds a two-page shared view at
    /// page 10, a private page with a backing of its own at page 20, and
    /// private bytes the guest wrote at pages 3 and 40, in its first 2 MiB,
    /// and at each edge of the three runs of base pages a copy copies
    /// (`[0, 10)`, `[12, 20)` and `[21, SPARSE_PAGES)`): pages 9, 12, 19, 21
    /// and the last page. Every other page was never written.
    fn sparse_snapshot_fixture() -> (GuestMemory, File) {
        let memory = fixture(SPARSE_PAGES);
        let original = file(2);
        install(&memory, &original, BASE + 10 * P, 2, 0);
        replace(&memory, BASE + 20 * P, 1, Some(b"own-backing"), true);
        memory.write_raw(BASE + 3 * P + 7, b"early").unwrap();
        memory.write_raw(BASE + 40 * P, b"late").unwrap();
        for page in SPARSE_EDGE_PAGES {
            memory
                .write_raw(BASE + page * P + P - 8, &page.to_ne_bytes())
                .unwrap();
        }
        (memory, original)
    }

    /// The first and last page of each run of base pages in
    /// [`sparse_snapshot_fixture`].
    const SPARSE_EDGE_PAGES: [u64; 5] = [9, 12, 19, 21, SPARSE_PAGES as u64 - 1];

    fn assert_private_pages_match(memory: &GuestMemory, child: &GuestMemory) {
        let mut source = vec![0; PAGE_SIZE];
        let mut copy = vec![0; PAGE_SIZE];
        for page in (0..SPARSE_PAGES as u64).filter(|page| !(10..12).contains(page)) {
            memory.read_raw(BASE + page * P, &mut source).unwrap();
            child.read_raw(BASE + page * P, &mut copy).unwrap();
            assert!(source == copy, "page {page}");
        }
        assert_eq!(read(child, BASE + 3 * P + 7, 5), b"early");
        assert_eq!(read(child, BASE + 20 * P, 11), b"own-backing");
        assert_eq!(read(child, BASE + 40 * P, 4), b"late");
        for page in SPARSE_EDGE_PAGES {
            assert_eq!(
                read(child, BASE + page * P + P - 8, 8),
                page.to_ne_bytes(),
                "page {page}"
            );
        }
    }

    /// A copy of a memory that holds shared views, a fork's or a vfork
    /// child's, copies only the private pages the guest wrote into its new
    /// base backing, so the 2 MiB regions it never wrote stay unallocated,
    /// and every private page reads as the source's, a page with a backing
    /// of its own included.
    #[test]
    fn shared_file_snapshots_copy_only_written_private_pages() {
        let (memory, original) = sparse_snapshot_fixture();
        for child in [
            memory.snapshot().unwrap(),
            memory.snapshot_sharing_address_space().unwrap(),
        ] {
            // Before any read of the copy: at most the first region and the
            // last of the eight.
            let allocated = allocated_bytes(&child);
            assert!(allocated <= 4 << 20, "{allocated} bytes allocated");
            assert_private_pages_match(&memory, &child);
            child.write_raw(BASE + 10 * P + 1, b"view").unwrap();
            assert_eq!(bytes(&original, 1, 4), b"view");
        }
    }

    /// A fork of a memory that holds a shared file view inherits the view as
    /// the same file and copies its private pages by data extents, reading
    /// no hole: a private page with a backing of its own that holds no data
    /// leaves that backing as unallocated as before, and reads as zeros in
    /// the copy. After the fork, a store through the view by the parent, one
    /// by the child, and one by another holder of the file (a write to the
    /// file itself) are all seen through both views, while each side's
    /// private pages stay as they were at the fork.
    #[test]
    fn a_fork_shares_a_view_changed_after_it_and_keeps_private_pages_apart() {
        let separate_allocated = |memory: &GuestMemory, page: u64| {
            let state = memory.mapping.address_space.lock().unwrap();
            let fd = state.backing_pages[&page]._slice.backing.fd.as_raw_fd();
            let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: the descriptor is live and metadata is valid for a stat.
            assert_eq!(unsafe { libc::fstat(fd, metadata.as_mut_ptr()) }, 0);
            // SAFETY: fstat succeeded.
            unsafe { metadata.assume_init() }.st_blocks as u64 * 512
        };
        let memory = fixture(SPARSE_PAGES);
        // A memfd, so that this test writes no file outside its own memory.
        // SAFETY: the name is a NUL-terminated string.
        let fd = unsafe { libc::memfd_create(c"view".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "memfd_create: {}", io::Error::last_os_error());
        // SAFETY: fd is a new descriptor that nothing else owns.
        let original = unsafe { File::from_raw_fd(fd) };
        original.set_len(2 * P).unwrap();
        original.write_all_at(&[0x11; 2 * PAGE_SIZE], 0).unwrap();
        install(&memory, &original, BASE + 10 * P, 2, 0);
        memory
            .write_raw(BASE + 3 * P, b"private before the fork")
            .unwrap();
        replace(&memory, BASE + 20 * P, 1, Some(b"own backing"), true);
        // Alone in its 2 MiB region, so that copying its zeros would show.
        replace(&memory, BASE + 3000 * P, 1, None, true);
        let hole_page = (BASE + 3000 * P) / P;
        let before = separate_allocated(&memory, hole_page);
        let child = memory.snapshot().unwrap();
        assert_eq!(separate_allocated(&memory, hole_page), before);
        // Before any read of the copy: the first 2 MiB region only.
        let allocated = allocated_bytes(&child);
        assert!(allocated <= 2 << 20, "{allocated} bytes allocated");
        assert_eq!(read(&child, BASE + 3000 * P, PAGE_SIZE), vec![0; PAGE_SIZE]);
        assert_eq!(read(&child, BASE + 20 * P, 11), b"own backing");
        assert_user_pages_match(&memory, &child, BASE);
        // After the fork: the parent, the child, and another holder of the
        // file each store one byte of the view's first page.
        memory.write_raw(BASE + 10 * P, b"P").unwrap();
        child.write_raw(BASE + 10 * P + 1, b"C").unwrap();
        original.write_all_at(b"O", 2).unwrap();
        assert_eq!(read(&memory, BASE + 10 * P, 3), b"PCO");
        assert_eq!(read(&child, BASE + 10 * P, 3), b"PCO");
        assert_eq!(bytes(&original, 0, 3), b"PCO");
        // Private pages stay as they were at the fork on the other side.
        memory
            .write_raw(BASE + 3 * P, b"parent after the fork..")
            .unwrap();
        child.write_raw(BASE + 20 * P, b"child after").unwrap();
        assert_eq!(read(&child, BASE + 3 * P, 23), b"private before the fork");
        assert_eq!(read(&memory, BASE + 20 * P, 11), b"own backing");
    }

    /// When the sparse copy reports a failure, the run is copied byte for
    /// byte instead, and the copy still reads as its source.
    #[test]
    fn a_failed_sparse_snapshot_copy_falls_back_to_every_byte() {
        let (memory, _original) = sparse_snapshot_fixture();
        FAIL_SPARSE_COPY.with(|fail| fail.set(true));
        let copies = [memory.snapshot(), memory.snapshot_sharing_address_space()];
        FAIL_SPARSE_COPY.with(|fail| fail.set(false));
        for child in copies {
            let child = child.unwrap();
            // Every private page was written, zeros included.
            let allocated = allocated_bytes(&child);
            assert!(allocated >= 14 << 20, "{allocated} bytes allocated");
            assert_private_pages_match(&memory, &child);
        }
    }

    /// Every user page of `parent` from `user` on reads as `child`'s.
    fn assert_user_pages_match(parent: &GuestMemory, child: &GuestMemory, user: u64) {
        let mut left = vec![0; PAGE_SIZE];
        let mut right = vec![0; PAGE_SIZE];
        let mut address = user;
        while address < parent.guest_end() {
            parent.read_raw(address, &mut left).unwrap();
            child.read_raw(address, &mut right).unwrap();
            assert!(left == right, "page {:#x}", address);
            address += P;
        }
    }

    /// A vfork child's stores to private memory, and the pages it zeroes, go
    /// back to its parent when its window ends, as on Linux, where the two
    /// share one address space; until then the parent, which waits in its
    /// call, reads its own bytes. Pages below the user range (the backend's
    /// own), and pages the child left alone, are not written; the pages
    /// compared are those either base holds data in. It happens once.
    #[test]
    fn vfork_child_private_changes_go_back_when_the_window_ends() {
        let memory = fixture(SPARSE_PAGES);
        let user = BASE + 2 * P;
        memory.write_raw(BASE, b"reserved").unwrap();
        memory.write_raw(user + 3 * P, b"parent-3").unwrap();
        memory.write_raw(user + 9 * P, b"parent-9").unwrap();
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.write_raw(BASE, b"RESERVED").unwrap();
        child.write_raw(user + 3 * P + 1, b"CHILD").unwrap();
        child.write_raw(user + 40 * P, b"new page").unwrap();
        child.discard_pages(user + 9 * P, PAGE_SIZE).unwrap();
        let last = BASE + (SPARSE_PAGES as u64 - 1) * P;
        child.write_raw(last, b"last").unwrap();
        assert_eq!(read(&memory, user + 3 * P, 8), b"parent-3");
        let returned = child.return_vfork_changes(user).unwrap().unwrap();
        assert_eq!(read(&memory, BASE, 8), b"reserved");
        assert_eq!(read(&memory, user + 3 * P, 8), b"pCHILD-3");
        assert_eq!(read(&memory, user + 9 * P, 8), [0; 8]);
        assert_eq!(read(&memory, user + 40 * P, 8), b"new page");
        assert_eq!(read(&memory, last, 4), b"last");
        assert_user_pages_match(&memory, &child, user);
        // Pages 3, 9, 40 and the last one, whole.
        assert_eq!(returned.bytes_written, 4 * PAGE_SIZE);
        // At most the first and the last 2 MiB, on a host whose shared
        // memory uses huge pages.
        assert!(returned.pages_compared <= 1024, "{returned:?}");
        child.write_raw(user + 3 * P, b"again").unwrap();
        assert_eq!(child.return_vfork_changes(user).unwrap(), None);
        assert_eq!(read(&memory, user + 3 * P, 8), b"pCHILD-3");
        // A fork's copy has no parent to return to.
        let fork = memory.snapshot().unwrap();
        fork.write_raw(user + 3 * P, b"fork").unwrap();
        assert_eq!(fork.return_vfork_changes(user).unwrap(), None);
        assert_eq!(read(&memory, user + 3 * P, 8), b"pCHILD-3");
    }

    /// Parent pages with a private backing of their own, and a page of a
    /// shared view, as the child left them: a private page's change goes
    /// into the parent's own backing, including a page the child zeroed,
    /// which neither base holds data for (the copy's hole and the parent's
    /// backing of its own), and the view, the same object, is not written.
    #[test]
    fn vfork_write_back_reaches_separately_backed_pages_and_skips_views() {
        let memory = fixture(8);
        let original = file(1);
        install(&memory, &original, BASE + 2 * P, 1, 0);
        replace(&memory, BASE + 5 * P, 1, Some(b"own-backing"), true);
        replace(&memory, BASE + 6 * P, 1, Some(b"own-six"), true);
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.write_raw(BASE + 5 * P, b"OWN").unwrap();
        child.discard_pages(BASE + 6 * P, PAGE_SIZE).unwrap();
        child.write_raw(BASE + 2 * P, b"view").unwrap();
        assert_eq!(bytes(&original, 0, 4), b"view");
        let returned = child.return_vfork_changes(BASE).unwrap().unwrap();
        assert_eq!(read(&memory, BASE + 5 * P, 11), b"OWN-backing");
        assert_eq!(read(&memory, BASE + 6 * P, 7), [0; 7]);
        assert_eq!(read(&memory, BASE + 2 * P, 4), b"view");
        assert_eq!(returned.bytes_written, 2 * PAGE_SIZE);
        assert_user_pages_match(&memory, &child, BASE);
    }

    /// Maps a new private anonymous mapping over `[address, address +
    /// pages)` as the provider's `mmap(MAP_FIXED)` does: zeroed, with the
    /// declared protection read-write, and recorded as a new mapping.
    fn map_anonymous_again(memory: &GuestMemory, address: u64, pages: u64) {
        memory.zero_lazily(address, (pages * P) as usize).unwrap();
        memory
            .map_user_protection(
                address,
                pages * P,
                (libc::PROT_READ | libc::PROT_WRITE) as u8,
            )
            .unwrap();
        memory.record_page_backing(address, pages * P, None, false);
    }

    /// The child may change a mapping only for a while. A mapping it removes,
    /// one it adds, a page it maps again with other access, or one it maps
    /// again as it was (a new mapping with the same protection), still so
    /// when the window ends, is refused by name before anything goes back,
    /// since on Linux the change would be the parent's too. A mapping it
    /// adds, stores into and removes again, as a tool's scratch page is, is
    /// gone by then, and its stores do not go back: Linux discards them with
    /// it; a protection it changes and restores is no change.
    #[test]
    fn a_vfork_child_may_change_a_mapping_only_until_its_window_ends() {
        let lasting = |change: &dyn Fn(&GuestMemory)| {
            let memory = fixture(8);
            memory.unmap_user_range(BASE + 6 * P, P).unwrap();
            let child = memory.snapshot_sharing_address_space().unwrap();
            child.write_raw(BASE + 3 * P, b"child").unwrap();
            change(&child);
            match child.return_vfork_changes(BASE) {
                Err(Error::VforkChildCapability {
                    operation: "vfork write-back",
                    reason,
                }) => assert!(reason.starts_with("the vfork child left a mapping changed")),
                other => panic!("expected the write-back refusal, got {other:?}"),
            }
            assert_eq!(read(&memory, BASE + 3 * P, 5), [0; 5]);
        };
        lasting(&|child| child.unmap_user_range(BASE + 4 * P, P).unwrap());
        lasting(&|child| child.map_user_range(BASE + 6 * P, P, false).unwrap());
        lasting(&|child| {
            child
                .map_user_protection(BASE + 4 * P, P, libc::PROT_READ as u8)
                .unwrap()
        });
        // A page mapped again as it was: the same pages, protection and
        // provenance, but another mapping.
        let as_it_was = |memory: &GuestMemory| {
            map_anonymous_again(memory, BASE + 4 * P, 1);
        };
        let memory = fixture(8);
        as_it_was(&memory);
        memory.unmap_user_range(BASE + 6 * P, P).unwrap();
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.write_raw(BASE + 3 * P, b"child").unwrap();
        child.unmap_user_range(BASE + 4 * P, P).unwrap();
        as_it_was(&child);
        assert!(
            matches!(
                child.return_vfork_changes(BASE),
                Err(Error::VforkChildCapability {
                    operation: "vfork write-back",
                    ..
                })
            ),
            "a page mapped again as it was"
        );
        assert_eq!(read(&memory, BASE + 3 * P, 5), [0; 5]);
        let memory = fixture(8);
        memory.unmap_user_range(BASE + 6 * P, P).unwrap();
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.write_raw(BASE + 3 * P, b"child").unwrap();
        child.map_user_range(BASE + 6 * P, P, false).unwrap();
        child.write_raw(BASE + 6 * P, b"scratch").unwrap();
        child.unmap_user_range(BASE + 6 * P, P).unwrap();
        child
            .protect_user_range(BASE + 5 * P, P, libc::PROT_READ as u8)
            .unwrap();
        child
            .protect_user_range(BASE + 5 * P, P, (libc::PROT_READ | libc::PROT_WRITE) as u8)
            .unwrap();
        let returned = child.return_vfork_changes(BASE).unwrap().unwrap();
        assert_eq!(read(&memory, BASE + 3 * P, 5), b"child");
        assert_eq!(read(&memory, BASE + 6 * P, 7), [0; 7]);
        assert_eq!(returned.bytes_written, PAGE_SIZE);
    }

    /// With a baseline, kept when another thread of the parent may run during
    /// the window, only the bytes the child changed go back: that thread's
    /// stores to the same pages stay, and a byte both set to the same value
    /// is no conflict.
    #[test]
    fn a_vfork_baseline_returns_only_the_bytes_the_child_changed() {
        let memory = fixture(8);
        memory.write_raw(BASE + 2 * P, &[1; 64]).unwrap();
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.keep_vfork_baseline().unwrap();
        // Another thread of the parent, during the window.
        memory.write_raw(BASE + 2 * P, b"thread").unwrap();
        memory.write_raw(BASE + 5 * P + 10, &[7]).unwrap();
        // The child.
        child.write_raw(BASE + 2 * P + 32, b"child").unwrap();
        child.write_raw(BASE + 5 * P + 10, &[7]).unwrap();
        child.write_raw(BASE + 6 * P, b"page six").unwrap();
        let returned = child.return_vfork_changes(BASE).unwrap().unwrap();
        assert_eq!(read(&memory, BASE + 2 * P, 6), b"thread");
        assert_eq!(read(&memory, BASE + 2 * P + 6, 26), [1; 26]);
        assert_eq!(read(&memory, BASE + 2 * P + 32, 5), b"child");
        assert_eq!(read(&memory, BASE + 5 * P + 10, 1), [7]);
        assert_eq!(read(&memory, BASE + 6 * P, 8), b"page six");
        assert_eq!(returned.bytes_written, 5 + 8);
    }

    /// A byte that the child and another thread of the parent both changed
    /// to different values during the window cannot be ordered by a copy and
    /// is refused by name before anything of its run is written; so is a
    /// page the child changed whose mapping the other thread replaced or
    /// removed: by a separately backed publication, by a new anonymous
    /// mapping over it with the protection it had (the provider's
    /// `mmap(MAP_FIXED)`), whose zeros the child's bytes would otherwise land
    /// in, or by an unmap and such a mapping, whether or not the page's
    /// mapping had been recorded before the window, or by a remap that shrank
    /// the mapping off the page and grew it back (the provider's in-place
    /// `mremap`), which leaves a fresh page there on Linux. A shrink that
    /// keeps the page keeps its mapping.
    #[test]
    fn a_vfork_baseline_refuses_what_a_copy_cannot_order() {
        for (case, recorded) in [
            ("same byte", false),
            ("replaced", false),
            ("unmapped", false),
            ("mapped over", false),
            ("mapped over", true),
            ("unmapped and mapped", true),
            ("shrunk and grown back", true),
        ] {
            let memory = fixture(8);
            if recorded {
                map_anonymous_again(&memory, BASE + 2 * P, 3);
            }
            let child = memory.snapshot_sharing_address_space().unwrap();
            child.keep_vfork_baseline().unwrap();
            child.write_raw(BASE + 3 * P + 1, b"child").unwrap();
            child.write_raw(BASE + 3 * P + 100, b"also").unwrap();
            match case {
                "same byte" => memory.write_raw(BASE + 3 * P + 2, b"T").unwrap(),
                "replaced" => replace(&memory, BASE + 3 * P, 1, Some(b"new mapping"), true),
                "mapped over" => map_anonymous_again(&memory, BASE + 3 * P, 1),
                "unmapped and mapped" => {
                    memory.unmap_user_range(BASE + 3 * P, P).unwrap();
                    map_anonymous_again(&memory, BASE + 3 * P, 1);
                }
                "shrunk and grown back" => {
                    // As the provider's mremap: the tail goes to zero, the
                    // mapping shrinks to one page, and then grows back.
                    memory.zero_raw(BASE + 3 * P, 2 * PAGE_SIZE).unwrap();
                    memory
                        .remap_user_range(BASE + 2 * P, 3 * P, BASE + 2 * P, P)
                        .unwrap();
                    memory
                        .remap_user_range(BASE + 2 * P, P, BASE + 2 * P, 3 * P)
                        .unwrap();
                }
                _ => memory.unmap_user_range(BASE + 3 * P, P).unwrap(),
            }
            let before = read(&memory, BASE + 3 * P, 128);
            match child.return_vfork_changes(BASE) {
                Err(Error::VforkChildCapability {
                    operation: "vfork write-back",
                    ..
                }) => {}
                other => panic!("{case}: expected the write-back refusal, got {other:?}"),
            }
            assert_eq!(read(&memory, BASE + 3 * P, 128), before, "{case}");
        }
        // A shrink that keeps the page the child changed keeps its mapping,
        // so the child's bytes go back.
        let memory = fixture(8);
        map_anonymous_again(&memory, BASE + 2 * P, 3);
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.keep_vfork_baseline().unwrap();
        child.write_raw(BASE + 3 * P + 1, b"child").unwrap();
        memory.zero_raw(BASE + 4 * P, PAGE_SIZE).unwrap();
        memory
            .remap_user_range(BASE + 2 * P, 3 * P, BASE + 2 * P, 2 * P)
            .unwrap();
        child.return_vfork_changes(BASE).unwrap().unwrap();
        assert_eq!(read(&memory, BASE + 3 * P + 1, 5), b"child");
        // A protection change, by the other thread, of a page the child
        // changed keeps the mapping, so the child's bytes go back.
        let memory = fixture(8);
        map_anonymous_again(&memory, BASE + 3 * P, 1);
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.keep_vfork_baseline().unwrap();
        child.write_raw(BASE + 3 * P + 1, b"child").unwrap();
        memory
            .protect_user_range(BASE + 3 * P, P, libc::PROT_READ as u8)
            .unwrap();
        memory
            .protect_user_range(BASE + 3 * P, P, (libc::PROT_READ | libc::PROT_WRITE) as u8)
            .unwrap();
        child.return_vfork_changes(BASE).unwrap();
        assert_eq!(read(&memory, BASE + 3 * P + 1, 5), b"child");
    }

    /// Copies of an address space share the mapping-incarnation map until one
    /// of them changes it: a fork's copy shares its parent's, an edit that
    /// changes no page's incarnation (an unmap of pages that have none, as a
    /// fork child's hidden Tool-scratch pages are) copies nothing, and the
    /// first real change copies the map into that copy alone, so the other
    /// keeps its own values.
    #[test]
    fn copies_share_the_incarnation_map_until_one_changes_it() {
        let incarnations = |memory: &GuestMemory| {
            memory
                .mapping
                .address_space
                .lock()
                .unwrap()
                .mapping_incarnations
                .clone()
        };
        let memory = fixture(8);
        map_anonymous_again(&memory, BASE + 2 * P, 3);
        let fork = memory.snapshot().unwrap();
        assert!(Arc::ptr_eq(&incarnations(&memory), &incarnations(&fork)));
        assert_eq!(incarnations(&memory).get(&((BASE + 6 * P) / P)), None);
        fork.unmap_user_range(BASE + 6 * P, P).unwrap();
        assert!(Arc::ptr_eq(&incarnations(&memory), &incarnations(&fork)));
        let page = (BASE + 3 * P) / P;
        let before = incarnations(&memory).get(&page).copied();
        assert!(before.is_some());
        fork.unmap_user_range(BASE + 3 * P, P).unwrap();
        assert!(!Arc::ptr_eq(&incarnations(&memory), &incarnations(&fork)));
        assert_eq!(incarnations(&fork).get(&page), None);
        assert_eq!(incarnations(&memory).get(&page).copied(), before);
        // The parent's own change, after the copy, is the parent's alone too.
        let child = memory.snapshot_sharing_address_space().unwrap();
        map_anonymous_again(&memory, BASE + 4 * P, 1);
        let page = (BASE + 4 * P) / P;
        assert_ne!(
            incarnations(&memory).get(&page),
            incarnations(&child).get(&page)
        );
    }

    /// The window also ends at the child's exec, after which nothing of the
    /// new image goes back; and a parent whose image another of its threads
    /// replaced by an exec during the window receives nothing, as on Linux,
    /// where the child's stores reach only the old address space.
    #[test]
    fn exec_ends_a_vfork_window_on_either_side() {
        let memory = fixture(4);
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.retire_shared_files_for_exec().unwrap();
        child.write_raw(BASE + P, b"new image").unwrap();
        assert_eq!(child.return_vfork_changes(BASE).unwrap(), None);
        assert_eq!(read(&memory, BASE + P, 9), [0; 9]);
        let child = memory.snapshot_sharing_address_space().unwrap();
        child.write_raw(BASE + P, b"old image").unwrap();
        memory.retire_shared_files_for_exec().unwrap();
        assert_eq!(child.return_vfork_changes(BASE).unwrap(), None);
        assert_eq!(read(&memory, BASE + P, 9), [0; 9]);
    }
}
