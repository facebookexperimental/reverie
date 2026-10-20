/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::BTreeMap;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use kvm_ioctls::Cap;
use kvm_ioctls::Kvm;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;

use crate::Error;
use crate::Result;
use crate::entry::Closed;
use crate::entry::CopyAccess;
use crate::entry::EntryGate;
use crate::entry::EntryOrigin;
use crate::entry::MappingGeneration;
use crate::entry::RetainedOperand;
use crate::entry::owner::OperationOrigin;
use crate::failure::FailureContext;

const PAGE_SIZE: usize = 4096;

mod shared_file;
pub(crate) use shared_file::AllocationGuard;
use shared_file::MemoryCopyAccess;
pub(crate) use shared_file::PrivateRangePlan;
pub(crate) use shared_file::SharedFileRangePlan;

#[cfg(test)]
type SyscallDispatchObserver = Arc<dyn Fn(&crate::SyscallRequest) + Send + Sync>;

/// Passive injection at the new method's result boundary, after its real copy.
/// No callback or notification runs under the admitted copy for this control.
#[cfg(test)]
struct TestUserCopyFailure {
    cause: Arc<Error>,
    calls: std::sync::atomic::AtomicUsize,
    copied: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
type SharedMapHook = Arc<dyn Fn(usize, usize) -> Option<io::Result<usize>> + Send + Sync>;
#[cfg(test)]
type SharedSyncHook = Arc<dyn Fn(usize, usize, i32) -> Option<i32> + Send + Sync>;

/// A contiguous, page-aligned guest-physical memory region.
#[derive(Clone)]
pub struct GuestMemory {
    mapping: Arc<Mapping>,
    failure_context: Option<FailureContext>,
    operation_origin: Option<OperationOrigin>,
    #[cfg(test)]
    after_vector_copy: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    #[cfg(test)]
    test_vector_copy_observer: Option<Arc<dyn Fn(usize, EntryOrigin) + Send + Sync>>,
    #[cfg(test)]
    test_syscall_dispatch_observer: Option<SyscallDispatchObserver>,
    #[cfg(test)]
    test_backing_contention: Option<Arc<dyn Fn() + Send + Sync>>,
    #[cfg(test)]
    test_user_copy_failure: Option<Arc<TestUserCopyFailure>>,
    #[cfg(test)]
    test_user_copy_backing_wait: Option<Arc<std::sync::atomic::AtomicBool>>,
    #[cfg(test)]
    test_shared_map: Option<SharedMapHook>,
    #[cfg(test)]
    test_shared_sync: Option<SharedSyncHook>,
}

impl std::fmt::Debug for GuestMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestMemory")
            .field("mapping", &self.mapping)
            .finish_non_exhaustive()
    }
}

/// A read accessor for one already admitted synchronous preparation. Its
/// private fields bind the memory and token; callers cannot substitute another
/// Mapping or retain the token beyond try_read_with's closure.
pub(crate) struct RawMemoryRead<'a> {
    memory: &'a GuestMemory,
    copy: &'a CopyAccess,
}

impl RawMemoryRead<'_> {
    pub(crate) fn read_raw(&self, address: u64, destination: &mut [u8]) -> Result<()> {
        self.memory
            .read_raw_admitted(address, destination, self.copy)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackingKind {
    Fixed,
    OrdinaryFile { max_writable: bool },
}

#[derive(Debug)]
struct Backing {
    fd: OwnedFd,
    length: usize,
    host_access: Mutex<()>,
    kind: BackingKind,
}

impl Backing {
    fn new(length: usize) -> io::Result<Self> {
        if length == 0 || !length.is_multiple_of(PAGE_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing length must be nonzero and page-aligned",
            ));
        }
        let file_length = libc::off_t::try_from(length)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "backing exceeds off_t"))?;
        let fd = create_memory_backing()?;
        // SAFETY: fd is a live, writable memfd and file_length fits off_t.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), file_length) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            length,
            host_access: Mutex::new(()),
            kind: BackingKind::Fixed,
        })
    }
}

/// An owned range of a fixed-size backing, independent of any mmap view.
#[derive(Clone, Debug)]
struct BackingSlice {
    backing: Arc<Backing>,
    offset: usize,
    length: usize,
}

impl BackingSlice {
    fn new(backing: Arc<Backing>, offset: usize, length: usize) -> io::Result<Self> {
        if length == 0 || !length.is_multiple_of(PAGE_SIZE) || !offset.is_multiple_of(PAGE_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing slice must be nonempty and page-aligned",
            ));
        }
        let end = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "backing slice end overflows")
        })?;
        libc::off_t::try_from(offset).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "backing offset exceeds off_t")
        })?;
        if backing.kind == BackingKind::Fixed && end > backing.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "backing slice exceeds its backing",
            ));
        }
        Ok(Self {
            backing,
            offset,
            length,
        })
    }
}

#[derive(Debug)]
struct Mapping {
    mapping: NonNull<u8>,
    /// Numeric start of the stable KVM slot. The initial mmap pointer is
    /// exposed once so address-only syscalls can keep naming this range after
    /// individual pages acquire distinct mmap provenance.
    base_address: usize,
    /// Page-start pointers derived while the original whole-range mmap was
    /// intact. After a partial MAP_FIXED, Rust accesses use these only within
    /// an untouched page and never span a replaced hole.
    original_pages: Box<[NonNull<u8>]>,
    slice: BackingSlice,
    guest_base: u64,
    address_space: Mutex<AddressSpaceState>,
    allocation: Mutex<()>,
    entry_gate: Arc<EntryGate>,
    retirement: Mutex<Option<Box<WriteAliasMapping>>>,
    deferred: Mutex<shared_file::DeferredFailures>,
    sync_mmu: Mutex<Option<bool>>,
}

#[derive(Clone, Debug)]
struct AddressSpaceState {
    coverage: IdentityCoverage,
    cursors: Option<AllocationCursors>,
    reservations: BTreeMap<u64, RegionKind>,
    enabled: bool,
    pages: BTreeMap<u64, UserPageState>,
    /// Pages whose stable slot-0 HVA now names a separately retained backing.
    /// The current source increment keeps guest placement identity-only.
    backing_pages: BTreeMap<u64, InstalledBackingPage>,
}

#[derive(Clone, Debug)]
struct InstalledBackingPage {
    _generation: MappingGeneration,
    _slice: BackingSlice,
    /// Exact pointer returned by the latest MAP_FIXED for this page. Repeated
    /// replacements can expose several provenances at one numeric address, so
    /// reconstructing this pointer from the address would be ambiguous.
    mapping: NonNull<u8>,
}

#[derive(Clone)]
struct HostChunk {
    mapping: NonNull<u8>,
    length: usize,
    backing: Arc<Backing>,
}

/// Compatibility placement for the current fixed physical arena. Coverage is
/// independent of reservations and user-copy permissions: a covered hole is
/// still RAM, and reserving it does not make it accessible to user copies.
#[derive(Clone, Debug)]
struct IdentityCoverage {
    start: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AllocationCursors {
    pub(crate) program_break: u64,
    pub(crate) mmap_base: u64,
    pub(crate) mmap_next: u64,
    pub(crate) mmap_limit: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegionKind {
    Bootstrap,
    Elf,
    ProgramHeaders,
    Stack,
    Heap,
    Mmap,
    ToolScratch,
    // The existing public policy helpers also serve native memory controls.
    User,
}

impl RegionKind {
    fn permanent(self) -> bool {
        matches!(
            self,
            Self::Bootstrap | Self::ProgramHeaders | Self::ToolScratch
        )
    }
}

impl AddressSpaceState {
    fn new(start: u64, length: usize) -> Self {
        Self {
            coverage: IdentityCoverage {
                start,
                end: start + length as u64,
            },
            cursors: None,
            reservations: BTreeMap::new(),
            enabled: false,
            pages: BTreeMap::new(),
            backing_pages: BTreeMap::new(),
        }
    }

    fn translate(&self, address: u64, length: usize) -> Result<u64> {
        let offset = address.checked_sub(self.coverage.start);
        let end = offset.and_then(|offset| offset.checked_add(length as u64));
        if end.is_none_or(|end| end > self.coverage.end - self.coverage.start) {
            return Err(Error::InvalidGuestAddress {
                address,
                length,
                guest_base: self.coverage.start,
                guest_end: self.coverage.end,
            });
        }
        // This is deliberately the only production placement in this step.
        // No page-table, memslot or backing mutation accompanies translation.
        Ok(self.coverage.start + offset.unwrap())
    }
}

/// An explicit user-virtual view of a retained physical mapping. Its owner is
/// the same address-space state used by ELF allocation and permission updates.
#[derive(Clone, Debug)]
pub(crate) struct UserMemory {
    memory: GuestMemory,
}

/// A contiguous kernel operand retains its mmap and backing until the host
/// operation returns. No permission/mutation lock is held across a blocking
/// syscall. This is sound only for the current immutable identity coverage;
/// live remapping and noncontiguous operands require a later adapter protocol.
/// This contract belongs to HostMemoryOperand; UserWriteAlias below instead
/// holds permission and host-copy locks through its scoped kernel operation.
#[derive(Debug)]
pub(crate) struct HostMemoryOperand {
    _memory: GuestMemory,
    _retained: RetainedOperand,
    address: usize,
    _length: usize,
}

struct WriteAliasExtent {
    offset: usize,
    slice: BackingSlice,
}

const AMBIGUOUS_WRITE_ALIAS_PHASE: &str =
    "failed writable-alias MAP_FIXED target retained until process exit (ownership unknown)";
const UNEXPECTED_WRITE_ALIAS_ADDRESS: &str =
    "MAP_FIXED installed a writable alias at an unexpected address";

#[derive(Clone, Copy)]
struct WriteAliasRange {
    address: usize,
    length: usize,
}

#[derive(Clone, Copy)]
struct WriteAliasCleanupFailure {
    range: WriteAliasRange,
    errno: i32,
}

/// Owns only virtual addresses; every accessible page aliases retained guest
/// backing. The numeric address is passed to the kernel, never dereferenced as
/// a Rust slice spanning its distinct shared mappings.
///
/// This box is allocated before reserving an address. If Linux refuses cleanup,
/// it becomes a process-lifetime ledger entry without allocating or retaining a
/// guest-memory handle, gate, callable origin, or retained-operand token.
struct WriteAliasMapping {
    address: usize,
    length: usize,
    // A failed MAP_FIXED may retain the reservation or leave a foreign-owned
    // gap. This interval is never included in owned or retried by raw address.
    ambiguous: Option<WriteAliasRange>,
    mapping_errno: Option<i32>,
    // Diagnostic metadata only, never raw cleanup authority. A positive mmap
    // result normally names a valid aligned allocation; if even those bounds
    // are invalid, retain the observation without attempting to unmap it.
    unexpected: Option<WriteAliasRange>,
    unexpected_bounds_valid: bool,
    // The reservation, or its prefix/suffix plus a defensive wrong-address
    // positive mmap result. Each interval is cleared only after munmap succeeds.
    owned: [Option<WriteAliasRange>; 3],
    cleanup: [Option<WriteAliasCleanupFailure>; 3],
    _extents: Vec<WriteAliasExtent>,
    next: Option<Box<WriteAliasMapping>>,
}

impl std::fmt::Debug for WriteAliasMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteAliasMapping")
            .field("address", &self.address)
            .field("length", &self.length)
            .field("ambiguous", &self.ambiguous.is_some())
            .field("backings", &self._extents.len())
            .finish()
    }
}

// Like the terminal-reader ledger, this intentionally has no process teardown
// destructor that retries uncertain addresses or forgets refused ownership.
// getdents64 bounds each reservation to 16 MiB + one page. This does not bound
// whole backing objects pinned by an alias, or accumulation across independent
// failed VMs. The poisoned gate prevents reuse by this VM; host exit finally
// retires the retained mappings. There is no global quota or retry policy.
static RETAINED_WRITE_ALIASES: Mutex<Option<Box<WriteAliasMapping>>> = Mutex::new(None);

#[derive(Default)]
struct WriteAliasRetirement {
    retention_id: usize,
    ambiguous: bool,
    mapping_errno: Option<i32>,
    cleanup: [Option<WriteAliasCleanupFailure>; 3],
}

impl WriteAliasMapping {
    fn lose_fixed_target(&mut self, offset: usize, length: usize, errno: Option<i32>) {
        // All bounds were established while constructing extents, before mmap.
        let end = offset + length;
        self.ambiguous = Some(WriteAliasRange {
            address: self.address + offset,
            length,
        });
        self.mapping_errno = errno;
        self.owned = [
            (offset != 0).then_some(WriteAliasRange {
                address: self.address,
                length: offset,
            }),
            (end != self.length).then_some(WriteAliasRange {
                address: self.address + end,
                length: self.length - end,
            }),
            None,
        ];
    }

    fn note_unexpected_address(&mut self, address: usize, length: usize) {
        self.unexpected = Some(WriteAliasRange { address, length });
        let Some(end) = address.checked_add(length) else {
            return;
        };
        if !address.is_multiple_of(PAGE_SIZE) || length > self.length {
            return;
        }
        self.unexpected_bounds_valid = true;
        let reservation_end = self.address + self.length;
        // Prefix/suffix already cover every still-owned byte inside the
        // reservation. Add only the returned allocation's outside portion,
        // excluding overlaps and the ambiguous target. Its length equals the
        // failed extent's length and cannot exceed the reservation, so it
        // cannot extend past both ends. There is at most one extra interval.
        self.owned[2] = if address < self.address {
            Some(WriteAliasRange {
                address,
                length: end.min(self.address) - address,
            })
        } else if end > reservation_end {
            let start = address.max(reservation_end);
            Some(WriteAliasRange {
                address: start,
                length: end - start,
            })
        } else {
            None
        };
    }

    fn retire(self: Box<Self>) -> WriteAliasRetirement {
        self.retire_with(|range| {
            // SAFETY: this interval remains ours. Failed fixed targets and
            // already retired intervals never enter the ownership array.
            let result = unsafe {
                libc::munmap(
                    std::ptr::with_exposed_provenance_mut::<libc::c_void>(range.address),
                    range.length,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO))
            }
        })
    }

    fn retire_with(
        mut self: Box<Self>,
        mut unmap: impl FnMut(WriteAliasRange) -> std::result::Result<(), i32>,
    ) -> WriteAliasRetirement {
        for (index, owned) in self.owned.iter_mut().enumerate() {
            let Some(range) = *owned else {
                continue;
            };
            // Linux's normal munmap error paths leave these pages mapped,
            // even if a VMA split occurred before refusal (5.15 __do_munmap;
            // 7.1 do_vmi_align_munmap's explicit point of no return).
            match unmap(range) {
                Ok(()) => *owned = None,
                Err(errno) => self.cleanup[index] = Some(WriteAliasCleanupFailure { range, errno }),
            }
        }
        let retained = self.ambiguous.is_some() || self.owned.iter().any(Option::is_some);
        let outcome = WriteAliasRetirement {
            retention_id: if retained {
                std::ptr::from_ref(self.as_ref()).addr()
            } else {
                0
            },
            ambiguous: self.ambiguous.is_some(),
            mapping_errno: self.mapping_errno,
            cleanup: self.cleanup,
        };
        if retained {
            // Ownership transfer allocates nothing, invokes no destructor or
            // notification, and does not depend on formatting the later error.
            let mut head = RETAINED_WRITE_ALIASES
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.next = head.take();
            *head = Some(self);
        }
        outcome
    }
}

impl WriteAliasRetirement {
    fn error(self, primary: Option<Error>) -> Option<Error> {
        let mut error = if self.ambiguous {
            let primary = primary.unwrap_or_else(|| {
                Error::MemoryMapping(match self.mapping_errno {
                    Some(errno) => io::Error::from_raw_os_error(errno),
                    None => io::Error::other(UNEXPECTED_WRITE_ALIAS_ADDRESS),
                })
            });
            Some(primary.cleanup(AMBIGUOUS_WRITE_ALIAS_PHASE))
        } else {
            primary
        };
        for failure in self.cleanup.into_iter().flatten() {
            let cleanup = Error::WriteAliasCleanup {
                source: io::Error::from_raw_os_error(failure.errno),
                address: failure.range.address,
                length: failure.range.length,
                retention_id: self.retention_id,
            };
            error = Some(match error {
                Some(primary) => primary.with_cleanup(vec![cleanup]),
                None => cleanup,
            });
        }
        error
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedWriteAliasSnapshot {
    pub(crate) retention_id: usize,
    pub(crate) address: usize,
    pub(crate) length: usize,
    // All tuples use absolute start addresses and byte lengths.
    pub(crate) ambiguous: Option<(usize, usize)>,
    // Unexpected positive return metadata, not additional cleanup authority.
    pub(crate) unexpected: Option<(usize, usize)>,
    pub(crate) unexpected_bounds_valid: bool,
    pub(crate) owned_ranges: [Option<(usize, usize)>; 3],
    pub(crate) cleanup_errors: [Option<(usize, usize, i32)>; 3],
    // Number of retained extent owners, not necessarily distinct backing files.
    pub(crate) backing_count: usize,
}

#[cfg(test)]
pub(crate) fn retained_write_aliases_for_test() -> Vec<RetainedWriteAliasSnapshot> {
    let head = RETAINED_WRITE_ALIASES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut next = head.as_deref();
    let mut snapshots = Vec::new();
    while let Some(record) = next {
        snapshots.push(RetainedWriteAliasSnapshot {
            retention_id: std::ptr::from_ref(record).addr(),
            address: record.address,
            length: record.length,
            ambiguous: record.ambiguous.map(|range| (range.address, range.length)),
            unexpected: record.unexpected.map(|range| (range.address, range.length)),
            unexpected_bounds_valid: record.unexpected_bounds_valid,
            owned_ranges: record
                .owned
                .map(|range| range.map(|range| (range.address, range.length))),
            cleanup_errors: record.cleanup.map(|failure| {
                failure.map(|failure| (failure.range.address, failure.range.length, failure.errno))
            }),
            backing_count: record._extents.len(),
        });
        next = record.next.as_deref();
    }
    snapshots
}

/// A scoped kernel copyout view. Permissions and host copies are serialized
/// through the syscall, while peer vCPUs still see the exact shared-byte writes.
/// Use only for synchronous operations with bounded buffer sizes that do not
/// reenter guest memory or acquire its allocation lock. Filesystem latency is
/// not bounded: a stalled syscall keeps these locks held. This does not hold a
/// short-copy admission.
pub(crate) struct UserWriteAlias<'a> {
    // Explicit retirement makes every field optional: finish, construction
    // failure, plain Drop and unwind all use the same exactly-once finalizer.
    mapping: Option<Box<WriteAliasMapping>>,
    offset: usize,
    memory: &'a GuestMemory,
    host_access: Option<MutexGuard<'a, ()>>,
    permissions: Option<MutexGuard<'a, AddressSpaceState>>,
    retained: Option<RetainedOperand>,
}

impl UserWriteAlias<'_> {
    /// Kernel-only operand for at most the requested byte count. For zero bytes
    /// this is an unowned sentinel, not a dereferenceable allocation. The caller
    /// must use a syscall whose zero-count contract never accesses that pointer.
    pub(crate) fn address(&self) -> *mut libc::c_void {
        let address = self
            .mapping
            .as_ref()
            .map_or(PAGE_SIZE, |mapping| mapping.address);
        std::ptr::with_exposed_provenance_mut(address + self.offset)
    }

    fn retire(&mut self, primary: Option<Error>) {
        let retirement = self
            .mapping
            .take()
            .map_or_else(WriteAliasRetirement::default, WriteAliasMapping::retire);
        // Neither error publication nor operand retirement may notify a waker
        // while either guest-memory lock is held. The ownership ledger has
        // already accepted every unresolved interval before these unlocks.
        drop(self.host_access.take());
        drop(self.permissions.take());
        if std::thread::panicking() {
            // The operand captures the original unwind before notifying. Do
            // not let a secondary munmap failure replace that primary cause.
            // With no cleanup error this remains the original single wake.
            drop(self.retained.take());
        }
        if let Some(error) = retirement.error(primary) {
            self.memory
                .mapping
                .entry_gate
                .poison(self.memory.entry_origin(), error);
        }
        drop(self.retained.take());
    }

    fn fail(mut self, error: Error) -> Error {
        if matches!(&error, Error::MemoryMapping(_)) {
            self.retire(Some(error));
            self.memory
                .check_copy_failure()
                .expect_err("writable alias infrastructure failure must poison its gate")
        } else {
            self.retire(None);
            self.memory.check_copy_failure().err().unwrap_or(error)
        }
    }

    pub(crate) fn finish(mut self) -> Result<()> {
        self.retire(None);
        self.memory.check_copy_failure()
    }
}

impl Drop for UserWriteAlias<'_> {
    fn drop(&mut self) {
        self.retire(None);
    }
}

/// Proof returned only after the memory owner has retained an installed mmap
/// view. Closed admission consumes this receipt before advancing the sole
/// mapping generation.
pub(crate) struct InstalledMapping {
    generation: MappingGeneration,
}

impl InstalledMapping {
    fn new(generation: MappingGeneration) -> Self {
        Self { generation }
    }

    pub(crate) fn generation(&self) -> MappingGeneration {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn gate_control(generation: MappingGeneration) -> Self {
        Self::new(generation)
    }
}

impl HostMemoryOperand {
    pub(crate) fn address(&self) -> usize {
        self.address
    }

    #[cfg(test)]
    pub(crate) unsafe fn read_volatile<T: Copy>(&self) -> T {
        let length = std::mem::size_of::<T>();
        assert!(length != 0 && length <= self._length);
        assert!(self.address.is_multiple_of(std::mem::align_of::<T>()));
        let offset = self
            .address
            .checked_sub(self._memory.mapping.base_address)
            .expect("retained host operand belongs to its mapping");
        let chunks = self._memory.mapping.host_chunks(offset, length);
        assert_eq!(chunks.len(), 1, "test value crosses an mmap boundary");
        let chunk = &chunks[0];
        assert_eq!(
            chunk.backing.kind,
            BackingKind::Fixed,
            "volatile Rust dereference requires fixed backing"
        );
        // SAFETY: the caller excludes concurrent writers. The retained operand
        // prevents publication, and host_chunks returned the exact live mmap
        // pointer rather than reconstructing it from the numeric HVA.
        unsafe { chunk.mapping.as_ptr().cast::<T>().read_volatile() }
    }
}

/// One completely prepared physical page whose installation is deferred until
/// a matching address-space close token is held. The allocation guard prevents
/// another layout transaction from passing preparation before this one either
/// publishes or is abandoned.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the generation-bound physical-page publisher is not activated by guest mappings yet"
    )
)]
pub(crate) struct PendingBackingPage<'a> {
    memory: &'a GuestMemory,
    _allocation: AllocationGuard<'a>,
    page: u64,
    expected_generation: MappingGeneration,
    slice: Option<BackingSlice>,
}

/// An allocation owns its proposed physical pages before initialization. A
/// failed initialization restores ownership metadata, without pretending to
/// undo any bytes that the historical operation already modified.
pub(crate) struct PendingReservation {
    memory: GuestMemory,
    old: Vec<(u64, Option<RegionKind>)>,
    committed: bool,
}

impl PendingReservation {
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingReservation {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let mut state = self
            .memory
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        for (page, old) in &self.old {
            match old {
                Some(kind) => {
                    state.reservations.insert(*page, *kind);
                }
                None => {
                    state.reservations.remove(page);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserPageState {
    Accessible { writable: bool },
    NoAccess,
}

// SAFETY: Mapping owns every mmap view until Drop, not a Rust reference.
// Arc<Backing> retains the shared host_access mutex and each file descriptor
// needed for backing operations. Host access through all views is serialized
// by the original backing's mutex. Rust dereferences touch only fixed RAM,
// split at mmap page boundaries with the exact live pointer for that page.
// Truncate-capable ordinary files are accessed only by fault-contained kernel
// copies using retained raw addresses, never Rust slices or raw memcpy.
// The KVM backend
// exposes handles only while its single vCPU is stopped at an exit; the host
// mutex does not stop vCPU access.
unsafe impl Send for Mapping {}
// SAFETY: See the Send implementation. All host reads and writes take the
// backing's mutex before dereferencing fixed RAM or issuing a contained file copy.
unsafe impl Sync for Mapping {}

impl GuestMemory {
    /// Allocates a shared, memfd-backed mapping for a guest-physical address range.
    pub fn new(guest_base: u64, size: usize) -> Result<Self> {
        Self::validate_layout(guest_base, size)?;
        let backing = Arc::new(Backing::new(size).map_err(Error::MemoryMapping)?);
        let slice = BackingSlice::new(backing, 0, size).map_err(Error::MemoryMapping)?;
        Self::from_backing_slice(guest_base, slice)
    }

    fn validate_layout(guest_base: u64, size: usize) -> Result<()> {
        let size_u64 = u64::try_from(size).expect("usize must fit in u64 on x86-64");
        if size == 0
            || !size.is_multiple_of(PAGE_SIZE)
            || !guest_base.is_multiple_of(PAGE_SIZE as u64)
            || guest_base.checked_add(size_u64).is_none()
            || libc::off_t::try_from(size).is_err()
        {
            return Err(Error::InvalidMemoryLayout { guest_base, size });
        }

        Ok(())
    }

    fn from_backing_slice(guest_base: u64, slice: BackingSlice) -> Result<Self> {
        Self::validate_layout(guest_base, slice.length)?;
        if slice.backing.kind != BackingKind::Fixed {
            return Err(Error::SharedFileCapability {
                operation: "initial memory image",
                reason: "ordinary files require the retained publication path",
            });
        }

        // SAFETY: slice owns a live memfd and a validated page-aligned range;
        // its offset fits off_t. The returned view is released once in Drop.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                slice.length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_NORESERVE,
                slice.backing.fd.as_raw_fd(),
                slice.offset as libc::off_t,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(Error::MemoryMapping(std::io::Error::last_os_error()));
        }

        let mapping: NonNull<u8> =
            NonNull::new(mapping.cast()).expect("mmap returned a null mapping");
        let base_address = mapping.as_ptr().expose_provenance();
        let original_pages = (0..slice.length / PAGE_SIZE)
            .map(|page| {
                // SAFETY: this is derived while the original whole-range mmap
                // is intact, and every offset names the start of a live page.
                unsafe { NonNull::new_unchecked(mapping.as_ptr().add(page * PAGE_SIZE)) }
            })
            .collect();
        let size = slice.length;
        Ok(Self {
            mapping: Arc::new(Mapping {
                mapping,
                base_address,
                original_pages,
                slice,
                guest_base,
                address_space: Mutex::new(AddressSpaceState::new(guest_base, size)),
                allocation: Mutex::new(()),
                entry_gate: EntryGate::new(),
                retirement: Mutex::new(None),
                deferred: Mutex::new(shared_file::DeferredFailures::default()),
                sync_mmu: Mutex::new(None),
            }),
            failure_context: None,
            operation_origin: None,
            #[cfg(test)]
            after_vector_copy: None,
            #[cfg(test)]
            test_vector_copy_observer: None,
            #[cfg(test)]
            test_syscall_dispatch_observer: None,
            #[cfg(test)]
            test_backing_contention: None,
            #[cfg(test)]
            test_user_copy_failure: None,
            #[cfg(test)]
            test_user_copy_backing_wait: None,
            #[cfg(test)]
            test_shared_map: None,
            #[cfg(test)]
            test_shared_sync: None,
        })
    }

    pub(crate) fn entry_gate(&self) -> Arc<EntryGate> {
        self.mapping.entry_gate.clone()
    }

    #[cfg(test)]
    pub(crate) fn test_mapping_owners(&self) -> impl Fn() -> usize + Send + Sync + 'static + use<> {
        let mapping = Arc::downgrade(&self.mapping);
        move || mapping.strong_count()
    }

    /// Attribution belongs to this handle, not to every alias of the Mapping.
    pub(crate) fn set_failure_context(&mut self, context: Option<FailureContext>) {
        self.failure_context = context;
    }

    /// Retained clones keep this exact generation. Rebinding this handle does
    /// not change any other view of the Mapping.
    pub(crate) fn set_operation_origin(&mut self, origin: Option<OperationOrigin>) {
        self.operation_origin = origin;
    }

    pub(crate) fn entry_origin(&self) -> EntryOrigin {
        EntryOrigin {
            failure: self.failure_context.clone(),
            operation: self.operation_origin.clone(),
        }
    }

    fn copy_access(&self) -> Result<MemoryCopyAccess<'_>> {
        self.check_copy_failure()?;
        self.mapping
            .entry_gate
            .copy_blocking(self.entry_origin())
            .map(|copy| MemoryCopyAccess::new(self, copy))
            .map_err(|failure| failure.error())
    }

    fn check_copy_failure(&self) -> Result<()> {
        match self.mapping.entry_gate.pending_failure() {
            Some(failure) => Err(failure.error()),
            None => match self.deferred_failure() {
                Some(cause) => Err(Error::SharedFailure(cause)),
                None => Ok(()),
            },
        }
    }

    fn with_copy<T>(&self, operation: impl FnOnce(&CopyAccess) -> Result<T>) -> Result<T> {
        // Admission precedes translation, permission and backing locks. An
        // enclosing allocation transaction (snapshot/mmap) may remain owned;
        // no admitted helper acquires allocation, and close never needs it.
        let copy = self.copy_access()?;
        let result = operation(&copy);
        // An admitted operation may have effects before poison. Keep them,
        // but do not turn an observed backend failure into ordinary success.
        let prior = self.check_copy_failure();
        drop(copy);
        let result = result.map_err(|error| self.capture_shared_file_error(error));
        prior?;
        self.check_copy_failure()?;
        result
    }

    /// Attempts a whole synchronous read preparation under one short token.
    /// The closure must not wait for admission or acquire allocation. It runs
    /// only after open admission, and neither accessor nor token can escape.
    pub(crate) fn try_read_with<T>(
        &self,
        operation: impl FnOnce(&RawMemoryRead<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        self.check_copy_failure()?;
        let Some(copy) = self
            .mapping
            .entry_gate
            .try_copy(self.entry_origin())
            .map_err(|failure| failure.error())?
        else {
            return Ok(None);
        };
        let copy = MemoryCopyAccess::new(self, copy);
        let result = operation(&RawMemoryRead {
            memory: self,
            copy: &copy,
        });
        let prior = self.check_copy_failure();
        drop(copy);
        let result = result.map_err(|error| self.capture_shared_file_error(error));
        prior?;
        self.check_copy_failure()?;
        result.map(Some)
    }

    #[cfg(test)]
    pub(crate) fn set_test_vector_copy_observer(
        &mut self,
        observer: Arc<dyn Fn(usize, EntryOrigin) + Send + Sync>,
    ) {
        self.test_vector_copy_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn set_test_syscall_dispatch_observer(&mut self, observer: SyscallDispatchObserver) {
        self.test_syscall_dispatch_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn observe_test_syscall_dispatch(&self, request: &crate::SyscallRequest) {
        if let Some(observer) = &self.test_syscall_dispatch_observer {
            observer(request);
        }
    }

    #[cfg(test)]
    fn before_vector_copy(&self, total: usize) {
        if total == 0 {
            crate::entry::driver::test_observation::current(
                crate::entry::driver::test_observation::Event::Copy(
                    self.entry_gate(),
                    self.entry_origin(),
                ),
            );
            self.observe_test_vector_copy(total);
        }
    }

    #[cfg(test)]
    fn observe_test_vector_copy(&self, total: usize) {
        if let Some(observer) = &self.test_vector_copy_observer {
            // Use this issuing handle's binding, not the binding that existed
            // when a public-driver fixture installed the observer.
            observer(total, self.entry_origin());
        }
    }

    #[cfg(test)]
    fn after_vector_copy(&self, total: usize) {
        if let Some(hook) = &self.after_vector_copy {
            hook(total);
        }
        self.observe_test_vector_copy(total);
    }

    pub(crate) fn snapshot(&self) -> Result<Self> {
        self.snapshot_with_sparse_copy(copy_sparse_file)
    }

    fn snapshot_with_sparse_copy(
        &self,
        sparse_copy: impl FnOnce(RawFd, RawFd, usize) -> io::Result<()>,
    ) -> Result<Self> {
        const COPY_CHUNK: usize = 1024 * 1024;

        self.check_copy_failure()?;
        let _allocation = self.allocation_guard();
        if self.contains_shared_file() {
            return self.snapshot_with_shared_files(_allocation);
        }
        if self.entry_gate().single_member_domain_active() {
            return Err(Error::SharedFileCapability {
                operation: "memory snapshot",
                reason: "shared-file publication is not quiescent",
            });
        }
        let snapshot = Self::new(self.guest_base(), self.len())?;
        let user_access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned")
            .clone();

        // The sparse helper requires whole, equal-sized files at offset zero.
        // A subset uses the existing view-relative copy without extending that
        // contract or copying bytes outside the view.
        let copied_sparse = if user_access.backing_pages.is_empty()
            && self.mapping.slice.offset == 0
            && self.len() == self.mapping.slice.backing.length
        {
            let _source_guard = self
                .mapping
                .slice
                .backing
                .host_access
                .lock()
                .expect("guest memory lock poisoned");
            let _destination_guard = snapshot
                .mapping
                .slice
                .backing
                .host_access
                .lock()
                .expect("guest memory lock poisoned");
            sparse_copy(
                self.mapping.slice.backing.fd.as_raw_fd(),
                snapshot.mapping.slice.backing.fd.as_raw_fd(),
                self.len(),
            )
            .is_ok()
        } else {
            false
        };

        // SEEK_DATA/SEEK_HOLE and copy_file_range are Linux optimizations, not
        // correctness requirements. If either is unavailable or cannot finish
        // an extent, overwrite the entire destination using the previous copy
        // path. This also replaces any prefix copied before the failure.
        if !copied_sparse {
            let mut buffer = vec![0; COPY_CHUNK.min(self.len())];
            let mut offset = 0;
            while offset < self.len() {
                let length = buffer.len().min(self.len() - offset);
                let address = self.guest_base() + offset as u64;
                self.read_raw(address, &mut buffer[..length])?;
                snapshot.write_raw(address, &buffer[..length])?;
                offset += length;
            }
        }
        let mut snapshot_state = user_access;
        // Snapshot copied the currently installed HVA bytes into its own one-
        // backing image. It starts an independent publication history and must
        // not claim that the source's separately retained page backings are
        // installed in the new HVA.
        snapshot_state.backing_pages.clear();
        *snapshot
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned") = snapshot_state;
        // The sparse fd operation is not a copy lease or a global snapshot
        // fence. Fallback byte copies each take their own short admission.
        self.check_copy_failure()?;
        Ok(snapshot)
    }

    #[cfg(test)]
    pub(crate) fn reservation_kind(&self, address: u64) -> Option<RegionKind> {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .reservations
            .get(&(address / PAGE_SIZE as u64))
            .copied()
    }

    #[cfg(test)]
    pub(crate) fn reserved_pages(&self) -> usize {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .reservations
            .len()
    }

    pub(crate) fn user(&self) -> UserMemory {
        UserMemory {
            memory: self.clone(),
        }
    }

    /// Prepare one page replacement without changing the live HVA or KVM
    /// translation. KVM's synchronous-MMU capability is checked before the
    /// allocation transaction is retained; publication performs no allocation
    /// and has a terminal failure contract.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the generation-bound physical-page publisher is not activated by guest mappings yet"
        )
    )]
    pub(crate) fn stage_backing_page<'a>(
        &'a self,
        guest_address: u64,
        contents: &[u8],
    ) -> Result<PendingBackingPage<'a>> {
        if !guest_address.is_multiple_of(PAGE_SIZE as u64) || contents.len() != PAGE_SIZE {
            return Err(Error::InvalidMemoryLayout {
                guest_base: guest_address,
                size: contents.len(),
            });
        }
        self.checked_offset(guest_address, PAGE_SIZE)?;
        let kvm = Kvm::new()?;
        if !kvm.check_extension(Cap::SyncMmu) {
            return Err(Error::SynchronousMmuUnsupported);
        }

        let backing = Arc::new(Backing::new(PAGE_SIZE).map_err(Error::MemoryMapping)?);
        write_backing(&backing, contents).map_err(Error::MemoryMapping)?;
        let slice = BackingSlice::new(backing, 0, PAGE_SIZE).map_err(Error::MemoryMapping)?;
        let allocation = self.allocation_guard();
        // Recheck after acquiring the transaction guard. The immutable bounds
        // cannot change today, but keeping validation here makes that ordering
        // explicit for the later virtual-map owner.
        self.checked_offset(guest_address, PAGE_SIZE)?;
        let expected_generation = self
            .mapping
            .entry_gate
            .generation()
            .map_err(|failure| failure.error())?;
        Ok(PendingBackingPage {
            memory: self,
            _allocation: allocation,
            page: guest_address / PAGE_SIZE as u64,
            expected_generation,
            slice: Some(slice),
        })
    }

    #[cfg(test)]
    pub(crate) fn backing_generation(&self) -> MappingGeneration {
        self.mapping.entry_gate.generation().unwrap()
    }

    #[cfg(test)]
    pub(crate) fn separately_backed_pages(&self) -> usize {
        self.mapping
            .address_space
            .lock()
            .unwrap()
            .backing_pages
            .len()
    }

    pub(crate) fn allocation_cursors(&self) -> Option<AllocationCursors> {
        self.mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned")
            .cursors
    }

    pub(crate) fn set_allocation_cursors(&self, cursors: AllocationCursors) {
        self.mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned")
            .cursors = Some(cursors);
    }

    pub(crate) fn reserve_region(
        &self,
        address: u64,
        length: u64,
        kind: RegionKind,
    ) -> Result<PendingReservation> {
        self.reserve_region_inner(address, length, kind, false)
    }

    /// mremap historically admits a mapped PHDR range below BOOT_RESERVED_END.
    /// Preserve that guest policy without transferring or releasing ownership
    /// of the underlying supervisor frame. No new low mapping is admitted.
    pub(crate) fn reserve_remap_region(
        &self,
        address: u64,
        length: u64,
    ) -> Result<PendingReservation> {
        self.reserve_region_inner(address, length, RegionKind::Mmap, true)
    }

    fn reserve_region_inner(
        &self,
        address: u64,
        length: u64,
        kind: RegionKind,
        preserve_supervisor: bool,
    ) -> Result<PendingReservation> {
        let range = self.checked_page_range(address, length)?;
        let mut state = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let mut old = Vec::new();
        if let Some((first, last)) = range {
            // User replacements remain admitted, including overlapping PT_LOAD
            // pages and MAP_FIXED. Supervisor replacement is only explicit PHDR
            // or Tool-scratch exposure, never an ordinary allocation.
            if !preserve_supervisor
                && !kind.permanent()
                && (first..=last).any(|page| {
                    state
                        .reservations
                        .get(&page)
                        .is_some_and(|kind| kind.permanent())
                })
            {
                return Err(Error::GuestMemoryAccessDenied {
                    address,
                    length: length as usize,
                });
            }
            for page in first..=last {
                if preserve_supervisor
                    && state
                        .reservations
                        .get(&page)
                        .is_some_and(|kind| kind.permanent())
                {
                    continue;
                }
                old.push((page, state.reservations.insert(page, kind)));
            }
        }
        Ok(PendingReservation {
            memory: self.clone(),
            old,
            committed: false,
        })
    }

    /// Returns the first guest-physical address in the mapping.
    pub fn guest_base(&self) -> u64 {
        self.mapping.guest_base
    }

    /// Returns the mapping size in bytes.
    pub fn len(&self) -> usize {
        self.mapping.slice.length
    }

    /// Returns the address immediately after this guest-memory region.
    pub fn guest_end(&self) -> u64 {
        self.mapping.guest_base + self.mapping.slice.length as u64
    }

    /// Returns whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.mapping.slice.length == 0
    }

    // TODO-HUMAN-REVIEW(PR-132): Review the host-side KVM user mapping API.
    pub(crate) fn clear_user_access(&self) {
        if self.contains_shared_file() {
            self.capture_shared_file_error(Error::SharedFileCapability {
                operation: "clear user access",
                reason: "ordinary-file views must retire before reset",
            });
            return;
        }
        let mut access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        access.enabled = false;
        access.pages.clear();
        access.reservations.clear();
        access.cursors = None;
    }

    // TODO-HUMAN-REVIEW(PR-132): Review the host-side KVM user mapping API.
    pub(crate) fn enable_user_access(&self) {
        self.mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned")
            .enabled = true;
    }

    // TODO-HUMAN-REVIEW(PR-132): Review the host-side KVM user mapping API.
    pub(crate) fn map_user_range(
        &self,
        guest_address: u64,
        length: u64,
        no_access: bool,
    ) -> Result<()> {
        self.map_user_permissions(guest_address, length, !no_access, !no_access)
    }

    pub(crate) fn map_user_permissions(
        &self,
        guest_address: u64,
        length: u64,
        accessible: bool,
        writable: bool,
    ) -> Result<()> {
        let Some((first_page, last_page)) = self.checked_page_range(guest_address, length)? else {
            return Ok(());
        };
        let state = if accessible {
            UserPageState::Accessible { writable }
        } else {
            UserPageState::NoAccess
        };
        let mut access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        if writable
            && access
                .backing_pages
                .range(first_page..=last_page)
                .any(|(_, page)| {
                    matches!(
                        page._slice.backing.kind,
                        BackingKind::OrdinaryFile {
                            max_writable: false
                        }
                    )
                })
        {
            return Err(Error::GuestMemoryAccessDenied {
                address: guest_address,
                length: length as usize,
            });
        }
        for page in first_page..=last_page {
            access.pages.insert(page, state);
            access.reservations.entry(page).or_insert(RegionKind::User);
        }
        Ok(())
    }

    // TODO-HUMAN-REVIEW(PR-132): Review the host-side KVM user mapping API.
    pub(crate) fn unmap_user_range(&self, guest_address: u64, length: u64) -> Result<()> {
        if self.range_contains_shared_file(guest_address, length as usize) {
            return Err(Error::SharedFileCapability {
                operation: "metadata-only unmap",
                reason: "ordinary-file backing requires physical private replacement",
            });
        }
        let Some((first_page, last_page)) = self.checked_page_range(guest_address, length)? else {
            return Ok(());
        };
        let mut access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        for page in first_page..=last_page {
            access.pages.remove(&page);
            if !access
                .reservations
                .get(&page)
                .is_some_and(|kind| kind.permanent())
            {
                access.reservations.remove(&page);
            }
        }
        Ok(())
    }

    // TODO-HUMAN-REVIEW(PR-132): Review the host-side KVM user mapping API.
    pub(crate) fn user_range_is_mapped(&self, guest_address: u64, length: u64) -> bool {
        let Ok(Some((first_page, last_page))) = self.checked_page_range(guest_address, length)
        else {
            return false;
        };
        let access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        (first_page..=last_page).all(|page| access.pages.contains_key(&page))
    }

    // AUTONOMOUS-BOT-IMPLEMENTED: Reuse deterministic holes in the KVM guest arena.
    // TODO-HUMAN-REVIEW(PR-176): Review mmap hole-selection semantics.
    pub(crate) fn find_unmapped_user_range(
        &self,
        start: u64,
        end: u64,
        length: u64,
    ) -> Option<u64> {
        let page_size = PAGE_SIZE as u64;
        if length == 0
            || !start.is_multiple_of(page_size)
            || !end.is_multiple_of(page_size)
            || !length.is_multiple_of(page_size)
            || start < self.guest_base()
            || end > self.guest_end()
            || start >= end
        {
            return None;
        }

        let pages_needed = length / page_size;
        let end_page = end / page_size;
        let mut candidate = start / page_size;
        if candidate.checked_add(pages_needed)? > end_page {
            return None;
        }

        let access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        for (&occupied, _) in access.pages.range(candidate..end_page) {
            if candidate.checked_add(pages_needed)? <= occupied {
                return candidate.checked_mul(page_size);
            }
            candidate = occupied.checked_add(1)?;
            if candidate.checked_add(pages_needed)? > end_page {
                return None;
            }
        }
        candidate.checked_mul(page_size)
    }

    // TODO-HUMAN-REVIEW(PR-132): Review the host-side KVM user mapping API.
    pub(crate) fn remap_user_range(
        &self,
        old_address: u64,
        old_length: u64,
        new_address: u64,
        new_length: u64,
    ) -> Result<()> {
        if self.range_contains_shared_file(old_address, old_length as usize)
            || self.range_contains_shared_file(new_address, new_length as usize)
        {
            return Err(Error::SharedFileCapability {
                operation: "memory remap",
                reason: "ordinary-file source or destination is not supported by the private-copy remapper",
            });
        }
        let Some((old_first, old_last)) = self.checked_page_range(old_address, old_length)? else {
            return Ok(());
        };
        let Some((new_first, new_last)) = self.checked_page_range(new_address, new_length)? else {
            return Ok(());
        };
        let mut access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let old_states = (old_first..=old_last)
            .map(|page| access.pages.get(&page).copied())
            .collect::<Vec<_>>();
        if old_states.iter().any(Option::is_none) {
            return Err(Error::GuestMemoryAccessDenied {
                address: old_address,
                length: usize::try_from(old_length).unwrap_or(usize::MAX),
            });
        }
        let old_kinds = (old_first..=old_last)
            .map(|page| {
                access
                    .reservations
                    .get(&page)
                    .copied()
                    .unwrap_or(RegionKind::User)
            })
            .collect::<Vec<_>>();
        let extension_state = old_states
            .last()
            .copied()
            .flatten()
            .expect("nonempty mapped range has a last page");
        for page in old_first..=old_last {
            access.pages.remove(&page);
            if !access
                .reservations
                .get(&page)
                .is_some_and(|kind| kind.permanent())
            {
                access.reservations.remove(&page);
            }
        }
        for (index, page) in (new_first..=new_last).enumerate() {
            let state = old_states
                .get(index)
                .copied()
                .flatten()
                .unwrap_or(extension_state);
            access.pages.insert(page, state);
            if !access
                .reservations
                .get(&page)
                .is_some_and(|kind| kind.permanent())
            {
                let kind = old_kinds
                    .get(index)
                    .copied()
                    .unwrap_or(*old_kinds.last().unwrap());
                // A low exposed supervisor page may supply the original user
                // policy; its physical reservation does not move with bytes.
                access.reservations.insert(
                    page,
                    if kind.permanent() {
                        RegionKind::Mmap
                    } else {
                        kind
                    },
                );
            }
        }
        Ok(())
    }

    /// Copies bytes from guest memory into a host buffer.
    // TODO-HUMAN-REVIEW(PR-132): Review user-map enforcement on this public API.
    pub fn read(&self, guest_address: u64, destination: &mut [u8]) -> Result<()> {
        self.with_copy(|copy| {
            self.checked_offset(guest_address, destination.len())?;
            if self.user().user_accessible_prefix_admitted(
                guest_address,
                destination.len(),
                copy,
            )? != destination.len()
            {
                return Err(Error::GuestMemoryAccessDenied {
                    address: guest_address,
                    length: destination.len(),
                });
            }
            self.read_raw_admitted(guest_address, destination, copy)
        })
    }

    // TODO-HUMAN-REVIEW(PR-132): Review internal copies that bypass the user map.
    pub(crate) fn read_raw(&self, guest_address: u64, destination: &mut [u8]) -> Result<()> {
        self.with_copy(|copy| self.read_raw_admitted(guest_address, destination, copy))
    }

    fn read_raw_admitted(
        &self,
        guest_address: u64,
        destination: &mut [u8],
        _copy: &CopyAccess,
    ) -> Result<()> {
        let offset = self.checked_offset(guest_address, destination.len())?;
        let chunks = self.mapping.host_chunks(offset, destination.len());
        #[cfg(test)]
        if let Some(observe) = &self.test_backing_contention {
            // Record a real failed lock attempt while the actual short-copy
            // admission remains owned. The normal blocking lock below is
            // unchanged; successful or poisoned probes do not report waiting.
            let contended = matches!(
                self.mapping.slice.backing.host_access.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            );
            if contended {
                observe();
            }
        }
        self.read_host_chunks(&chunks, guest_address, destination)
    }

    /// Copies bytes from a host slice into guest memory.
    // TODO-HUMAN-REVIEW(PR-132): Review user-map enforcement on this public API.
    pub fn write(&mut self, guest_address: u64, source: &[u8]) -> Result<()> {
        self.with_copy(|copy| {
            self.checked_offset(guest_address, source.len())?;
            if self
                .user()
                .user_accessible_prefix_admitted(guest_address, source.len(), copy)?
                != source.len()
            {
                return Err(Error::GuestMemoryAccessDenied {
                    address: guest_address,
                    length: source.len(),
                });
            }
            self.write_raw_admitted(guest_address, source, copy)
        })
    }

    #[cfg(test)]
    pub(crate) fn copy_to_user(&self, guest_address: u64, source: &[u8]) -> Result<()> {
        self.user().copy_to_user(guest_address, source)
    }

    #[cfg(test)]
    pub(crate) fn put_user_i32(&self, guest_address: u64, value: i32) -> Result<()> {
        self.user().put_user_i32(guest_address, value)
    }

    /// Copies and returns the writable prefix while retaining the permission
    /// lock through the copy. Callers that consume a stream must advance only
    /// by this actual count, including a partial fault.
    #[cfg(test)]
    pub(crate) fn copy_to_user_prefix(&self, guest_address: u64, source: &[u8]) -> Result<usize> {
        self.user().copy_to_user_prefix(guest_address, source)
    }

    // TODO-HUMAN-REVIEW(PR-132): Review internal copies that bypass the user map.
    pub(crate) fn write_raw(&self, guest_address: u64, source: &[u8]) -> Result<()> {
        self.with_copy(|copy| self.write_raw_admitted(guest_address, source, copy))
    }

    /// Attempts one short copy without parking the calling executor. A closed
    /// gate returns None before inspecting layout or taking a backing lock.
    /// The owner must subscribe, recheck its stop predicates and await before
    /// retrying; None is neither a completed copy nor a guest memory fault.
    pub(crate) fn try_write_raw(&self, guest_address: u64, source: &[u8]) -> Result<Option<()>> {
        self.check_copy_failure()?;
        let Some(copy) = self
            .mapping
            .entry_gate
            .try_copy(self.entry_origin())
            .map_err(|failure| failure.error())?
        else {
            return Ok(None);
        };
        let copy = MemoryCopyAccess::new(self, copy);
        let result = self.write_raw_admitted(guest_address, source, &copy);
        let prior = self.check_copy_failure();
        drop(copy);
        let result = result.map_err(|error| self.capture_shared_file_error(error));
        prior?;
        self.check_copy_failure()?;
        result.map(Some)
    }

    fn write_raw_admitted(
        &self,
        guest_address: u64,
        source: &[u8],
        _copy: &CopyAccess,
    ) -> Result<()> {
        let offset = self.checked_offset(guest_address, source.len())?;
        let chunks = self.mapping.host_chunks(offset, source.len());
        self.write_host_chunks(&chunks, guest_address, source)
    }

    /// Write through pointers already resolved under the caller's applicable
    /// address-space guard. Keeping resolution separate lets permission-aware
    /// copyout retain that guard through the actual write without re-locking.
    fn write_host_chunks(&self, chunks: &[HostChunk], address: u64, source: &[u8]) -> Result<()> {
        #[cfg(test)]
        if let Some(observed) = &self.test_user_copy_backing_wait {
            // Passive observation of an actual failed lock attempt. The test
            // controller can inspect the still-owned permission guard without
            // introducing a callback under a copy token or memory lock.
            if matches!(
                self.mapping.slice.backing.host_access.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ) {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let _guard = self
            .mapping
            .slice
            .backing
            .host_access
            .lock()
            .expect("guest memory lock poisoned");
        let mut copied = 0;
        for chunk in chunks {
            let local = unsafe { source.as_ptr().add(copied).cast_mut() };
            match chunk.backing.kind {
                BackingKind::OrdinaryFile { .. } => {
                    self.copy_file_chunk(chunk, local, true, address, source.len(), copied)?
                }
                BackingKind::Fixed => unsafe {
                    std::ptr::copy_nonoverlapping(local, chunk.mapping.as_ptr(), chunk.length);
                },
            }
            copied += chunk.length;
        }
        debug_assert_eq!(copied, source.len());
        Ok(())
    }
    /// Zeros a guest-physical address range.
    // TODO-HUMAN-REVIEW(PR-132): Review user-map enforcement on this public API.
    pub fn zero(&mut self, guest_address: u64, length: usize) -> Result<()> {
        self.with_copy(|copy| {
            self.checked_offset(guest_address, length)?;
            if self
                .user()
                .user_accessible_prefix_admitted(guest_address, length, copy)?
                != length
            {
                return Err(Error::GuestMemoryAccessDenied {
                    address: guest_address,
                    length,
                });
            }
            self.zero_raw_admitted(guest_address, length, copy)
        })
    }

    // TODO-HUMAN-REVIEW(PR-132): Review internal copies that bypass the user map.
    pub(crate) fn zero_raw(&self, guest_address: u64, length: usize) -> Result<()> {
        self.with_copy(|copy| self.zero_raw_admitted(guest_address, length, copy))
    }

    fn zero_raw_admitted(
        &self,
        guest_address: u64,
        length: usize,
        _copy: &CopyAccess,
    ) -> Result<()> {
        let offset = self.checked_offset(guest_address, length)?;
        let chunks = self.mapping.host_chunks(offset, length);
        let _guard = self
            .mapping
            .slice
            .backing
            .host_access
            .lock()
            .expect("guest memory lock poisoned");
        let mut zeroed = 0;
        let mut zeros = [0_u8; PAGE_SIZE];
        for chunk in chunks {
            match chunk.backing.kind {
                BackingKind::OrdinaryFile { .. } => {
                    debug_assert!(chunk.length <= zeros.len());
                    self.copy_file_chunk(
                        &chunk,
                        zeros.as_mut_ptr(),
                        true,
                        guest_address,
                        length,
                        zeroed,
                    )?;
                }
                BackingKind::Fixed => unsafe {
                    std::ptr::write_bytes(chunk.mapping.as_ptr(), 0, chunk.length);
                },
            }
            zeroed += chunk.length;
        }
        debug_assert_eq!(zeroed, length);
        Ok(())
    }

    /// Discards complete host pages while preserving this mapping's identity.
    ///
    /// Every mapping of this backing range observes zero-filled pages after
    /// the discard. Callers must stop all vCPUs in every VM that can access
    /// the backing range, including through another mapping, just as they
    /// must for [`Self::zero_raw`].
    pub(crate) fn discard_pages(&self, guest_address: u64, length: usize) -> Result<()> {
        self.with_copy(|copy| self.discard_pages_admitted(guest_address, length, copy))
    }

    fn discard_pages_admitted(
        &self,
        guest_address: u64,
        length: usize,
        _copy: &CopyAccess,
    ) -> Result<()> {
        let offset = self.checked_offset(guest_address, length)?;
        if length == 0 {
            return Ok(());
        }
        if !guest_address.is_multiple_of(PAGE_SIZE as u64) || !length.is_multiple_of(PAGE_SIZE) {
            return Err(Error::InvalidMemoryLayout {
                guest_base: guest_address,
                size: length,
            });
        }
        let chunks = self.mapping.host_chunks(offset, length);
        if chunks
            .iter()
            .any(|chunk| matches!(chunk.backing.kind, BackingKind::OrdinaryFile { .. }))
        {
            return Err(Error::SharedFileCapability {
                operation: "discard pages",
                reason: "ordinary-file views must be physically retired before reset",
            });
        }
        let _guard = self
            .mapping
            .slice
            .backing
            .host_access
            .lock()
            .expect("guest memory lock poisoned");
        for chunk in chunks {
            let address = chunk.mapping.as_ptr().expose_provenance();
            // SAFETY: checked_offset proved that this complete page lies in a
            // live MAP_SHARED memfd view. madvise consumes only its numeric
            // address; Rust dereferences below retain the exact mmap pointer.
            let result = unsafe {
                libc::madvise(
                    std::ptr::with_exposed_provenance_mut::<u8>(address).cast(),
                    chunk.length,
                    libc::MADV_REMOVE,
                )
            };
            if result != 0 {
                // MADV_REMOVE is an optimization. Preserve reset semantics on
                // kernels that reject it by zeroing this exact mapping chunk.
                // SAFETY: host_chunks supplied the current pointer and length,
                // and the host-access guard serializes this write.
                unsafe {
                    std::ptr::write_bytes(chunk.mapping.as_ptr(), 0, chunk.length);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn host_address(&self) -> u64 {
        self.mapping.base_address as u64
    }

    fn checked_offset(&self, guest_address: u64, length: usize) -> Result<usize> {
        let relative = guest_address.checked_sub(self.mapping.guest_base);
        let length_u64 = u64::try_from(length).expect("usize must fit in u64 on x86-64");
        let end = relative.and_then(|offset| offset.checked_add(length_u64));
        if end.is_none_or(|end| end > self.mapping.slice.length as u64) {
            return Err(Error::InvalidGuestAddress {
                address: guest_address,
                length,
                guest_base: self.mapping.guest_base,
                guest_end: self.mapping.guest_base + self.mapping.slice.length as u64,
            });
        }
        Ok(relative.unwrap() as usize)
    }

    fn checked_page_range(&self, guest_address: u64, length: u64) -> Result<Option<(u64, u64)>> {
        if length == 0 {
            return Ok(None);
        }
        let length = usize::try_from(length).map_err(|_| Error::InvalidGuestAddress {
            address: guest_address,
            length: usize::MAX,
            guest_base: self.guest_base(),
            guest_end: self.guest_end(),
        })?;
        self.checked_offset(guest_address, length)?;
        let first_page = guest_address / PAGE_SIZE as u64;
        let last_page = (guest_address + length as u64 - 1) / PAGE_SIZE as u64;
        Ok(Some((first_page, last_page)))
    }

    // TODO-HUMAN-REVIEW(PR-132): Review partial user-range validation.
    #[cfg(test)]
    pub(crate) fn user_accessible_prefix(
        &self,
        guest_address: u64,
        length: usize,
    ) -> Result<usize> {
        self.user().user_accessible_prefix(guest_address, length)
    }

    /// Returns the writable prefix of a guest userspace range.
    #[cfg(test)]
    pub(crate) fn user_writable_prefix(&self, guest_address: u64, length: usize) -> Result<usize> {
        self.user().user_writable_prefix(guest_address, length)
    }
}

impl PendingBackingPage<'_> {
    /// Replace the stable HVA page and bind it to the next gate generation.
    /// Linux KVM specifies that mmap changes to a registered userspace memory
    /// region are reflected immediately; keeping every vCPU outside KVM_RUN
    /// makes the transition one deterministic boundary for all VMs sharing the
    /// Mapping. MAP_FIXED failure is terminal because the previous host mapping
    /// may already have been disturbed.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the generation-bound page publisher is not activated by guest mappings yet"
        )
    )]
    pub(crate) fn publish(mut self, closed: &mut Closed) -> Result<MappingGeneration> {
        let gate = self.memory.entry_gate();
        if !closed.belongs_to(&gate) {
            return Err(Error::MappingPublicationGateMismatch);
        }
        let page = self.page;
        let expected_generation = self.expected_generation;
        let slice = self.slice.take().unwrap();
        let mapping = &self.memory.mapping;
        let offset = usize::try_from(
            page.checked_mul(PAGE_SIZE as u64)
                .and_then(|address| address.checked_sub(mapping.guest_base))
                .expect("staged page remains inside its mapping"),
        )
        .expect("mapping offset must fit usize");
        let origin = self.memory.entry_origin();
        let memory = self.memory;
        let allocation = self._allocation;
        let mut prepared = mapping.address_space.lock().unwrap().clone();
        prepared.backing_pages.insert(
            page,
            InstalledBackingPage {
                _generation: expected_generation,
                _slice: slice.clone(),
                mapping: mapping.original_pages[offset / PAGE_SIZE],
            },
        );
        let ledger = self.memory.prepare_mapping_retirement(&prepared);
        let generation = closed
            .publish(origin, expected_generation, move |generation| {
                let outcome = (|| {
                    let mut ownership = mapping.retirement.lock().unwrap();
                    *ownership = Some(ledger);
                    let target_address = mapping.base_address + offset;
                    // All cleanup authority and metadata nodes are already
                    // allocated. The target becomes ambiguous on any failure.
                    ownership
                        .as_mut()
                        .unwrap()
                        .lose_fixed_target(offset, PAGE_SIZE, None);
                    let installed = memory.map_shared_image(
                        target_address,
                        &slice,
                        libc::PROT_READ | libc::PROT_WRITE,
                    );
                    let installed = match installed {
                        Ok(installed) => installed,
                        Err(error) => {
                            ownership.as_mut().unwrap().mapping_errno = error.raw_os_error();
                            return Err(Error::MemoryMapping(error));
                        }
                    };
                    if installed.expose_provenance() != target_address {
                        ownership
                            .as_mut()
                            .unwrap()
                            .note_unexpected_address(installed.expose_provenance(), PAGE_SIZE);
                        return Err(Error::MemoryMapping(io::Error::other(
                            "MAP_FIXED installed a guest page at an unexpected address",
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
                    let page_state = prepared.backing_pages.get_mut(&page).unwrap();
                    page_state._generation = generation;
                    page_state.mapping =
                        NonNull::new(installed.cast()).expect("nonzero fixed arena");
                    *mapping.address_space.lock().unwrap() = prepared;
                    Ok(InstalledMapping::new(generation))
                })();
                drop(allocation);
                outcome
            })
            .map_err(|failure| failure.error())?;
        Ok(generation)
    }
}

impl UserMemory {
    fn guest_base(&self) -> u64 {
        self.memory.guest_base()
    }
    fn guest_end(&self) -> u64 {
        self.memory.guest_end()
    }

    fn translate_admitted(&self, address: u64, length: usize, _copy: &CopyAccess) -> Result<u64> {
        self.memory
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned")
            .translate(address, length)
    }

    fn read_translated_raw_admitted(
        &self,
        address: u64,
        destination: &mut [u8],
        copy: &CopyAccess,
    ) -> Result<()> {
        let physical = self.translate_admitted(address, destination.len(), copy)?;
        self.memory.read_raw_admitted(physical, destination, copy)
    }

    fn write_translated_raw_admitted(
        &self,
        address: u64,
        source: &[u8],
        copy: &CopyAccess,
    ) -> Result<()> {
        let physical = self.translate_admitted(address, source.len(), copy)?;
        self.memory.write_raw_admitted(physical, source, copy)
    }

    /// Tool scratch is initialized before it is temporarily exposed to the
    /// injected syscall. Preserve that existing privileged staging operation.
    pub(crate) fn write_injection(&self, address: u64, source: &[u8]) -> Result<()> {
        self.memory
            .with_copy(|copy| self.write_translated_raw_admitted(address, source, copy))
    }

    pub(crate) fn host_operand(&self, address: u64, length: usize) -> Result<HostMemoryOperand> {
        self.memory
            .with_copy(|copy| self.host_operand_admitted(address, length, copy))
    }

    /// Mirror current writable guest pages into a bounded kernel-only alias.
    /// Invalid and protected addresses remain PROT_NONE so the actual syscall
    /// decides whether it needs to touch them, including at EOF or zero count.
    pub(crate) fn writable_alias(&self, address: u64, length: usize) -> Result<UserWriteAlias<'_>> {
        // Retire the short copy before taking either alias lock: retirement
        // notifies subscribers synchronously and their wakers may read memory.
        // The retained operand still prevents a mapping-generation change.
        let retained = self.memory.with_copy(|copy| {
            self.memory
                .mapping
                .entry_gate
                .retain_operand(copy)
                .map_err(|failure| failure.error())
        })?;
        let mut alias = UserWriteAlias {
            mapping: None,
            offset: address as usize % PAGE_SIZE,
            memory: &self.memory,
            host_access: None,
            permissions: None,
            retained: Some(retained),
        };
        let result = (|| {
            // Match permission-aware copyout's lock order. Keeping both guards
            // through the syscall prevents stale mprotect/munmap permissions
            // and simultaneous Rust dereferences of kernel-written memory.
            alias.permissions = Some(
                self.memory
                    .mapping
                    .address_space
                    .lock()
                    .expect("guest memory access map lock poisoned"),
            );
            alias.host_access = Some(
                self.memory
                    .mapping
                    .slice
                    .backing
                    .host_access
                    .lock()
                    .expect("guest memory lock poisoned"),
            );
            let permissions = alias.permissions.as_ref().unwrap();
            let offset = alias.offset;
            let mapping_length = if length == 0 {
                0
            } else {
                offset
                    .checked_add(length)
                    .and_then(|size| size.checked_add(PAGE_SIZE - 1))
                    .map(|size| size & !(PAGE_SIZE - 1))
                    .ok_or(Error::GuestMemoryAccessDenied { address, length })?
            };
            let mut extents: Vec<WriteAliasExtent> = Vec::new();
            let first_page = address - offset as u64;
            for alias_offset in (0..mapping_length).step_by(PAGE_SIZE) {
                let Some(page_address) = first_page.checked_add(alias_offset as u64) else {
                    break;
                };
                if page_address < self.guest_base() || page_address >= self.guest_end() {
                    continue;
                }
                let page = page_address / PAGE_SIZE as u64;
                if permissions.enabled
                    && !matches!(
                        permissions.pages.get(&page),
                        Some(UserPageState::Accessible { writable: true })
                    )
                {
                    continue;
                }
                let slice = match permissions.backing_pages.get(&page) {
                    Some(installed) => installed._slice.clone(),
                    None => BackingSlice {
                        backing: self.memory.mapping.slice.backing.clone(),
                        offset: self.memory.mapping.slice.offset
                            + (page_address - self.guest_base()) as usize,
                        length: PAGE_SIZE,
                    },
                };
                if let Some(last) = extents.last_mut()
                    && last.offset + last.slice.length == alias_offset
                    && Arc::ptr_eq(&last.slice.backing, &slice.backing)
                    && last.slice.offset + last.slice.length == slice.offset
                {
                    last.slice.length += slice.length;
                } else {
                    extents.push(WriteAliasExtent {
                        offset: alias_offset,
                        slice,
                    });
                }
            }
            if mapping_length == 0 {
                // The unowned sentinel still retains admission and both locks.
                return Ok(());
            }
            // Preallocate both the normal owner and its terminal ledger link
            // before acquiring any address that might later refuse retirement.
            alias.mapping = Some(Box::new(WriteAliasMapping {
                address: 0,
                length: mapping_length,
                ambiguous: None,
                mapping_errno: None,
                unexpected: None,
                unexpected_bounds_valid: false,
                owned: [None; 3],
                cleanup: [None; 3],
                _extents: extents,
                next: None,
            }));
            let mapping = alias.mapping.as_mut().unwrap();
            // SAFETY: this anonymous inaccessible reservation owns no guest
            // bytes; shared extents below replace only its own pages.
            let reservation = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    mapping_length,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if reservation == libc::MAP_FAILED {
                return Err(Error::MemoryMapping(io::Error::last_os_error()));
            }
            mapping.address = reservation.expose_provenance();
            mapping.owned[0] = Some(WriteAliasRange {
                address: mapping.address,
                length: mapping_length,
            });
            for index in 0..mapping._extents.len() {
                let extent = &mapping._extents[index];
                let offset = extent.offset;
                let length = extent.slice.length;
                let target = mapping.address + offset;
                // SAFETY: this range is still ours and the memfd slice remains
                // retained. Atomic MAP_FIXED replacement does not expose a
                // successful-path hole to another ordinary host allocator.
                let installed = unsafe {
                    libc::mmap(
                        std::ptr::with_exposed_provenance_mut::<libc::c_void>(target),
                        length,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED | libc::MAP_FIXED,
                        extent.slice.backing.fd.as_raw_fd(),
                        extent.slice.offset as libc::off_t,
                    )
                };
                if installed == libc::MAP_FAILED {
                    let error = io::Error::last_os_error();
                    // Linux 5.15 mmap_region and Linux 7.1 __mmap_setup /
                    // __mmap_new_vma / vms_abort_munmap_vmas can leave a gap
                    // after a failed fixed replacement. It may already have a
                    // foreign occupant. Earlier failures can retain the old
                    // reservation. Never unmap or retry this ambiguous target.
                    mapping.lose_fixed_target(offset, length, error.raw_os_error());
                    return Err(Error::MemoryMapping(error));
                }
                if installed.expose_provenance() != target {
                    // MAP_FIXED must return its exact target. Partition a
                    // defensive positive result into disjoint owned ranges,
                    // excluding the requested ambiguous interval throughout.
                    mapping.lose_fixed_target(offset, length, None);
                    mapping.note_unexpected_address(installed.expose_provenance(), length);
                    return Err(Error::MemoryMapping(io::Error::other(
                        UNEXPECTED_WRITE_ALIAS_ADDRESS,
                    )));
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            return Err(alias.fail(error));
        }
        // A preparation notification may have poisoned admission. Retire first
        // so the returned failure includes any newly refused cleanup as well.
        if let Err(primary) = self.memory.check_copy_failure() {
            return Err(alias.finish().err().unwrap_or(primary));
        }
        Ok(alias)
    }

    fn host_operand_admitted(
        &self,
        address: u64,
        length: usize,
        copy: &CopyAccess,
    ) -> Result<HostMemoryOperand> {
        // Preserve the existing Accessible probe, including its actual read;
        // PI/requeue operands do not gain a new permission policy here.
        let mut probe = vec![0; length];
        self.read_admitted(address, &mut probe, copy)?;
        self.retain_translated_range_admitted(address, length, copy)
    }

    /// Retain a range already admitted by the caller's exact copy/check. This
    /// adds no second permission observation before a best-effort clear-TID wake.
    pub(crate) fn retain_translated_range(
        &self,
        address: u64,
        length: usize,
    ) -> Result<HostMemoryOperand> {
        self.memory
            .with_copy(|copy| self.retain_translated_range_admitted(address, length, copy))
    }

    fn retain_translated_range_admitted(
        &self,
        address: u64,
        length: usize,
        copy: &CopyAccess,
    ) -> Result<HostMemoryOperand> {
        let physical = self.translate_admitted(address, length, copy)?;
        let offset = self.memory.checked_offset(physical, length)?;
        let retained = self
            .memory
            .mapping
            .entry_gate
            .retain_operand(copy)
            .map_err(|failure| failure.error())?;
        Ok(HostMemoryOperand {
            _memory: self.memory.clone(),
            _retained: retained,
            address: (self.memory.host_address() as usize) + offset,
            _length: length,
        })
    }
    pub fn read(&self, guest_address: u64, destination: &mut [u8]) -> Result<()> {
        self.memory
            .with_copy(|copy| self.read_admitted(guest_address, destination, copy))
    }

    fn read_admitted(
        &self,
        guest_address: u64,
        destination: &mut [u8],
        copy: &CopyAccess,
    ) -> Result<()> {
        self.translate_admitted(guest_address, destination.len(), copy)?;
        if self.user_accessible_prefix_admitted(guest_address, destination.len(), copy)?
            != destination.len()
        {
            return Err(Error::GuestMemoryAccessDenied {
                address: guest_address,
                length: destination.len(),
            });
        }
        self.read_translated_raw_admitted(guest_address, destination, copy)
    }

    pub fn write(&mut self, guest_address: u64, source: &[u8]) -> Result<()> {
        self.memory
            .with_copy(|copy| self.write_admitted(guest_address, source, copy))
    }

    fn write_admitted(&self, guest_address: u64, source: &[u8], copy: &CopyAccess) -> Result<()> {
        self.translate_admitted(guest_address, source.len(), copy)?;
        if self.user_accessible_prefix_admitted(guest_address, source.len(), copy)? != source.len()
        {
            return Err(Error::GuestMemoryAccessDenied {
                address: guest_address,
                length: source.len(),
            });
        }
        self.write_translated_raw_admitted(guest_address, source, copy)
    }

    pub(crate) fn copy_to_user(&self, guest_address: u64, source: &[u8]) -> Result<()> {
        self.write_user(guest_address, source, true)
    }

    pub(crate) fn put_user_i16(&self, guest_address: u64, value: i16) -> Result<()> {
        self.write_user(guest_address, &value.to_ne_bytes(), false)
    }

    pub(crate) fn put_user_i32(&self, guest_address: u64, value: i32) -> Result<()> {
        self.write_user(guest_address, &value.to_ne_bytes(), false)
    }

    pub(crate) fn copy_to_user_prefix(&self, guest_address: u64, source: &[u8]) -> Result<usize> {
        self.write_user_prefix(guest_address, source, true)
    }

    /// Copy the readable prefix under one admission and one permission/backing
    /// transaction. Unlike a separate probe followed by read, mappings cannot
    /// change between deciding the prefix and consuming its actual bytes.
    pub(crate) fn copy_from_user_prefix(
        &self,
        guest_address: u64,
        destination: &mut [u8],
    ) -> Result<usize> {
        self.memory.with_copy(|copy| {
            if destination.is_empty() {
                return Ok(0);
            }
            self.translate_admitted(guest_address, 1, copy)?;
            let end = guest_address
                .checked_add(destination.len() as u64)
                .ok_or(Error::GuestMemoryAccessDenied {
                    address: guest_address,
                    length: destination.len(),
                })?
                .min(self.guest_end());
            let access = self
                .memory
                .mapping
                .address_space
                .lock()
                .expect("guest memory access map lock poisoned");
            let mut cursor = guest_address;
            while cursor < end {
                if access.enabled
                    && !matches!(
                        access.pages.get(&(cursor / PAGE_SIZE as u64)),
                        Some(UserPageState::Accessible { .. })
                    )
                {
                    break;
                }
                cursor = ((cursor / PAGE_SIZE as u64 + 1) * PAGE_SIZE as u64).min(end);
            }
            let length = (cursor - guest_address) as usize;
            if length != 0 {
                let physical = access.translate(guest_address, length)?;
                let offset = self.memory.checked_offset(physical, length)?;
                let chunks = self
                    .memory
                    .mapping
                    .host_chunks_from_state(&access, offset, length);
                self.memory
                    .read_host_chunks(&chunks, guest_address, &mut destination[..length])?;
            }
            drop(access);
            Ok(length)
        })
    }

    fn write_user(&self, guest_address: u64, source: &[u8], partial: bool) -> Result<()> {
        if self.write_user_prefix(guest_address, source, partial)? != source.len() {
            return Err(Error::GuestMemoryAccessDenied {
                address: guest_address,
                length: source.len(),
            });
        }
        Ok(())
    }

    fn write_user_prefix(&self, guest_address: u64, source: &[u8], partial: bool) -> Result<usize> {
        self.memory
            .with_copy(|copy| self.write_user_prefix_admitted(guest_address, source, partial, copy))
    }

    fn write_user_prefix_admitted(
        &self,
        guest_address: u64,
        source: &[u8],
        partial: bool,
        copy: &CopyAccess,
    ) -> Result<usize> {
        if source.is_empty() {
            return Ok(0);
        }
        self.translate_admitted(guest_address, 1, copy)?;
        let requested_end = guest_address.checked_add(source.len() as u64).ok_or(
            Error::GuestMemoryAccessDenied {
                address: guest_address,
                length: source.len(),
            },
        )?;
        let end = requested_end.min(self.guest_end());
        let access = self
            .memory
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let mut cursor = guest_address;
        while cursor < end {
            if access.enabled
                && !matches!(
                    access.pages.get(&(cursor / PAGE_SIZE as u64)),
                    Some(UserPageState::Accessible { writable: true })
                )
            {
                break;
            }
            cursor = ((cursor / PAGE_SIZE as u64 + 1) * PAGE_SIZE as u64).min(end);
        }
        let length = usize::try_from(cursor - guest_address).expect("copyout prefix fits usize");
        if length == source.len() || (partial && length != 0) {
            let physical = access.translate(guest_address, length)?;
            let offset = self.memory.checked_offset(physical, length)?;
            let chunks = self
                .memory
                .mapping
                .host_chunks_from_state(&access, offset, length);
            // Permission failure takes precedence. A scalar must refuse the
            // entire destination before even a preceding private chunk changes.
            if !partial
                && chunks
                    .iter()
                    .any(|chunk| matches!(chunk.backing.kind, BackingKind::OrdinaryFile { .. }))
            {
                return Err(Error::SharedFileCapability {
                    operation: "atomic scalar store",
                    reason: "truncate-capable file backing has no proven fault-contained atomic store",
                });
            }
            self.memory
                .write_host_chunks(&chunks, guest_address, &source[..length])?;
        }
        // Preserve the API's permission-atomicity contract through the write.
        drop(access);
        Ok(length)
    }

    #[cfg(test)]
    pub fn zero(&mut self, guest_address: u64, length: usize) -> Result<()> {
        self.memory
            .with_copy(|copy| self.zero_admitted(guest_address, length, copy))
    }

    #[cfg(test)]
    fn zero_admitted(&self, guest_address: u64, length: usize, copy: &CopyAccess) -> Result<()> {
        self.translate_admitted(guest_address, length, copy)?;
        if self.user_accessible_prefix_admitted(guest_address, length, copy)? != length {
            return Err(Error::GuestMemoryAccessDenied {
                address: guest_address,
                length,
            });
        }
        self.memory.zero_raw_admitted(
            self.translate_admitted(guest_address, length, copy)?,
            length,
            copy,
        )
    }

    pub(crate) fn user_accessible_prefix(
        &self,
        guest_address: u64,
        length: usize,
    ) -> Result<usize> {
        self.memory
            .with_copy(|copy| self.user_accessible_prefix_admitted(guest_address, length, copy))
    }

    fn user_accessible_prefix_admitted(
        &self,
        guest_address: u64,
        length: usize,
        _copy: &CopyAccess,
    ) -> Result<usize> {
        if length == 0 {
            return Ok(0);
        }
        if guest_address < self.guest_base() || guest_address >= self.guest_end() {
            return Err(Error::InvalidGuestAddress {
                address: guest_address,
                length,
                guest_base: self.guest_base(),
                guest_end: self.guest_end(),
            });
        }
        let requested_end = guest_address.saturating_add(length as u64);
        let end = requested_end.min(self.guest_end());
        let access = self
            .memory
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        if !access.enabled {
            return Ok(
                usize::try_from(end - guest_address).expect("guest memory prefix must fit usize")
            );
        }

        let mut cursor = guest_address;
        while cursor < end {
            if !matches!(
                access.pages.get(&(cursor / PAGE_SIZE as u64)),
                Some(UserPageState::Accessible { .. })
            ) {
                break;
            }
            let next_page = (cursor / PAGE_SIZE as u64 + 1) * PAGE_SIZE as u64;
            cursor = next_page.min(end);
        }
        Ok(usize::try_from(cursor - guest_address).expect("guest memory prefix must fit usize"))
    }

    pub(crate) fn user_writable_prefix(&self, guest_address: u64, length: usize) -> Result<usize> {
        self.memory
            .with_copy(|copy| self.user_writable_prefix_admitted(guest_address, length, copy))
    }

    fn user_writable_prefix_admitted(
        &self,
        guest_address: u64,
        length: usize,
        _copy: &CopyAccess,
    ) -> Result<usize> {
        if length == 0 {
            return Ok(0);
        }
        if guest_address < self.guest_base() || guest_address >= self.guest_end() {
            return Err(Error::InvalidGuestAddress {
                address: guest_address,
                length,
                guest_base: self.guest_base(),
                guest_end: self.guest_end(),
            });
        }
        let end = guest_address
            .saturating_add(length as u64)
            .min(self.guest_end());
        let access = self
            .memory
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        if !access.enabled {
            return Ok(
                usize::try_from(end - guest_address).expect("guest memory prefix must fit usize")
            );
        }
        let mut cursor = guest_address;
        while cursor < end {
            if !matches!(
                access.pages.get(&(cursor / PAGE_SIZE as u64)),
                Some(UserPageState::Accessible { writable: true })
            ) {
                break;
            }
            let next_page = (cursor / PAGE_SIZE as u64 + 1) * PAGE_SIZE as u64;
            cursor = next_page.min(end);
        }
        Ok(usize::try_from(cursor - guest_address).expect("guest memory prefix must fit usize"))
    }
}

impl MemoryAccess for GuestMemory {
    fn write_with_user_access(
        &mut self,
        addr: reverie::syscalls::AddrMut<u8>,
        buf: &[u8],
    ) -> std::result::Result<usize, Errno> {
        self.user().write_with_user_access(addr, buf)
    }

    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        let mut source_index = 0;
        let mut source_offset = 0;
        let mut destination_index = 0;
        let mut destination_offset = 0;
        let mut total = 0;

        while source_index < read_from.len() && destination_index < write_to.len() {
            if source_offset == read_from[source_index].len() {
                source_index += 1;
                source_offset = 0;
                continue;
            }
            if destination_offset == write_to[destination_index].len() {
                destination_index += 1;
                destination_offset = 0;
                continue;
            }

            // Admission errors are backend failures, never ordinary faults.
            // The admitted helpers below can only produce layout/access
            // faults; poison is checked separately even after a real prefix.
            #[cfg(test)]
            self.before_vector_copy(total);
            let copy = self.copy_access().map_err(|_| Errno::EIO)?;
            let requested = (read_from[source_index].len() - source_offset)
                .min(write_to[destination_index].len() - destination_offset);
            let address = read_from[source_index].as_ptr() as u64 + source_offset as u64;
            let count = self
                .user()
                .user_accessible_prefix_admitted(address, requested, &copy)
                .unwrap_or_default();
            self.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count == 0 {
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            let destination =
                &mut write_to[destination_index][destination_offset..destination_offset + count];
            if let Err(error) = self.read_raw_admitted(address, destination, &copy) {
                drop(copy);
                if matches!(
                    error.primary(),
                    Error::SharedFileCopy { .. } | Error::SharedFileCapability { .. }
                ) {
                    self.capture_shared_file_error(shared_file::vector_copy_error(error, total));
                    return Err(Errno::EIO);
                }
                self.check_copy_failure().map_err(|_| Errno::EIO)?;
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            source_offset += count;
            destination_offset += count;
            total += count;
            #[cfg(test)]
            self.after_vector_copy(total);
            self.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count < requested {
                return Ok(total);
            }
        }
        Ok(total)
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        let mut source_index = 0;
        let mut source_offset = 0;
        let mut destination_index = 0;
        let mut destination_offset = 0;
        let mut total = 0;

        while source_index < read_from.len() && destination_index < write_to.len() {
            if source_offset == read_from[source_index].len() {
                source_index += 1;
                source_offset = 0;
                continue;
            }
            if destination_offset == write_to[destination_index].len() {
                destination_index += 1;
                destination_offset = 0;
                continue;
            }

            #[cfg(test)]
            self.before_vector_copy(total);
            let copy = self.copy_access().map_err(|_| Errno::EIO)?;
            let count = (read_from[source_index].len() - source_offset)
                .min(write_to[destination_index].len() - destination_offset);
            let address =
                write_to[destination_index].as_mut_ptr() as u64 + destination_offset as u64;
            let requested = count;
            let count = self
                .user()
                .user_accessible_prefix_admitted(address, requested, &copy)
                .unwrap_or_default();
            self.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count == 0 {
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            let source = &read_from[source_index][source_offset..source_offset + count];
            if let Err(error) = self.write_raw_admitted(address, source, &copy) {
                drop(copy);
                if matches!(
                    error.primary(),
                    Error::SharedFileCopy { .. } | Error::SharedFileCapability { .. }
                ) {
                    self.capture_shared_file_error(shared_file::vector_copy_error(error, total));
                    return Err(Errno::EIO);
                }
                self.check_copy_failure().map_err(|_| Errno::EIO)?;
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            source_offset += count;
            destination_offset += count;
            total += count;
            #[cfg(test)]
            self.after_vector_copy(total);
            self.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count < requested {
                return Ok(total);
            }
        }
        Ok(total)
    }
}

fn write_backing(backing: &Backing, bytes: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        let offset = libc::off_t::try_from(written)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "backing offset overflow"))?;
        // SAFETY: backing owns a writable memfd for at least bytes.len()
        // bytes, and this live slice supplies the remaining initialized input.
        let result = unsafe {
            libc::pwrite(
                backing.fd.as_raw_fd(),
                bytes[written..].as_ptr().cast(),
                bytes.len() - written,
                offset,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "guest backing write made no progress",
            ));
        }
        written += usize::try_from(result).expect("positive pwrite result must fit usize");
    }
    Ok(())
}

fn create_memory_backing() -> io::Result<OwnedFd> {
    let name = c"reverie-kvm-guest-memory";
    // Guest RAM is never executable in the host mapping. Prefer the flag that
    // also works when the host requires non-executable memfds, but retain
    // compatibility with kernels predating MFD_NOEXEC_SEAL.
    // SAFETY: name is a live, NUL-terminated C string.
    let mut fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_NOEXEC_SEAL) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINVAL) {
            return Err(error);
        }
        // SAFETY: name is a live, NUL-terminated C string. Old kernels reject
        // MFD_NOEXEC_SEAL with EINVAL but accept the original flag set.
        fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: memfd_create returned a new descriptor owned by this call.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Copies every data extent from one equal-sized sparse file to another.
///
/// The destination must initially be entirely zero-filled; source holes are
/// neither written nor cleared in the destination.
///
/// A filesystem may conservatively report holes as data, which only makes
/// this slower. It must not report stored data as a hole. The caller falls
/// back to a byte-for-byte mapping copy on every error or incomplete extent.
fn copy_sparse_file(source: RawFd, destination: RawFd, length: usize) -> io::Result<()> {
    let end = libc::off_t::try_from(length)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mapping exceeds off_t"))?;
    let mut cursor: libc::off_t = 0;

    while cursor < end {
        // SAFETY: source is a live descriptor owned by the source Mapping.
        let data = unsafe { libc::lseek(source, cursor, libc::SEEK_DATA) };
        if data < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                return Ok(());
            }
            return Err(error);
        }
        if data < cursor || data >= end {
            return if data >= end {
                Ok(())
            } else {
                Err(io::Error::other("SEEK_DATA moved backwards"))
            };
        }

        // SAFETY: source is a live descriptor owned by the source Mapping.
        let hole = unsafe { libc::lseek(source, data, libc::SEEK_HOLE) };
        if hole <= data {
            return Err(if hole < 0 {
                io::Error::last_os_error()
            } else {
                io::Error::other("SEEK_HOLE returned an empty extent")
            });
        }
        let extent_end = hole.min(end);
        let mut source_offset = data;
        let mut destination_offset = data;
        while source_offset < extent_end {
            let remaining = usize::try_from(extent_end - source_offset)
                .expect("nonnegative extent length must fit usize");
            // SAFETY: both descriptors are live for the call, the offsets are
            // within their equal file sizes, and both offset pointers are valid.
            let copied = unsafe {
                libc::copy_file_range(
                    source,
                    &mut source_offset,
                    destination,
                    &mut destination_offset,
                    remaining,
                    0,
                )
            };
            if copied < 0 {
                return Err(io::Error::last_os_error());
            }
            if copied == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "copy_file_range stopped before the end of an extent",
                ));
            }
            if source_offset != destination_offset || source_offset > extent_end {
                return Err(io::Error::other(
                    "copy_file_range returned inconsistent offsets",
                ));
            }
        }
        cursor = extent_end;
    }
    Ok(())
}

impl Mapping {
    /// Resolve a validated relative range into exact live mmap pointers. Once a
    /// page has been replaced, no Rust operation may cross that mapping
    /// boundary with a pointer derived from the original whole-arena mmap.
    fn host_chunks(&self, offset: usize, length: usize) -> Vec<HostChunk> {
        let state = self
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        self.host_chunks_from_state(&state, offset, length)
    }

    /// Resolve while a caller-owned address-space guard remains live. This is
    /// used by permission-aware copyout so validation and write stay atomic.
    fn host_chunks_from_state(
        &self,
        state: &AddressSpaceState,
        offset: usize,
        length: usize,
    ) -> Vec<HostChunk> {
        let end = offset
            .checked_add(length)
            .expect("validated guest-memory range cannot overflow");
        debug_assert!(end <= self.slice.length);
        if length == 0 {
            return Vec::new();
        }

        if state.backing_pages.is_empty() {
            // SAFETY: no page of the original whole-range mmap has ever been
            // replaced, and the validated range remains within that mapping.
            let mapping = unsafe { NonNull::new_unchecked(self.mapping.as_ptr().add(offset)) };
            return vec![HostChunk {
                mapping,
                length,
                backing: self.slice.backing.clone(),
            }];
        }

        let mut chunks = Vec::with_capacity(length.div_ceil(PAGE_SIZE) + 1);
        let mut cursor = offset;
        while cursor < end {
            let relative_page = cursor / PAGE_SIZE;
            let within_page = cursor % PAGE_SIZE;
            let chunk_length = (PAGE_SIZE - within_page).min(end - cursor);
            let page = self.guest_base / PAGE_SIZE as u64 + relative_page as u64;
            let (page_start, backing) = match state.backing_pages.get(&page) {
                Some(installed) => (installed.mapping, installed._slice.backing.clone()),
                None => (
                    self.original_pages[relative_page],
                    self.slice.backing.clone(),
                ),
            };
            // SAFETY: page_start is the exact live pointer for this page and
            // chunk_length cannot cross the page boundary.
            let mapping = unsafe { NonNull::new_unchecked(page_start.as_ptr().add(within_page)) };
            chunks.push(HostChunk {
                mapping,
                length: chunk_length,
                backing,
            });
            cursor += chunk_length;
        }
        chunks
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        if let Some(ledger) = self
            .retirement
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let retired = ledger.retire();
            if let Some(error) = retired.error(None) {
                self.entry_gate.poison(None, error);
            }
            return;
        }
        // No MAP_FIXED has ever affected this arena. Only that untouched
        // initial case still owns the complete original interval.
        unsafe {
            libc::munmap(
                std::ptr::with_exposed_provenance_mut::<u8>(self.base_address).cast(),
                self.slice.length,
            );
        }
    }
}

#[cfg(test)]
mod user_copy_tests {
    use std::future::Future;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Context;
    use std::task::Wake;
    use std::task::Waker;
    use std::time::Duration;
    use std::time::Instant;

    use futures::FutureExt;
    use reverie::syscalls::AddrMut;

    use super::*;
    use crate::entry::PendingFailure;
    use crate::entry::owner::DriverScope;

    const BASE: u64 = 0x1000;
    const SOURCE: &[u8] = b"12345678";

    fn fixture() -> GuestMemory {
        let memory = GuestMemory::new(BASE, 3 * PAGE_SIZE).unwrap();
        memory.write_raw(BASE, &vec![0xa5; 3 * PAGE_SIZE]).unwrap();
        memory
            .map_user_permissions(BASE, (3 * PAGE_SIZE) as u64, true, true)
            .unwrap();
        memory.enable_user_access();
        memory
    }

    fn observer(memory: &GuestMemory) -> GuestMemory {
        // Existing test-only independent gate over stable backing. It only
        // observes effects after the subject gate refuses any further access.
        GuestMemory::from_backing_slice(BASE, memory.mapping.slice.clone()).unwrap()
    }

    fn copy(
        memory: &GuestMemory,
        user: bool,
        address: u64,
        bytes: &[u8],
    ) -> std::result::Result<usize, Errno> {
        let address = AddrMut::from_raw(address as usize).unwrap();
        if user {
            memory.user().write_with_user_access(address, bytes)
        } else {
            memory.clone().write_with_user_access(address, bytes)
        }
    }

    fn assert_bytes(memory: &GuestMemory, offset: usize, source: &[u8]) {
        let mut actual = vec![0; 3 * PAGE_SIZE];
        memory.read_raw(BASE, &mut actual).unwrap();
        let mut expected = vec![0xa5; 3 * PAGE_SIZE];
        expected[offset..offset + source.len()].copy_from_slice(source);
        assert_eq!(actual, expected);
    }

    fn assert_released(memory: &GuestMemory) {
        assert_eq!(memory.entry_gate().test_state().copies, 0);
        assert!(memory.mapping.address_space.try_lock().is_ok());
        assert!(memory.mapping.slice.backing.host_access.try_lock().is_ok());
        assert!(memory.mapping.allocation.try_lock().is_ok());
    }

    fn primary(failure: &PendingFailure) -> Arc<Error> {
        assert_eq!(failure.causes().len(), 1, "unexpected cleanup growth");
        match failure.error() {
            Error::SharedFailure(primary) => primary,
            error => panic!("expected exactly one retained primary: {error:?}"),
        }
    }

    fn assert_same_failure(
        memory: &GuestMemory,
        pending: &Arc<PendingFailure>,
        original: &Arc<Error>,
    ) {
        let current = memory.entry_gate().pending_failure().unwrap();
        assert!(Arc::ptr_eq(&current, pending));
        assert!(Arc::ptr_eq(&primary(&current), original));
    }

    fn cause(operation: &'static str) -> Error {
        Error::EntryControl {
            operation,
            source: io::Error::from_raw_os_error(libc::EBUSY),
        }
    }

    fn until(mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(
                Instant::now() < deadline,
                "controlled copy state was not reached"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn user_copy_permissions_counts_and_all_bytes() {
        for user in [false, true] {
            for accessible in [false, true] {
                for offset in [0, PAGE_SIZE - 3, PAGE_SIZE] {
                    for length in [0, 1, 7, 8, 9, PAGE_SIZE + 8] {
                        let memory = fixture();
                        memory
                            .map_user_permissions(
                                BASE + PAGE_SIZE as u64,
                                PAGE_SIZE as u64,
                                accessible,
                                false,
                            )
                            .unwrap();
                        let source: Vec<_> = (0..length).map(|i| (19 + 37 * i) as u8).collect();
                        let count = if offset < PAGE_SIZE {
                            length.min(PAGE_SIZE - offset)
                        } else {
                            0
                        };
                        assert_eq!(
                            copy(&memory, user, BASE + offset as u64, &source),
                            if count != 0 || length == 0 {
                                Ok(count)
                            } else {
                                Err(Errno::EFAULT)
                            }
                        );
                        assert_bytes(&memory, offset, &source[..count]);
                        assert_released(&memory);
                    }
                }
            }
        }
    }

    #[test]
    fn user_copy_geometry_empty_and_disabled_access_contract() {
        for user in [false, true] {
            let memory = fixture();
            for address in [1, BASE - 1, memory.guest_end(), u64::MAX - 3, u64::MAX] {
                assert_eq!(copy(&memory, user, address, &[]), Ok(0));
                assert_eq!(copy(&memory, user, address, SOURCE), Err(Errno::EFAULT));
                assert_bytes(&memory, 0, &[]);
                assert_released(&memory);
            }
            assert_eq!(copy(&memory, user, memory.guest_end() - 3, SOURCE), Ok(3));
            assert_bytes(&memory, 3 * PAGE_SIZE - 3, &SOURCE[..3]);
            assert_released(&memory);

            let memory = fixture();
            memory.clear_user_access();
            memory
                .map_user_permissions(BASE, PAGE_SIZE as u64, true, false)
                .unwrap();
            assert_eq!(copy(&memory, user, BASE, SOURCE), Ok(8));
            assert_bytes(&memory, 0, SOURCE);
            assert_released(&memory);
            memory.enable_user_access();
            assert_eq!(copy(&memory, user, BASE, b"muststay"), Err(Errno::EFAULT));
            assert_bytes(&memory, 0, SOURCE);
            assert_released(&memory);
        }
    }

    #[test]
    fn user_copy_retained_poison_has_exact_identity_without_cleanup_growth() {
        for user in [false, true] {
            for copied in [0, 3, 8] {
                let mut memory = fixture();
                memory
                    .map_user_permissions(BASE + PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
                    .unwrap();
                let observation = observer(&memory);
                let gate = memory.entry_gate();
                if copied == 0 {
                    gate.poison(None, cause("before usercopy admission"));
                } else {
                    let gate = gate.clone();
                    memory.after_vector_copy = Some(Arc::new(move |count| {
                        assert_eq!(count, copied);
                        assert_eq!(gate.test_state().copies, 0);
                        gate.poison(None, cause("after usercopy effects"));
                    }));
                }
                let offset = if copied == 3 { PAGE_SIZE - 3 } else { 0 };
                assert_eq!(
                    copy(&memory, user, BASE + offset as u64, SOURCE),
                    Err(Errno::EIO)
                );
                let pending = gate.pending_failure().unwrap();
                let original = primary(&pending);
                assert_bytes(&observation, offset, &SOURCE[..copied]);
                for bytes in [&[][..], SOURCE, b"again"] {
                    assert_eq!(copy(&memory, user, BASE, bytes), Err(Errno::EIO));
                    assert_same_failure(&memory, &pending, &original);
                    assert_bytes(&observation, offset, &SOURCE[..copied]);
                    assert_released(&memory);
                }
                assert_eq!(copy(&memory, user, u64::MAX, &[]), Err(Errno::EIO));
                assert_same_failure(&memory, &pending, &original);
            }
        }
    }

    #[test]
    fn user_copy_poison_after_admission_overrides_readonly_fault_and_written_prefix() {
        for user in [false, true] {
            for (offset, copied) in [(PAGE_SIZE, 0), (PAGE_SIZE - 3, 3), (0, 8)] {
                let memory = fixture();
                memory
                    .map_user_permissions(BASE + PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
                    .unwrap();
                let observation = observer(&memory);
                let gate = memory.entry_gate();
                std::thread::scope(|scope| {
                    // The method can acquire its real token, but its first
                    // translation cannot run until this guard is released.
                    let access = memory.mapping.address_space.lock().unwrap();
                    let worker = scope.spawn(|| copy(&memory, user, BASE + offset as u64, SOURCE));
                    until(|| gate.test_state().copies == 1);
                    let pending =
                        gate.poison(memory.entry_origin(), cause("poison after admission"));
                    let original = primary(&pending);
                    drop(access);
                    assert_eq!(worker.join().unwrap(), Err(Errno::EIO));
                    assert_same_failure(&memory, &pending, &original);
                    assert_eq!(copy(&memory, user, BASE, SOURCE), Err(Errno::EIO));
                    assert_same_failure(&memory, &pending, &original);
                });
                assert_bytes(&observation, offset, &SOURCE[..copied]);
                assert_released(&memory);
            }
        }
    }

    #[test]
    fn user_copy_waits_without_memory_locks_and_reopens_or_retains_poison() {
        for user in [false, true] {
            for poison in [false, true] {
                let memory = fixture();
                let observation = observer(&memory);
                let gate = memory.entry_gate();
                let closed = gate
                    .try_close()
                    .unwrap()
                    .unwrap()
                    .finish()
                    .now_or_never()
                    .unwrap()
                    .unwrap();
                std::thread::scope(|scope| {
                    let worker = scope.spawn(|| copy(&memory, user, BASE, SOURCE));
                    until(|| !gate.test_state().copy_waiters.is_empty());
                    assert_released(&memory);
                    let pending = poison.then(|| gate.poison(None, cause("closed copy refused")));
                    drop(closed);
                    assert_eq!(
                        worker.join().unwrap(),
                        if poison { Err(Errno::EIO) } else { Ok(8) }
                    );
                    if let Some(pending) = pending {
                        let original = primary(&pending);
                        assert_eq!(copy(&memory, user, BASE, SOURCE), Err(Errno::EIO));
                        assert_same_failure(&memory, &pending, &original);
                    }
                });
                assert_bytes(&observation, 0, if poison { &[] } else { SOURCE });
                assert_released(&memory);
            }
        }
    }

    #[test]
    fn user_copy_keeps_permission_guard_through_actual_backing_contention() {
        for user in [false, true] {
            let mut memory = fixture();
            let waiting = Arc::new(AtomicBool::new(false));
            memory.test_user_copy_backing_wait = Some(waiting.clone());
            std::thread::scope(|scope| {
                let backing = memory.mapping.slice.backing.host_access.lock().unwrap();
                let writer = scope.spawn(|| copy(&memory, user, BASE, SOURCE));
                until(|| waiting.load(Ordering::SeqCst));
                assert_eq!(memory.entry_gate().test_state().copies, 1);
                assert!(matches!(
                    memory.mapping.address_space.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                let (started, start) = std::sync::mpsc::channel();
                let (done, completion) = std::sync::mpsc::channel();
                let memory = &memory;
                let updater = scope.spawn(move || {
                    started.send(()).unwrap();
                    memory
                        .map_user_permissions(BASE, PAGE_SIZE as u64, true, false)
                        .unwrap();
                    done.send(()).unwrap();
                });
                start.recv_timeout(Duration::from_secs(5)).unwrap();
                assert!(matches!(
                    completion.try_recv(),
                    Err(std::sync::mpsc::TryRecvError::Empty)
                ));
                drop(backing);
                assert_eq!(writer.join().unwrap(), Ok(8));
                completion.recv_timeout(Duration::from_secs(5)).unwrap();
                updater.join().unwrap();
            });
            assert_bytes(&memory, 0, SOURCE);
            assert_eq!(copy(&memory, user, BASE, b"muststay"), Err(Errno::EFAULT));
            assert_bytes(&memory, 0, SOURCE);
            assert_released(&memory);
        }
    }

    struct WakeObservation {
        copies: usize,
        address_unlocked: bool,
        backing_unlocked: bool,
        returned: bool,
        pending: Option<Arc<PendingFailure>>,
    }

    struct ObserveWake {
        memory: GuestMemory,
        returned: Arc<AtomicBool>,
        observations: Mutex<Vec<WakeObservation>>,
        peer: Mutex<Option<EntryOrigin>>,
    }

    impl Wake for ObserveWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let gate = self.memory.entry_gate();
            let observation = WakeObservation {
                copies: gate.test_state().copies,
                address_unlocked: self.memory.mapping.address_space.try_lock().is_ok(),
                backing_unlocked: self
                    .memory
                    .mapping
                    .slice
                    .backing
                    .host_access
                    .try_lock()
                    .is_ok(),
                returned: self.returned.load(Ordering::SeqCst),
                pending: gate.pending_failure(),
            };
            self.observations.lock().unwrap().push(observation);
            // Release even the test-only observation/peer locks before poison
            // can synchronously notify another registered waker.
            let peer = self.peer.lock().unwrap().take();
            if let Some(origin) = peer {
                gate.poison(origin, cause("peer captures at copy retirement"));
            }
        }
    }

    fn wake_probe(memory: &GuestMemory, returned: &Arc<AtomicBool>) -> Arc<ObserveWake> {
        Arc::new(ObserveWake {
            memory: memory.clone(),
            returned: returned.clone(),
            observations: Mutex::new(Vec::new()),
            peer: Mutex::new(None),
        })
    }

    #[test]
    fn user_copy_fresh_failure_notifies_after_retirement_with_exact_origin_and_effects() {
        for user in [false, true] {
            for (offset, copied) in [(PAGE_SIZE, 0), (PAGE_SIZE - 3, 3), (0, 8)] {
                for other_copy in [false, true] {
                    let driver = DriverScope::new();
                    let owner = driver.owner();
                    let first = owner.begin_callback(None).unwrap();
                    let first_origin = first.origin();
                    let second = owner.begin_callback(None).unwrap();
                    let global = Arc::new(());
                    let run = crate::failure::RunFailure::new(&global);
                    let other_run = crate::failure::RunFailure::new(&global);
                    let mut memory = fixture();
                    memory
                        .map_user_permissions(
                            BASE + PAGE_SIZE as u64,
                            PAGE_SIZE as u64,
                            true,
                            false,
                        )
                        .unwrap();
                    memory.set_operation_origin(Some(first_origin.clone()));
                    memory.set_failure_context(Some(FailureContext::new(
                        run.clone(),
                        reverie::Pid::from_raw(3),
                        reverie::Pid::from_raw(5),
                    )));
                    let original = Arc::new(cause("usercopy unexpected-error control"));
                    let injection = Arc::new(TestUserCopyFailure {
                        cause: original.clone(),
                        calls: AtomicUsize::new(0),
                        copied: AtomicUsize::new(usize::MAX),
                    });
                    memory.test_user_copy_failure = Some(injection.clone());
                    let issuing = memory.clone();
                    memory.set_operation_origin(Some(second.origin()));
                    memory.set_failure_context(Some(FailureContext::new(
                        other_run.clone(),
                        reverie::Pid::from_raw(7),
                        reverie::Pid::from_raw(9),
                    )));
                    let observation = observer(&memory);
                    let gate = memory.entry_gate();
                    let peer_copy = other_copy.then(|| gate.try_copy(None).unwrap().unwrap());
                    let returned = Arc::new(AtomicBool::new(false));
                    let gate_probe = wake_probe(&memory, &returned);
                    let owner_probe = wake_probe(&memory, &returned);
                    let mut gate_change = Box::pin(gate.subscribe());
                    let mut owner_change = Box::pin(owner.subscribe());
                    assert!(
                        gate_change
                            .as_mut()
                            .poll(&mut Context::from_waker(&Waker::from(gate_probe.clone())))
                            .is_pending()
                    );
                    assert!(
                        owner_change
                            .as_mut()
                            .poll(&mut Context::from_waker(&Waker::from(owner_probe.clone())))
                            .is_pending()
                    );
                    assert_eq!(
                        copy(&issuing, user, BASE + offset as u64, SOURCE),
                        Err(Errno::EIO)
                    );
                    returned.store(true, Ordering::SeqCst);
                    let pending = gate.pending_failure().unwrap();
                    let captured = primary(&pending);
                    match captured.as_ref() {
                        Error::SharedFailure(retained) => assert!(Arc::ptr_eq(retained, &original)),
                        error => panic!("injected typed cause lost: {error:?}"),
                    }
                    assert!(
                        matches!(captured.primary(), Error::EntryControl { operation: "usercopy unexpected-error control", source } if source.raw_os_error() == Some(libc::EBUSY))
                    );
                    assert!(
                        pending
                            .operation
                            .as_ref()
                            .unwrap()
                            .same_callback(&first_origin)
                    );
                    assert!(
                        !pending
                            .operation
                            .as_ref()
                            .unwrap()
                            .same_callback(&second.origin())
                    );
                    assert!(Arc::ptr_eq(
                        &pending.origin.as_ref().unwrap().run.upgrade().unwrap(),
                        &run
                    ));
                    assert!(pending.owner_registered());
                    assert_eq!(owner.pending().len(), 1);
                    assert!(Arc::ptr_eq(&owner.pending()[0], &pending));
                    assert!(run.primary().is_none() && other_run.primary().is_none());
                    for probe in [&gate_probe, &owner_probe] {
                        let events = probe.observations.lock().unwrap();
                        assert!(!events.is_empty(), "actual notification was not observed");
                        for event in events.iter() {
                            assert_eq!(event.copies, usize::from(other_copy));
                            assert!(
                                event.address_unlocked && event.backing_unlocked && !event.returned
                            );
                        }
                    }
                    assert!(
                        owner_probe
                            .observations
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|event| event
                                .pending
                                .as_ref()
                                .is_some_and(|seen| Arc::ptr_eq(seen, &pending)))
                    );
                    assert_eq!(injection.calls.load(Ordering::SeqCst), 1);
                    assert_eq!(injection.copied.load(Ordering::SeqCst), copied);
                    assert_bytes(&observation, offset, &SOURCE[..copied]);
                    for (address, bytes) in [(BASE, SOURCE), (u64::MAX, &[][..])] {
                        assert_eq!(copy(&issuing, user, address, bytes), Err(Errno::EIO));
                        assert_same_failure(&issuing, &pending, &captured);
                        assert_bytes(&observation, offset, &SOURCE[..copied]);
                    }
                    assert_eq!(injection.calls.load(Ordering::SeqCst), 1);
                    drop((gate_change, owner_change, gate_probe, owner_probe));
                    drop(peer_copy);
                    assert_released(&memory);
                    drop((first, second));
                    let retirement = driver.retire();
                    retirement.result.unwrap();
                    assert_eq!(retirement.pending.len(), 1);
                    assert!(Arc::ptr_eq(&retirement.pending[0], &pending));
                    retirement.notification.notify();
                }
            }
        }
    }

    #[test]
    fn user_copy_retirement_capture_race_keeps_distinct_local_cause_once() {
        for user in [false, true] {
            let driver = DriverScope::new();
            let owner = driver.owner();
            let first = owner.begin_callback(None).unwrap();
            let peer = owner.begin_callback(None).unwrap();
            let mut memory = fixture();
            memory.set_operation_origin(Some(first.origin()));
            let local_cause = Arc::new(cause("local usercopy failure"));
            memory.test_user_copy_failure = Some(Arc::new(TestUserCopyFailure {
                cause: local_cause.clone(),
                calls: AtomicUsize::new(0),
                copied: AtomicUsize::new(0),
            }));
            let observation = observer(&memory);
            let returned = Arc::new(AtomicBool::new(false));
            let probe = wake_probe(&memory, &returned);
            *probe.peer.lock().unwrap() = Some(EntryOrigin {
                failure: None,
                operation: Some(peer.origin()),
            });
            let gate = memory.entry_gate();
            let mut changed = Box::pin(gate.subscribe());
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&Waker::from(probe.clone())))
                    .is_pending()
            );
            assert_eq!(copy(&memory, user, BASE, SOURCE), Err(Errno::EIO));
            let pending = gate.pending_failure().unwrap();
            assert!(
                pending
                    .operation
                    .as_ref()
                    .unwrap()
                    .same_callback(&peer.origin())
            );
            assert!(matches!(
                pending.error().primary(),
                Error::EntryControl {
                    operation: "peer captures at copy retirement",
                    ..
                }
            ));
            let causes = pending.causes();
            assert_eq!(causes.len(), 2);
            match causes[1].as_ref() {
                Error::SharedFailure(retained) => assert!(Arc::ptr_eq(retained, &local_cause)),
                error => panic!("distinct local cause was rewrapped or replaced: {error:?}"),
            }
            for bytes in [SOURCE, &[][..]] {
                assert_eq!(copy(&memory, user, BASE, bytes), Err(Errno::EIO));
                let retained = pending.causes();
                assert_eq!(retained.len(), 2);
                assert!(retained.iter().zip(&causes).all(|(a, b)| Arc::ptr_eq(a, b)));
            }
            for event in probe.observations.lock().unwrap().iter() {
                assert_eq!(event.copies, 0);
                assert!(event.address_unlocked && event.backing_unlocked && !event.returned);
            }
            assert_bytes(&observation, 0, SOURCE);
            assert_released(&memory);
            drop((changed, probe, first, peer));
            let retirement = driver.retire();
            retirement.result.unwrap();
            assert_eq!(retirement.pending.len(), 1);
            assert!(Arc::ptr_eq(&retirement.pending[0], &pending));
            retirement.notification.notify();
        }
    }
}

// TODO-HUMAN-REVIEW(PR-132): Review KVM partial user-copy semantics.
impl MemoryAccess for UserMemory {
    /// Admission can wait for a closer. The caller must not already own this
    /// gate's CopyAccess/Closed token or a dependency needed by its closer.
    /// Disabled user-access tracking retains copy_to_user's coverage-only
    /// behavior; installed ELF guests enable tracking before execution.
    fn write_with_user_access(
        &mut self,
        addr: reverie::syscalls::AddrMut<u8>,
        buf: &[u8],
    ) -> std::result::Result<usize, Errno> {
        let gate = self.memory.entry_gate();
        let origin = self.memory.entry_origin();
        #[cfg(test)]
        self.memory.before_vector_copy(0);
        let (local_result, post_copy_failure) = {
            // Admission failures are already retained. Do not classify them
            // together with fresh helper errors and poison the same cause again.
            self.memory.check_copy_failure().map_err(|_| Errno::EIO)?;
            let copy = MemoryCopyAccess::new(
                &self.memory,
                gate.copy_blocking(origin.clone()).map_err(|_| Errno::EIO)?,
            );
            let local_result =
                self.write_user_prefix_admitted(addr.as_raw() as u64, buf, true, &copy);
            #[cfg(test)]
            let local_result = match (local_result, &self.memory.test_user_copy_failure) {
                (Ok(copied), Some(injection)) => {
                    use std::sync::atomic::Ordering;
                    injection.calls.fetch_add(1, Ordering::SeqCst);
                    injection.copied.store(copied, Ordering::SeqCst);
                    Err(Error::SharedFailure(injection.cause.clone()))
                }
                (result, _) => result,
            };
            // Poison after admission may coexist with prefix/full effects.
            // Keep those bytes, but never return ordinary success or EFAULT
            // in place of an observed terminal failure, even for an empty copy.
            let post_copy_failure = gate.pending_failure();
            // The helper has released address/backing guards and host chunks.
            // Retirement itself can wake subscribers; they must see this copy
            // already uncounted before a fresh-error capture notifies owners.
            drop(copy);
            (local_result, post_copy_failure)
        };
        #[cfg(test)]
        if let Ok(copied) = &local_result {
            self.memory.after_vector_copy(*copied);
        }
        let ordinary = match local_result {
            Ok(0) if !buf.is_empty() => Err(Errno::EFAULT),
            Ok(copied) => Ok(copied),
            Err(Error::InvalidGuestAddress { .. } | Error::GuestMemoryAccessDenied { .. }) => {
                Err(Errno::EFAULT)
            }
            Err(error) => {
                // This admitted helper does not capture gate failures itself.
                // Its fresh unexpected error must remain typed. Capture only
                // after our token/guards retire; a peer may have captured first,
                // in which case the gate retains this distinct cause as cleanup.
                if matches!(
                    error.primary(),
                    Error::SharedFileCopy { .. } | Error::SharedFileCapability { .. }
                ) {
                    self.memory.capture_shared_file_error(error);
                } else {
                    // SharedFailure also wraps unrelated typed failures. They
                    // still require the original unexpected-copy capture.
                    gate.poison(origin, error);
                }
                return Err(Errno::EIO);
            }
        };
        if post_copy_failure.is_some() || self.memory.check_copy_failure().is_err() {
            Err(Errno::EIO)
        } else {
            ordinary
        }
    }

    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        let mut source_index = 0;
        let mut source_offset = 0;
        let mut destination_index = 0;
        let mut destination_offset = 0;
        let mut total = 0;

        while source_index < read_from.len() && destination_index < write_to.len() {
            if source_offset == read_from[source_index].len() {
                source_index += 1;
                source_offset = 0;
                continue;
            }
            if destination_offset == write_to[destination_index].len() {
                destination_index += 1;
                destination_offset = 0;
                continue;
            }

            // Keep gate failure out of the ordinary EFAULT/partial mapping.
            #[cfg(test)]
            self.memory.before_vector_copy(total);
            let copy = self.memory.copy_access().map_err(|_| Errno::EIO)?;
            let requested = (read_from[source_index].len() - source_offset)
                .min(write_to[destination_index].len() - destination_offset);
            let address = read_from[source_index].as_ptr() as u64 + source_offset as u64;
            let count = self
                .user_accessible_prefix_admitted(address, requested, &copy)
                .unwrap_or_default();
            self.memory.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count == 0 {
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            let destination =
                &mut write_to[destination_index][destination_offset..destination_offset + count];
            if let Err(error) = self.read_translated_raw_admitted(address, destination, &copy) {
                drop(copy);
                if matches!(
                    error.primary(),
                    Error::SharedFileCopy { .. } | Error::SharedFileCapability { .. }
                ) {
                    self.memory
                        .capture_shared_file_error(shared_file::vector_copy_error(error, total));
                    return Err(Errno::EIO);
                }
                self.memory.check_copy_failure().map_err(|_| Errno::EIO)?;
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            source_offset += count;
            destination_offset += count;
            total += count;
            #[cfg(test)]
            self.memory.after_vector_copy(total);
            self.memory.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count < requested {
                return Ok(total);
            }
        }
        Ok(total)
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        let mut source_index = 0;
        let mut source_offset = 0;
        let mut destination_index = 0;
        let mut destination_offset = 0;
        let mut total = 0;

        while source_index < read_from.len() && destination_index < write_to.len() {
            if source_offset == read_from[source_index].len() {
                source_index += 1;
                source_offset = 0;
                continue;
            }
            if destination_offset == write_to[destination_index].len() {
                destination_index += 1;
                destination_offset = 0;
                continue;
            }

            #[cfg(test)]
            self.memory.before_vector_copy(total);
            let copy = self.memory.copy_access().map_err(|_| Errno::EIO)?;
            let count = (read_from[source_index].len() - source_offset)
                .min(write_to[destination_index].len() - destination_offset);
            let address =
                write_to[destination_index].as_mut_ptr() as u64 + destination_offset as u64;
            let requested = count;
            let count = self
                .user_accessible_prefix_admitted(address, requested, &copy)
                .unwrap_or_default();
            self.memory.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count == 0 {
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            let source = &read_from[source_index][source_offset..source_offset + count];
            if let Err(error) = self.write_translated_raw_admitted(address, source, &copy) {
                drop(copy);
                if matches!(
                    error.primary(),
                    Error::SharedFileCopy { .. } | Error::SharedFileCapability { .. }
                ) {
                    self.memory
                        .capture_shared_file_error(shared_file::vector_copy_error(error, total));
                    return Err(Errno::EIO);
                }
                self.memory.check_copy_failure().map_err(|_| Errno::EIO)?;
                return if total == 0 {
                    Err(Errno::EFAULT)
                } else {
                    Ok(total)
                };
            }
            source_offset += count;
            destination_offset += count;
            total += count;
            #[cfg(test)]
            self.memory.after_vector_copy(total);
            self.memory.check_copy_failure().map_err(|_| Errno::EIO)?;
            if count < requested {
                return Ok(total);
            }
        }
        Ok(total)
    }
}

#[cfg(test)]
#[path = "memory/entry_snapshot_tests.rs"]
mod entry_snapshot_tests;

#[cfg(test)]
mod tests {
    use reverie::syscalls::AddrMut;

    use super::*;

    impl GuestMemory {
        /// Independent admission for observing the initial backing in alias
        /// failure fixtures. This intentionally does not mirror installed
        /// replacement pages; callers create it before arming the interposer.
        pub(crate) fn test_alias_backing_observer(&self) -> Self {
            let observer =
                Self::from_backing_slice(self.guest_base(), self.mapping.slice.clone()).unwrap();
            assert!(!Arc::ptr_eq(&self.entry_gate(), &observer.entry_gate()));
            observer
        }
    }

    mod entry_copy_tests {
        use std::sync::atomic::AtomicUsize;
        use std::sync::atomic::Ordering;

        use futures::FutureExt;
        use reverie::syscalls::Addr;
        use reverie::syscalls::AddrSlice;
        use reverie::syscalls::AddrSliceMut;

        use super::*;

        const BASE: u64 = 0x1000;

        fn cause() -> Arc<Error> {
            Arc::new(Error::EntryControl {
                operation: "controlled memory-copy poison",
                source: io::Error::other("controlled memory-copy poison"),
            })
        }

        fn assert_cause<T>(result: Result<T>, cause: &Arc<Error>) {
            match result {
                Err(error) => assert!(error.retains_primary(cause), "{error}"),
                Ok(_) => panic!("poison became typed success"),
            }
        }

        #[test]
        fn clones_share_gate_but_new_views_and_snapshots_do_not() {
            let mut memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            memory.write_raw(BASE, b"data").unwrap();
            let mut clone = memory.clone();
            let global = Arc::new(());
            let run = crate::failure::RunFailure::new(&global);
            clone.set_failure_context(Some(FailureContext::new(
                run.clone(),
                reverie::Pid::from_raw(3),
                reverie::Pid::from_raw(4),
            )));
            assert!(memory.failure_context.is_none());
            assert!(clone.clone().failure_context.is_some());
            assert!(Arc::ptr_eq(&memory.entry_gate(), &clone.entry_gate()));
            assert!(format!("{clone:?}").contains("GuestMemory"));

            let view = GuestMemory::from_backing_slice(BASE, memory.mapping.slice.clone()).unwrap();
            let sparse = clone.snapshot().unwrap();
            let fallback = clone
                .snapshot_with_sparse_copy(|_, _, _| Err(io::Error::other("forced fallback")))
                .unwrap();
            for fresh in [&view, &sparse, &fallback] {
                assert!(!Arc::ptr_eq(&memory.entry_gate(), &fresh.entry_gate()));
                assert!(fresh.failure_context.is_none());
            }
            let original = cause();
            let pending = clone
                .entry_gate()
                .poison(None, Error::SharedFailure(original.clone()));
            assert!(Arc::ptr_eq(
                &pending,
                &memory.entry_gate().pending_failure().unwrap()
            ));
            assert_cause(memory.write(BASE, b"stop"), &original);
            for fresh in [&view, &sparse, &fallback] {
                let mut bytes = [0; 4];
                fresh.read_raw(BASE, &mut bytes).unwrap();
                assert_eq!(&bytes, b"data");
            }
            assert!(
                run.primary().is_none(),
                "memory must not publish Tool failure"
            );
        }

        #[test]
        fn typed_access_poison_preserves_cause_bytes_and_empty_distinctions() {
            let mut memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            memory.write_raw(BASE, b"keep").unwrap();
            // A separate test view observes effects without bypassing the
            // poisoned Mapping's admission. No production shared-view claim.
            let observer =
                GuestMemory::from_backing_slice(BASE, memory.mapping.slice.clone()).unwrap();
            let original = cause();
            memory
                .entry_gate()
                .poison(None, Error::SharedFailure(original.clone()));
            let mut user = memory.user();
            assert_cause(memory.read(BASE, &mut [0; 4]), &original);
            assert_cause(memory.read_raw(BASE, &mut [0; 4]), &original);
            assert_cause(memory.write(BASE, b"lost"), &original);
            assert_cause(memory.write_raw(BASE, b"lost"), &original);
            assert_cause(memory.zero(BASE, 4), &original);
            assert_cause(memory.zero_raw(BASE, 4), &original);
            assert_cause(memory.discard_pages(BASE, PAGE_SIZE), &original);
            assert_cause(user.read(BASE, &mut [0; 4]), &original);
            assert_cause(user.write(BASE, b"lost"), &original);
            assert_cause(user.zero(BASE, 4), &original);
            assert_cause(user.write_injection(BASE, b"lost"), &original);
            assert_cause(user.copy_to_user(BASE, b"lost"), &original);
            assert_cause(user.copy_to_user_prefix(BASE, b"lost"), &original);
            assert_cause(user.put_user_i32(BASE, 0), &original);
            assert_cause(user.user_accessible_prefix(BASE, 4), &original);
            assert_cause(user.user_writable_prefix(BASE, 4), &original);
            assert_cause(user.host_operand(BASE, 4), &original);
            assert_cause(user.retain_translated_range(BASE, 4), &original);
            assert_cause(memory.snapshot(), &original);
            assert_cause(memory.read(u64::MAX, &mut []), &original);
            assert_cause(user.copy_to_user_prefix(u64::MAX, &[]), &original);
            assert_cause(user.user_accessible_prefix(u64::MAX, 0), &original);
            let mut bytes = [0; 4];
            observer.read_raw(BASE, &mut bytes).unwrap();
            assert_eq!(&bytes, b"keep");
        }

        fn vector_poison_case<M: MemoryAccess>(
            mut adapter: M,
            memory: &GuestMemory,
            observer: &GuestMemory,
            original: &Arc<Error>,
            poison_after: usize,
            write: bool,
        ) {
            let mut output = [0xa5; 4];
            let result = if write {
                let source = [io::IoSlice::new(b"AB"), io::IoSlice::new(b"CD")];
                // SAFETY: MemoryAccess treats these guest addresses only as
                // remote operands; this caller never dereferences the slice.
                let mut destination = unsafe {
                    AddrSliceMut::from_raw_parts(AddrMut::from_raw(BASE as usize).unwrap(), 4)
                };
                adapter.write_vectored(&source, &mut [unsafe { destination.as_ioslice_mut() }])
            } else {
                // SAFETY: as above, this is an address descriptor for the
                // actual adapter, not a host dereference of the guest address.
                let source =
                    unsafe { AddrSlice::from_raw_parts(Addr::from_raw(BASE as usize).unwrap(), 4) };
                let (left, right) = output.split_at_mut(2);
                adapter.read_vectored(
                    &[unsafe { source.as_ioslice() }],
                    &mut [io::IoSliceMut::new(left), io::IoSliceMut::new(right)],
                )
            };
            assert_eq!(result, Err(Errno::EIO));
            let mut expected = [0xa5; 4];
            expected[..poison_after].copy_from_slice(&b"ABCD"[..poison_after]);
            if write {
                observer.read_raw(BASE, &mut output).unwrap();
            }
            assert_eq!(
                output, expected,
                "actual prefix must remain; suffix must not change"
            );
            assert_cause(memory.read(BASE, &mut [0]), original);
            assert_eq!(
                MemoryAccess::read(&adapter, Addr::from_raw(BASE as usize).unwrap(), &mut [0]),
                Err(Errno::EIO)
            );
            assert_eq!(
                MemoryAccess::write(
                    &mut adapter,
                    AddrMut::from_raw(BASE as usize).unwrap(),
                    b"x"
                ),
                Err(Errno::EIO)
            );
            // Empty trait transfers do not acquire admission or erase poison.
            assert_eq!(adapter.read_vectored(&[], &mut []), Ok(0));
            assert_eq!(adapter.write_vectored(&[], &mut []), Ok(0));
            assert_eq!(
                MemoryAccess::read(&adapter, Addr::from_raw(usize::MAX).unwrap(), &mut []),
                Ok(0)
            );
            assert_eq!(
                MemoryAccess::write(&mut adapter, AddrMut::from_raw(usize::MAX).unwrap(), &[]),
                Ok(0)
            );
            assert!(memory.entry_gate().pending_failure().is_some());
        }

        #[test]
        fn both_vectored_adapters_return_eio_before_between_and_after_actual_portions() {
            for user in [false, true] {
                for write in [false, true] {
                    for poison_after in [0, 2, 4] {
                        let mut memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
                        memory
                            .write_raw(BASE, if write { &[0xa5; 4] } else { b"ABCD" })
                            .unwrap();
                        let observer =
                            GuestMemory::from_backing_slice(BASE, memory.mapping.slice.clone())
                                .unwrap();
                        let original = cause();
                        let gate = memory.entry_gate();
                        let calls = Arc::new(AtomicUsize::new(0));
                        let hook_calls = calls.clone();
                        let hook_cause = original.clone();
                        memory.after_vector_copy = Some(Arc::new(move |total| {
                            hook_calls.fetch_add(1, Ordering::Relaxed);
                            if total == poison_after {
                                gate.poison(None, Error::SharedFailure(hook_cause.clone()));
                            }
                        }));
                        if poison_after == 0 {
                            memory
                                .entry_gate()
                                .poison(None, Error::SharedFailure(original.clone()));
                        }
                        if user {
                            vector_poison_case(
                                memory.user(),
                                &memory,
                                &observer,
                                &original,
                                poison_after,
                                write,
                            );
                        } else {
                            vector_poison_case(
                                memory.clone(),
                                &memory,
                                &observer,
                                &original,
                                poison_after,
                                write,
                            );
                        }
                        assert_eq!(calls.load(Ordering::Relaxed), poison_after / 2);
                    }
                }
            }
        }

        fn healthy_adapter<M: MemoryAccess>(mut adapter: M) {
            let address = AddrMut::from_raw(BASE as usize).unwrap();
            assert_eq!(MemoryAccess::write(&mut adapter, address, b"RO"), Ok(2));
            let boundary = BASE as usize + PAGE_SIZE - 2;
            assert_eq!(
                MemoryAccess::write(&mut adapter, AddrMut::from_raw(boundary).unwrap(), b"ABCD"),
                Ok(2)
            );
            let mut bytes = [0xa5; 4];
            assert_eq!(
                MemoryAccess::read(&adapter, Addr::from_raw(boundary).unwrap(), &mut bytes),
                Ok(2)
            );
            assert_eq!(bytes, [b'A', b'B', 0xa5, 0xa5]);
            assert_eq!(
                MemoryAccess::read(
                    &adapter,
                    Addr::from_raw(BASE as usize - 1).unwrap(),
                    &mut [0]
                ),
                Err(Errno::EFAULT)
            );
            assert_eq!(
                MemoryAccess::write(
                    &mut adapter,
                    AddrMut::from_raw(BASE as usize - 1).unwrap(),
                    b"x"
                ),
                Err(Errno::EFAULT)
            );
            assert_eq!(adapter.read_vectored(&[], &mut []), Ok(0));
            assert_eq!(adapter.write_vectored(&[], &mut []), Ok(0));
        }

        #[test]
        fn healthy_adapters_keep_accessible_writes_faults_and_partial_counts() {
            for user in [false, true] {
                let memory = GuestMemory::new(BASE, 2 * PAGE_SIZE).unwrap();
                memory
                    .map_user_permissions(BASE, PAGE_SIZE as u64, true, false)
                    .unwrap();
                memory
                    .map_user_range(BASE + PAGE_SIZE as u64, PAGE_SIZE as u64, true)
                    .unwrap();
                memory.enable_user_access();
                if user {
                    healthy_adapter(memory.user());
                } else {
                    healthy_adapter(memory.clone());
                }
                assert!(memory.user().copy_to_user(BASE, b"denied").is_err());
                assert!(memory.user().put_user_i32(BASE, 0).is_err());
                let mut bytes = [0; 2];
                memory.read_raw(BASE, &mut bytes).unwrap();
                assert_eq!(&bytes, b"RO");
                assert!(memory.user().read(memory.guest_end(), &mut []).is_ok());
                assert!(memory.user().read(u64::MAX, &mut []).is_err());
                assert_eq!(memory.user().copy_to_user_prefix(u64::MAX, &[]).unwrap(), 0);
            }
        }

        #[test]
        fn admitted_nested_copies_finish_and_retained_operands_do_not_block_unchanged_close() {
            let memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            memory.write_raw(BASE, b"data").unwrap();
            let gate = memory.entry_gate();
            let copy = memory.copy_access().unwrap();
            let closing = gate.try_close().unwrap().unwrap();
            let mut finish = Box::pin(closing.finish());
            assert!(finish.as_mut().now_or_never().is_none());
            let user = memory.user();
            let mut bytes = [0; 4];
            user.read_admitted(BASE, &mut bytes, &copy).unwrap();
            assert_eq!(&bytes, b"data");
            assert_eq!(
                user.write_user_prefix_admitted(BASE, b"next", true, &copy)
                    .unwrap(),
                4
            );
            user.zero_admitted(BASE + 4, 4, &copy).unwrap();
            assert!(finish.as_mut().now_or_never().is_none());
            drop(copy);
            let closed = finish
                .now_or_never()
                .expect("last copy did not retire")
                .unwrap();
            assert!(gate.try_copy(None).unwrap().is_none());
            drop(closed);
            let operand = user.host_operand(BASE, 4).unwrap();
            assert_eq!(gate.test_state().retained_operands, 1);
            let closed = gate
                .try_close()
                .unwrap()
                .unwrap()
                .finish()
                .now_or_never()
                .expect("retained operand blocked an unchanged close")
                .unwrap();
            assert!(memory.mapping.address_space.try_lock().is_ok());
            assert!(memory.mapping.slice.backing.host_access.try_lock().is_ok());
            assert_eq!(operand.address(), memory.host_address() as usize);
            drop(closed);
            memory.read_raw(BASE, &mut bytes).unwrap();
            assert_eq!(&bytes, b"next");
        }

        #[test]
        fn copy_unwind_captures_handle_origin_without_publishing_tool_failure() {
            let mut memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            let global = Arc::new(());
            let run = crate::failure::RunFailure::new(&global);
            memory.set_failure_context(Some(FailureContext::new(
                run.clone(),
                reverie::Pid::from_raw(3),
                reverie::Pid::from_raw(5),
            )));
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _copy = memory.copy_access().unwrap();
                    panic!("controlled admitted-copy unwind");
                }))
                .is_err()
            );
            let failure = memory.entry_gate().pending_failure().unwrap();
            assert!(failure.origin.is_some());
            assert!(matches!(
                failure.error().primary(),
                Error::EntryControl {
                    operation: "host copy unwound",
                    ..
                }
            ));
            assert!(
                run.primary().is_none(),
                "memory helpers must capture, never publish"
            );
        }

        #[test]
        fn retained_memory_copy_keeps_its_issuing_callback_generation() {
            use crate::entry::owner::DriverScope;

            let driver = DriverScope::new();
            let owner = driver.owner();
            let first = owner.begin_callback(None).unwrap();
            let first_origin = first.origin();
            let mut memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            memory.set_operation_origin(Some(first_origin.clone()));
            let retained = memory.clone();
            drop(first);
            let second = owner.begin_callback(None).unwrap();
            let second_origin = second.origin();
            memory.set_operation_origin(Some(second_origin.clone()));
            let snapshot = memory.snapshot().unwrap();
            assert!(snapshot.operation_origin.is_none());

            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _copy = retained.copy_access().unwrap();
                    panic!("retained callback copy unwind");
                }))
                .is_err()
            );
            let pending = memory.entry_gate().pending_failure().unwrap();
            let captured = pending.operation.as_ref().unwrap();
            assert!(captured.same_callback(&first_origin));
            assert!(!captured.same_callback(&second_origin));
            assert!(captured.callback_dropped());
            assert!(!second_origin.callback_dropped());
            assert!(Arc::ptr_eq(&owner.pending()[0], &pending));
            assert!(matches!(
                memory.read_raw(BASE, &mut [0]).unwrap_err().primary(),
                Error::EntryControl {
                    operation: "host copy unwound",
                    ..
                }
            ));
            drop(second);
            let retirement = driver.retire();
            retirement.result.unwrap();
            assert_eq!(retirement.pending.len(), 1);
            assert!(Arc::ptr_eq(&retirement.pending[0], &pending));
            retirement.notification.notify();
        }

        #[test]
        fn retired_memory_origin_retains_cause_without_expired_publisher() {
            use crate::entry::owner::DriverLifecycle;
            use crate::entry::owner::DriverScope;

            let driver = DriverScope::new();
            let owner = driver.owner();
            let callback = owner.begin_callback(None).unwrap();
            let origin = callback.origin();
            let mut memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            let global = Arc::new(());
            let run = crate::failure::RunFailure::new(&global);
            memory.set_failure_context(Some(FailureContext::new(
                run.clone(),
                reverie::Pid::from_raw(7),
                reverie::Pid::from_raw(9),
            )));
            memory.set_operation_origin(Some(origin.clone()));
            drop(callback);
            let retirement = driver.retire();
            retirement.result.unwrap();
            assert!(retirement.pending.is_empty());
            retirement.notification.notify();
            drop(global);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _copy = memory.copy_access().unwrap();
                    panic!("copy after owner retirement");
                }))
                .is_err()
            );
            let pending = memory.entry_gate().pending_failure().unwrap();
            assert_eq!(
                pending.operation.as_ref().unwrap().lifecycle(),
                DriverLifecycle::Retired
            );
            assert!(pending.operation.as_ref().unwrap().same_callback(&origin));
            assert!(
                owner.pending().is_empty(),
                "closed registration accepted a cause"
            );
            assert!(
                run.primary().is_none(),
                "copy called an expired Tool publisher"
            );
            assert!(matches!(
                pending.error().primary(),
                Error::EntryControl {
                    operation: "host copy unwound",
                    ..
                }
            ));
            assert!(matches!(
                memory.read_raw(BASE, &mut [0]).unwrap_err().primary(),
                Error::EntryControl {
                    operation: "host copy unwound",
                    ..
                }
            ));
        }

        #[test]
        fn snapshot_fallback_refuses_a_retained_failure_before_copying() {
            let memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            memory.write_raw(BASE, b"keep").unwrap();
            let original = cause();
            let result = memory.snapshot_with_sparse_copy(|_, _, _| {
                memory
                    .entry_gate()
                    .poison(None, Error::SharedFailure(original.clone()));
                Err(io::Error::other("force fallback after poison"))
            });
            assert_cause(result, &original);
            assert!(memory.mapping.allocation.try_lock().is_ok());
            assert!(memory.mapping.address_space.try_lock().is_ok());
            assert!(memory.mapping.slice.backing.host_access.try_lock().is_ok());
        }

        #[test]
        fn try_raw_write_defers_closed_copy_and_retains_poison_and_bounds() {
            let memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            memory.write_raw(BASE, b"keep").unwrap();
            // This separate test view observes the bytes while the original
            // Mapping is closed; it grants no production shared-view policy.
            let observer =
                GuestMemory::from_backing_slice(BASE, memory.mapping.slice.clone()).unwrap();
            let gate = memory.entry_gate();
            let closed = gate
                .try_close()
                .unwrap()
                .unwrap()
                .finish()
                .now_or_never()
                .expect("idle Mapping did not close")
                .unwrap();
            // Holding these locks makes any premature backing/state access a
            // test deadlock rather than a falsely successful admission check.
            {
                let _state = memory.mapping.address_space.lock().unwrap();
                let _backing = memory.mapping.slice.backing.host_access.lock().unwrap();
                assert_eq!(memory.try_write_raw(BASE, b"lost").unwrap(), None);
                assert_eq!(memory.try_write_raw(u64::MAX, b"x").unwrap(), None);
            }
            let mut bytes = [0; 4];
            observer.read_raw(BASE, &mut bytes).unwrap();
            assert_eq!(&bytes, b"keep");
            drop(closed);
            assert_eq!(memory.try_write_raw(BASE, b"next").unwrap(), Some(()));
            observer.read_raw(BASE, &mut bytes).unwrap();
            assert_eq!(&bytes, b"next");
            assert_eq!(
                memory.try_write_raw(memory.guest_end(), &[]).unwrap(),
                Some(())
            );
            for (address, source) in [
                (BASE - 1, b"x".as_slice()),
                (memory.guest_end() - 1, b"xy".as_slice()),
            ] {
                let expected = memory.write_raw(address, source).unwrap_err();
                let actual = memory.try_write_raw(address, source).unwrap_err();
                assert_eq!(actual.to_string(), expected.to_string());
                assert!(matches!(
                    actual,
                    Error::InvalidGuestAddress {
                        address: found_address,
                        length,
                        guest_base,
                        guest_end,
                    } if found_address == address
                        && length == source.len()
                        && guest_base == BASE
                        && guest_end == memory.guest_end()
                ));
            }
            observer.read_raw(BASE, &mut bytes).unwrap();
            assert_eq!(&bytes, b"next");
            let original = cause();
            gate.poison(None, Error::SharedFailure(original.clone()));
            assert_cause(memory.try_write_raw(BASE, b"lost"), &original);
            assert_cause(memory.try_write_raw(u64::MAX, &[]), &original);
            observer.read_raw(BASE, &mut bytes).unwrap();
            assert_eq!(&bytes, b"next");
        }

        #[test]
        fn read_preparation_runs_once_with_one_token_and_preserves_poison() {
            let memory = GuestMemory::new(BASE, PAGE_SIZE).unwrap();
            memory.write_raw(BASE, b"data").unwrap();
            let gate = memory.entry_gate();
            let closed = gate
                .try_close()
                .unwrap()
                .unwrap()
                .finish()
                .now_or_never()
                .unwrap()
                .unwrap();
            let calls = std::cell::Cell::new(0);
            assert_eq!(
                memory
                    .try_read_with(|_| {
                        calls.set(calls.get() + 1);
                        Ok(())
                    })
                    .unwrap(),
                None
            );
            assert_eq!(calls.get(), 0);
            drop(closed);
            let mut closing = None;
            let result = memory
                .try_read_with(|access| {
                    calls.set(calls.get() + 1);
                    // A nested read must use this token even after close starts.
                    closing = Some(gate.try_close().unwrap().unwrap());
                    let mut bytes = [0; 4];
                    access.read_raw(BASE, &mut bytes)?;
                    access.read_raw(BASE, &mut bytes)?;
                    Ok(bytes)
                })
                .unwrap();
            assert_eq!(result, Some(*b"data"));
            assert_eq!(calls.get(), 1);
            let closed = closing
                .unwrap()
                .finish()
                .now_or_never()
                .expect("read token escaped")
                .unwrap();
            drop(closed);
            let original = cause();
            assert_cause(
                memory.try_read_with(|access| {
                    let mut bytes = [0; 4];
                    access.read_raw(BASE, &mut bytes)?;
                    assert_eq!(&bytes, b"data");
                    gate.poison(None, Error::SharedFailure(original.clone()));
                    Ok(bytes)
                }),
                &original,
            );
            assert_cause(
                memory.try_read_with(|_| -> Result<()> {
                    panic!("poison ran the preparation closure")
                }),
                &original,
            );
        }
    }

    #[test]
    fn identity_view_preserves_tool_writes_copyout_faults_and_partial_reads() {
        use reverie::syscalls::Addr;
        let memory = GuestMemory::new(0x1_0000, 3 * PAGE_SIZE).unwrap();
        memory
            .map_user_permissions(0x1_0000, PAGE_SIZE as u64, true, false)
            .unwrap();
        memory
            .map_user_range(0x1_1000, PAGE_SIZE as u64, false)
            .unwrap();
        memory.enable_user_access();
        let mut user = memory.user();
        user.write(0x1_0000, b"tool").unwrap();
        assert!(user.copy_to_user(0x1_0000, b"bad!").is_err());
        let mut bytes = [0; 4];
        memory.read_raw(0x1_0000, &mut bytes).unwrap();
        assert_eq!(&bytes, b"tool");
        assert!(user.copy_to_user(0x1_1ffe, b"abcd").is_err());
        memory.read_raw(0x1_1ffe, &mut bytes).unwrap();
        assert_eq!(&bytes, b"ab\0\0");
        assert_eq!(user.copy_to_user_prefix(0x1_1ffe, b"wxyz").unwrap(), 2);
        assert!(user.put_user_i32(0x1_1ffe, 0x01020304).is_err());
        memory.read_raw(0x1_1ffe, &mut bytes).unwrap();
        assert_eq!(&bytes, b"wx\0\0");
        let mut output = [0; 4];
        assert_eq!(
            MemoryAccess::read(&user, Addr::from_raw(0x1_1ffe).unwrap(), &mut output).unwrap(),
            2
        );
        assert_eq!(&output, b"wx\0\0");
        assert!(user.read(0x1_2000, &mut [0]).is_err());
        assert!(user.read(u64::MAX, &mut [0; 2]).is_err());
        assert!(user.read(0x1_3000, &mut []).is_ok());
        assert!(user.read(u64::MAX, &mut []).is_err());
        assert_eq!(user.copy_to_user_prefix(u64::MAX, &[]).unwrap(), 0);
        // Reservation classes must not turn a physically covered hole into
        // accessible userspace, and physical compatibility remains unchanged.
        memory.write_raw(0x1_2000, b"physical").unwrap();
        assert!(memory.read(0x1_2000, &mut [0]).is_err());
    }

    #[test]
    fn identity_reservations_validate_transactionally_and_keep_coverage_distinct() {
        let memory = GuestMemory::new(0, 4 * PAGE_SIZE).unwrap();
        memory
            .reserve_region(0, PAGE_SIZE as u64, RegionKind::Bootstrap)
            .unwrap()
            .commit();
        assert!(
            memory
                .reserve_region(0, PAGE_SIZE as u64, RegionKind::Heap)
                .is_err()
        );
        assert!(
            memory
                .reserve_region(u64::MAX - 1, 4, RegionKind::Mmap)
                .is_err()
        );
        assert!(
            memory
                .reserve_region(4 * PAGE_SIZE as u64, PAGE_SIZE as u64, RegionKind::Mmap)
                .is_err()
        );
        assert_eq!(memory.reserved_pages(), 1);
        {
            let _proposed = memory
                .reserve_region(PAGE_SIZE as u64, 2 * PAGE_SIZE as u64, RegionKind::Mmap)
                .unwrap();
            assert_eq!(memory.reserved_pages(), 3);
        }
        assert_eq!(memory.reserved_pages(), 1);
        memory
            .reserve_region(PAGE_SIZE as u64, 2 * PAGE_SIZE as u64, RegionKind::Elf)
            .unwrap()
            .commit();
        memory
            .reserve_region(PAGE_SIZE as u64, PAGE_SIZE as u64, RegionKind::Elf)
            .unwrap()
            .commit();
        assert_eq!(memory.reserved_pages(), 3); // overlapping load pages count once
        memory.enable_user_access();
        assert!(memory.user().read(PAGE_SIZE as u64, &mut [0]).is_err());
        assert!(memory.read_raw(3 * PAGE_SIZE as u64, &mut [0]).is_ok());
        memory
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, true)
            .unwrap();
        assert!(memory.user().read(PAGE_SIZE as u64, &mut [0]).is_err());
        memory
            .unmap_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64)
            .unwrap();
        assert_eq!(memory.reservation_kind(PAGE_SIZE as u64), None);
        assert_eq!(memory.reservation_kind(0), Some(RegionKind::Bootstrap));
    }

    #[test]
    fn retained_host_operand_keeps_view_alive_without_a_sleeping_layout_lock() {
        let mut memory = GuestMemory::new(0x2_0000, PAGE_SIZE).unwrap();
        memory
            .map_user_range(0x2_0000, PAGE_SIZE as u64, false)
            .unwrap();
        memory.enable_user_access();
        memory.write(0x2_0000, &7_u32.to_ne_bytes()).unwrap();
        let weak = Arc::downgrade(&memory.mapping);
        let operand = memory.user().host_operand(0x2_0000, 4).unwrap();
        // Resolving an operand must not hold either owner lock across futex.
        assert!(memory.mapping.allocation.try_lock().is_ok());
        assert!(memory.mapping.address_space.try_lock().is_ok());
        memory.unmap_user_range(0x2_0000, PAGE_SIZE as u64).unwrap();
        drop(memory);
        assert!(weak.upgrade().is_some());
        // SAFETY: no guest or host thread writes this exact retained word.
        assert_eq!(unsafe { operand.read_volatile::<u32>() }, 7);
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    operand.address(),
                    libc::FUTEX_WAKE,
                    1,
                    0,
                    0,
                    0,
                )
            },
            0
        );
        drop(operand);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn private_snapshot_copies_one_allocation_owner_and_keeps_policy_independent() {
        let memory = GuestMemory::new(0, 4 * PAGE_SIZE).unwrap();
        let cursors = AllocationCursors {
            program_break: 4096,
            mmap_base: 8192,
            mmap_next: 8192,
            mmap_limit: 16384,
        };
        memory.set_allocation_cursors(cursors);
        memory
            .reserve_region(4096, 4096, RegionKind::Heap)
            .unwrap()
            .commit();
        memory.map_user_range(4096, 4096, false).unwrap();
        memory.enable_user_access();
        memory.user().copy_to_user(4096, b"private").unwrap();
        let shared = memory.clone();
        let snapshot = memory
            .snapshot_with_sparse_copy(|_, _, _| Err(io::Error::other("forced fallback")))
            .unwrap();
        assert_eq!(snapshot.allocation_cursors(), Some(cursors));
        assert_eq!(snapshot.reservation_kind(4096), Some(RegionKind::Heap));
        shared.set_allocation_cursors(AllocationCursors {
            mmap_next: 12288,
            ..cursors
        });
        shared.unmap_user_range(4096, 4096).unwrap();
        assert_eq!(memory.allocation_cursors().unwrap().mmap_next, 12288);
        assert!(memory.user().read(4096, &mut [0]).is_err());
        assert_eq!(snapshot.allocation_cursors(), Some(cursors));
        let mut bytes = [0; 7];
        snapshot.user().read(4096, &mut bytes).unwrap();
        assert_eq!(&bytes, b"private");
        snapshot.user().copy_to_user(4096, b"changed").unwrap();
        memory.read_raw(4096, &mut bytes).unwrap();
        assert_eq!(&bytes, b"private");
    }

    #[test]
    fn reads_and_writes_guest_memory() {
        let mut memory = GuestMemory::new(0x1000, PAGE_SIZE).unwrap();
        memory.write(0x1123, b"hello").unwrap();

        let mut bytes = [0; 5];
        memory.read(0x1123, &mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
    }

    #[test]
    fn permits_access_to_last_byte() {
        let mut memory = GuestMemory::new(0x2000, PAGE_SIZE).unwrap();
        memory.write(0x2fff, &[0x5a]).unwrap();

        let mut byte = [0];
        memory.read(0x2fff, &mut byte).unwrap();
        assert_eq!(byte, [0x5a]);
    }

    #[test]
    fn rejects_address_below_mapping() {
        let memory = GuestMemory::new(0x2000, PAGE_SIZE).unwrap();
        let error = memory.read(0x1fff, &mut [0]).unwrap_err();
        assert!(matches!(error, Error::InvalidGuestAddress { .. }));
    }

    #[test]
    fn rejects_access_past_mapping() {
        let mut memory = GuestMemory::new(0x2000, PAGE_SIZE).unwrap();
        let error = memory.write(0x2fff, &[1, 2]).unwrap_err();
        assert!(matches!(error, Error::InvalidGuestAddress { .. }));
    }

    #[test]
    fn cloned_handles_share_memory() {
        let mut first = GuestMemory::new(0x1000, PAGE_SIZE).unwrap();
        let mut second = first.clone();

        first.write(0x1100, b"shared").unwrap();
        let mut bytes = [0; 6];
        second.read(0x1100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"shared");

        second.write(0x1200, b"api").unwrap();
        let mut bytes = [0; 3];
        first.read(0x1200, &mut bytes).unwrap();
        assert_eq!(&bytes, b"api");
    }

    #[test]
    fn independent_views_retain_shared_backing_after_drop() {
        let backing = Arc::new(Backing::new(PAGE_SIZE).unwrap());
        let weak_backing = Arc::downgrade(&backing);
        let slice = BackingSlice::new(backing.clone(), 0, PAGE_SIZE).unwrap();
        let first = GuestMemory::from_backing_slice(0x1000, slice.clone()).unwrap();
        let second = GuestMemory::from_backing_slice(0x2000, slice).unwrap();
        let weak_first = Arc::downgrade(&first.mapping);
        assert_ne!(first.host_address(), second.host_address());
        assert!(Arc::ptr_eq(
            &first.mapping.slice.backing,
            &second.mapping.slice.backing,
        ));

        first.write_raw(0x1100, b"first!").unwrap();
        let mut bytes = [0; 6];
        second.read_raw(0x2100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"first!");
        second.write_raw(0x2100, b"second").unwrap();
        first.read_raw(0x1100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"second");
        {
            let _guard = first.mapping.slice.backing.host_access.lock().unwrap();
            assert!(matches!(
                second.mapping.slice.backing.host_access.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            let unrelated = GuestMemory::new(0, PAGE_SIZE).unwrap();
            assert!(
                unrelated
                    .mapping
                    .slice
                    .backing
                    .host_access
                    .try_lock()
                    .is_ok()
            );
        }

        drop(backing);
        drop(first);
        assert!(weak_first.upgrade().is_none());
        assert!(weak_backing.upgrade().is_some());
        second.read_raw(0x2100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"second");
        second.write_raw(0x2100, b"alive!").unwrap();
        second.read_raw(0x2100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"alive!");
        drop(second);
        assert!(weak_backing.upgrade().is_none());
    }

    #[test]
    fn backing_slices_validate_alignment_bounds_and_overflow() {
        let backing = Arc::new(Backing::new(PAGE_SIZE * 3).unwrap());
        let whole = BackingSlice::new(backing.clone(), 0, PAGE_SIZE * 3).unwrap();
        assert_eq!((whole.offset, whole.length), (0, PAGE_SIZE * 3));
        let tail = BackingSlice::new(backing.clone(), PAGE_SIZE, PAGE_SIZE * 2).unwrap();
        assert_eq!((tail.offset, tail.length), (PAGE_SIZE, PAGE_SIZE * 2));
        let unrepresentable = libc::off_t::MAX as usize + 1;
        for (offset, length) in [
            (0, 0),
            (1, PAGE_SIZE),
            (0, PAGE_SIZE - 1),
            (PAGE_SIZE * 2, PAGE_SIZE * 2),
            (PAGE_SIZE * 4, PAGE_SIZE),
            (usize::MAX - (PAGE_SIZE - 1), PAGE_SIZE),
            (unrepresentable, PAGE_SIZE),
        ] {
            let error = BackingSlice::new(backing.clone(), offset, length).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
        for size in [0, PAGE_SIZE - 1, unrepresentable] {
            assert_eq!(
                Backing::new(size).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        for (guest_base, size) in [
            (0, 0),
            (0, PAGE_SIZE - 1),
            (1, PAGE_SIZE),
            (u64::MAX - (PAGE_SIZE as u64 - 1), PAGE_SIZE),
            (0, unrepresentable),
        ] {
            assert!(matches!(
                GuestMemory::new(guest_base, size),
                Err(Error::InvalidMemoryLayout { .. })
            ));
        }
        assert!(matches!(
            GuestMemory::from_backing_slice(1, whole.clone()),
            Err(Error::InvalidMemoryLayout { .. })
        ));
        assert!(matches!(
            GuestMemory::from_backing_slice(u64::MAX - (PAGE_SIZE as u64 - 1), tail),
            Err(Error::InvalidMemoryLayout { .. })
        ));
    }

    #[test]
    fn independent_view_permissions_do_not_alias_clone_permissions() {
        let first = GuestMemory::new(0, PAGE_SIZE * 2).unwrap();
        let second = GuestMemory::from_backing_slice(0, first.mapping.slice.clone()).unwrap();
        let clone = first.clone();
        first.write_raw(0, &[0xa5; PAGE_SIZE * 2]).unwrap();
        first.map_user_range(0, PAGE_SIZE as u64, false).unwrap();
        first
            .map_user_permissions(PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
            .unwrap();
        first.enable_user_access();
        second
            .map_user_range(0, (PAGE_SIZE * 2) as u64, false)
            .unwrap();
        second.enable_user_access();

        second.copy_to_user(PAGE_SIZE as u64, b"shared").unwrap();
        let mut bytes = [0; 6];
        first.read(PAGE_SIZE as u64, &mut bytes).unwrap();
        assert_eq!(&bytes, b"shared");
        assert!(first.copy_to_user(PAGE_SIZE as u64, b"denied").is_err());
        assert_eq!(
            clone.copy_to_user_prefix(PAGE_SIZE as u64, b"x").unwrap(),
            0
        );
        let boundary = PAGE_SIZE as u64 - 2;
        assert!(clone.put_user_i32(boundary, 0).is_err());
        let mut scalar_bytes = [0; 4];
        second.read_raw(boundary, &mut scalar_bytes).unwrap();
        assert_eq!(scalar_bytes, [0xa5, 0xa5, b's', b'h']);
        assert_eq!(clone.copy_to_user_prefix(boundary, b"ABCD").unwrap(), 2);
        second.read_raw(boundary, &mut scalar_bytes).unwrap();
        assert_eq!(&scalar_bytes, b"ABsh");

        clone
            .map_user_permissions(0, PAGE_SIZE as u64, true, false)
            .unwrap();
        assert!(first.put_user_i32(0, 0).is_err());
        second.put_user_i32(0, 0).unwrap();
        clone
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, true)
            .unwrap();
        assert!(first.read(PAGE_SIZE as u64, &mut bytes).is_err());
        second.read(PAGE_SIZE as u64, &mut bytes).unwrap();
        assert_eq!(&bytes, b"shared");
        first
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, false)
            .unwrap();
        clone.copy_to_user(PAGE_SIZE as u64, b"cloned").unwrap();
        second.read(PAGE_SIZE as u64, &mut bytes).unwrap();
        assert_eq!(&bytes, b"cloned");
    }

    #[test]
    fn snapshot_of_nonzero_slice_copies_view_and_stays_private() {
        // Both an offset-zero subset and an interior slice must bypass the
        // whole-file sparse helper. The public allocation path remains whole.
        for backing_offset in [0, PAGE_SIZE] {
            let parent = GuestMemory::new(0, PAGE_SIZE * 4).unwrap();
            let mut original = vec![0; PAGE_SIZE * 4];
            for (page, bytes) in original.chunks_mut(PAGE_SIZE).enumerate() {
                bytes.fill(0x11 * (page as u8 + 1));
            }
            parent.write_raw(0, &original).unwrap();
            let slice = BackingSlice::new(
                parent.mapping.slice.backing.clone(),
                backing_offset,
                PAGE_SIZE * 2,
            )
            .unwrap();
            let base = 0x10000;
            let view = GuestMemory::from_backing_slice(base, slice).unwrap();
            view.map_user_range(base, PAGE_SIZE as u64, false).unwrap();
            view.map_user_permissions(base + PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
                .unwrap();
            view.enable_user_access();
            let snapshot = view
                .snapshot_with_sparse_copy(|_, _, _| panic!("subset reached sparse file copy"))
                .unwrap();
            assert!(!Arc::ptr_eq(
                &view.mapping.slice.backing,
                &snapshot.mapping.slice.backing,
            ));
            assert_eq!(snapshot.guest_base(), base);
            assert_eq!(snapshot.len(), PAGE_SIZE * 2);
            let mut expected = original[backing_offset..backing_offset + PAGE_SIZE * 2].to_vec();
            let mut actual = vec![0; PAGE_SIZE * 2];
            snapshot.read(base, &mut actual).unwrap();
            assert_eq!(actual, expected);
            assert!(snapshot.read_raw(base - 1, &mut [0]).is_err());
            assert!(snapshot.read_raw(snapshot.guest_end(), &mut [0]).is_err());
            assert!(snapshot.put_user_i32(base + PAGE_SIZE as u64, 0).is_err());
            snapshot.write_raw(base, &[0xa1]).unwrap();
            expected[0] = 0xa1;
            view.write_raw(base + PAGE_SIZE as u64, &[0xb2]).unwrap();
            original[backing_offset + PAGE_SIZE] = 0xb2;
            snapshot.read_raw(base, &mut actual).unwrap();
            assert_eq!(actual, expected);
            let mut parent_bytes = vec![0; original.len()];
            parent.read_raw(0, &mut parent_bytes).unwrap();
            assert_eq!(parent_bytes, original);
            snapshot
                .map_user_range(base + PAGE_SIZE as u64, PAGE_SIZE as u64, false)
                .unwrap();
            snapshot.put_user_i32(base + PAGE_SIZE as u64, 0).unwrap();
            assert!(view.put_user_i32(base + PAGE_SIZE as u64, 0).is_err());
        }
    }

    #[test]
    fn discarded_pages_are_lazy_zeroes_in_every_cloned_handle() {
        let memory = GuestMemory::new(0x1000, PAGE_SIZE * 3).unwrap();
        let clone = memory.clone();
        memory.write_raw(0x1000, &[0x11; PAGE_SIZE]).unwrap();
        memory.write_raw(0x2000, &[0x5a; PAGE_SIZE]).unwrap();
        memory.write_raw(0x3000, &[0x33; PAGE_SIZE]).unwrap();

        memory.discard_pages(0x2000, PAGE_SIZE).unwrap();
        let mut bytes = vec![0xff; PAGE_SIZE];
        clone.read_raw(0x2000, &mut bytes).unwrap();
        assert_eq!(bytes, vec![0; PAGE_SIZE]);
        let mut boundary = [0; 1];
        clone.read_raw(0x1000, &mut boundary).unwrap();
        assert_eq!(boundary, [0x11]);
        clone.read_raw(0x3000, &mut boundary).unwrap();
        assert_eq!(boundary, [0x33]);
        assert_eq!(memory.host_address(), clone.host_address());
    }

    #[test]
    fn discard_pages_rejects_unaligned_ranges() {
        let memory = GuestMemory::new(0x1000, PAGE_SIZE * 2).unwrap();
        assert!(matches!(
            memory.discard_pages(0x1001, PAGE_SIZE),
            Err(Error::InvalidMemoryLayout { .. })
        ));
        assert!(matches!(
            memory.discard_pages(0x1000, PAGE_SIZE - 1),
            Err(Error::InvalidMemoryLayout { .. })
        ));
    }

    #[test]
    fn snapshot_copies_without_sharing_memory() {
        let mut parent = GuestMemory::new(0x1000, PAGE_SIZE * 3).unwrap();
        parent.write(0x1100, b"parent").unwrap();
        parent.write(0x3100, b"tail!!").unwrap();

        let mut child = parent.snapshot().unwrap();
        let mut bytes = [0; 6];
        child.read(0x1100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"parent");
        child.read(0x3100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"tail!!");

        child.write(0x1100, b"child!").unwrap();
        parent.write(0x3100, b"source").unwrap();
        parent.read(0x1100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"parent");
        child.read(0x1100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"child!");
        parent.read(0x3100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"source");
        child.read(0x3100, &mut bytes).unwrap();
        assert_eq!(&bytes, b"tail!!");
    }

    #[test]
    fn sparse_snapshot_copies_distant_extents_and_page_boundaries() {
        const MAPPING_PAGES: usize = 16 * 1024;
        let mut parent = GuestMemory::new(0, PAGE_SIZE * MAPPING_PAGES).unwrap();
        let boundary = PAGE_SIZE as u64 - 2;
        let middle = (PAGE_SIZE * (MAPPING_PAGES / 2)) as u64 + 37;
        let tail = (PAGE_SIZE * MAPPING_PAGES - 4) as u64;

        parent.write(boundary, b"edge").unwrap();
        parent.write(middle, b"middle").unwrap();
        parent.write(tail, b"last").unwrap();

        let snapshot = parent.snapshot().unwrap();
        let mut bytes = [0; 6];
        snapshot.read(boundary, &mut bytes[..4]).unwrap();
        assert_eq!(&bytes[..4], b"edge");
        snapshot.read(middle, &mut bytes).unwrap();
        assert_eq!(&bytes, b"middle");
        snapshot.read(tail, &mut bytes[..4]).unwrap();
        assert_eq!(&bytes[..4], b"last");
        snapshot
            .read((PAGE_SIZE * (MAPPING_PAGES / 4)) as u64, &mut bytes)
            .unwrap();
        assert_eq!(bytes, [0; 6]);

        let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: stat points to writable storage and the backing descriptor is live.
        assert_eq!(
            unsafe {
                libc::fstat(
                    snapshot.mapping.slice.backing.fd.as_raw_fd(),
                    stat.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: fstat succeeded and initialized the structure.
        let allocated_bytes = unsafe { stat.assume_init() }.st_blocks as u64 * 512;
        assert!(
            allocated_bytes < (snapshot.len() / 2) as u64,
            "snapshot unexpectedly became dense: {allocated_bytes} allocated bytes"
        );
    }

    #[test]
    fn sparse_snapshot_failure_falls_back_after_a_partial_copy() {
        let mut parent = GuestMemory::new(0, PAGE_SIZE * 4).unwrap();
        parent.write(0, &[0x11; PAGE_SIZE]).unwrap();
        parent
            .write((PAGE_SIZE * 3) as u64, &[0x44; PAGE_SIZE])
            .unwrap();

        let snapshot = parent
            .snapshot_with_sparse_copy(|source, destination, _| {
                let mut source_offset = (PAGE_SIZE * 3) as libc::loff_t;
                let mut destination_offset: libc::loff_t = 0;
                while destination_offset < PAGE_SIZE as libc::loff_t {
                    // SAFETY: snapshot_with_sparse_copy supplies two live,
                    // equal-sized backing descriptors and valid offset pointers.
                    let copied = unsafe {
                        libc::copy_file_range(
                            source,
                            &mut source_offset,
                            destination,
                            &mut destination_offset,
                            PAGE_SIZE - destination_offset as usize,
                            0,
                        )
                    };
                    assert!(copied > 0);
                }
                assert_eq!(source_offset, (PAGE_SIZE * 4) as libc::loff_t);
                assert_eq!(destination_offset, PAGE_SIZE as libc::loff_t);
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            })
            .unwrap();

        let mut bytes = vec![0; PAGE_SIZE * 4];
        snapshot.read(0, &mut bytes).unwrap();
        assert_eq!(&bytes[..PAGE_SIZE], &[0x11; PAGE_SIZE]);
        assert_eq!(&bytes[PAGE_SIZE..PAGE_SIZE * 3], &[0; PAGE_SIZE * 2]);
        assert_eq!(&bytes[PAGE_SIZE * 3..], &[0x44; PAGE_SIZE]);
        let mut parent_bytes = vec![0; PAGE_SIZE * 4];
        parent.read(0, &mut parent_bytes).unwrap();
        assert_eq!(parent_bytes, bytes);
    }

    #[test]
    fn untouched_snapshot_is_zero_filled_and_independent() {
        let mut parent = GuestMemory::new(0, PAGE_SIZE * 4).unwrap();
        let mut snapshot = parent
            .snapshot_with_sparse_copy(|source, destination, length| {
                let data = unsafe { libc::lseek(source, 0, libc::SEEK_DATA) };
                let error = (data < 0).then(io::Error::last_os_error);
                let initial_enxio = error
                    .as_ref()
                    .is_some_and(|error| error.raw_os_error() == Some(libc::ENXIO));
                let result = copy_sparse_file(source, destination, length);
                eprintln!(
                    "untouched snapshot: SEEK_DATA(0)={data}, error={error:?}, initial_enxio={initial_enxio}, sparse_copy={result:?}"
                );
                if initial_enxio {
                    assert!(result.is_ok());
                }
                result
            })
            .unwrap();

        let mut parent_bytes = vec![0xff; PAGE_SIZE * 4];
        let mut snapshot_bytes = vec![0xff; PAGE_SIZE * 4];
        parent.read(0, &mut parent_bytes).unwrap();
        snapshot.read(0, &mut snapshot_bytes).unwrap();
        assert_eq!(parent_bytes, vec![0; PAGE_SIZE * 4]);
        assert_eq!(snapshot_bytes, vec![0; PAGE_SIZE * 4]);

        snapshot.write(0, &[0x22; PAGE_SIZE]).unwrap();
        parent
            .write((PAGE_SIZE * 3) as u64, &[0x44; PAGE_SIZE])
            .unwrap();
        parent.read(0, &mut parent_bytes).unwrap();
        snapshot.read(0, &mut snapshot_bytes).unwrap();
        let mut expected_parent = vec![0; PAGE_SIZE * 4];
        expected_parent[PAGE_SIZE * 3..].fill(0x44);
        let mut expected_snapshot = vec![0; PAGE_SIZE * 4];
        expected_snapshot[..PAGE_SIZE].fill(0x22);
        assert_eq!(parent_bytes, expected_parent);
        assert_eq!(snapshot_bytes, expected_snapshot);
    }

    #[test]
    fn sparse_snapshot_copies_file_data_after_dontneed() {
        let mut parent = GuestMemory::new(0, PAGE_SIZE * 4).unwrap();
        parent
            .write(PAGE_SIZE as u64, b"backed after dontneed")
            .unwrap();

        // MAP_SHARED writes belong to the memfd. Flushing followed by
        // MADV_DONTNEED gives the kernel permission to discard the resident
        // mapping pages; sparse copying must enumerate file data, not PTEs.
        // MADV_DONTNEED is only a hint, so this checks correctness after the
        // transition without claiming that the kernel actually evicted it.
        // SAFETY: the address and length identify a page-aligned live mapping.
        assert_eq!(
            unsafe {
                libc::msync(
                    parent.mapping.mapping.as_ptr().add(PAGE_SIZE).cast(),
                    PAGE_SIZE,
                    libc::MS_SYNC,
                )
            },
            0
        );
        // SAFETY: the address and length identify a page-aligned live mapping.
        assert_eq!(
            unsafe {
                libc::madvise(
                    parent.mapping.mapping.as_ptr().add(PAGE_SIZE).cast(),
                    PAGE_SIZE,
                    libc::MADV_DONTNEED,
                )
            },
            0
        );

        let snapshot = parent.snapshot().unwrap();
        let mut bytes = [0; 21];
        snapshot.read(PAGE_SIZE as u64, &mut bytes).unwrap();
        assert_eq!(&bytes, b"backed after dontneed");
    }

    #[test]
    fn tracked_user_access_faults_and_returns_partial_copies() {
        let mut memory = GuestMemory::new(0, PAGE_SIZE * 3).unwrap();
        memory
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, false)
            .unwrap();
        memory
            .map_user_range((PAGE_SIZE * 2) as u64, PAGE_SIZE as u64, true)
            .unwrap();
        memory.enable_user_access();

        assert!(matches!(
            memory.write(1, &[0x11]),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
        let address = AddrMut::from_raw(PAGE_SIZE * 2 - 8).unwrap();
        let written = MemoryAccess::write(&mut memory, address, &[0x5a; 16]).unwrap();
        assert_eq!(written, 8);

        let mut bytes = [0; 8];
        memory.read((PAGE_SIZE * 2 - 8) as u64, &mut bytes).unwrap();
        assert_eq!(bytes, [0x5a; 8]);
        assert!(matches!(
            memory.read((PAGE_SIZE * 2) as u64, &mut [0]),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
    }

    #[test]
    fn snapshot_preserves_user_access_map() {
        let mut parent = GuestMemory::new(0, PAGE_SIZE * 2).unwrap();
        parent
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, false)
            .unwrap();
        parent.enable_user_access();
        parent.write(PAGE_SIZE as u64, b"mapped").unwrap();

        let mut child = parent.snapshot().unwrap();
        assert!(matches!(
            child.write(1, &[1]),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
        child.write(PAGE_SIZE as u64, b"child!").unwrap();
        let mut bytes = [0; 6];
        parent.read(PAGE_SIZE as u64, &mut bytes).unwrap();
        assert_eq!(&bytes, b"mapped");
    }

    #[test]
    fn counted_copyout_reports_exact_writable_prefix_without_weakening_scalar_copy() {
        let memory = GuestMemory::new(0, PAGE_SIZE * 2).unwrap();
        memory.write_raw(0, &[0xa5; PAGE_SIZE * 2]).unwrap();
        memory
            .map_user_permissions(0, PAGE_SIZE as u64, true, true)
            .unwrap();
        memory
            .map_user_permissions(PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
            .unwrap();
        memory.enable_user_access();
        assert_eq!(memory.copy_to_user_prefix(u64::MAX, b"").unwrap(), 0);
        assert_eq!(
            memory
                .copy_to_user_prefix(PAGE_SIZE as u64, b"refused")
                .unwrap(),
            0
        );
        assert_eq!(
            memory
                .copy_to_user_prefix(PAGE_SIZE as u64 - 7, b"ABCDEFGHIJKLMN")
                .unwrap(),
            7
        );
        let mut actual = [0; PAGE_SIZE * 2];
        memory.read_raw(0, &mut actual).unwrap();
        let mut expected = [0xa5; PAGE_SIZE * 2];
        expected[PAGE_SIZE - 7..PAGE_SIZE].copy_from_slice(b"ABCDEFG");
        assert_eq!(actual, expected);
        assert!(memory.put_user_i32(PAGE_SIZE as u64 - 2, 0).is_err());
        memory.read_raw(0, &mut actual).unwrap();
        assert_eq!(actual, expected, "scalar copy must remain all-or-nothing");
        assert!(memory.copy_to_user(PAGE_SIZE as u64 - 2, b"1234").is_err());
        expected[PAGE_SIZE - 2..PAGE_SIZE].copy_from_slice(b"12");
        memory.read_raw(0, &mut actual).unwrap();
        assert_eq!(
            actual, expected,
            "legacy partial-copy side effect must remain"
        );
        memory
            .map_user_permissions(PAGE_SIZE as u64, PAGE_SIZE as u64, true, true)
            .unwrap();
        assert_eq!(
            memory
                .copy_to_user_prefix(PAGE_SIZE as u64 - 7, b"ABCDEFGHIJKLMN")
                .unwrap(),
            14
        );
        memory.read_raw(0, &mut actual).unwrap();
        expected[PAGE_SIZE - 7..PAGE_SIZE + 7].copy_from_slice(b"ABCDEFGHIJKLMN");
        assert_eq!(actual, expected);
        assert!(
            memory
                .copy_to_user_prefix(2 * PAGE_SIZE as u64, b"x")
                .is_err()
        );
    }

    mod writable_alias_notification_tests {
        use std::future::Future;
        use std::task::Context;
        use std::task::Wake;
        use std::task::Waker;

        use super::*;

        enum WakeAction {
            SetWritable(bool),
            Poison(Arc<Error>),
        }

        #[derive(Debug)]
        struct Observation {
            copies: usize,
            retained: usize,
            permissions_available: bool,
            host_access_available: bool,
            read: Option<Result<[u8; 4]>>,
        }

        struct ObserveAliasWake {
            memory: GuestMemory,
            action: Mutex<Option<WakeAction>>,
            observations: Mutex<Vec<Observation>>,
        }

        impl Wake for ObserveAliasWake {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }

            fn wake_by_ref(self: &Arc<Self>) {
                let state = self.memory.entry_gate().test_state();
                let permissions_available = !matches!(
                    self.memory.mapping.address_space.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                );
                let host_access_available = !matches!(
                    self.memory.mapping.slice.backing.host_access.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                );
                // Do not hang the baseline: record lock contention instead of
                // reentering a mutex held by the notifying thread. On the fixed
                // path this performs a real public GuestMemory read. Both
                // try_lock temporaries have retired before that operation.
                // Unwinding may poison an unlocked mutex; the real read then
                // observes the already-retained gate failure before locking.
                let read = if permissions_available && host_access_available {
                    let mut bytes = [0; 4];
                    Some(self.memory.read(0, &mut bytes).map(|()| bytes))
                } else {
                    None
                };
                self.observations.lock().unwrap().push(Observation {
                    copies: state.copies,
                    retained: state.retained_operands,
                    permissions_available,
                    host_access_available,
                    read,
                });
                // No observation lock crosses a permission update or poison,
                // which can itself notify another registered subscriber.
                let action = if permissions_available && host_access_available {
                    self.action.lock().unwrap().take()
                } else {
                    None
                };
                match action {
                    Some(WakeAction::SetWritable(writable)) => self
                        .memory
                        .map_user_permissions(0, PAGE_SIZE as u64, true, writable)
                        .unwrap(),
                    Some(WakeAction::Poison(cause)) => {
                        self.memory
                            .entry_gate()
                            .poison(self.memory.entry_origin(), Error::SharedFailure(cause));
                    }
                    None => {}
                }
            }
        }

        fn fixture(writable: bool) -> GuestMemory {
            let memory = GuestMemory::new(0, PAGE_SIZE).unwrap();
            memory.write_raw(0, &[0xa5; PAGE_SIZE]).unwrap();
            memory
                .map_user_permissions(0, PAGE_SIZE as u64, true, writable)
                .unwrap();
            memory.enable_user_access();
            memory
        }

        fn probe(memory: &GuestMemory, action: Option<WakeAction>) -> Arc<ObserveAliasWake> {
            Arc::new(ObserveAliasWake {
                memory: memory.clone(),
                action: Mutex::new(action),
                observations: Mutex::new(Vec::new()),
            })
        }

        fn assert_preparation_notification(probe: &ObserveAliasWake) {
            let observations = probe.observations.lock().unwrap();
            assert_eq!(observations.len(), 1, "{observations:?}");
            let observed = &observations[0];
            assert_eq!(observed.copies, 0);
            assert_eq!(observed.retained, 1);
            assert!(observed.permissions_available, "{observed:?}");
            assert!(observed.host_access_available, "{observed:?}");
            assert_eq!(
                observed
                    .read
                    .as_ref()
                    .expect("reentrant read was not attempted")
                    .as_ref()
                    .unwrap(),
                &[0xa5; 4]
            );
            assert!(probe.action.lock().unwrap().is_none());
        }

        fn assert_retired(memory: &GuestMemory) {
            let state = memory.entry_gate().test_state();
            assert_eq!(state.copies, 0);
            assert_eq!(state.retained_operands, 0);
            assert!(memory.mapping.address_space.try_lock().is_ok());
            assert!(memory.mapping.slice.backing.host_access.try_lock().is_ok());
            assert_eq!(Arc::strong_count(&memory.mapping.slice.backing), 1);
        }

        #[test]
        fn successful_preparation_notifies_before_alias_locks() {
            for (address, length) in [(u64::MAX, 0), (3, 17)] {
                let memory = fixture(true);
                let mapping = Arc::downgrade(&memory.mapping);
                let generation = memory.entry_gate().test_state().generation;
                let probe = probe(&memory, None);
                let waker = Waker::from(probe.clone());
                // This is the same subscription used by the checked Tool
                // driver's private-failure future before polling its callback.
                let watch = crate::entry::driver::EntryDriverWatch::for_memory(&memory);
                let mut changed = Box::pin(watch.wait());
                assert!(
                    changed
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                let user = memory.user();
                let alias = user.writable_alias(address, length).unwrap();
                assert_eq!(memory.entry_gate().test_state().copies, 0);
                assert_eq!(memory.entry_gate().test_state().retained_operands, 1);
                assert_eq!(memory.entry_gate().test_state().generation, generation);
                assert!(memory.mapping.address_space.try_lock().is_err());
                assert!(memory.mapping.slice.backing.host_access.try_lock().is_err());
                alias.finish().unwrap();
                assert_preparation_notification(&probe);
                assert_retired(&memory);
                let mut actual = [0; PAGE_SIZE];
                memory.read(0, &mut actual).unwrap();
                assert_eq!(actual, [0xa5; PAGE_SIZE]);
                drop(changed);
                drop(watch);
                drop(waker);
                drop(probe);
                drop(user);
                drop(memory);
                assert!(mapping.upgrade().is_none());
            }
        }

        #[test]
        fn preparation_uses_permissions_changed_by_notification() {
            for writable in [false, true] {
                let memory = fixture(!writable);
                let probe = probe(&memory, Some(WakeAction::SetWritable(writable)));
                let waker = Waker::from(probe.clone());
                let watch = crate::entry::driver::EntryDriverWatch::for_memory(&memory);
                let mut changed = Box::pin(watch.wait());
                assert!(
                    changed
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                let zero = std::fs::File::open("/dev/zero").unwrap();
                let user = memory.user();
                let alias = user.writable_alias(3, 1).unwrap();
                // SAFETY: the alias owns this kernel destination until finish;
                // protected pages are deliberately inaccessible to the kernel.
                let copied = unsafe { libc::read(zero.as_raw_fd(), alias.address(), 1) };
                let errno = io::Error::last_os_error().raw_os_error();
                alias.finish().unwrap();
                assert_preparation_notification(&probe);
                assert_retired(&memory);
                if writable {
                    assert_eq!(copied, 1);
                } else {
                    assert_eq!(copied, -1);
                    assert_eq!(errno, Some(libc::EFAULT));
                }
                let mut actual = [0; PAGE_SIZE];
                memory.read(0, &mut actual).unwrap();
                let mut expected = [0xa5; PAGE_SIZE];
                if writable {
                    expected[3] = 0;
                }
                assert_eq!(actual, expected);
            }
        }

        #[test]
        fn preparation_preserves_poison_from_notification() {
            for length in [0, 1, usize::MAX] {
                let memory = fixture(true);
                let cause = Arc::new(Error::UnexpectedVcpuExit(
                    "alias preparation notification poison".to_owned(),
                ));
                let probe = probe(&memory, Some(WakeAction::Poison(cause.clone())));
                let waker = Waker::from(probe.clone());
                let watch = crate::entry::driver::EntryDriverWatch::for_memory(&memory);
                let mut changed = Box::pin(watch.wait());
                assert!(
                    changed
                        .as_mut()
                        .poll(&mut Context::from_waker(&waker))
                        .is_pending()
                );
                let user = memory.user();
                let error = user
                    .writable_alias(3, length)
                    .err()
                    .expect("poison became success");
                assert!(error.retains_primary(&cause), "{error}");
                assert!(
                    memory
                        .entry_gate()
                        .pending_failure()
                        .unwrap()
                        .error()
                        .retains_primary(&cause)
                );
                assert_preparation_notification(&probe);
                assert_retired(&memory);
            }
        }

        #[test]
        fn unwinding_alias_releases_locks_before_retained_notification() {
            let memory = fixture(true);
            let user = memory.user();
            let alias = user.writable_alias(3, 1).unwrap();
            let probe = probe(&memory, None);
            let waker = Waker::from(probe.clone());
            let watch = crate::entry::driver::EntryDriverWatch::for_memory(&memory);
            let mut changed = Box::pin(watch.wait());
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _alias = alias;
                panic!("controlled alias unwind");
            }));
            assert!(result.is_err());
            let observations = probe.observations.lock().unwrap();
            assert_eq!(observations.len(), 1, "{observations:?}");
            let observed = &observations[0];
            assert_eq!((observed.copies, observed.retained), (0, 0));
            assert!(
                observed.permissions_available && observed.host_access_available,
                "{observed:?}"
            );
            let error = observed
                .read
                .as_ref()
                .expect("reentrant read was not attempted")
                .as_ref()
                .unwrap_err();
            assert!(matches!(
                error.primary(),
                Error::EntryControl {
                    operation: "retained host operand unwound",
                    ..
                }
            ));
            let state = memory.entry_gate().test_state();
            assert_eq!((state.copies, state.retained_operands), (0, 0));
            // Guard destruction during unwind preserves ordinary Mutex poison.
            // Poisoned means try_lock acquired the now-unlocked mutex, unlike
            // WouldBlock; do not clear either mutex's poison for this control.
            assert!(matches!(
                memory.mapping.address_space.try_lock(),
                Err(std::sync::TryLockError::Poisoned(_))
            ));
            assert!(matches!(
                memory.mapping.slice.backing.host_access.try_lock(),
                Err(std::sync::TryLockError::Poisoned(_))
            ));
            assert_eq!(Arc::strong_count(&memory.mapping.slice.backing), 1);
        }
    }

    #[test]
    fn writable_alias_shares_live_bytes_and_holds_copyout_permissions() {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering;

        const BASE: u64 = 0x1000;
        let backing = Arc::new(Backing::new(4 * PAGE_SIZE).unwrap());
        let slice = BackingSlice::new(backing, PAGE_SIZE, 3 * PAGE_SIZE).unwrap();
        let memory = GuestMemory::from_backing_slice(BASE, slice).unwrap();
        memory.write_raw(BASE, &[0xa5; 3 * PAGE_SIZE]).unwrap();
        memory
            .map_user_range(BASE, PAGE_SIZE as u64, false)
            .unwrap();
        memory
            .map_user_permissions(BASE + PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
            .unwrap();
        memory
            .map_user_range(BASE + 2 * PAGE_SIZE as u64, PAGE_SIZE as u64, true)
            .unwrap();
        memory.enable_user_access();
        // This atomic is a controlled peer-vCPU store, which deliberately does
        // not acquire the host-copy mutex. It is naturally aligned and remains
        // in this live mapping, disjoint from the kernel's one-byte output.
        let marker = unsafe { &*memory.mapping.mapping.as_ptr().add(512).cast::<AtomicU64>() };
        marker.store(41, Ordering::SeqCst);
        let zero = std::fs::File::open("/dev/zero").unwrap();
        let user = memory.user();
        let alias = user.writable_alias(BASE + 3, 3 * PAGE_SIZE - 3).unwrap();
        assert_eq!(alias.address() as usize % PAGE_SIZE, 3);
        assert_eq!(memory.entry_gate().test_state().copies, 0);
        assert_eq!(memory.entry_gate().test_state().retained_operands, 1);
        assert!(memory.mapping.address_space.try_lock().is_err());
        assert!(memory.mapping.slice.backing.host_access.try_lock().is_err());
        // SAFETY: the alias retains every mapping through these kernel copies.
        assert_eq!(
            unsafe { libc::read(zero.as_raw_fd(), alias.address(), 1) },
            1
        );
        for offset in [PAGE_SIZE - 3, 2 * PAGE_SIZE - 3] {
            let destination = alias.address().cast::<u8>().wrapping_add(offset).cast();
            assert_eq!(unsafe { libc::read(zero.as_raw_fd(), destination, 1) }, -1);
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EFAULT)
            );
        }
        std::thread::scope(|scope| {
            scope
                .spawn(|| marker.store(42, Ordering::SeqCst))
                .join()
                .unwrap();
        });
        alias.finish().unwrap();
        assert_eq!(marker.load(Ordering::SeqCst), 42);
        assert_eq!(memory.entry_gate().test_state().retained_operands, 0);
        let mut actual = vec![0; 3 * PAGE_SIZE];
        memory.read_raw(BASE, &mut actual).unwrap();
        let mut expected = vec![0xa5; 3 * PAGE_SIZE];
        expected[3] = 0;
        expected[512..520].copy_from_slice(&42_u64.to_ne_bytes());
        assert_eq!(actual, expected);
    }

    #[test]
    fn writable_alias_uses_installed_backings_across_page_boundaries() {
        match Kvm::new() {
            Ok(_) => {}
            Err(error) if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) => {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "installed-backing alias test requires /dev/kvm: {error}"
                );
                eprintln!(
                    "skipping KVM installed-backing alias test: cannot open /dev/kvm: {error}"
                );
                return;
            }
            Err(error) => panic!("failed to probe /dev/kvm: {error}"),
        }

        let memory = GuestMemory::new(0, 3 * PAGE_SIZE).unwrap();
        memory.write_raw(0, &[0xa5; 3 * PAGE_SIZE]).unwrap();
        memory
            .map_user_range(0, 3 * PAGE_SIZE as u64, false)
            .unwrap();
        memory.enable_user_access();
        let pending = memory
            .stage_backing_page(PAGE_SIZE as u64, &[0x5a; PAGE_SIZE])
            .unwrap();
        let gate = memory.entry_gate();
        let mut closed =
            futures::executor::block_on(gate.try_close().unwrap().unwrap().finish()).unwrap();
        pending.publish(&mut closed).unwrap();
        drop(closed);
        let zero = std::fs::File::open("/dev/zero").unwrap();
        let user = memory.user();
        let alias = user.writable_alias(0, 3 * PAGE_SIZE).unwrap();
        for offset in [PAGE_SIZE - 1, 2 * PAGE_SIZE - 1] {
            let destination = alias.address().cast::<u8>().wrapping_add(offset).cast();
            // SAFETY: both bytes are writable in the retained alias, crossing
            // from one separately mapped backing to another only in the kernel.
            assert_eq!(unsafe { libc::read(zero.as_raw_fd(), destination, 2) }, 2);
        }
        alias.finish().unwrap();
        let mut actual = vec![0; 3 * PAGE_SIZE];
        memory.read_raw(0, &mut actual).unwrap();
        let mut expected = vec![0xa5; 3 * PAGE_SIZE];
        expected[PAGE_SIZE..2 * PAGE_SIZE].fill(0x5a);
        expected[PAGE_SIZE - 1..PAGE_SIZE + 1].fill(0);
        expected[2 * PAGE_SIZE - 1..2 * PAGE_SIZE + 1].fill(0);
        assert_eq!(actual, expected);
    }

    fn alias_failure_memory(fault: &crate::alias_failure::Fault) -> (GuestMemory, GuestMemory) {
        let length = fault.pages() * PAGE_SIZE;
        let memory = GuestMemory::new(0, length).unwrap();
        memory.write_raw(0, &vec![0xa5; length]).unwrap();
        if fault.case() != crate::alias_failure::Case::CleanupAtEof {
            for page in (0..fault.pages()).step_by(2) {
                memory
                    .map_user_range((page * PAGE_SIZE) as u64, PAGE_SIZE as u64, false)
                    .unwrap();
            }
        }
        memory.enable_user_access();
        let observer = memory.test_alias_backing_observer();
        (memory, observer)
    }

    fn assert_alias_ledger(
        fault: &crate::alias_failure::Fault,
        before: &[RetainedWriteAliasSnapshot],
    ) -> Option<RetainedWriteAliasSnapshot> {
        use crate::alias_failure::Case;
        let after = retained_write_aliases_for_test();
        if matches!(fault.case(), Case::Reservation | Case::AtomicCollision) {
            assert_eq!(after, before);
            return None;
        }
        assert_eq!(after.len(), before.len() + 1);
        assert_eq!(&after[1..], before, "earlier retained records changed");
        let actual = &after[0];
        let addresses = fault.addresses();
        assert_ne!(actual.retention_id, 0);
        assert!(
            before
                .iter()
                .all(|prior| prior.retention_id != actual.retention_id)
        );
        assert_ne!(addresses.base, 0);
        assert_eq!(addresses.length, fault.pages() * PAGE_SIZE);
        let ambiguous = matches!(
            fault.case(),
            Case::SecondExtent
                | Case::Foreign
                | Case::WrongAddress
                | Case::MiddleExtent
                | Case::ConstructionCleanup
                | Case::SuffixCleanup
        );
        let mut expected = RetainedWriteAliasSnapshot {
            retention_id: actual.retention_id,
            address: addresses.base,
            length: addresses.length,
            ambiguous: ambiguous.then_some((addresses.base + 2 * PAGE_SIZE, PAGE_SIZE)),
            unexpected: (fault.case() == Case::WrongAddress)
                .then_some((addresses.wrong, PAGE_SIZE)),
            unexpected_bounds_valid: fault.case() == Case::WrongAddress,
            owned_ranges: [None; 3],
            cleanup_errors: [None; 3],
            backing_count: if fault.case() == Case::CleanupAtEof {
                0
            } else {
                fault.pages().div_ceil(2)
            },
        };
        assert_eq!(
            addresses.ambiguous,
            expected.ambiguous.map_or(0, |range| range.0)
        );
        let refused = match fault.case() {
            Case::CleanupAfterSuccess | Case::PersistentCleanup | Case::CleanupAtEof => {
                Some((0, addresses.base, addresses.length))
            }
            Case::ConstructionCleanup => Some((0, addresses.base, 2 * PAGE_SIZE)),
            Case::SuffixCleanup => Some((1, addresses.base + 3 * PAGE_SIZE, 2 * PAGE_SIZE)),
            _ => None,
        };
        if let Some((slot, address, length)) = refused {
            expected.owned_ranges[slot] = Some((address, length));
            expected.cleanup_errors[slot] = Some((address, length, libc::ENOMEM));
        }
        if fault.case() == Case::WrongAddress {
            assert_ne!(addresses.wrong, 0);
            assert!(
                addresses.wrong + PAGE_SIZE <= addresses.base
                    || addresses.base + addresses.length <= addresses.wrong
            );
        } else {
            assert_eq!(addresses.wrong, 0);
        }
        assert_eq!(*actual, expected, "case {:?}", fault.case());
        Some(actual.clone())
    }

    fn alias_expected_cause<'a>(
        fault: &crate::alias_failure::Fault,
        error: &'a Error,
        retained: Option<&RetainedWriteAliasSnapshot>,
    ) -> &'a Error {
        let cause = match retained {
            Some(record) => fault.cause(error, Some(record.retention_id)),
            None => fault.cause(error, None),
        };
        cause.unwrap_or_else(|| panic!("wrong alias cause for {:?}: {error:?}", fault.case()))
    }

    fn assert_alias_terminal_identity(
        fault: &crate::alias_failure::Fault,
        memory: &GuestMemory,
        error: &Error,
        retained: Option<&RetainedWriteAliasSnapshot>,
    ) {
        let cause = alias_expected_cause(fault, error, retained);
        let pending = memory.entry_gate().pending_failure().unwrap();
        let sticky = pending.error();
        assert!(std::ptr::eq(
            cause,
            alias_expected_cause(fault, &sticky, retained)
        ));
        let mut bytes = [0; 4];
        let read = memory.read_raw(0, &mut bytes).unwrap_err();
        assert!(std::ptr::eq(
            cause,
            alias_expected_cause(fault, &read, retained)
        ));
        let user = memory.user();
        let retry = user
            .writable_alias(0, PAGE_SIZE)
            .err()
            .expect("poison allowed another alias");
        assert!(std::ptr::eq(
            cause,
            alias_expected_cause(fault, &retry, retained)
        ));
        let state = memory.entry_gate().test_state();
        assert_eq!((state.copies, state.retained_operands), (0, 0));
        assert!(memory.mapping.address_space.try_lock().is_ok());
        assert!(memory.mapping.slice.backing.host_access.try_lock().is_ok());
    }

    fn release_alias_test_handles(
        memory: GuestMemory,
        observer: GuestMemory,
        error: Option<Error>,
        expected: &[RetainedWriteAliasSnapshot],
        retained_backings: usize,
    ) {
        let mapping = Arc::downgrade(&memory.mapping);
        let observed_mapping = Arc::downgrade(&observer.mapping);
        let gate = Arc::downgrade(&memory.entry_gate());
        let observed_gate = Arc::downgrade(&observer.entry_gate());
        let backing = Arc::downgrade(&memory.mapping.slice.backing);
        drop(error);
        drop(observer);
        drop(memory);
        assert!(
            mapping.upgrade().is_none(),
            "ledger retained a guest Mapping"
        );
        assert!(observed_mapping.upgrade().is_none());
        assert!(gate.upgrade().is_none(), "ledger retained an entry gate");
        assert!(observed_gate.upgrade().is_none());
        assert_eq!(backing.strong_count(), retained_backings);
        assert_eq!(
            retained_write_aliases_for_test(),
            expected,
            "ordinary teardown changed retained ownership"
        );
    }

    fn writable_alias_construction_failure_case(fault: crate::alias_failure::Fault) {
        assert!(!fault.case().setup_succeeds());
        let before = retained_write_aliases_for_test();
        assert!(before.is_empty(), "fault child was not isolated");
        let (memory, observer) = alias_failure_memory(&fault);
        fault.arm();
        let error = {
            let user = memory.user();
            user.writable_alias(u64::MAX, 0).unwrap().finish().unwrap();
            user.writable_alias(0, fault.pages() * PAGE_SIZE)
                .err()
                .unwrap()
        };
        let retained = assert_alias_ledger(&fault, &before);
        assert_alias_terminal_identity(&fault, &memory, &error, retained.as_ref());
        let mut actual = vec![0; fault.pages() * PAGE_SIZE];
        observer.read_raw(0, &mut actual).unwrap();
        assert_eq!(actual, vec![0xa5; actual.len()]);
        let after = retained_write_aliases_for_test();
        release_alias_test_handles(
            memory,
            observer,
            Some(error),
            &after,
            retained.as_ref().map_or(0, |record| record.backing_count),
        );
        fault.assert_fired();
        assert_eq!(retained_write_aliases_for_test(), after);
    }

    #[test]
    fn writable_alias_construction_failure_has_exact_ownership() {
        let Some(fault) = crate::alias_failure::child(
            "memory::tests::writable_alias_construction_failure_has_exact_ownership",
        ) else {
            return;
        };
        writable_alias_construction_failure_case(fault);
    }

    #[test]
    fn writable_alias_foreign_mapping_preserves_ownership() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_foreign_mapping_preserves_ownership",
            crate::alias_failure::Case::Foreign,
        ) else {
            return;
        };
        writable_alias_construction_failure_case(fault);
    }

    #[test]
    fn writable_alias_unexpected_address_preserves_ownership() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_unexpected_address_preserves_ownership",
            crate::alias_failure::Case::WrongAddress,
        ) else {
            return;
        };
        writable_alias_construction_failure_case(fault);
    }

    #[test]
    fn writable_alias_middle_extent_preserves_ownership() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_middle_extent_preserves_ownership",
            crate::alias_failure::Case::MiddleExtent,
        ) else {
            return;
        };
        writable_alias_construction_failure_case(fault);
    }

    #[test]
    fn writable_alias_construction_cleanup_retains_prefix_and_primary() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_construction_cleanup_retains_prefix_and_primary",
            crate::alias_failure::Case::ConstructionCleanup,
        ) else {
            return;
        };
        writable_alias_construction_failure_case(fault);
    }

    #[test]
    fn writable_alias_suffix_cleanup_never_retries_reallocated_prefix() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_suffix_cleanup_never_retries_reallocated_prefix",
            crate::alias_failure::Case::SuffixCleanup,
        ) else {
            return;
        };
        writable_alias_construction_failure_case(fault);
    }

    #[test]
    fn writable_alias_atomic_replacement_survives_allocator_contention() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_atomic_replacement_survives_allocator_contention",
            crate::alias_failure::Case::AtomicCollision,
        ) else {
            return;
        };
        // The old NOREPLACE collision control expected terminal EEXIST. This
        // distinct positive control requires our fixed replacement to succeed
        // while the real competing allocator receives EEXIST instead.
        assert!(fault.succeeds());
        let before = retained_write_aliases_for_test();
        assert!(before.is_empty());
        let (memory, observer) = alias_failure_memory(&fault);
        let zero = std::fs::File::open("/dev/zero").unwrap();
        fault.arm();
        {
            let user = memory.user();
            user.writable_alias(u64::MAX, 0).unwrap().finish().unwrap();
            let alias = user.writable_alias(0, fault.pages() * PAGE_SIZE).unwrap();
            // SAFETY: the alias remains live for this synchronous kernel write.
            assert_eq!(
                unsafe { libc::read(zero.as_raw_fd(), alias.address(), 1) },
                1
            );
            alias.finish().unwrap();
            user.writable_alias(u64::MAX, 0).unwrap().finish().unwrap();
        }
        let mut expected = vec![0xa5; fault.pages() * PAGE_SIZE];
        expected[0] = 0;
        for view in [&memory, &observer] {
            let mut actual = vec![0; expected.len()];
            view.read_raw(0, &mut actual).unwrap();
            assert_eq!(actual, expected);
            view.check_copy_failure().unwrap();
        }
        assert!(assert_alias_ledger(&fault, &before).is_none());
        drop(zero);
        release_alias_test_handles(memory, observer, None, &before, 0);
        let observed = fault.assert_fired();
        assert_eq!(observed.case, crate::alias_failure::Case::AtomicCollision);
        assert_eq!(
            observed.counters[18], 1,
            "allocator did not observe real EEXIST"
        );
        assert_eq!(
            observed.counters[3], 0,
            "successful install was mislabeled failure"
        );
    }

    struct AliasEofDirectory {
        file: std::fs::File,
        path: std::path::PathBuf,
    }

    impl AliasEofDirectory {
        fn drained() -> Self {
            let path =
                std::env::temp_dir().join(format!("reverie-alias-eof-{}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            let directory = Self {
                file: std::fs::File::open(&path).unwrap(),
                path,
            };
            let mut buffer = [0_u8; 256];
            let mut calls = 0;
            loop {
                // SAFETY: this stack buffer is writable for its stated size.
                let count = unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        directory.file.as_raw_fd(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                    )
                };
                assert!(
                    count >= 0,
                    "directory drain: {}",
                    io::Error::last_os_error()
                );
                calls += 1;
                assert!(calls <= 4, "empty test directory did not reach EOF");
                if count == 0 {
                    break;
                }
            }
            assert!(calls >= 2, "empty directory lacked dot entries");
            directory
        }
    }

    impl Drop for AliasEofDirectory {
        fn drop(&mut self) {
            let removed = std::fs::remove_dir(&self.path);
            if !std::thread::panicking() {
                removed.unwrap();
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum AliasRetirementMode {
        Finish,
        Drop,
        Unwind,
        PriorFailure,
    }

    #[derive(Debug)]
    struct AliasRetirementObservation {
        copies: usize,
        retained: usize,
        permissions_available: bool,
        backing_available: bool,
        read: Option<Result<[u8; 4]>>,
        ledger: Vec<RetainedWriteAliasSnapshot>,
    }

    struct AliasRetirementWake {
        memory: GuestMemory,
        observations: Mutex<Vec<AliasRetirementObservation>>,
    }

    impl std::task::Wake for AliasRetirementWake {
        fn wake(self: Arc<Self>) {
            std::task::Wake::wake_by_ref(&self);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            let state = self.memory.entry_gate().test_state();
            let permissions_available = !matches!(
                self.memory.mapping.address_space.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            );
            let backing_available = !matches!(
                self.memory.mapping.slice.backing.host_access.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            );
            let ledger = retained_write_aliases_for_test();
            let read = if permissions_available && backing_available {
                let mut bytes = [0; 4];
                Some(self.memory.read_raw(0, &mut bytes).map(|()| bytes))
            } else {
                None
            };
            self.observations
                .lock()
                .unwrap()
                .push(AliasRetirementObservation {
                    copies: state.copies,
                    retained: state.retained_operands,
                    permissions_available,
                    backing_available,
                    read,
                    ledger,
                });
        }
    }

    fn writable_alias_cleanup_case(
        fault: &crate::alias_failure::Fault,
        mode: AliasRetirementMode,
        before: &[RetainedWriteAliasSnapshot],
    ) -> RetainedWriteAliasSnapshot {
        use std::future::Future;
        use std::os::unix::fs::FileExt;
        use std::task::Context;
        use std::task::Waker;
        assert!(fault.case().setup_succeeds() && !fault.succeeds());
        assert_eq!(retained_write_aliases_for_test(), before);
        let (memory, observer) = alias_failure_memory(fault);
        let backing_file =
            std::fs::File::from(memory.mapping.slice.backing.fd.try_clone().unwrap());
        let zero = std::fs::File::open("/dev/zero").unwrap();
        let eof = (fault.case() == crate::alias_failure::Case::CleanupAtEof)
            .then(AliasEofDirectory::drained);
        let original = (mode == AliasRetirementMode::PriorFailure).then(|| {
            Arc::new(Error::UnexpectedVcpuExit(
                "prior alias cleanup failure".to_owned(),
            ))
        });
        fault.arm();
        let user = memory.user();
        user.writable_alias(u64::MAX, 0).unwrap().finish().unwrap();
        let alias = user.writable_alias(0, fault.pages() * PAGE_SIZE).unwrap();
        let mut expected = vec![0xa5; fault.pages() * PAGE_SIZE];
        if let Some(directory) = &eof {
            // SAFETY: the positive alias is entirely PROT_NONE; Linux at an
            // actually drained directory must return EOF without touching it.
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        directory.file.as_raw_fd(),
                        alias.address(),
                        expected.len(),
                    )
                },
                0
            );
        } else {
            // SAFETY: first page is writable and retained through the syscall.
            assert_eq!(
                unsafe { libc::read(zero.as_raw_fd(), alias.address(), 1) },
                1
            );
            expected[0] = 0;
        }
        if let Some(primary) = &original {
            // No notification observer is armed yet. The cleanup must preserve
            // this already-sticky cause, rather than publishing a replacement.
            memory
                .entry_gate()
                .poison(None, Error::SharedFailure(primary.clone()));
        }
        let wake = Arc::new(AliasRetirementWake {
            memory: memory.clone(),
            observations: Mutex::new(Vec::new()),
        });
        let waker = Waker::from(wake.clone());
        let watch = crate::entry::driver::EntryDriverWatch::for_memory(&memory);
        let mut changed = Box::pin(watch.wait());
        if original.is_none() {
            assert!(
                changed
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }
        let error = match mode {
            AliasRetirementMode::Finish | AliasRetirementMode::PriorFailure => {
                alias.finish().unwrap_err()
            }
            AliasRetirementMode::Drop => {
                drop(alias);
                memory.check_copy_failure().unwrap_err()
            }
            AliasRetirementMode::Unwind => {
                let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _alias = alias;
                    panic!("controlled cleanup alias unwind");
                }))
                .expect_err("alias unwind was swallowed");
                assert_eq!(
                    panic.downcast_ref::<&str>(),
                    Some(&"controlled cleanup alias unwind")
                );
                drop(panic);
                memory.check_copy_failure().unwrap_err()
            }
        };
        drop(user);
        let record = assert_alias_ledger(fault, before).unwrap();
        let after = retained_write_aliases_for_test();
        let gate = memory.entry_gate();
        let pending = gate.pending_failure().unwrap();
        let causes = pending.causes();
        let alias_cause = if matches!(
            mode,
            AliasRetirementMode::Unwind | AliasRetirementMode::PriorFailure
        ) {
            assert_eq!(
                causes.len(),
                2,
                "primary or cleanup was duplicated: {error:?}"
            );
            if let Some(primary) = &original {
                assert!(error.retains_primary(primary));
                assert!(causes[0].retains_primary(primary));
                assert!(std::ptr::eq(error.primary(), primary.primary()));
            } else {
                assert!(matches!(
                    error.primary(),
                    Error::EntryControl {
                        operation: "retained host operand unwound",
                        ..
                    }
                ));
                assert!(std::ptr::eq(error.primary(), causes[0].primary()));
            }
            alias_expected_cause(fault, &causes[1], Some(&record))
        } else {
            assert_eq!(causes.len(), 1, "cleanup was published twice: {error:?}");
            assert_alias_terminal_identity(fault, &memory, &error, Some(&record));
            let cause = alias_expected_cause(fault, &error, Some(&record));
            assert!(std::ptr::eq(
                cause,
                alias_expected_cause(fault, &causes[0], Some(&record))
            ));
            cause
        };
        assert!(
            matches!(alias_cause, Error::WriteAliasCleanup { source, address, length, retention_id }
            if source.raw_os_error() == Some(libc::ENOMEM) && *address == record.address && *length == record.length && *retention_id == record.retention_id)
        );
        let denied = memory.read_raw(0, &mut [0; 4]).unwrap_err();
        assert!(std::ptr::eq(denied.primary(), error.primary()));
        let retry = memory
            .user()
            .writable_alias(0, PAGE_SIZE)
            .err()
            .expect("poison allowed an alias retry");
        assert!(std::ptr::eq(retry.primary(), error.primary()));
        assert_eq!(retained_write_aliases_for_test(), after);
        let state = gate.test_state();
        assert_eq!((state.copies, state.retained_operands), (0, 0));
        {
            let observations = wake.observations.lock().unwrap();
            if mode == AliasRetirementMode::PriorFailure {
                assert!(observations.is_empty());
            } else {
                assert_eq!(
                    observations.len(),
                    1,
                    "unexpected notification count: {observations:?}"
                );
                let observed = &observations[0];
                assert_eq!(observed.copies, 0);
                assert_eq!(
                    observed.retained,
                    usize::from(mode != AliasRetirementMode::Unwind)
                );
                assert!(observed.permissions_available && observed.backing_available);
                assert_eq!(
                    observed.ledger, after,
                    "notification preceded ownership transfer"
                );
                let observed_error = observed
                    .read
                    .as_ref()
                    .expect("waker could not reenter memory")
                    .as_ref()
                    .unwrap_err();
                assert!(std::ptr::eq(observed_error.primary(), error.primary()));
            }
        }
        let mut actual = vec![0; expected.len()];
        if mode == AliasRetirementMode::Unwind {
            assert!(matches!(
                memory.mapping.address_space.try_lock(),
                Err(std::sync::TryLockError::Poisoned(_))
            ));
            assert!(matches!(
                memory.mapping.slice.backing.host_access.try_lock(),
                Err(std::sync::TryLockError::Poisoned(_))
            ));
            // Original Mutex poison remains. A preowned duplicate backing fd
            // observes bytes without reopening guest admission or clearing it.
            backing_file.read_exact_at(&mut actual, 0).unwrap();
        } else {
            observer.read_raw(0, &mut actual).unwrap();
        }
        assert_eq!(actual, expected);
        drop(retry);
        drop(denied);
        drop(causes);
        drop(pending);
        drop(gate);
        drop(original);
        drop(changed);
        drop(watch);
        drop(waker);
        drop(wake);
        drop(backing_file);
        drop(zero);
        drop(eof);
        release_alias_test_handles(memory, observer, Some(error), &after, record.backing_count);
        fault.assert_fired();
        assert_eq!(retained_write_aliases_for_test(), after);
        record
    }

    #[test]
    fn writable_alias_finish_cleanup_failure_is_terminal_after_unlock() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_finish_cleanup_failure_is_terminal_after_unlock",
            crate::alias_failure::Case::CleanupAfterSuccess,
        ) else {
            return;
        };
        assert!(retained_write_aliases_for_test().is_empty());
        writable_alias_cleanup_case(&fault, AliasRetirementMode::Finish, &[]);
    }

    #[test]
    fn writable_alias_drop_cleanup_failure_retains_ownership_once() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_drop_cleanup_failure_retains_ownership_once",
            crate::alias_failure::Case::CleanupAfterSuccess,
        ) else {
            return;
        };
        assert!(retained_write_aliases_for_test().is_empty());
        writable_alias_cleanup_case(&fault, AliasRetirementMode::Drop, &[]);
    }

    #[test]
    fn writable_alias_unwind_cleanup_preserves_primary_before_notification() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_unwind_cleanup_preserves_primary_before_notification",
            crate::alias_failure::Case::CleanupAfterSuccess,
        ) else {
            return;
        };
        assert!(retained_write_aliases_for_test().is_empty());
        writable_alias_cleanup_case(&fault, AliasRetirementMode::Unwind, &[]);
    }

    #[test]
    fn writable_alias_cleanup_preserves_existing_primary_identity() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_cleanup_preserves_existing_primary_identity",
            crate::alias_failure::Case::CleanupAfterSuccess,
        ) else {
            return;
        };
        assert!(retained_write_aliases_for_test().is_empty());
        writable_alias_cleanup_case(&fault, AliasRetirementMode::PriorFailure, &[]);
    }

    #[test]
    fn writable_alias_eof_cleanup_failure_retains_inaccessible_reservation() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_eof_cleanup_failure_retains_inaccessible_reservation",
            crate::alias_failure::Case::CleanupAtEof,
        ) else {
            return;
        };
        assert!(retained_write_aliases_for_test().is_empty());
        writable_alias_cleanup_case(&fault, AliasRetirementMode::Finish, &[]);
    }

    #[test]
    fn writable_alias_three_independent_failures_keep_exact_retained_records() {
        let Some(fault) = crate::alias_failure::child_case(
            "memory::tests::writable_alias_three_independent_failures_keep_exact_retained_records",
            crate::alias_failure::Case::PersistentCleanup,
        ) else {
            return;
        };
        assert!(retained_write_aliases_for_test().is_empty());
        let mut expected = Vec::new();
        for operation in 1..=3 {
            let record =
                writable_alias_cleanup_case(&fault, AliasRetirementMode::Finish, &expected);
            assert_eq!(fault.addresses().operation, operation);
            expected.insert(0, record);
            assert_eq!(retained_write_aliases_for_test(), expected);
        }
        assert_eq!(expected.len(), 3);
        for (index, record) in expected.iter().enumerate() {
            assert!(
                expected[index + 1..]
                    .iter()
                    .all(|other| other.retention_id != record.retention_id
                        && other.address != record.address)
            );
        }
    }

    #[test]
    fn writable_alias_unexpected_address_geometry_excludes_ambiguous_and_owned_overlaps() {
        const START: usize = 100 * PAGE_SIZE;
        const LENGTH: usize = 9 * PAGE_SIZE;
        let prefix = Some((START, 3 * PAGE_SIZE));
        let suffix = Some((START + 6 * PAGE_SIZE, 3 * PAGE_SIZE));
        // These are arithmetic-only records, not mappings. The exact expected
        // outside intervals are stated independently of the production helper.
        let cases = [
            (
                "disjoint below",
                90 * PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                Some((90 * PAGE_SIZE, 3 * PAGE_SIZE)),
            ),
            (
                "overlaps lower boundary",
                START - PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                Some((START - PAGE_SIZE, PAGE_SIZE)),
            ),
            ("exact prefix", START, 3 * PAGE_SIZE, true, None),
            (
                "prefix and ambiguous",
                START + PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                None,
            ),
            (
                "inside ambiguous",
                START + 3 * PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                None,
            ),
            (
                "ambiguous and suffix",
                START + 4 * PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                None,
            ),
            (
                "exact suffix",
                START + 6 * PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                None,
            ),
            (
                "overlaps upper boundary",
                START + 8 * PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                Some((START + 9 * PAGE_SIZE, 2 * PAGE_SIZE)),
            ),
            (
                "disjoint above",
                START + 12 * PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                Some((START + 12 * PAGE_SIZE, 3 * PAGE_SIZE)),
            ),
            ("unaligned positive", START - 1, 3 * PAGE_SIZE, false, None),
            (
                "overflowing positive",
                usize::MAX - (PAGE_SIZE - 1),
                3 * PAGE_SIZE,
                false,
                None,
            ),
            (
                "oversized positive",
                START - PAGE_SIZE,
                LENGTH + PAGE_SIZE,
                false,
                None,
            ),
        ];
        for (name, address, length, bounds_valid, outside) in cases {
            // Suppress any future ownership destructor as well: these addresses
            // are synthetic and this pure geometry test must never unmap them.
            let mut record = std::mem::ManuallyDrop::new(WriteAliasMapping {
                address: START,
                length: LENGTH,
                ambiguous: None,
                mapping_errno: None,
                unexpected: None,
                unexpected_bounds_valid: false,
                owned: [None; 3],
                cleanup: [None; 3],
                _extents: Vec::new(),
                next: None,
            });
            record.lose_fixed_target(3 * PAGE_SIZE, 3 * PAGE_SIZE, None);
            record.note_unexpected_address(address, length);
            assert_eq!(
                record.unexpected.map(|range| (range.address, range.length)),
                Some((address, length)),
                "{name}"
            );
            assert_eq!(record.unexpected_bounds_valid, bounds_valid, "{name}");
            let ambiguous = record.ambiguous.unwrap();
            assert_eq!(
                (ambiguous.address, ambiguous.length),
                (START + 3 * PAGE_SIZE, 3 * PAGE_SIZE)
            );
            let owned = record
                .owned
                .map(|range| range.map(|range| (range.address, range.length)));
            assert_eq!(owned, [prefix, suffix, outside], "{name}");
            let intervals: Vec<_> = owned.into_iter().flatten().collect();
            for (index, &(start, bytes)) in intervals.iter().enumerate() {
                assert_ne!(bytes, 0, "{name}");
                assert!(
                    start + bytes <= ambiguous.address
                        || ambiguous.address + ambiguous.length <= start,
                    "{name}: touches ambiguous target"
                );
                for &(other, other_bytes) in &intervals[index + 1..] {
                    assert!(
                        start + bytes <= other || other + other_bytes <= start,
                        "{name}: overlapping cleanup intervals"
                    );
                }
            }
            assert!(record.cleanup.iter().all(Option::is_none), "{name}");
            assert!(record.next.is_none(), "{name}");
        }
    }

    #[test]
    fn writable_alias_zero_length_checks_poison_and_releases_failed_preparation() {
        let memory = GuestMemory::new(0, PAGE_SIZE).unwrap();
        let user = memory.user();
        assert!(user.writable_alias(1, usize::MAX).is_err());
        assert_eq!(memory.entry_gate().test_state().retained_operands, 0);
        assert!(memory.mapping.address_space.try_lock().is_ok());
        assert!(memory.mapping.slice.backing.host_access.try_lock().is_ok());
        let alias = user.writable_alias(u64::MAX, 0).unwrap();
        memory.entry_gate().poison(
            None,
            Error::UnexpectedVcpuExit("alias poison control".to_owned()),
        );
        assert!(alias.finish().is_err());
        assert_eq!(memory.entry_gate().test_state().retained_operands, 0);
        assert!(user.writable_alias(u64::MAX, 0).is_err());
    }

    #[test]
    fn copyout_holds_permission_lock_through_the_backing_write() {
        let memory = GuestMemory::new(0, PAGE_SIZE).unwrap();
        memory.map_user_range(0, PAGE_SIZE as u64, false).unwrap();
        memory.enable_user_access();
        let backing = memory.mapping.slice.backing.host_access.lock().unwrap();
        let worker_memory = memory.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender.send(worker_memory.copy_to_user(0, b"x")).unwrap();
        });

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match memory.mapping.address_space.try_lock() {
                Err(std::sync::TryLockError::WouldBlock) => break,
                Err(std::sync::TryLockError::Poisoned(error)) => {
                    panic!("address-space lock poisoned: {error}")
                }
                Ok(guard) => drop(guard),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "copyout released permission state before waiting on the backing"
            );
            std::thread::yield_now();
        }
        assert!(matches!(
            receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        drop(backing);
        receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn prctl_copyout_keeps_privileged_write_and_scalar_contracts() {
        let mut memory = GuestMemory::new(0, PAGE_SIZE * 2).unwrap();
        memory.write_raw(0, &[0xa5; PAGE_SIZE * 2]).unwrap();
        memory.map_user_range(0, PAGE_SIZE as u64, false).unwrap();
        memory
            .map_user_permissions(PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
            .unwrap();
        memory.enable_user_access();
        assert!(memory.put_user_i32(PAGE_SIZE as u64 - 2, 0).is_err());
        let mut expected = [0xa5; PAGE_SIZE * 2];
        let mut actual = [0; PAGE_SIZE * 2];
        memory.read_raw(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(
            memory
                .copy_to_user(PAGE_SIZE as u64 - 8, b"ABCDEFGHIJKLMNO\0")
                .is_err()
        );
        expected[PAGE_SIZE - 8..PAGE_SIZE].copy_from_slice(b"ABCDEFGH");
        memory.read_raw(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(memory.copy_to_user(PAGE_SIZE as u64, b"denied").is_err());
        memory.write(PAGE_SIZE as u64, b"loader").unwrap();
        expected[PAGE_SIZE..PAGE_SIZE + 6].copy_from_slice(b"loader");
        memory.write_raw(PAGE_SIZE as u64 + 8, b"raw").unwrap();
        expected[PAGE_SIZE + 8..PAGE_SIZE + 11].copy_from_slice(b"raw");
        memory.read_raw(0, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn prctl_copyout_permissions_survive_snapshot_fallback_and_shared_clone() {
        let memory = GuestMemory::new(0, PAGE_SIZE * 3).unwrap();
        memory.write_raw(0, &[0xa5; PAGE_SIZE * 3]).unwrap();
        memory
            .map_user_permissions(0, PAGE_SIZE as u64, true, false)
            .unwrap();
        memory
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, false)
            .unwrap();
        memory
            .map_user_range((PAGE_SIZE * 2) as u64, PAGE_SIZE as u64, true)
            .unwrap();
        memory.enable_user_access();
        for snapshot in [
            memory.snapshot().unwrap(),
            memory
                .snapshot_with_sparse_copy(|_, _, _| {
                    Err(io::Error::from_raw_os_error(libc::ENOSYS))
                })
                .unwrap(),
        ] {
            assert!(snapshot.put_user_i32(0, 0).is_err());
            assert!(snapshot.put_user_i32((PAGE_SIZE * 2) as u64, 0).is_err());
            snapshot.put_user_i32(PAGE_SIZE as u64, 0).unwrap();
            snapshot.map_user_range(0, PAGE_SIZE as u64, false).unwrap();
            snapshot.put_user_i32(0, 0).unwrap();
            assert!(memory.put_user_i32(0, 0).is_err());
            let mut expected = [0xa5; PAGE_SIZE * 3];
            expected[..4].fill(0);
            expected[PAGE_SIZE..PAGE_SIZE + 4].fill(0);
            let mut actual = [0; PAGE_SIZE * 3];
            snapshot.read_raw(0, &mut actual).unwrap();
            assert_eq!(actual, expected);
            memory.read_raw(0, &mut actual).unwrap();
            assert_eq!(actual, [0xa5; PAGE_SIZE * 3]);
        }
        let shared = memory.clone();
        shared.map_user_range(0, PAGE_SIZE as u64, false).unwrap();
        memory.put_user_i32(0, 0).unwrap();
        shared
            .map_user_permissions(0, PAGE_SIZE as u64, true, false)
            .unwrap();
        assert!(memory.put_user_i32(0, 0).is_err());
    }

    #[test]
    fn prctl_copyout_permissions_follow_remap_unmap_and_reset() {
        let memory = GuestMemory::new(0, PAGE_SIZE * 8).unwrap();
        memory.map_user_range(0, PAGE_SIZE as u64, false).unwrap();
        memory
            .map_user_permissions(PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
            .unwrap();
        memory.enable_user_access();
        memory
            .remap_user_range(
                0,
                (PAGE_SIZE * 2) as u64,
                (PAGE_SIZE * 3) as u64,
                (PAGE_SIZE * 3) as u64,
            )
            .unwrap();
        assert!(memory.put_user_i32(0, 0).is_err());
        memory.put_user_i32((PAGE_SIZE * 3) as u64, 0).unwrap();
        assert!(memory.put_user_i32((PAGE_SIZE * 4) as u64, 0).is_err());
        assert!(memory.put_user_i32((PAGE_SIZE * 5) as u64, 0).is_err());
        memory
            .unmap_user_range((PAGE_SIZE * 3) as u64, PAGE_SIZE as u64)
            .unwrap();
        assert!(memory.put_user_i32((PAGE_SIZE * 3) as u64, 0).is_err());
        memory
            .map_user_range((PAGE_SIZE * 4) as u64, PAGE_SIZE as u64, false)
            .unwrap();
        memory.put_user_i32((PAGE_SIZE * 4) as u64, 0).unwrap();
        memory.clear_user_access();
        memory
            .map_user_permissions(0, PAGE_SIZE as u64, true, false)
            .unwrap();
        memory
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, false)
            .unwrap();
        memory.enable_user_access();
        assert!(memory.put_user_i32((PAGE_SIZE * 4) as u64, 0).is_err());
        assert!(memory.put_user_i32(0, 0).is_err());
        memory.put_user_i32(PAGE_SIZE as u64, 0).unwrap();
    }

    #[test]
    fn tracked_read_only_pages_reject_backend_copyout_but_remain_readable() {
        let mut memory = GuestMemory::new(0, PAGE_SIZE * 2).unwrap();
        memory
            .map_user_range(PAGE_SIZE as u64, PAGE_SIZE as u64, false)
            .unwrap();
        memory.enable_user_access();
        memory.write(PAGE_SIZE as u64, b"before").unwrap();
        memory
            .map_user_permissions(PAGE_SIZE as u64, PAGE_SIZE as u64, true, false)
            .unwrap();

        let mut bytes = [0; 6];
        memory.read(PAGE_SIZE as u64, &mut bytes).unwrap();
        assert_eq!(&bytes, b"before");
        assert_eq!(
            memory
                .user_accessible_prefix(PAGE_SIZE as u64, PAGE_SIZE)
                .unwrap(),
            PAGE_SIZE,
        );
        assert_eq!(
            memory
                .user_writable_prefix(PAGE_SIZE as u64, PAGE_SIZE)
                .unwrap(),
            0
        );
        assert!(matches!(
            memory.copy_to_user(PAGE_SIZE as u64, b"after!"),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
        assert!(matches!(
            memory.copy_to_user(PAGE_SIZE as u64, &[0]),
            Err(Error::GuestMemoryAccessDenied { .. })
        ));
        memory
            .map_user_permissions(PAGE_SIZE as u64, PAGE_SIZE as u64, true, true)
            .unwrap();
        memory.copy_to_user(PAGE_SIZE as u64, b"after!").unwrap();
    }

    #[test]
    fn finds_first_unmapped_user_range() {
        let memory = GuestMemory::new(0x1000, PAGE_SIZE * 8).unwrap();
        memory.map_user_range(0x2000, 0x2000, false).unwrap();
        memory.map_user_range(0x5000, 0x1000, true).unwrap();

        assert_eq!(
            memory.find_unmapped_user_range(0x1000, 0x9000, 0x1000),
            Some(0x1000)
        );
        assert_eq!(
            memory.find_unmapped_user_range(0x2000, 0x9000, 0x2000),
            Some(0x6000)
        );
        assert_eq!(
            memory.find_unmapped_user_range(0x2000, 0x7000, 0x2000),
            None
        );
        assert_eq!(
            memory.find_unmapped_user_range(0x1001, 0x9000, 0x1000),
            None
        );
    }
}
