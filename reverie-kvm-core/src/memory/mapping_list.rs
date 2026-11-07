/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! What a provider needs to list an address space's mappings as Linux lists
//! them (`/proc/<pid>/maps`): the identity of what each mapping maps, which
//! the provider names ([`MappingIdentity`], [`GuestMemory::describe_mapping`]),
//! and the address space's mapped pages in runs of equal state
//! ([`GuestMemory::user_mapping_runs`]).
//!
//! The memory holds no mapping list: it keeps pages. Linux keeps one
//! `vm_area_struct` per mapping and splits or merges them as calls change
//! them; two adjacent mappings merge when their flags, file, file offsets and
//! name agree (`is_mergeable_vma` in `mm/vma.c`). The pages here hold the
//! state those rules read (the declared protection and provider flags, the
//! file offset of each page, whether it is shared), and each page keeps the
//! incarnation of the mapping that placed it, which a move keeps, an unmap
//! removes and a fork copies. The identity a provider gives a mapping is kept
//! by that incarnation, so it follows the mapping's pages wherever they go
//! with no bookkeeping of its own: a move, a split by a protection change, a
//! partial unmap, a fork's copy and a new image's reset all act on the pages.
//! The runs report every difference; which runs Linux would print as one
//! mapping is the provider's to decide.

use std::any::Any;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::AddressSpaceState;
use super::DeclaredMapping;
use super::GuestMemory;
use super::PAGE_SIZE;
use super::RegionKind;
use super::UserPageState;

/// What a mapping maps, as its provider names it: any value the provider
/// gives a new mapping ([`GuestMemory::describe_mapping`]) and reads back
/// with its pages ([`UserMappingRun::identity`]). Two identities are the same
/// one only when one is a clone of the other ([`MappingIdentity::same`]).
#[derive(Clone)]
pub struct MappingIdentity(Arc<dyn Any + Send + Sync>);

impl MappingIdentity {
    /// An identity holding `value`.
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Arc::new(value))
    }

    /// The value, if it is a `T`.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }

    /// Whether `self` and `other` are clones of one identity.
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for MappingIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MappingIdentity({:p})", Arc::as_ptr(&self.0))
    }
}

/// A run of mapped user pages, adjacent and in address order, that agree in
/// every field below, file offsets counting as agreeing when each page's
/// continues the one before it.
#[derive(Clone, Debug)]
pub struct UserMappingRun {
    /// The run's first user address.
    pub start: u64,
    /// The user address just past the run.
    pub end: u64,
    /// The mapping declared for the pages, if one was ([`DeclaredMapping`]).
    pub declared: Option<DeclaredMapping>,
    /// Whether the guest may reach the pages, for pages with no declared
    /// mapping (a guard does not count: it splits no mapping).
    pub accessible: bool,
    /// Whether the guest may write the pages, as `accessible`.
    pub writable: bool,
    /// What the pages are reserved for, if anything.
    pub reservation: Option<RegionKind>,
    /// The file offset of the run's first byte, where the pages map a file.
    pub file_offset: Option<u64>,
    /// Whether the pages are `MAP_SHARED | MAP_ANONYMOUS` memory.
    pub shared_anonymous: bool,
    /// Whether the pages are a shared view of an ordinary file.
    pub shared_file: bool,
    /// The identity the provider gave the mapping that placed the pages, if
    /// it gave one ([`GuestMemory::describe_mapping`]).
    pub identity: Option<MappingIdentity>,
}

impl UserMappingRun {
    /// Whether `next`, a page at this run's end, continues the run.
    fn continued_by(&self, next: &UserMappingRun) -> bool {
        self.end == next.start
            && self.declared == next.declared
            && self.accessible == next.accessible
            && self.writable == next.writable
            && self.reservation == next.reservation
            && self.shared_anonymous == next.shared_anonymous
            && self.shared_file == next.shared_file
            && match (self.file_offset, next.file_offset) {
                (None, None) => true,
                (Some(offset), Some(next_offset)) => {
                    offset.checked_add(self.end - self.start) == Some(next_offset)
                }
                _ => false,
            }
            && match (&self.identity, &next.identity) {
                (None, None) => true,
                (Some(identity), Some(next_identity)) => identity.same(next_identity),
                _ => false,
            }
    }
}

/// An address space's mapped user pages ([`GuestMemory::user_mapping_runs`]).
#[derive(Clone, Debug)]
pub struct UserMappingRuns {
    /// The runs, in address order.
    pub runs: Vec<UserMappingRun>,
}

impl AddressSpaceState {
    /// Keeps `identity` as that of each mapping incarnation in `incarnations`,
    /// and forgets, now and then, the identities of incarnations no page has
    /// any more, so that the identities kept stay proportional to the
    /// mappings.
    fn keep_identity(&mut self, incarnations: BTreeSet<u64>, identity: MappingIdentity) {
        let identities = Arc::make_mut(&mut self.mapping_identities);
        for incarnation in incarnations {
            identities.insert(incarnation, identity.clone());
        }
        if identities.len() > 2 * self.live_identities.max(32) {
            let live: BTreeSet<u64> = self.mapping_incarnations.values().copied().collect();
            let identities = Arc::make_mut(&mut self.mapping_identities);
            identities.retain(|incarnation, _| live.contains(incarnation));
            self.live_identities = identities.len();
        }
    }

    /// The identity of the mapping that placed physical page `page`, if its
    /// provider gave one.
    pub(super) fn identity_of(&self, page: u64) -> Option<MappingIdentity> {
        let incarnation = self.mapping_incarnations.get(&page)?;
        self.mapping_identities.get(incarnation).cloned()
    }

    /// Gives the pages a remap grew a mapping by (incarnation `grown`) the
    /// identity of the mapping they grew (that of physical page `last`, its
    /// last page before the remap), as Linux grows the one mapping.
    pub(super) fn grow_identity(&mut self, last: Option<MappingIdentity>, grown: Option<u64>) {
        if let (Some(identity), Some(grown)) = (last, grown) {
            self.keep_identity(BTreeSet::from([grown]), identity);
        }
    }
}

impl GuestMemory {
    /// Describes the mapping just placed at physical `[guest_address,
    /// guest_address + length)`, for its provider's list of mappings
    /// ([`GuestMemory::user_mapping_runs`]): with `prot`, it declares the
    /// pages' protection (`PROT_READ`, `PROT_WRITE` and `PROT_EXEC` bits) as
    /// [`GuestMemory::map_user_protection`] does, keeping any guard and any
    /// provider flags, for a mapping the path that placed it gave access
    /// alone; it sets the provider flags `flags` on each declared page
    /// ([`DeclaredMapping::flags`]); with `identity`, it gives the mapping of each page that
    /// identity, which then follows the mapping's pages: a move, a fork's copy
    /// and a protection change keep it, an unmap and a new mapping over a page
    /// end it there. Unmapped pages are skipped. Nothing about the pages'
    /// access changes but what `prot` gives them.
    pub fn describe_mapping(
        &self,
        guest_address: u64,
        length: u64,
        prot: Option<u8>,
        flags: u16,
        identity: Option<MappingIdentity>,
    ) {
        let Ok(Some((first_page, last_page))) = self.checked_page_range(guest_address, length)
        else {
            return;
        };
        let mut access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let mut incarnations = BTreeSet::new();
        for page in first_page..=last_page {
            let Some(old) = access.pages.get(&page).copied() else {
                continue;
            };
            let declared = match (prot, old.declared()) {
                (Some(prot), declared) => Some(DeclaredMapping {
                    prot,
                    ..declared.unwrap_or_default()
                }),
                (None, declared) => declared,
            };
            if let Some(declared) = declared {
                let declared = DeclaredMapping {
                    flags: declared.flags | flags,
                    ..declared
                };
                let new = old.keeping_guard(UserPageState::of(declared));
                if new != old {
                    access.pages.insert(page, new);
                }
            }
            if let Some(incarnation) = access.mapping_incarnations.get(&page) {
                incarnations.insert(*incarnation);
            }
        }
        if let Some(identity) = identity {
            access.keep_identity(incarnations, identity);
        }
    }

    /// Replaces the declared mapping of each declared page of the user range
    /// `[user_address, user_address + length)` outside the stack window
    /// ([`GuestMemory::flag_user_range`] edits the window's) with
    /// `edit(its declared mapping, whether the page is shared)`, keeping its
    /// guard. The edit must keep the protection. An undeclared page stays so,
    /// and an unmapped one is skipped.
    pub fn edit_user_declared(
        &self,
        user_address: u64,
        length: u64,
        edit: impl Fn(DeclaredMapping, bool) -> DeclaredMapping,
    ) {
        let page_size = PAGE_SIZE as u64;
        let start = user_address & !(page_size - 1);
        let Some(end) = user_address
            .checked_add(length)
            .and_then(|end| end.checked_add(page_size - 1))
            .map(|end| end & !(page_size - 1))
        else {
            return;
        };
        let mut access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let (pages, _) = access.mapped_pages_in(start, end - start);
        for page in pages {
            if access.reservations.get(&page) == Some(&RegionKind::Stack) {
                continue;
            }
            let Some(old) = access.pages.get(&page).copied() else {
                continue;
            };
            let Some(declared) = old.declared() else {
                continue;
            };
            let shared = access.shared_anonymous_pages.contains(&page)
                || access.backing_pages.get(&page).is_some_and(|installed| {
                    matches!(
                        installed._slice.backing.kind,
                        super::BackingKind::OrdinaryFile { .. }
                    )
                });
            let new = old.keeping_guard(UserPageState::of(edit(declared, shared)));
            if new != old {
                access.pages.insert(page, new);
            }
        }
    }

    /// The identities the provider gave the mappings of the pages of physical
    /// `[guest_address, guest_address + length)`, each once.
    pub fn mapping_identities_in(&self, guest_address: u64, length: u64) -> Vec<MappingIdentity> {
        let Ok(Some((first_page, last_page))) = self.checked_page_range(guest_address, length)
        else {
            return Vec::new();
        };
        let access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let mut identities: Vec<MappingIdentity> = Vec::new();
        for (page, _) in access.mapping_incarnations.range(first_page..=last_page) {
            if let Some(identity) = access.identity_of(*page)
                && !identities.iter().any(|known| known.same(&identity))
            {
                identities.push(identity);
            }
        }
        identities
    }

    /// The address space's mapped user pages, in runs of equal state
    /// ([`UserMappingRun`]), leaving out the pages this backend reserves for
    /// itself (bootstrap, program headers and Tool scratch), which the guest
    /// did not map. Read under one acquisition of the address space's lock,
    /// which every change to a page's state takes too, so the answer is never
    /// part of a change.
    pub fn user_mapping_runs(&self) -> UserMappingRuns {
        let access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let pages: Vec<UserMappingRun> = access
            .pages
            .iter()
            .filter_map(|(&page, state)| access.page_run(page, *state))
            .collect();
        drop(access);
        UserMappingRuns::of_pages(pages)
    }

    /// The mapped user pages of the user range
    /// `[user_address, user_address + length)` in runs of equal state, as
    /// [`GuestMemory::user_mapping_runs`] gives them for the whole address
    /// space but cut at the range's ends: a run that continues past an end
    /// is cut there. The work is proportional to the smaller of the range's
    /// pages and the address space's.
    pub fn user_mapping_runs_in(&self, user_address: u64, length: u64) -> UserMappingRuns {
        let page_size = PAGE_SIZE as u64;
        let start = user_address & !(page_size - 1);
        let end = user_address
            .saturating_add(length)
            .saturating_add(page_size - 1)
            & !(page_size - 1);
        if end <= start {
            return UserMappingRuns { runs: Vec::new() };
        }
        let access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let (physical, _) = access.mapped_pages_in(start, end - start);
        let pages: Vec<UserMappingRun> = physical
            .into_iter()
            .filter_map(|page| access.page_run(page, *access.pages.get(&page)?))
            .collect();
        drop(access);
        UserMappingRuns::of_pages(pages)
    }

    /// How many pages of the address space carry the provider flags in
    /// `mask` ([`DeclaredMapping::flags`]), counted once per bit: zero
    /// exactly when no page carries any bit of `mask`, and for one bit the
    /// number of pages that carry it. Kept as the pages change, so the answer
    /// costs no walk.
    pub fn flagged_pages(&self, mask: u16) -> usize {
        self.mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned")
            .pages
            .flagged_pages(mask)
    }
}

impl AddressSpaceState {
    /// The one-page run of physical page `page`, in state `state`, for the
    /// list of mappings; `None` for a page this backend reserves for itself
    /// or one with no user address.
    fn page_run(&self, page: u64, state: UserPageState) -> Option<UserMappingRun> {
        let page_size = PAGE_SIZE as u64;
        let reservation = self.reservations.get(&page).copied();
        if reservation.is_some_and(RegionKind::permanent) {
            return None;
        }
        let start = self.physical_to_user(page * page_size)?;
        let (accessible, writable) = match state.unguarded() {
            UserPageState::Accessible { writable, .. } => (true, writable),
            _ => (false, false),
        };
        Some(UserMappingRun {
            start,
            end: start + page_size,
            declared: state.declared(),
            accessible,
            writable,
            reservation,
            file_offset: self.file_pages.get(&page).copied(),
            shared_anonymous: self.shared_anonymous_pages.contains(&page),
            shared_file: self.backing_pages.get(&page).is_some_and(|installed| {
                matches!(
                    installed._slice.backing.kind,
                    super::BackingKind::OrdinaryFile { .. }
                )
            }),
            identity: self.identity_of(page),
        })
    }
}

impl UserMappingRuns {
    /// The runs of the one-page runs `pages`, in any order.
    fn of_pages(mut pages: Vec<UserMappingRun>) -> Self {
        pages.sort_by_key(|page| page.start);
        let mut runs: Vec<UserMappingRun> = Vec::new();
        for page in pages {
            match runs.last_mut() {
                Some(run) if run.continued_by(&page) => run.end = page.end,
                _ => runs.push(page),
            }
        }
        Self { runs }
    }
}

/// A handle on an address space that does not keep it alive
/// ([`GuestMemory::downgrade`]), for a provider that answers for another
/// process's mappings while that process's own threads hold its memory.
#[derive(Clone, Debug)]
pub struct WeakGuestMemory(std::sync::Weak<super::Mapping>);

impl WeakGuestMemory {
    /// The address space, while something else still holds it: a memory with
    /// no failure context, operation origin or test hooks, for reading its
    /// state.
    pub fn upgrade(&self) -> Option<GuestMemory> {
        Some(GuestMemory::observing(self.0.upgrade()?))
    }
}

impl GuestMemory {
    /// A handle on this address space that does not keep it alive.
    pub fn downgrade(&self) -> WeakGuestMemory {
        WeakGuestMemory(Arc::downgrade(&self.mapping))
    }

    /// Whether `self` and `other` are handles on one address space.
    pub fn same_address_space(&self, other: &GuestMemory) -> bool {
        Arc::ptr_eq(&self.mapping, &other.mapping)
    }

    fn observing(mapping: Arc<super::Mapping>) -> Self {
        Self {
            mapping,
            failure_context: None,
            operation_origin: None,
            #[cfg(any(test, feature = "test-support"))]
            after_vector_copy: None,
            #[cfg(any(test, feature = "test-support"))]
            test_vector_copy_observer: None,
            #[cfg(any(test, feature = "test-support"))]
            test_syscall_dispatch_observer: None,
            #[cfg(any(test, feature = "test-support"))]
            test_backing_contention: None,
            #[cfg(any(test, feature = "test-support"))]
            test_user_copy_failure: None,
            #[cfg(any(test, feature = "test-support"))]
            test_user_copy_backing_wait: None,
            #[cfg(any(test, feature = "test-support"))]
            test_between_read_and_write: None,
            #[cfg(any(test, feature = "test-support"))]
            test_shared_map: None,
            #[cfg(any(test, feature = "test-support"))]
            test_shared_sync: None,
        }
    }
}
