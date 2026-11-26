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
use std::collections::BTreeMap;
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

/// The stack window's mapped pages as runs of the index
/// ([`MappingRuns::stack_window`]), each cut to the window.
#[derive(Clone, Debug)]
pub struct StackWindowRuns {
    /// The window's first user address.
    pub start: u64,
    /// The user address just past the window.
    pub end: u64,
    /// The runs, in address order.
    pub runs: Vec<UserMappingRun>,
    /// Whether the runs hold every mapped page of the window: false when a
    /// mapped page of it belongs to no run (a page this backend reserves for
    /// itself, which no run includes).
    pub holds_every_page: bool,
}

/// The identity of the mapping that placed physical page `page`, given the
/// pages' mapping incarnations and the incarnations' identities.
fn identity_in(
    incarnations: &BTreeMap<u64, u64>,
    identities: &BTreeMap<u64, MappingIdentity>,
    page: u64,
) -> Option<MappingIdentity> {
    identities.get(incarnations.get(&page)?).cloned()
}

impl AddressSpaceState {
    /// Keeps `identity` as that of each mapping incarnation in `incarnations`,
    /// and forgets, now and then, the identities of incarnations no page has
    /// any more, so that the identities kept stay proportional to the
    /// mappings.
    ///
    /// Every page whose identity this changes lies in physical pages
    /// `first..=last` (the pages the incarnations were found on, which a new
    /// mapping's incarnation never leaves), which the write names for the
    /// index of mapping runs. The identity map's writer checks that in a test
    /// build ([`page_maps::IncarnationKeyed::insert_naming_pages`]); in a
    /// product build it is this argument. Forgetting an identity no page has
    /// changes no page.
    ///
    /// [`page_maps::IncarnationKeyed::insert_naming_pages`]: super::page_maps::IncarnationKeyed::insert_naming_pages
    fn keep_identity(
        &mut self,
        first: u64,
        last: u64,
        incarnations: BTreeSet<u64>,
        identity: MappingIdentity,
    ) {
        self.mapping_identities.insert_naming_pages(
            first,
            last,
            &incarnations,
            identity,
            &self.mapping_incarnations,
        );
        if self.mapping_identities.len() > 2 * self.live_identities.max(32) {
            self.live_identities = self
                .mapping_identities
                .forget_unplaced(&self.mapping_incarnations);
        }
    }

    /// The identity of the mapping that placed physical page `page`, if its
    /// provider gave one.
    pub(super) fn identity_of(&self, page: u64) -> Option<MappingIdentity> {
        identity_in(&self.mapping_incarnations, &self.mapping_identities, page)
    }

    /// Gives the pages a remap grew a mapping by (incarnation `grown`) the
    /// identity of the mapping they grew (that of physical page `last`, its
    /// last page before the remap), as Linux grows the one mapping.
    /// The grown pages lie in physical pages `first..=last`, the remap's new
    /// range.
    pub(super) fn grow_identity(
        &mut self,
        first: u64,
        last_page: u64,
        last: Option<MappingIdentity>,
        grown: Option<u64>,
    ) {
        if let (Some(identity), Some(grown)) = (last, grown) {
            self.keep_identity(first, last_page, BTreeSet::from([grown]), identity);
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
    ///
    /// The range must hold every page of the mappings it describes with an
    /// `identity` (a range just mapped, whose incarnations are new): the
    /// index of mapping runs settles the pages of the range, so a page of
    /// one of those mappings outside it would keep an old run boundary. A
    /// test build checks it.
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
            access.keep_identity(first_page, last_page, incarnations, identity);
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

    /// Reads the address space's mapping runs with `read`, under one
    /// acquisition of the address space's lock, which every change to a
    /// page's state takes too, so every answer `read` gets is of one state of
    /// the address space and never part of a change. The index of runs is
    /// settled first. `read` must not use this memory otherwise: the lock is
    /// held while it runs.
    pub fn read_mapping_runs<T>(&self, read: impl FnOnce(&MappingRuns<'_>) -> T) -> T {
        let mut access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let runs = access.settle_runs();
        read(&runs)
    }

    /// The address space's mapped user pages, in runs of equal state
    /// ([`UserMappingRun`]), leaving out the pages this backend reserves for
    /// itself (bootstrap, program headers and Tool scratch), which the guest
    /// did not map. Read under one acquisition of the address space's lock
    /// ([`GuestMemory::read_mapping_runs`]), from the index of runs: one
    /// page's facts per run, and no page walk.
    pub fn user_mapping_runs(&self) -> UserMappingRuns {
        UserMappingRuns {
            runs: self.read_mapping_runs(|runs| runs.view.all_runs()),
        }
    }

    /// The mapped user pages of the user range
    /// `[user_address, user_address + length)` in runs of equal state, as
    /// [`GuestMemory::user_mapping_runs`] gives them for the whole address
    /// space but cut at the range's ends: a run that continues past an end
    /// is cut there. Read from the index of runs: the work is proportional
    /// to the runs the range meets, plus a search.
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
        let (first, past) = (start / page_size, end / page_size);
        UserMappingRuns {
            runs: self.read_mapping_runs(|runs| runs.view.runs_in(first, past)),
        }
    }

    /// What the reads of the mapping runs did since the last call
    /// ([`QueryLog`]), for a test that holds a query to the runs its range
    /// needs and to no page walk.
    #[cfg(any(test, feature = "test-support"))]
    pub fn take_query_log(&self) -> QueryLog {
        let access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        let mut log = access.query_log.take();
        log.index_visits = runs::take_visits(&access);
        log
    }

    /// The address space's runs rebuilt from every page, as the list of
    /// mappings read them before the index (one page at a time, then
    /// merged): the oracle the index is checked against.
    #[cfg(any(test, feature = "test-support"))]
    pub fn user_mapping_runs_by_pages(&self) -> UserMappingRuns {
        let access = self
            .mapping
            .address_space
            .lock()
            .expect("guest memory access map lock poisoned");
        runs::runs_by_pages(&access)
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

/// An address space's mapping runs, read under one acquisition of its lock
/// ([`GuestMemory::read_mapping_runs`]). Every read is of the index of runs
/// and of the page facts behind its runs, through the module's counted
/// reads (`runs::RunView`), so a query here walks no page, and a test build
/// counts each index entry looked at and each page's facts read (the memory's
/// `take_query_log`).
pub struct MappingRuns<'a> {
    view: runs::RunView<'a>,
}

impl MappingRuns<'_> {
    /// Every whole run (not cut at the range's ends) that meets the user
    /// range `[user_address, user_address + length)`, in address order: a
    /// search plus those runs.
    pub fn meeting(&self, user_address: u64, length: u64) -> Vec<UserMappingRun> {
        let page_size = PAGE_SIZE as u64;
        let first = user_address / page_size;
        let past = user_address
            .saturating_add(length)
            .saturating_add(page_size - 1)
            / page_size;
        if past <= first {
            return Vec::new();
        }
        self.view.runs_meeting(first, past)
    }

    /// The whole run just before user address `user_address`: the last run
    /// that ends at or below it.
    pub fn before(&self, user_address: u64) -> Option<UserMappingRun> {
        self.view.run_before(user_address / PAGE_SIZE as u64)
    }

    /// The whole run just after user address `user_address`: the first run
    /// that starts at or above it.
    pub fn after(&self, user_address: u64) -> Option<UserMappingRun> {
        self.view.run_after(user_address.div_ceil(PAGE_SIZE as u64))
    }

    /// The stack window's mapped pages as runs, each cut to the window, and
    /// whether they hold every mapped page of it ([`StackWindowRuns`]):
    /// `None` when nothing watches the window, and when its record is not
    /// certain, as [`GuestMemory::user_stack_window_pages`] answers. Read
    /// from the index and from a count of the window's mapped pages that the
    /// page map keeps, so the work is the window's runs, not its pages.
    pub fn stack_window(&self) -> Option<StackWindowRuns> {
        self.view.stack_window()
    }
}

impl UserMappingRuns {
    /// The runs of the one-page runs `pages`, in any order: how the list of
    /// mappings merged pages before the index, kept for its oracle.
    #[cfg(any(test, feature = "test-support"))]
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

/// What a query of the mapping runs read, as the user range it covers, for a
/// test that holds a query to the runs its range needs
/// ([`GuestMemory::take_query_log`]).
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingRead {
    /// One page's facts, read on their own.
    Page(u64),
    /// One run of the index, `[start, end)`.
    Run(u64, u64),
}

/// What the reads of an address space's mapping runs did
/// ([`GuestMemory::take_query_log`]), each counted where it happens: in the
/// one read of the index's entries and the one read of a page's facts
/// (`runs::index::RunIndex::entries`, `runs::inputs::RunInputs::page_run`),
/// which every query and every settle goes through, and in the one page
/// walk the memory still makes (`GuestMemory::user_stack_window_pages`).
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct QueryLog {
    /// The runs whose facts the queries read, in order, the first
    /// [`QueryLog::READS_KEPT`] of them.
    pub reads: Vec<MappingRead>,
    /// The reads past [`QueryLog::READS_KEPT`], left out of `reads`, so a
    /// log no test takes stays bounded.
    pub reads_dropped: u64,
    /// The index entries the queries looked at.
    pub index_visits: u64,
    /// The pages' facts the queries read.
    pub page_facts: u64,
    /// The pages' facts read to settle the index after writes: a write's
    /// work, proportional to the pages it changed.
    pub settle_pages: u64,
}

#[cfg(any(test, feature = "test-support"))]
impl QueryLog {
    /// How many reads a log keeps before it only counts them.
    pub const READS_KEPT: usize = 1 << 16;

    fn record(&mut self, read: MappingRead) {
        if self.reads.len() < Self::READS_KEPT {
            self.reads.push(read);
        } else {
            self.reads_dropped += 1;
        }
    }
}

impl AddressSpaceState {
    /// Records that the user layout (windows, identity end) moved: the next
    /// settle derives every run again.
    pub(super) fn note_layout_moved(&mut self) {
        runs::note_layout_moved(self);
    }

    /// Whether a page map noted a change, or the layout moved, since the
    /// index of runs was last settled: cheap, read at every release of the
    /// address space's lock.
    pub(super) fn runs_unsettled(&self) -> bool {
        runs::unsettled(self)
    }

    /// Brings the index of mapping runs up to date with the page maps
    /// (`runs::settle`) and gives the reader of the settled index: the only
    /// way to get one, so no reader is ever over an index that is not
    /// settled. The reader borrows the state, so no write through this lock
    /// can change it while the reader is alive; a vfork partner's copy can
    /// still make the stack window's shared record lose certainty, which only
    /// makes the window's answer more conservative. A caller that only
    /// settles drops the reader.
    pub(super) fn settle_runs(&mut self) -> MappingRuns<'_> {
        MappingRuns {
            view: runs::settle(self),
        }
    }

    /// In a test build, at a release of the address space's lock that noted
    /// nothing: the layout the index records is the current one
    /// (`runs::check_layout_noted`).
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn check_layout_noted(&self) {
        runs::check_layout_noted(self);
    }
}

/// The index of mapping runs, and the one view of the address space it is
/// derived from, apart from the rest of the address space's state. Outside
/// this module nothing can read the index's entries or the derivation's
/// inputs: the queries read through [`runs::RunView`], whose reads are the
/// counted ones of its two inner modules and whose one constructor outside
/// this module is the settle (`runs::settle`), and the settle and the test
/// builds' checks are this module's own functions.
mod runs {
    pub(in super::super) use index::RunIndex;
    use inputs::RunInputs;
    use inputs::RunLayout;
    use inputs::Window;
    use inputs::WindowRuns;

    use super::super::AddressSpaceState;
    use super::super::PAGE_SIZE;
    use super::StackWindowRuns;
    use super::UserMappingRun;
    #[cfg(any(test, feature = "test-support"))]
    use super::UserMappingRuns;

    /// The derivation's inputs, readable only through methods that count
    /// every page fact they read.
    mod inputs {
        use std::collections::BTreeMap;
        use std::collections::BTreeSet;

        use super::super::super::AddressSpaceState;
        use super::super::super::BackingKind;
        use super::super::super::InstalledBackingPage;
        use super::super::super::PAGE_SIZE;
        use super::super::super::RegionKind;
        use super::super::super::UserPageState;
        use super::super::super::UserWindow;
        use super::super::super::page_maps::IncarnationKeyed;
        use super::super::super::page_maps::PageKeyed;
        use super::super::super::page_maps::UserPages;
        use super::super::super::page_maps::Versioned;
        use super::super::MappingIdentity;
        #[cfg(any(test, feature = "test-support"))]
        use super::super::MappingRead;
        use super::super::UserMappingRun;
        #[cfg(any(test, feature = "test-support"))]
        use super::super::UserMappingRuns;

        /// What places physical pages at user addresses: the user windows
        /// and the identity user addresses. With the seven page maps of
        /// [`RunInputs`], it is all the index of runs is derived from.
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub(super) struct RunLayout {
            windows: Vec<UserWindow>,
            coverage: (u64, u64),
            identity_limit: u64,
        }

        impl RunLayout {
            /// The current layout of `state`.
            pub(super) fn of(state: &AddressSpaceState) -> Self {
                Self {
                    windows: state.windows.clone(),
                    coverage: (state.coverage.start, state.coverage.end),
                    identity_limit: state.identity_limit(),
                }
            }

            /// The identity user pages, `[first, past)`.
            fn identity_pages(&self) -> (u64, u64) {
                let page_size = PAGE_SIZE as u64;
                (
                    self.coverage.0.div_ceil(page_size),
                    self.identity_limit / page_size,
                )
            }

            /// The user address of physical address `physical`.
            fn physical_to_user(&self, physical: u64) -> Option<u64> {
                super::super::super::physical_to_user_in(
                    &self.windows,
                    self.coverage.0,
                    self.identity_limit,
                    physical,
                )
            }

            /// The stack window, once established.
            pub(super) fn stack_window(&self) -> Option<UserWindow> {
                super::super::super::stack_window_in(&self.windows)
            }

            /// The user page ranges, inclusive, of physical pages
            /// `first..=last`: the identity part and each window's part.
            pub(super) fn user_pages_of_physical(&self, first: u64, last: u64) -> Vec<(u64, u64)> {
                let page_size = PAGE_SIZE as u64;
                let mut user = Vec::new();
                let identity = self.identity_pages();
                if first < identity.1 && last >= identity.0 {
                    user.push((first.max(identity.0), last.min(identity.1 - 1)));
                }
                for window in &self.windows {
                    let physical = (
                        window.physical_start / page_size,
                        window.physical_end / page_size,
                    );
                    if first < physical.1 && last >= physical.0 {
                        let (from, to) = (first.max(physical.0), last.min(physical.1 - 1));
                        let shift = |page: u64| page - physical.0 + window.user_start / page_size;
                        user.push((shift(from), shift(to)));
                    }
                }
                // An empty part (a window or identity range of no page) has
                // no page.
                user.retain(|&(from, to)| from <= to);
                user
            }

            /// The parts of user pages `first..=last` the identity range and
            /// each window place, each as `(first user page, last user page,
            /// physical page of the first)`.
            fn user_segments(&self, first: u64, last: u64) -> Vec<(u64, u64, u64)> {
                let page_size = PAGE_SIZE as u64;
                let mut segments = Vec::new();
                let identity = self.identity_pages();
                if first < identity.1 && last >= identity.0 {
                    let from = first.max(identity.0);
                    segments.push((from, last.min(identity.1 - 1), from));
                }
                for window in &self.windows {
                    let user = (window.user_start / page_size, window.user_end / page_size);
                    if first < user.1 && last >= user.0 {
                        let from = first.max(user.0);
                        let physical = window.physical(from * page_size) / page_size;
                        segments.push((from, last.min(user.1 - 1), physical));
                    }
                }
                // An empty part (a window or identity range of no page, such
                // as a one-page stack window's) has no page.
                segments.retain(|&(from, to, _)| from <= to);
                segments
            }
        }

        /// What reads through [`RunInputs`] are for, which decides where a
        /// test build counts the pages' facts they read. Each constructor of
        /// [`RunInputs`] fixes one, so a caller cannot choose to go
        /// uncounted.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Purpose {
            /// A query of the runs: each page fact and run read is the
            /// query's.
            Query,
            /// Settling the index after writes: the write's work.
            Settle,
            /// A test build's check, or its oracle: counted nowhere.
            #[cfg(any(test, feature = "test-support"))]
            Check,
        }

        /// Everything the index of runs is derived from, and nothing else:
        /// the user layout and the seven page maps whose every write names
        /// the pages it changes (`page_maps::DirtyPages`). The fields are
        /// private to this module, so a derivation cannot read another part
        /// of the address space's state, and nothing reads a page map but
        /// through [`RunInputs::page_run`], which counts each page's facts
        /// it reads. An input added later has to come through here, as a
        /// noted page map or as part of [`RunLayout`], which a release that
        /// noted nothing compares (`check_layout_noted`).
        pub(super) struct RunInputs<'a> {
            layout: &'a RunLayout,
            pages: &'a UserPages,
            reservations: &'a Versioned<BTreeMap<u64, RegionKind>>,
            file_pages: &'a Versioned<BTreeMap<u64, u64>>,
            shared_anonymous_pages: &'a Versioned<BTreeSet<u64>>,
            mapping_incarnations: &'a PageKeyed<BTreeMap<u64, u64>>,
            mapping_identities: &'a IncarnationKeyed<MappingIdentity>,
            backing_pages: &'a PageKeyed<BTreeMap<u64, InstalledBackingPage>>,
            #[cfg(any(test, feature = "test-support"))]
            purpose: Purpose,
            #[cfg(any(test, feature = "test-support"))]
            log: &'a std::cell::RefCell<super::super::QueryLog>,
        }

        impl<'a> RunInputs<'a> {
            fn of(state: &'a AddressSpaceState, layout: &'a RunLayout, purpose: Purpose) -> Self {
                #[cfg(not(any(test, feature = "test-support")))]
                let _ = purpose;
                Self {
                    layout,
                    pages: &state.pages,
                    reservations: &state.reservations,
                    file_pages: &state.file_pages,
                    shared_anonymous_pages: &state.shared_anonymous_pages,
                    mapping_incarnations: &state.mapping_incarnations,
                    mapping_identities: &state.mapping_identities,
                    backing_pages: &state.backing_pages,
                    #[cfg(any(test, feature = "test-support"))]
                    purpose,
                    #[cfg(any(test, feature = "test-support"))]
                    log: &state.query_log,
                }
            }

            /// The inputs of `state` under `layout`, for a query: a test
            /// build counts each page's facts and each run read as the
            /// query's.
            pub(super) fn for_query(state: &'a AddressSpaceState, layout: &'a RunLayout) -> Self {
                Self::of(state, layout, Purpose::Query)
            }

            /// The inputs of `state` under `layout`, for settling the index:
            /// a test build counts each page's facts as settle work.
            pub(super) fn for_settle(state: &'a AddressSpaceState, layout: &'a RunLayout) -> Self {
                Self::of(state, layout, Purpose::Settle)
            }

            /// The inputs of `state` under `layout`, for a test build's
            /// check or oracle, counted nowhere.
            #[cfg(any(test, feature = "test-support"))]
            pub(super) fn for_check(state: &'a AddressSpaceState, layout: &'a RunLayout) -> Self {
                Self::of(state, layout, Purpose::Check)
            }

            /// The one-page run of physical page `page`, in state `state`;
            /// `None` for a page this backend reserves for itself or one
            /// with no user address. The one read of a page's facts: a test
            /// build counts it for its purpose.
            fn page_run(&self, page: u64, state: UserPageState) -> Option<UserMappingRun> {
                #[cfg(any(test, feature = "test-support"))]
                match self.purpose {
                    Purpose::Query => self.log.borrow_mut().page_facts += 1,
                    Purpose::Settle => self.log.borrow_mut().settle_pages += 1,
                    Purpose::Check => {}
                }
                let page_size = PAGE_SIZE as u64;
                let reservation = self.reservations.get(&page).copied();
                if reservation.is_some_and(RegionKind::permanent) {
                    return None;
                }
                let start = self.layout.physical_to_user(page * page_size)?;
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
                            BackingKind::OrdinaryFile { .. }
                        )
                    }),
                    identity: super::super::identity_in(
                        self.mapping_incarnations,
                        self.mapping_identities,
                        page,
                    ),
                })
            }

            /// The maximal runs of user pages `first..=last` alone,
            /// `(first, past)` in address order: each mapped page's
            /// one-page run, at the user address its physical page has,
            /// merged with the next while that one continues it. Every page
            /// it reads is read through [`RunInputs::page_run`].
            pub(super) fn derive_runs(&self, first: u64, last: u64) -> Vec<(u64, u64)> {
                let page_size = PAGE_SIZE as u64;
                let mut pages: Vec<(u64, UserMappingRun)> = Vec::new();
                for (user_first, user_last, physical_first) in
                    self.layout.user_segments(first, last)
                {
                    let physical_last = physical_first + (user_last - user_first);
                    for (&physical, &state) in self.pages.range(physical_first..=physical_last) {
                        let user = user_first + (physical - physical_first);
                        if let Some(run) = self.page_run(physical, state)
                            && run.start == user * page_size
                        {
                            pages.push((user, run));
                        }
                    }
                }
                pages.sort_by_key(|(user, _)| *user);
                let mut runs = Vec::new();
                let mut current: Option<(u64, UserMappingRun)> = None;
                for (user, run) in pages {
                    match &mut current {
                        Some((_, merged)) if merged.continued_by(&run) => merged.end = run.end,
                        _ => {
                            if let Some((run_first, merged)) = current.replace((user, run)) {
                                runs.push((run_first, merged.end / page_size));
                            }
                        }
                    }
                }
                if let Some((run_first, merged)) = current {
                    runs.push((run_first, merged.end / page_size));
                }
                runs
            }

            /// The runs of `window`'s user pages alone
            /// ([`RunInputs::derive_runs`]), tied to that window.
            pub(super) fn derive_window(&self, window: Window) -> WindowRuns {
                WindowRuns {
                    runs: self.derive_runs(window.low, window.high),
                    window,
                }
            }

            /// The run of user pages `[at, past)` of an index run, its
            /// fields read at page `at`: one page's facts. A test build
            /// records the run read for a query.
            pub(super) fn index_run(&self, at: u64, past: u64) -> Option<UserMappingRun> {
                let page_size = PAGE_SIZE as u64;
                #[cfg(any(test, feature = "test-support"))]
                if self.purpose == Purpose::Query {
                    self.log
                        .borrow_mut()
                        .record(MappingRead::Run(at * page_size, past * page_size));
                }
                let (_, _, physical) = *self.layout.user_segments(at, at).first()?;
                let state = *self.pages.get(&physical)?;
                let mut run = self.page_run(physical, state)?;
                if run.start != at * page_size {
                    return None;
                }
                run.end = past * page_size;
                Some(run)
            }

            /// The runs merged from every page: the oracle the index is
            /// checked against.
            #[cfg(any(test, feature = "test-support"))]
            pub(super) fn runs_by_pages(&self) -> UserMappingRuns {
                let pages: Vec<UserMappingRun> = self
                    .pages
                    .iter()
                    .filter_map(|(&page, state)| self.page_run(page, *state))
                    .collect();
                UserMappingRuns::of_pages(pages)
            }

            /// The stack window, from the layout.
            pub(super) fn stack_window(&self) -> Option<UserWindow> {
                self.layout.stack_window()
            }

            /// How many of physical pages `first..=last` have a state, when
            /// the page map watches exactly them and its record is certain:
            /// a count the page map keeps, not a page read.
            pub(super) fn watched_mapped(&self, first: u64, last: u64) -> Option<usize> {
                self.pages.certain_watch_mapped(first, last)
            }
        }

        /// The user pages a settle derives again around noted user pages
        /// `first..=last`: one page beyond each end, `low..=high`, made only
        /// by [`Window::around`]. An end page is never a noted page, except
        /// where the window stops at the first or last user page, which has
        /// no outer neighbour on that side. A settle takes windows around
        /// noted ranges at least one unnoted page apart
        /// ([`merge_noted`](super::merge_noted)), so two windows share at
        /// most one end page, and it splices them in address order.
        ///
        /// That the index keeps the right outer part of a run that reaches
        /// past an end ([`RunIndex::splice`](super::index::RunIndex::splice))
        /// is an argument, which test builds check after every settle against
        /// a rebuild and in the windowed update's property test. At a
        /// window's low end, the end page and its outer neighbour were both
        /// unnoted, so their relation in the index is still the pages' own, or
        /// the neighbour lies in the window spliced just before, which derived
        /// both from the current pages. At its high end, both were unnoted, or
        /// the next window starts at that end page and derives it and its
        /// neighbour again.
        #[derive(Clone, Copy, Debug)]
        pub(super) struct Window {
            low: u64,
            high: u64,
        }

        impl Window {
            /// The window around noted user pages `first..=last`.
            pub(super) fn around(first: u64, last: u64) -> Self {
                Self {
                    low: first.saturating_sub(1),
                    high: last.saturating_add(1),
                }
            }

            /// The window's end pages, `(low, high)`, for a test.
            #[cfg(test)]
            pub(super) fn ends(self) -> (u64, u64) {
                (self.low, self.high)
            }
        }

        /// The runs derived from exactly the user pages of one [`Window`]
        /// ([`RunInputs::derive_window`]). The index's windowed update takes
        /// nothing else, so it never puts in runs derived from pages other
        /// than those of the window it replaces.
        pub(super) struct WindowRuns {
            window: Window,
            runs: Vec<(u64, u64)>,
        }

        impl WindowRuns {
            /// The window's end pages and its runs: `(low, high, runs)`.
            pub(super) fn into_parts(self) -> (u64, u64, Vec<(u64, u64)>) {
                (self.window.low, self.window.high, self.runs)
            }

            /// Runs a test derived from `window`'s pages itself, for a test
            /// of the windowed update alone.
            #[cfg(test)]
            pub(super) fn for_test(window: Window, runs: Vec<(u64, u64)>) -> Self {
                Self { window, runs }
            }
        }
    }

    /// The index, readable only through searches that count every entry
    /// they look at.
    mod index {
        use std::collections::BTreeMap;
        use std::ops::RangeBounds;
        use std::sync::Arc;

        use super::inputs::RunLayout;
        use super::inputs::WindowRuns;

        /// The index of an address space's mapping runs: the maximal runs
        /// of mapped user pages, exactly those a merge of every page gives
        /// (`runs_by_pages`), as their user page extents `first -> past`, in
        /// address order. It holds no facts: each run's fields are read
        /// from the page maps at its first page, which every page of the run
        /// shares (file offsets continuing).
        ///
        /// The index changes only in `settle`, from the pages the page maps
        /// note as changed (`page_maps::DirtyPages`; no write to them names
        /// no pages), so a change costs a search plus the pages it changed,
        /// and a reader settles it before reading, so it is never read
        /// stale. Copies of an address space share it until one of them
        /// changes it, as they share the page maps: a fork's copy costs no
        /// derivation.
        #[derive(Clone, Debug, Default)]
        pub(in super::super::super) struct RunIndex {
            runs: Arc<BTreeMap<u64, u64>>,
            /// The user layout the runs were derived under; another one
            /// rebuilds them.
            layout: Option<RunLayout>,
            /// Whether the user layout may have moved since the runs were
            /// derived (`note_layout_moved`).
            layout_moved: bool,
            /// In a test build, the entries [`RunIndex::entries`] yielded.
            #[cfg(any(test, feature = "test-support"))]
            visits: std::cell::Cell<u64>,
        }

        impl RunIndex {
            /// The entries with first pages in `range`, in address order:
            /// the one read of the index's entries but its own upkeep, so a
            /// test build counts every entry a search looks at, however it
            /// walks them.
            fn entries<R: RangeBounds<u64> + 'static>(
                &self,
                range: R,
            ) -> impl DoubleEndedIterator<Item = (u64, u64)> + '_ {
                self.runs.range(range).map(move |(&first, &past)| {
                    #[cfg(any(test, feature = "test-support"))]
                    self.visits.set(self.visits.get() + 1);
                    (first, past)
                })
            }

            /// Every run, in address order.
            pub(super) fn all(&self) -> Vec<(u64, u64)> {
                self.entries(..).collect()
            }

            /// The runs that meet user pages `[first, past)`, in address
            /// order.
            pub(super) fn meeting(&self, first: u64, past: u64) -> Vec<(u64, u64)> {
                let mut met: Vec<(u64, u64)> = self
                    .entries(..first)
                    .next_back()
                    .filter(|&(_, run_past)| run_past > first)
                    .into_iter()
                    .collect();
                met.extend(self.entries(first..past));
                met
            }

            /// The last run that ends at or below user page `page`: one
            /// entry looked at, or two when `page` lies inside a run.
            pub(super) fn before(&self, page: u64) -> Option<(u64, u64)> {
                self.entries(..page).rev().find(|&(_, past)| past <= page)
            }

            /// The first run that starts at or above user page `page`.
            pub(super) fn after(&self, page: u64) -> Option<(u64, u64)> {
                self.entries(page..).next()
            }

            /// The entries a test build counted since the last call.
            #[cfg(any(test, feature = "test-support"))]
            pub(super) fn take_visits(&self) -> u64 {
                self.visits.take()
            }

            /// The layout the runs were derived under, once settled.
            pub(super) fn layout(&self) -> Option<&RunLayout> {
                self.layout.as_ref()
            }

            /// Records that the user layout may have moved.
            pub(super) fn note_layout_moved(&mut self) {
                self.layout_moved = true;
            }

            /// Whether the runs need deriving under the current layout
            /// before a read, whatever the page maps noted.
            pub(super) fn unsettled(&self) -> bool {
                self.layout_moved || self.layout.is_none()
            }

            /// Whether the runs were derived under `layout`.
            pub(super) fn records(&self, layout: &RunLayout) -> bool {
                self.layout.as_ref() == Some(layout)
            }

            /// Whether the runs are exactly `runs`, for a test build's
            /// check.
            #[cfg(any(test, feature = "test-support"))]
            pub(super) fn holds(&self, runs: &BTreeMap<u64, u64>) -> bool {
                *self.runs == *runs
            }

            /// Replaces every run with `runs`, derived under `layout`.
            pub(super) fn rebuild(&mut self, runs: Vec<(u64, u64)>, layout: RunLayout) {
                self.runs = Arc::new(runs.into_iter().collect());
                self.layout = Some(layout);
                self.layout_moved = false;
            }

            /// Records that a settle found the layout the runs were derived
            /// under still current.
            pub(super) fn settled_under_its_layout(&mut self) {
                self.layout_moved = false;
            }

            /// Replaces the runs that meet the user pages of `derived`'s
            /// window, `low..=high`, with the runs derived from those pages
            /// alone. A run that reached past either end keeps its part
            /// outside, and that part joins the derived run at the end page
            /// again, as the end page and its outer neighbour continue each
            /// other in the index; why that relation is the current pages'
            /// is [`Window`]'s argument. The only change to the index but a
            /// rebuild.
            ///
            /// [`Window`]: super::inputs::Window
            pub(super) fn splice(&mut self, derived: WindowRuns) {
                let (low, high, mut derived) = derived.into_parts();
                let runs = Arc::make_mut(&mut self.runs);
                let mut old: Vec<(u64, u64)> = runs
                    .range(..low)
                    .next_back()
                    .filter(|&(_, &past)| past > low)
                    .map(|(&run_first, &past)| (run_first, past))
                    .into_iter()
                    .collect();
                old.extend(
                    runs.range(low..=high)
                        .map(|(&run_first, &past)| (run_first, past)),
                );
                for (run_first, _) in &old {
                    runs.remove(run_first);
                }
                // The part of a run below `low` that held `low`.
                if let Some(&(run_first, _)) = old.first()
                    && run_first < low
                {
                    match derived.first_mut() {
                        Some(first_derived) if first_derived.0 == low => {
                            first_derived.0 = run_first
                        }
                        _ => derived.insert(0, (run_first, low)),
                    }
                }
                // The part of a run above `high` that held `high`.
                if let Some(&(_, past)) = old.last()
                    && past > high.saturating_add(1)
                {
                    match derived.last_mut() {
                        Some(last_derived) if last_derived.1 == high.saturating_add(1) => {
                            last_derived.1 = past
                        }
                        _ => derived.push((high.saturating_add(1), past)),
                    }
                }
                for (run_first, past) in derived {
                    runs.insert(run_first, past);
                }
            }
        }

        #[cfg(test)]
        mod tests {
            use std::collections::BTreeMap;
            use std::sync::Arc;

            use super::super::inputs::Window;
            use super::super::inputs::WindowRuns;
            use super::super::merge_noted;
            use super::RunIndex;

            /// The maximal runs of pages `low..=high` of `colours`, `(first,
            /// past)`: a page with a colour continues the page before it when
            /// both have the same colour. A stand-in for the page maps'
            /// derivation, which is as local: whether a page continues the
            /// one before it depends on those two pages alone.
            fn derive(colours: &[Option<u8>], low: u64, high: u64) -> Vec<(u64, u64)> {
                let high = high.min(colours.len() as u64 - 1);
                let mut runs = Vec::new();
                let mut current: Option<(u64, u64, u8)> = None;
                for page in low..=high {
                    let colour = colours[page as usize];
                    if let (Some(colour), Some((_, past, current_colour))) =
                        (colour, current.as_mut())
                        && *current_colour == colour
                    {
                        *past = page + 1;
                        continue;
                    }
                    if let Some((first, past, _)) = current.take() {
                        runs.push((first, past));
                    }
                    if let Some(colour) = colour {
                        current = Some((page, page + 1, colour));
                    }
                }
                if let Some((first, past, _)) = current {
                    runs.push((first, past));
                }
                runs
            }

            /// A page with no colour a third of the time, else one of two.
            fn colour(next: &mut impl FnMut(u64) -> u64) -> Option<u8> {
                match next(3) {
                    0 => None,
                    colour => Some(colour as u8),
                }
            }

            /// The windowed update, as a settle applies it (the noted ranges
            /// joined, a window around each, every window derived and then
            /// spliced in address order), leaves exactly the runs a rebuild
            /// from every page gives, after every step of seeded sequences
            /// of writes to up to three ranges at a time, at both ends of the
            /// pages included.
            #[test]
            fn a_spliced_window_equals_a_rebuild_from_every_page() {
                const PAGES: u64 = 48;
                for seed in 1..=300u64 {
                    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
                    let mut next = move |bound: u64| {
                        state ^= state << 13;
                        state ^= state >> 7;
                        state ^= state << 17;
                        state % bound
                    };
                    let mut colours: Vec<Option<u8>> =
                        (0..PAGES).map(|_| colour(&mut next)).collect();
                    let mut index = RunIndex {
                        runs: Arc::new(derive(&colours, 0, PAGES - 1).into_iter().collect()),
                        ..RunIndex::default()
                    };
                    for step in 0..40 {
                        let mut noted = Vec::new();
                        for _ in 0..=next(3) {
                            let first = next(PAGES);
                            let last = (first + next(6)).min(PAGES - 1);
                            for page in first..=last {
                                colours[page as usize] = colour(&mut next);
                            }
                            noted.push((first, last));
                        }
                        let windows: Vec<WindowRuns> = merge_noted(noted)
                            .into_iter()
                            .map(|(first, last)| {
                                let window = Window::around(first, last);
                                let (low, high) = window.ends();
                                WindowRuns::for_test(window, derive(&colours, low, high))
                            })
                            .collect();
                        for windowed in windows {
                            index.splice(windowed);
                        }
                        let rebuilt: BTreeMap<u64, u64> =
                            derive(&colours, 0, PAGES - 1).into_iter().collect();
                        assert_eq!(*index.runs, rebuilt, "seed {seed}, step {step}");
                    }
                }
            }
        }
    }

    /// The noted user page ranges `user`, sorted and joined where they touch
    /// or overlap: the ranges a settle takes a window around
    /// ([`Window::around`]), in address order.
    fn merge_noted(mut user: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
        user.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (first, last) in user {
            match merged.last_mut() {
                Some(back) if first <= back.1.saturating_add(1) => back.1 = back.1.max(last),
                _ => merged.push((first, last)),
            }
        }
        merged
    }

    /// Records that the user layout of `state` moved.
    pub(super) fn note_layout_moved(state: &mut AddressSpaceState) {
        state.runs.note_layout_moved();
    }

    /// Whether `state`'s page maps noted a change, or its layout moved,
    /// since its index was last settled.
    pub(super) fn unsettled(state: &AddressSpaceState) -> bool {
        state.runs.unsettled()
            || !state.pages.dirty_is_empty()
            || !state.file_pages.dirty_is_empty()
            || !state.shared_anonymous_pages.dirty_is_empty()
            || !state.reservations.dirty_is_empty()
            || !state.mapping_incarnations.dirty_is_empty()
            || !state.mapping_identities.dirty_is_empty()
            || !state.backing_pages.dirty_is_empty()
    }

    /// Brings `state`'s index of mapping runs up to date with its page maps:
    /// the runs around every page a map noted as changed since the last
    /// settle are derived again from the page maps, or all of them where a
    /// write may have touched any page or the user layout changed. In a test
    /// build, the result is then checked against a rebuild from every page
    /// and the current layout (`check_settled`), whatever the settle found
    /// to do. It gives the reader of the settled index ([`RunView`]), which
    /// nothing outside this module can make otherwise.
    pub(super) fn settle(state: &mut AddressSpaceState) -> RunView<'_> {
        let mut dirty = super::super::page_maps::DirtyPages::default();
        dirty.absorb(state.pages.take_dirty());
        dirty.absorb(state.file_pages.take_dirty());
        dirty.absorb(state.shared_anonymous_pages.take_dirty());
        dirty.absorb(state.reservations.take_dirty());
        dirty.absorb(state.mapping_incarnations.take_dirty());
        dirty.absorb(state.mapping_identities.take_dirty());
        dirty.absorb(state.backing_pages.take_dirty());
        let layout = RunLayout::of(state);
        if dirty.every() || !state.runs.records(&layout) {
            let derived =
                RunInputs::for_settle(state, &layout).derive_runs(0, u64::MAX / PAGE_SIZE as u64);
            state.runs.rebuild(derived, layout);
        } else {
            state.runs.settled_under_its_layout();
            let noted = merge_noted(
                dirty
                    .ranges()
                    .iter()
                    .flat_map(|&(first, last)| layout.user_pages_of_physical(first, last))
                    .collect(),
            );
            // Each range's runs are derived again from the window one page
            // beyond each end, so a run reaching past an end keeps its outer
            // part (`RunIndex::splice`). Every window is derived before any
            // is spliced: a derivation reads the page maps, never the index.
            // The windows are spliced in address order, as the splice's
            // argument needs (`Window`).
            let inputs = RunInputs::for_settle(state, &layout);
            let derived: Vec<WindowRuns> = noted
                .into_iter()
                .map(|(first, last)| inputs.derive_window(Window::around(first, last)))
                .collect();
            for windowed in derived {
                state.runs.splice(windowed);
            }
        }
        #[cfg(any(test, feature = "test-support"))]
        check_settled(state);
        RunView::of(state)
    }

    /// In a test build, after a settle: the index's runs equal a rebuild
    /// from every page, the layout it records is the current one, and the
    /// page map's count of the stack window's mapped pages is a recount.
    #[cfg(any(test, feature = "test-support"))]
    fn check_settled(state: &AddressSpaceState) {
        if std::thread::panicking() {
            return;
        }
        let layout = RunLayout::of(state);
        let rebuilt: std::collections::BTreeMap<u64, u64> = RunInputs::for_check(state, &layout)
            .derive_runs(0, u64::MAX / PAGE_SIZE as u64)
            .into_iter()
            .collect();
        assert!(
            state.runs.holds(&rebuilt),
            "the index of mapping runs differs from a rebuild from the page maps"
        );
        assert!(
            state.runs.records(&layout),
            "the index of mapping runs records a user layout that is not the current one"
        );
        state.pages.check_watched_count();
    }

    /// In a test build, at a release of the address space's lock that noted
    /// nothing: the layout the index records is the current one. The index
    /// is derived from the noted page maps and the layout alone
    /// ([`RunInputs`]), a write to a page map's tree always notes its pages,
    /// and every settle checks the index against a rebuild. Two inputs can
    /// change at a release without a note: the layout, checked here, so a
    /// layout change that forgot its note fails at the release where it
    /// happened; and the Tool-scratch overlay of the page map, which changes
    /// only pages a permanent reservation keeps out of every run, checked
    /// where it changes (`AddressSpaceState::check_overlay_change`).
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn check_layout_noted(state: &AddressSpaceState) {
        if std::thread::panicking() {
            return;
        }
        assert!(
            state.runs.records(&RunLayout::of(state)),
            "the user layout moved without a note for the index of mapping runs"
        );
    }

    /// The runs merged from every page of `state`, as the list of mappings
    /// read them before the index: the oracle the index is checked against.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn runs_by_pages(state: &AddressSpaceState) -> UserMappingRuns {
        let layout = RunLayout::of(state);
        RunInputs::for_check(state, &layout).runs_by_pages()
    }

    /// The index entries a test build counted since the last call.
    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn take_visits(state: &AddressSpaceState) -> u64 {
        state.runs.take_visits()
    }

    /// A settled index of runs and its inputs, for the queries: the only
    /// reads a query makes are the counted ones of the index's searches and
    /// of [`RunInputs::index_run`].
    pub(super) struct RunView<'a> {
        index: &'a RunIndex,
        inputs: RunInputs<'a>,
    }

    impl<'a> RunView<'a> {
        /// The view of `state`, whose index is settled: private to this
        /// module, whose one caller is the settle, so a reader outside it
        /// comes only from a settle ([`settle`]).
        fn of(state: &'a AddressSpaceState) -> Self {
            let layout = state
                .runs
                .layout()
                .expect("the index of mapping runs is settled before a read");
            Self {
                index: &state.runs,
                inputs: RunInputs::for_query(state, layout),
            }
        }

        /// Every run.
        pub(super) fn all_runs(&self) -> Vec<UserMappingRun> {
            self.index
                .all()
                .into_iter()
                .filter_map(|(first, past)| self.inputs.index_run(first, past))
                .collect()
        }

        /// The runs that meet user pages `[first, past)`, cut to them.
        pub(super) fn runs_in(&self, first: u64, past: u64) -> Vec<UserMappingRun> {
            self.index
                .meeting(first, past)
                .into_iter()
                .filter_map(|(run_first, run_past)| {
                    self.inputs
                        .index_run(run_first.max(first), run_past.min(past))
                })
                .collect()
        }

        /// The whole runs that meet user pages `[first, past)`.
        pub(super) fn runs_meeting(&self, first: u64, past: u64) -> Vec<UserMappingRun> {
            self.index
                .meeting(first, past)
                .into_iter()
                .filter_map(|(run_first, run_past)| self.inputs.index_run(run_first, run_past))
                .collect()
        }

        /// The whole run that ends last at or below user page `page`.
        pub(super) fn run_before(&self, page: u64) -> Option<UserMappingRun> {
            let (first, past) = self.index.before(page)?;
            self.inputs.index_run(first, past)
        }

        /// The whole run that starts first at or above user page `page`.
        pub(super) fn run_after(&self, page: u64) -> Option<UserMappingRun> {
            let (first, past) = self.index.after(page)?;
            self.inputs.index_run(first, past)
        }

        /// The stack window's runs, cut to it, and whether they hold every
        /// mapped page of it: `None` unless the page map watches exactly the
        /// window's pages and its record is certain. The runs are whole
        /// index runs, read as such and cut afterwards; the count of mapped
        /// pages is the page map's own.
        pub(super) fn stack_window(&self) -> Option<StackWindowRuns> {
            let window = self.inputs.stack_window()?;
            let (first, last) = AddressSpaceState::window_pages(window)?;
            let mapped = self.inputs.watched_mapped(first, last)?;
            let page_size = PAGE_SIZE as u64;
            let mut held = 0;
            let runs: Vec<UserMappingRun> = self
                .index
                .meeting(window.user_start / page_size, window.user_end / page_size)
                .into_iter()
                .filter_map(|(run_first, run_past)| {
                    let mut run = self.inputs.index_run(run_first, run_past)?;
                    run.start = run.start.max(window.user_start);
                    run.end = run.end.min(window.user_end);
                    held += (run.end - run.start) / page_size;
                    Some(run)
                })
                .collect();
            Some(StackWindowRuns {
                start: window.user_start,
                end: window.user_end,
                runs,
                holds_every_page: held == mapped as u64,
            })
        }
    }
}

pub(super) use runs::RunIndex;

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
