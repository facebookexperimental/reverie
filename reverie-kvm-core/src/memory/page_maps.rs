/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The page-keyed host-side access maps, with two properties the Tool-scratch
//! fast paths rely on.
//!
//! - [`Versioned`] collections change only through [`Versioned::edit`], which
//!   gives the collection a process-unique version. Two collections with the
//!   same version therefore have the same contents: the only way to share a
//!   version is to clone the collection that drew it. The inner collection is
//!   private to this module, so a mutation that skips the version does not
//!   compile.
//! - [`UserPages`] is logically a `BTreeMap<u64, UserPageState>`. Its
//!   representation adds a tiny overlay of exposed Tool-scratch pages, each
//!   logically `Accessible { writable: true, declared: None }`, so exposing
//!   and hiding a scratch page touches no tree node. Every method answers for
//!   the logical map, and the overlay is never a key of the tree.
//! - [`UserPages`] can watch a range of pages ([`UserPages::watch`]): every
//!   method that changes the logical state of a watched page counts it, so
//!   no caller can change one unseen, and the watch stays certain while this
//!   map's own states tell everything about the watched pages. A clone
//!   shares the record until it takes one of its own
//!   ([`UserPages::detach_watch`]).
//! - [`UserPages`] counts, for each bit of the provider flags
//!   ([`super::DeclaredMapping::flags`]), the pages whose declared mapping
//!   carries it ([`UserPages::flagged_pages`]). Every method that changes a
//!   page's logical state keeps the counts, so a provider can tell at once
//!   that no page carries a flag without walking the pages.

use std::collections::BTreeMap;
use std::fmt;
use std::ops::Bound;
use std::ops::Deref;
use std::ops::RangeBounds;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::UserPageState;

static NEXT_VERSION: AtomicU64 = AtomicU64::new(1);

fn fresh_version() -> u64 {
    NEXT_VERSION.fetch_add(1, Ordering::Relaxed)
}

/// A collection readable through `Deref` and writable only through
/// [`Versioned::edit`]. See the module documentation.
#[derive(Clone)]
pub(super) struct Versioned<M> {
    inner: M,
    version: u64,
}

impl<M> Versioned<M> {
    pub(super) fn new(inner: M) -> Self {
        Self {
            inner,
            version: fresh_version(),
        }
    }

    /// Mutable access. The collection takes a fresh version first, whether or
    /// not the caller ends up changing it, so a stale version can only be
    /// conservative.
    pub(super) fn edit(&mut self) -> &mut M {
        self.version = fresh_version();
        &mut self.inner
    }

    pub(super) fn version(&self) -> u64 {
        self.version
    }
}

impl<M> Deref for Versioned<M> {
    type Target = M;

    fn deref(&self) -> &M {
        &self.inner
    }
}

impl<'a, M> IntoIterator for &'a Versioned<M>
where
    &'a M: IntoIterator,
{
    type Item = <&'a M as IntoIterator>::Item;
    type IntoIter = <&'a M as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.inner).into_iter()
    }
}

impl<M: fmt::Debug> fmt::Debug for Versioned<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)
    }
}

/// The logical state of every exposed Tool-scratch page.
const EXPOSED: UserPageState = UserPageState::Accessible {
    writable: true,
    declared: None,
};

/// The page-state map; see the module documentation.
#[derive(Clone)]
pub(super) struct UserPages {
    map: Versioned<BTreeMap<u64, UserPageState>>,
    /// Exposed Tool-scratch pages, ascending, never keys of `map`. One per
    /// Tool thread inside a callback, so a linear scan is the right search.
    scratch: Vec<u64>,
    /// The watched pages, if any; see [`UserPages::watch`].
    watch: Option<Watch>,
    /// For each bit of the provider flags, how many pages of the logical map
    /// carry it in their declared mapping ([`UserPages::flagged_pages`]).
    flag_pages: [usize; 16],
}

/// A range of pages whose logical state [`UserPages`] watches.
#[derive(Clone, Debug)]
struct Watch {
    /// The first watched page.
    first: u64,
    /// The last watched page.
    last: u64,
    /// The record this map shares with its clones.
    record: Arc<SharedRecord>,
    /// How many of the record's changes this map made.
    own: u64,
}

impl Watch {
    /// No note, and no change but this map's own.
    fn certain(&self) -> bool {
        !self.record.uncertain.load(Ordering::SeqCst)
            && self.record.changes.load(Ordering::SeqCst) == self.own
    }
}

/// What the maps that share a watch record have recorded since it began.
#[derive(Debug, Default)]
struct SharedRecord {
    /// The changes to the logical state of a watched page, by any of them.
    changes: AtomicU64,
    /// Whether something changed for a watched page that no logical state
    /// holds ([`UserPages::note_change`]). It only goes from false to true.
    uncertain: AtomicBool,
}

impl UserPages {
    pub(super) fn new() -> Self {
        Self {
            map: Versioned::new(BTreeMap::new()),
            scratch: Vec::new(),
            watch: None,
            flag_pages: [0; 16],
        }
    }

    /// The provider flags a page in `state` carries.
    fn flags_of(state: Option<UserPageState>) -> u16 {
        state
            .and_then(UserPageState::declared)
            .map_or(0, |declared| declared.flags)
    }

    /// Keeps the flag counts for a page whose logical state goes from `old`
    /// to `new` (`None`: absent).
    fn count_flags(&mut self, old: Option<UserPageState>, new: Option<UserPageState>) {
        let (old, new) = (Self::flags_of(old), Self::flags_of(new));
        if old == new {
            return;
        }
        for (bit, count) in self.flag_pages.iter_mut().enumerate() {
            let mask = 1u16 << bit;
            match (old & mask != 0, new & mask != 0) {
                (true, false) => *count -= 1,
                (false, true) => *count += 1,
                _ => {}
            }
        }
    }

    /// How many pages carry the provider flags in `mask`, counted once per
    /// bit: zero exactly when no page carries any bit of `mask`, and for one
    /// bit the number of pages that carry it.
    pub(super) fn flagged_pages(&self, mask: u16) -> usize {
        self.flag_pages
            .iter()
            .enumerate()
            .filter(|(bit, _)| mask & (1u16 << bit) != 0)
            .map(|(_, count)| count)
            .sum()
    }

    /// Watches pages `first..=last` from now on, with a record of its own,
    /// replacing any earlier watch. Every method of this map that changes
    /// the logical state of a watched page (inserts a page with another
    /// state, removes one, clears the map, or exposes or hides a scratch page
    /// over one) counts the change in the record, as one of this map's own.
    /// The watch is certain ([`UserPages::certain_watch`]) while this map's
    /// logical states tell everything about the watched pages: until
    /// [`UserPages::note_change`] names one, or until another map that
    /// shares the record changes one.
    ///
    /// A clone shares the record and its count of own changes, so a copy
    /// prepared from this map and installed in its place stays certain, one
    /// dropped after a change leaves this map uncertain, which only loses
    /// certainty, and a copy for a process that shares the address space (a
    /// vfork child's) makes either uncertain once the other changes a watched
    /// page. A copy that becomes another address space, a fork's, takes a
    /// record of its own ([`UserPages::detach_watch`]).
    pub(super) fn watch(&mut self, first: u64, last: u64) {
        self.watch = Some(Watch {
            first,
            last,
            record: Arc::default(),
            own: 0,
        });
    }

    /// The watched pages, `(first, last)`, if a watch is set and certain.
    pub(super) fn certain_watch(&self) -> Option<(u64, u64)> {
        self.watch
            .as_ref()
            .filter(|watch| watch.certain())
            .map(|watch| (watch.first, watch.last))
    }

    /// Records that something the logical states do not hold changed for
    /// pages `first..=last`: when they overlap the watch, it is no longer
    /// certain, for this map and for every map that shares its record.
    pub(super) fn note_change(&mut self, first: u64, last: u64) {
        if let Some(watch) = &self.watch
            && first <= watch.last
            && last >= watch.first
        {
            watch.record.uncertain.store(true, Ordering::SeqCst);
        }
    }

    /// Counts a change this map made to pages `first..=last`, which its own
    /// state holds, when they overlap the watch: a map that shares the
    /// record and lacks the change is no longer certain.
    pub(super) fn count_change(&mut self, first: u64, last: u64) {
        if let Some(watch) = &mut self.watch
            && first <= watch.last
            && last >= watch.first
        {
            watch.record.changes.fetch_add(1, Ordering::SeqCst);
            watch.own += 1;
        }
    }

    /// Gives this map's watch a record of its own, which starts certain
    /// exactly when the shared one is now for this map: changes by the maps
    /// that shared it no longer reach this one, and this one's no longer
    /// reach them.
    pub(super) fn detach_watch(&mut self) {
        if let Some(watch) = &mut self.watch {
            let record = SharedRecord::default();
            record.uncertain.store(!watch.certain(), Ordering::SeqCst);
            watch.record = Arc::new(record);
            watch.own = 0;
        }
    }

    /// The version of the tree. Overlay changes do not move it: they change
    /// no tree key.
    pub(super) fn map_version(&self) -> u64 {
        self.map.version()
    }

    fn scratch_index(&self, page: u64) -> Result<usize, usize> {
        self.scratch.binary_search(&page)
    }

    fn take_scratch(&mut self, page: u64) -> bool {
        match self.scratch_index(page) {
            Ok(index) => {
                self.scratch.remove(index);
                true
            }
            Err(_) => false,
        }
    }

    pub(super) fn get(&self, page: &u64) -> Option<&UserPageState> {
        if !self.scratch.is_empty() && self.scratch_index(*page).is_ok() {
            return Some(&EXPOSED);
        }
        self.map.get(page)
    }

    pub(super) fn contains_key(&self, page: &u64) -> bool {
        self.get(page).is_some()
    }

    pub(super) fn len(&self) -> usize {
        self.map.len() + self.scratch.len()
    }

    /// `BTreeMap::insert` of the logical map.
    pub(super) fn insert(&mut self, page: u64, state: UserPageState) -> Option<UserPageState> {
        let exposed = self.take_scratch(page);
        let previous = self.map.edit().insert(page, state);
        debug_assert!(!(exposed && previous.is_some()));
        let previous = if exposed { Some(EXPOSED) } else { previous };
        self.count_flags(previous, Some(state));
        if previous != Some(state) {
            self.count_change(page, page);
        }
        previous
    }

    /// `BTreeMap::remove` of the logical map.
    pub(super) fn remove(&mut self, page: &u64) -> Option<UserPageState> {
        let previous = if self.take_scratch(*page) {
            Some(EXPOSED)
        } else {
            self.map.edit().remove(page)
        };
        self.count_flags(previous, None);
        if previous.is_some() {
            self.count_change(*page, *page);
        }
        previous
    }

    pub(super) fn clear(&mut self) {
        if let Some((first, last)) = self.watch.as_ref().map(|watch| (watch.first, watch.last))
            && self.range(first..=last).next().is_some()
        {
            self.count_change(first, last);
        }
        self.scratch.clear();
        self.map.edit().clear();
        self.flag_pages = [0; 16];
    }

    /// Exactly `insert(page, EXPOSED)` of the logical map, without touching
    /// the tree when `page` is known not to be one of its keys.
    /// `known_absent` must be a fact, not a guess: with it the tree is not
    /// searched.
    pub(super) fn expose_scratch(&mut self, page: u64, known_absent: bool) {
        let Err(index) = self.scratch_index(page) else {
            // Already exposed: inserting the same state changes nothing.
            return;
        };
        let previous = if !known_absent && self.map.contains_key(&page) {
            self.map.edit().remove(&page)
        } else {
            None
        };
        self.count_flags(previous, Some(EXPOSED));
        self.scratch.insert(index, page);
        if previous != Some(EXPOSED) {
            self.count_change(page, page);
        }
    }

    /// Exactly `remove(&page)` of the logical map, without touching the tree
    /// when `page` is known not to be one of its keys.
    pub(super) fn hide_scratch(&mut self, page: u64, known_absent: bool) {
        if self.take_scratch(page) {
            self.count_change(page, page);
            return;
        }
        if known_absent {
            return;
        }
        if self.map.contains_key(&page) {
            let previous = self.map.edit().remove(&page);
            self.count_flags(previous, None);
            self.count_change(page, page);
        }
    }

    /// The logical entries with keys in `range`, ascending, double-ended.
    pub(super) fn range<R: RangeBounds<u64> + Clone>(&self, range: R) -> Iter<'_> {
        let tree = self.map.range(range.clone());
        let lo = self
            .scratch
            .partition_point(|page| match range.start_bound() {
                Bound::Included(start) => page < start,
                Bound::Excluded(start) => page <= start,
                Bound::Unbounded => false,
            });
        let hi = self
            .scratch
            .partition_point(|page| match range.end_bound() {
                Bound::Included(end) => page <= end,
                Bound::Excluded(end) => page < end,
                Bound::Unbounded => true,
            });
        Iter {
            tree,
            scratch: &self.scratch[lo..hi.max(lo)],
            front: None,
            back: None,
        }
    }

    pub(super) fn iter(&self) -> Iter<'_> {
        self.range(..)
    }

    pub(super) fn keys(&self) -> impl DoubleEndedIterator<Item = &u64> + '_ {
        self.iter().map(|(page, _)| page)
    }

    /// The logical map as an ordinary map.
    #[cfg(test)]
    pub(super) fn to_map(&self) -> BTreeMap<u64, UserPageState> {
        self.iter().map(|(&page, &state)| (page, state)).collect()
    }
}

impl fmt::Debug for UserPages {
    /// Formats as the logical `BTreeMap` would.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// A sorted merge of tree entries and overlay pages, which are disjoint.
pub(super) struct Iter<'a> {
    tree: std::collections::btree_map::Range<'a, u64, UserPageState>,
    scratch: &'a [u64],
    /// A tree entry taken from the front and not yet yielded.
    front: Option<(&'a u64, &'a UserPageState)>,
    /// A tree entry taken from the back and not yet yielded.
    back: Option<(&'a u64, &'a UserPageState)>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a u64, &'a UserPageState);

    fn next(&mut self) -> Option<Self::Item> {
        if self.front.is_none() {
            // Once the tree is drained from the front, its smallest remaining
            // entry may be the one already taken from the back.
            self.front = self.tree.next().or_else(|| self.back.take());
        }
        match (self.front, self.scratch.first()) {
            (Some((page, _)), Some(exposed)) if exposed < page => {
                self.scratch = &self.scratch[1..];
                Some((exposed, &EXPOSED))
            }
            (Some(_), _) => self.front.take(),
            (None, Some(exposed)) => {
                self.scratch = &self.scratch[1..];
                Some((exposed, &EXPOSED))
            }
            (None, None) => None,
        }
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.back.is_none() {
            self.back = self.tree.next_back().or_else(|| self.front.take());
        }
        match (self.back, self.scratch.last()) {
            (Some((page, _)), Some(exposed)) if exposed > page => {
                self.scratch = &self.scratch[..self.scratch.len() - 1];
                Some((exposed, &EXPOSED))
            }
            (Some(_), _) => self.back.take(),
            (None, Some(exposed)) => {
                self.scratch = &self.scratch[..self.scratch.len() - 1];
                Some((exposed, &EXPOSED))
            }
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small deterministic generator; the test needs coverage, not quality.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) % bound
        }
    }

    fn state(choice: u64) -> UserPageState {
        let declared = |prot: libc::c_int, flags| super::super::DeclaredMapping {
            prot: prot as u8,
            flags,
            lineage: 0,
        };
        match choice % 7 {
            0 => UserPageState::undeclared(false, false),
            1 => UserPageState::undeclared(true, false),
            2 => UserPageState::undeclared(true, true),
            3 => UserPageState::of(declared(libc::PROT_READ | libc::PROT_WRITE, 0)),
            4 => UserPageState::of(declared(libc::PROT_READ | libc::PROT_WRITE, 1)),
            5 => UserPageState::of(declared(libc::PROT_READ, 0x1001)).guarded(),
            _ => UserPageState::NoAccess {
                declared: Some(declared(0, 0x8000)),
            },
        }
    }

    fn assert_same(pages: &UserPages, model: &BTreeMap<u64, UserPageState>, rng: &mut Lcg) {
        assert_eq!(pages.len(), model.len());
        // Each flag bit's count is the number of the model's pages that
        // carry it.
        for bit in 0..16 {
            let mask = 1u16 << bit;
            let carrying = model
                .values()
                .filter(|state| UserPages::flags_of(Some(**state)) & mask != 0)
                .count();
            assert_eq!(pages.flagged_pages(mask), carrying, "bit {bit}");
        }
        let any = model
            .values()
            .filter(|state| UserPages::flags_of(Some(**state)) & 0x1001 != 0)
            .count();
        assert_eq!(pages.flagged_pages(0x1001) == 0, any == 0);
        assert_eq!(&pages.to_map(), model);
        assert!(pages.keys().eq(model.keys()));
        assert!(pages.keys().rev().eq(model.keys().rev()));
        assert_eq!(format!("{pages:?}"), format!("{model:?}"));
        for page in 0..24 {
            assert_eq!(pages.get(&page), model.get(&page), "page {page}");
            assert_eq!(pages.contains_key(&page), model.contains_key(&page));
        }
        // Random bounded ranges, both directions, and interleaved ends.
        for _ in 0..4 {
            let start = rng.next(24);
            let end = start + rng.next(24 - start + 1);
            assert!(pages.range(start..end).eq(model.range(start..end)));
            assert!(
                pages
                    .range(start..=end)
                    .rev()
                    .eq(model.range(start..=end).rev())
            );
            let (mut ours, mut theirs) = (pages.range(start..), model.range(start..));
            loop {
                let back = rng.next(2) == 0;
                let (a, b) = if back {
                    (ours.next_back(), theirs.next_back())
                } else {
                    (ours.next(), theirs.next())
                };
                assert_eq!(a, b);
                if a.is_none() {
                    break;
                }
            }
        }
    }

    /// Model check: every operation, overlay paths included, leaves the same
    /// logical map as the plain `BTreeMap` operation it stands for. The
    /// map's own changes, which its states hold, leave the watch certain, and
    /// a note that names a watched page leaves it uncertain for good; a clone
    /// starts as certain as the map.
    #[test]
    fn user_pages_behave_as_their_logical_btree_map() {
        let mut rng = Lcg(0x5eed);
        let mut changes = 0;
        let mut notes = 0;
        for _round in 0..64 {
            let mut pages = UserPages::new();
            let mut model = BTreeMap::new();
            assert_eq!(pages.certain_watch(), None);
            let first = rng.next(20);
            let last = first + rng.next(20 - first);
            let mut watching = false;
            let mut noted = false;
            for step in 0..200 {
                if step == 20 {
                    // A watch begun on a map that already holds pages.
                    pages.watch(first, last);
                    watching = true;
                }
                let page = rng.next(20);
                let before: Vec<_> = model
                    .range(first..=last)
                    .map(|(&page, &state)| (page, state))
                    .collect();
                match rng.next(8) {
                    0 | 1 => {
                        let value = state(rng.next(7));
                        assert_eq!(pages.insert(page, value), model.insert(page, value));
                    }
                    2 => assert_eq!(pages.remove(&page), model.remove(&page)),
                    3 => {
                        // `known_absent` only when it is true of the tree.
                        let absent = !pages.map.contains_key(&page) && rng.next(2) == 0;
                        pages.expose_scratch(page, absent);
                        model.insert(page, EXPOSED);
                    }
                    4 | 5 => {
                        let absent = !pages.map.contains_key(&page) && rng.next(2) == 0;
                        pages.hide_scratch(page, absent);
                        model.remove(&page);
                    }
                    6 => {
                        if rng.next(8) == 0 {
                            let end = page + rng.next(4);
                            pages.note_change(page, end);
                            if watching && page <= last && end >= first {
                                noted = true;
                                notes += 1;
                            }
                        }
                    }
                    _ => {
                        if rng.next(16) == 0 {
                            pages.clear();
                            model.clear();
                        }
                    }
                }
                let after: Vec<_> = model
                    .range(first..=last)
                    .map(|(&page, &state)| (page, state))
                    .collect();
                if watching && before != after {
                    changes += 1;
                }
                let expected = (watching && !noted).then_some((first, last));
                assert_eq!(pages.certain_watch(), expected, "step {step}");
                assert!(
                    pages
                        .scratch
                        .iter()
                        .all(|page| !pages.map.contains_key(page))
                );
                assert!(pages.scratch.windows(2).all(|w| w[0] < w[1]));
                assert_same(&pages, &model, &mut rng);
                let cloned = pages.clone();
                assert_same(&cloned, &model, &mut rng);
                assert_eq!(cloned.certain_watch(), expected);
            }
        }
        // The rounds exercised the watch, not only its absence.
        assert!(changes > 64 && notes > 0, "{changes} {notes}");
    }

    /// What leaves a watch uncertain: a note, by the map or by a clone that
    /// shares its record, and a change to a watched page by a clone, which
    /// the other's states lack; the map's own changes, and changes outside
    /// the watch, do not. A clone starts as certain as the map, a detached
    /// copy shares nothing and starts as certain as the record was for it,
    /// and a new watch shares with no one.
    #[test]
    fn a_watch_is_certain_until_a_map_sharing_its_record_changes_a_watched_page() {
        let watched = || {
            let mut pages = UserPages::new();
            pages.insert(5, state(0));
            pages.watch(4, 6);
            pages
        };
        let certain = Some((4, 6));

        // Its own changes keep it certain.
        let mut own = watched();
        own.remove(&5);
        own.insert(4, state(3));
        own.expose_scratch(6, true);
        own.hide_scratch(6, true);
        own.clear();
        assert_eq!(own.certain_watch(), certain);

        // A change by a clone, or by the original after the cloning, leaves
        // the other uncertain and the one that made it certain; a change
        // outside the watch reaches no one.
        for clone_changes in [true, false] {
            let mut original = watched();
            let mut clone = original.clone();
            let (changing, other) = if clone_changes {
                (&mut clone, &mut original)
            } else {
                (&mut original, &mut clone)
            };
            changing.insert(9, state(2));
            assert_eq!(other.certain_watch(), certain, "{clone_changes}");
            changing.remove(&5);
            assert_eq!(changing.certain_watch(), certain, "{clone_changes}");
            assert_eq!(other.certain_watch(), None, "{clone_changes}");
        }

        // A note by either leaves both uncertain.
        for clone_notes in [true, false] {
            let mut original = watched();
            let mut clone = original.clone();
            let noting = if clone_notes {
                &mut clone
            } else {
                &mut original
            };
            noting.note_change(6, 9);
            assert_eq!(original.certain_watch(), None, "{clone_notes}");
            assert_eq!(clone.certain_watch(), None, "{clone_notes}");
        }

        // A detached copy shares nothing, either way, and starts as certain
        // as the record was for it.
        for detach_copy in [true, false] {
            let mut original = watched();
            let mut copy = original.clone();
            if detach_copy {
                copy.detach_watch();
            } else {
                original.detach_watch();
            }
            copy.insert(6, state(2));
            copy.note_change(6, 6);
            assert_eq!(original.certain_watch(), certain, "{detach_copy}");
            original.remove(&5);
            original.note_change(5, 5);
            assert_eq!(original.certain_watch(), None, "{detach_copy}");
        }
        let mut original = watched();
        let mut clone = original.clone();
        clone.remove(&5);
        original.detach_watch();
        assert_eq!(original.certain_watch(), None);
        let mut noted = watched();
        noted.note_change(4, 4);
        noted.detach_watch();
        assert_eq!(noted.certain_watch(), None);

        // A clone of an uncertain map is uncertain, and a new watch starts
        // certain again.
        let mut uncertain = watched();
        uncertain.clone().remove(&5);
        assert_eq!(uncertain.clone().certain_watch(), None);
        uncertain.watch(4, 6);
        assert_eq!(uncertain.certain_watch(), certain);

        // A new watch has a record of its own.
        let mut original = watched();
        let mut clone = original.clone();
        clone.watch(4, 6);
        clone.insert(5, state(1));
        clone.note_change(5, 5);
        assert_eq!(original.certain_watch(), certain);
        let shared = original.clone();
        original.watch(4, 6);
        original.remove(&5);
        original.note_change(4, 4);
        assert_eq!(shared.certain_watch(), certain);

        // Without a watch there is nothing to detach or count.
        let mut none = UserPages::new();
        none.detach_watch();
        none.insert(5, state(1));
        none.note_change(0, u64::MAX);
        assert_eq!(none.certain_watch(), None);
    }

    #[test]
    fn scratch_overlay_moves_no_tree_version_and_tree_edits_do() {
        let mut pages = UserPages::new();
        pages.insert(3, UserPageState::undeclared(false, false));
        let version = pages.map_version();
        pages.expose_scratch(9, true);
        pages.hide_scratch(9, true);
        pages.expose_scratch(9, false);
        pages.hide_scratch(9, false);
        assert_eq!(pages.map_version(), version, "no tree key changed");
        // Negative controls: exposing over a tree key, or any tree edit,
        // takes a fresh version.
        pages.expose_scratch(3, false);
        let after_expose = pages.map_version();
        assert_ne!(after_expose, version);
        assert_eq!(pages.get(&3), Some(&EXPOSED));
        pages.insert(4, UserPageState::undeclared(false, false));
        assert_ne!(pages.map_version(), after_expose);
    }

    #[test]
    fn versions_are_shared_only_by_clones() {
        let mut first = Versioned::new(BTreeMap::<u64, u64>::new());
        let second = Versioned::new(BTreeMap::<u64, u64>::new());
        assert_ne!(first.version(), second.version());
        let clone = first.clone();
        assert_eq!(clone.version(), first.version());
        first.edit().insert(1, 1);
        assert_ne!(clone.version(), first.version());
        let before = first.version();
        // Even an edit that changes nothing moves the version.
        first.edit().remove(&7);
        assert_ne!(first.version(), before);
    }
}
