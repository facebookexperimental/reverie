/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::AcqRel;
use core::sync::atomic::Ordering::Acquire;
use core::sync::atomic::Ordering::Release;
use core::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std::sync::RwLock;

// Every SlotMap access increments the reader count. A process-forming clone
// sets the high bit and waits for the count to reach zero, which proves that
// none of the per-map locks is held when the kernel copies them into the child.
// These atomics deliberately avoid a host lock: the child has to release the
// copied state before it can use runtime services after a raw clone.
const SLOT_MAP_FORK_BIT: usize = 1 << (usize::BITS - 1);
static SLOT_MAP_ACCESS: AtomicUsize = AtomicUsize::new(0);
static SLOT_MAP_FORK_OWNER: AtomicBool = AtomicBool::new(false);

struct SlotMapAccessGuard;

impl Drop for SlotMapAccessGuard {
    fn drop(&mut self) {
        let previous = SLOT_MAP_ACCESS.fetch_sub(1, Release);
        debug_assert_ne!(previous & !SLOT_MAP_FORK_BIT, 0);
    }
}

fn lock_for_access() -> SlotMapAccessGuard {
    loop {
        let state = SLOT_MAP_ACCESS.load(Acquire);
        if state & SLOT_MAP_FORK_BIT != 0 {
            core::hint::spin_loop();
            continue;
        }
        assert_ne!(
            state,
            SLOT_MAP_FORK_BIT - 1,
            "slot map reader count overflow"
        );
        if SLOT_MAP_ACCESS
            .compare_exchange_weak(state, state + 1, Acquire, Acquire)
            .is_ok()
        {
            return SlotMapAccessGuard;
        }
    }
}

pub(crate) struct SlotMapForkGuard;

impl Drop for SlotMapForkGuard {
    fn drop(&mut self) {
        SLOT_MAP_ACCESS.store(0, Release);
        SLOT_MAP_FORK_OWNER.store(false, Release);
    }
}

pub(crate) fn lock_for_fork() -> SlotMapForkGuard {
    while SLOT_MAP_FORK_OWNER
        .compare_exchange_weak(false, true, Acquire, Acquire)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let previous = SLOT_MAP_ACCESS.fetch_or(SLOT_MAP_FORK_BIT, AcqRel);
    debug_assert_eq!(previous & SLOT_MAP_FORK_BIT, 0);
    while SLOT_MAP_ACCESS.load(Acquire) != SLOT_MAP_FORK_BIT {
        core::hint::spin_loop();
    }
    SlotMapForkGuard
}

/// Release the write lock copied into a process created by a raw clone.
///
/// # Safety
///
/// The caller must establish that this process inherited the lock while it
/// was held by the thread that created the process, and that the copied guard
/// cannot subsequently be dropped in this process.
pub(crate) unsafe fn unlock_after_fork_child() {
    SLOT_MAP_ACCESS.store(0, Release);
    SLOT_MAP_FORK_OWNER.store(false, Release);
}

/// This is the key for addressing specific values from the slot map.
#[repr(transparent)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotKey(u32);

impl SlotKey {
    pub fn new<S: Into<u32>>(value: S) -> Self {
        Self(value.into())
    }

    fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Debug, Clone, Copy)]
pub enum InsertError {
    InsertsDisallowedBeforeInsert,
    InsertsDisallowedDuringInsert,
}

/// An append-only concurrent slot map.
///
/// Values are reference counted so readers can retain them after the read lock
/// is released. Iteration takes an `Arc` snapshot and does not hold a lock
/// while callers inspect entries. The async signal handler never accesses this
/// map; it only enqueues fixed-size events for normal runtime context.
pub struct SlotMap<T> {
    entries: RwLock<Vec<Arc<T>>>,
    disallowed_partition_value: AtomicU32,
}

#[cfg(test)]
pub(crate) struct SlotMapEntriesGuard<'a, T> {
    // Drop the per-map lock before decrementing the global reader count.
    _entries: std::sync::RwLockWriteGuard<'a, Vec<Arc<T>>>,
    _access: SlotMapAccessGuard,
}

impl<T: 'static> SlotMap<T> {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
            disallowed_partition_value: AtomicU32::new(u32::MAX),
        }
    }

    pub fn stop_inserts_for_partition(&self, partition: u32) -> bool {
        // Serialize with insertion so a successful insert cannot linearize
        // after this method returns.
        let _access = lock_for_access();
        let _entries = self.entries.write().unwrap_or_else(|err| err.into_inner());
        self.disallowed_partition_value.swap(partition, SeqCst) != partition
    }

    pub fn inserts_allowed_for_partition(&self, partition: u32) -> bool {
        self.disallowed_partition_value.load(SeqCst) != partition
    }

    pub fn insert(&self, value: T) -> SlotKey {
        self.insert_impl(None, value)
            .expect("unpartitioned inserts cannot fail")
    }

    pub fn try_insert(&self, partition: u32, value: T) -> Result<SlotKey, InsertError> {
        self.insert_impl(Some(partition), value)
    }

    fn insert_impl(&self, partition: Option<u32>, value: T) -> Result<SlotKey, InsertError> {
        if partition.is_some_and(|p| !self.inserts_allowed_for_partition(p)) {
            return Err(InsertError::InsertsDisallowedBeforeInsert);
        }

        let _access = lock_for_access();
        let mut entries = self.entries.write().unwrap_or_else(|err| err.into_inner());
        if partition.is_some_and(|p| !self.inserts_allowed_for_partition(p)) {
            return Err(InsertError::InsertsDisallowedDuringInsert);
        }

        let key = SlotKey::new(u32::try_from(entries.len()).expect("maximum map size exceeded"));
        entries.push(Arc::new(value));
        Ok(key)
    }

    pub fn get(&self, key: SlotKey) -> Option<Arc<T>> {
        let _access = lock_for_access();
        self.entries
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .get(key.index())
            .cloned()
    }

    pub fn entries(&self) -> impl Iterator<Item = (SlotKey, Arc<T>)> {
        let _access = lock_for_access();
        self.entries
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, value)| {
                (
                    SlotKey::new(u32::try_from(index).expect("maximum map size exceeded")),
                    value,
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[cfg(test)]
    pub fn clear(&self) {
        let _access = lock_for_access();
        self.entries
            .write()
            .unwrap_or_else(|err| err.into_inner())
            .clear();
        self.disallowed_partition_value.store(u32::MAX, SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn lock_entries_for_test(&self) -> SlotMapEntriesGuard<'_, T> {
        let access = lock_for_access();
        let entries = self.entries.write().unwrap_or_else(|err| err.into_inner());
        SlotMapEntriesGuard {
            _entries: entries,
            _access: access,
        }
    }
}

impl<T: 'static> Default for SlotMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU32;
    use core::sync::atomic::Ordering::Relaxed;
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn insert_get_and_snapshot_iteration() {
        let map = SlotMap::new();
        let first = map.insert(AtomicU32::new(42));
        let second = map.insert(AtomicU32::new(101));
        assert_eq!(map.get(first).unwrap().load(Relaxed), 42);
        assert_eq!(map.get(second).unwrap().load(Relaxed), 101);

        let snapshot = map.entries().collect::<Vec<_>>();
        map.insert(AtomicU32::new(7));
        assert_eq!(snapshot.len(), 2);
        for (_, value) in snapshot {
            value.fetch_add(1, Relaxed);
        }
        assert_eq!(map.get(first).unwrap().load(Relaxed), 43);
    }

    #[test]
    fn concurrent_publication_is_visible_to_readers() {
        const THREADS: usize = 16;
        const INSERTS: usize = 1_000;
        let map = Arc::new(SlotMap::new());
        let workers = (0..THREADS)
            .map(|thread_number| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    for offset in 0..INSERTS {
                        let value = thread_number * INSERTS + offset;
                        let key = map.try_insert(0, value).unwrap();
                        assert_eq!(*map.get(key).unwrap(), value);
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }

        let mut values = map.entries().map(|(_, value)| *value).collect::<Vec<_>>();
        values.sort_unstable();
        assert_eq!(values, (0..THREADS * INSERTS).collect::<Vec<_>>());
    }

    #[test]
    fn disabling_a_partition_does_not_block_unpartitioned_inserts() {
        let map = SlotMap::new();
        assert!(map.try_insert(9, 1).is_ok());
        assert!(map.stop_inserts_for_partition(9));
        assert!(matches!(
            map.try_insert(9, 2),
            Err(InsertError::InsertsDisallowedBeforeInsert)
        ));
        assert_eq!(*map.get(map.insert(3)).unwrap(), 3);
    }

    #[test]
    fn disabling_a_partition_excludes_late_concurrent_inserts() {
        let map = Arc::new(SlotMap::new());
        let workers = (0..8)
            .map(|worker| {
                let map = Arc::clone(&map);
                thread::spawn(move || {
                    let mut value = worker;
                    while map.try_insert(7, value).is_ok() {
                        value += 8;
                    }
                })
            })
            .collect::<Vec<_>>();

        while map.entries().count() < 100 {
            thread::yield_now();
        }
        assert!(map.stop_inserts_for_partition(7));
        let count_at_stop = map.entries().count();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(map.entries().count(), count_at_stop);
    }
}
