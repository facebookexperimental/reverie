/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

#![allow(invalid_reference_casting)]

use core::iter::repeat;
use core::mem::MaybeUninit;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering::*;

use array_macro::array;

/// This is the key for addressing specific values from the slot map. A slot's
/// address is made up of three parts and those parts are encoded into this one
/// unsigned integer as follows:
///
/// |<-------------------------- 32 Bits Total ----------------------------->|
/// |<-12 Bits: Generation->|<-10 Bits: Chunk Index->|<-10 Bits: Slot Index->|
///
/// Generation - Number of times the slot has been written (including deletes)
/// Chunk Index - The index of the chunk containing the slot
/// Slot Index - The slot's index within its chunk
///
/// Defining generation this way has the nice property that any slot with an
/// even generation is empty. Each slot's generation starts at zero and is
/// incremented by one after its first write
#[repr(transparent)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotKey(u32);

/// These constants define the bit pattern above.
const INDEX_IN_CHUNK_BITS: u8 = 10;
const CHUNK_INDEX_BITS: u8 = 10;
const GENERATION_BITS: u8 = 32 - CHUNK_INDEX_BITS - INDEX_IN_CHUNK_BITS;
const INDEX_IN_CHUNK_MASK: u32 = (0x1 << INDEX_IN_CHUNK_BITS) - 1;
const CHUNK_INDEX_SHIFT: u8 = INDEX_IN_CHUNK_BITS;
const CHUNK_INDEX_MASK: u32 = ((0x1 << CHUNK_INDEX_BITS) - 1) << CHUNK_INDEX_SHIFT;
const GENERATION_SHIFT: u8 = CHUNK_INDEX_SHIFT + CHUNK_INDEX_BITS;
const GENERATION_MASK: u32 = ((0x1 << GENERATION_BITS) - 1) << GENERATION_SHIFT;

// These are some useful constants related to the slotkey's bit pattern
const MAX_CHUNK_COUNT: usize = 1 << CHUNK_INDEX_BITS;
const ONE_GENERATION: u32 = 1 << GENERATION_SHIFT;
const SLOTS_PER_CHUNK: usize = 1 << CHUNK_INDEX_BITS;

/// Each slot needs to know what its generation is and if the slot is empty, it
/// needs to point to the next empty slot
type SlotMetaData = AtomicU32;
type Slot<T> = (SlotMetaData, T);
type Chunk<T> = [Slot<T>; SLOTS_PER_CHUNK];
type ChunkPointer<T> = MaybeUninit<Box<Chunk<T>>>;

/// Allocate a new chunk and return it
fn new_chunk<T: ?Sized + Default>() -> ChunkPointer<T> {
    MaybeUninit::new(Box::new(array![Default::default(); SLOTS_PER_CHUNK]))
}

impl SlotKey {
    /// Construct a slot key from its parts
    fn new_from_parts(chunk_index: usize, slot_index: usize, generation: u32) -> Self {
        SlotKey::new(
            (((chunk_index as u32) << CHUNK_INDEX_SHIFT) & CHUNK_INDEX_MASK)
                + ((generation << GENERATION_SHIFT) & GENERATION_MASK)
                + ((slot_index as u32) & INDEX_IN_CHUNK_MASK),
        )
    }

    pub fn new<S>(int_value: S) -> Self
    where
        S: Into<u32>,
    {
        Self(int_value.into())
    }

    /// Get the index of the slot encoded in the slot key
    fn slot_index(self) -> usize {
        (self.0 & INDEX_IN_CHUNK_MASK) as usize
    }

    /// Get the index of the chunk encoded in the slot key
    fn chunk_index(self) -> usize {
        ((self.0 & CHUNK_INDEX_MASK) >> CHUNK_INDEX_SHIFT) as usize
    }

    /// Get the generation encoded in the slot key
    fn generation(self) -> u32 {
        (self.0 & GENERATION_MASK) >> GENERATION_SHIFT
    }
}

/// Enumeration of the types of errors that can occur
#[derive(Debug, Clone, Copy)]
pub enum InsertError {
    /// Indicates that inserts with the partition were stopped before trying to
    /// insert the value. This means the map was not altered during the
    /// operation
    InsertsDisallowedBeforeInsert,

    /// Indicates that inserts for the partition were disallowed during the
    /// process of inserting the value. This means the map might have been
    /// temporarily updated to contain the given value, so the caller is
    /// needs to take action to correct any side effects of the value being
    /// temporarily present to other consumers of this map.
    ///
    /// Note. This does not indicate any corruption in the map.
    InsertsDisallowedDuringInsert,
}

/// This is a specialized, concurrent, lock-free slotmap that allows for
/// wait-free reads and guarantees safety and well-defined behavior with only a
/// few caveats.
///
/// 1. Some operations will wait by spinning if their is operational contentions:
///    - When a new chunk needs to be allocated only one thread can do the allocation,
///      and all the others have to wait
/// 2. Currently deletes are not supported <- Todo(T117692439)
pub struct SlotMap<T> {
    chunk_count_for_reads: AtomicUsize,
    chunk_count_for_writes: AtomicUsize,
    next_slot_key: AtomicU32,

    disallowed_partition_value: AtomicU32,

    /// This array stores pointers to all the allocated chunks indexed by chunk
    /// id. Initially all values in the array are uninitiallized.
    chunks: [ChunkPointer<T>; MAX_CHUNK_COUNT],
}

impl<T> SlotMap<T>
where
    T: 'static + ?Sized + Default,
{
    pub fn new() -> Self {
        SlotMap {
            chunk_count_for_reads: Default::default(),
            chunk_count_for_writes: Default::default(),
            next_slot_key: Default::default(),
            disallowed_partition_value: AtomicU32::new(u32::MAX),
            chunks: array![MaybeUninit::uninit(); MAX_CHUNK_COUNT],
        }
    }

    /// Stop this map from accepting new insertions. Any insertsions in progress
    /// when this is called will fail. This method can be called multiple times,
    /// but only the first caller (that actually changes the state) will receive
    /// true as the return value. All other calls will receive false.
    pub fn stop_inserts_for_partition(&self, partition: u32) -> bool {
        self.disallowed_partition_value.swap(partition, SeqCst) != partition
    }

    /// checks to see if inserts are allowed for the given partition
    pub fn inserts_allowed_for_partition(&self, partition: u32) -> bool {
        self.disallowed_partition_value.load(Acquire) != partition
    }

    /// Insert the given value without checking whether partitions are allowed
    pub fn insert(&self, value: T) -> SlotKey {
        if let Ok(key) = self.insert_impl(None, value) {
            key
        } else {
            unreachable!("Inserts without partition are infalible");
        }
    }

    /// Attempt to insert the given value into the slotmap with the given
    /// partiion. If inserts are allowed on the given partition, the insert will
    /// succeed, but if inserts are disallowed on the partition, then the insert
    /// will fail.
    ///
    /// Note. Partition is purely about exluding inserts. It has no bearing on
    /// how values are stored in the slot map
    pub fn try_insert(&self, partition: u32, value: T) -> Result<SlotKey, InsertError> {
        self.insert_impl(Some(partition), value)
    }

    /// Attempt to insert the given value into the slotmap with the given
    /// optional partiion. If inserts are allowed on the given partition or if
    /// no partition is specified, the insert will succeed, but if inserts are
    /// disallowed on the partition, then the insert will fail.
    ///
    /// Note. Partition is purely about exluding inserts. It has no bearing on
    /// how values are stored in the slot map
    fn insert_impl(&self, partition_opt: Option<u32>, value: T) -> Result<SlotKey, InsertError> {
        if let Some(partition) = partition_opt {
            if !self.inserts_allowed_for_partition(partition) {
                return Err(InsertError::InsertsDisallowedBeforeInsert);
            }
        }

        let result = SlotKey::new(self.next_slot_key.fetch_add(1, Relaxed) + ONE_GENERATION);

        let chunk_index = result.chunk_index();

        // We are preallocating the space for all the possible pointers to
        // chunks, so if we run out of space for chunks, we can't get more :(
        assert!(chunk_index < MAX_CHUNK_COUNT, "Maximum map size exceeded");

        // Check to see if a chunk has been allocated for this chunk_id
        loop {
            let chunk_count = self.chunk_count_for_reads.load(Acquire);
            if chunk_count > chunk_index {
                break;
            }

            if self
                .chunk_count_for_writes
                .compare_exchange(chunk_count, chunk_count + 1, SeqCst, Relaxed)
                .is_ok()
            {
                let next_chunk = new_chunk();

                // Allocate the next chunk. This is safe because
                //  1. `chunk_count` < MAX_CHUNK_COUNT
                //  2. We will be writing a valid pointer to the chunk array
                //     before dereferencing.
                //  3. We are inside a spin lock that ensures each entry in the
                //     chunks array will only be written to once.
                //
                // TODO: remove #![allow(invalid_reference_casting)] and replace with
                //       UnsafeCell
                unsafe {
                    let chunk_pointer_pointer =
                        self.chunks.get_unchecked(chunk_count as usize) as *const ChunkPointer<T>;

                    let chunk_pointer_writeable =
                        &mut *(chunk_pointer_pointer as *mut ChunkPointer<T>);

                    *chunk_pointer_writeable = next_chunk;
                }

                self.chunk_count_for_reads.store(chunk_count + 1, Release);

                break;
            }
        }

        // This is safe because
        //  1. The ChunkPointer at the current index is guaranteed to be valid
        //     because of the above.
        //  2. The Chunk pointed to by the chunk pointer is guaranteed to be
        //     allocated.
        //  3. The size of the allocated chunk is greater than index in the
        //     slot.
        unsafe {
            let slot = (self.get_unchecked_slot(result) as *const Slot<T>) as *mut Slot<T>;
            (*slot).1 = value;
            (*slot).0.fetch_add(ONE_GENERATION, SeqCst);

            // Last chance to check if inserts were blocked was called during
            // insertion. If it was, then we increase the generation on
            // the slot again and return None indicating the insert failed
            if let Some(partition) = partition_opt {
                if !self.inserts_allowed_for_partition(partition) {
                    (*slot).0.fetch_add(ONE_GENERATION, SeqCst);

                    return Err(InsertError::InsertsDisallowedDuringInsert);
                }
            }
        }

        Ok(result)
    }

    /// Gets a reference to the slot at the given slotkey, but with no checks to
    /// ensure the slot exists and is not deleted.
    unsafe fn get_unchecked_slot(&self, slot_key: SlotKey) -> &Slot<T> {
        let chunk_index = slot_key.chunk_index();
        let index_in_chunk = slot_key.slot_index();

        let chunk = self.chunks.get_unchecked(chunk_index).assume_init_ref();

        chunk.get_unchecked(index_in_chunk)
    }

    /// Gets a reference to the value at the given slotkey, but with no checks
    /// to ensure the slot exists and is not deleted.
    pub unsafe fn get_unchecked(&self, slot_key: SlotKey) -> &T {
        &self.get_unchecked_slot(slot_key).1
    }

    /// Gets the value of the slot at the given key if the slot exists and if the
    /// generation of the key matches the generation in the slot.
    pub fn get(&self, slot_key: SlotKey) -> Option<&T> {
        let chunk_index = slot_key.chunk_index();
        let index_in_chunk = slot_key.slot_index();
        let key_generation = slot_key.generation();

        let chunk_count = self.chunk_count_for_reads.load(Acquire) as usize;

        (chunk_count > chunk_index)
            .then(|| {
                // This is safe because the chunk_index is less than the number
                // of chunks that have been allocated
                unsafe { self.chunks.get_unchecked(chunk_index).assume_init_ref() }
            })
            .map(|chunk| {
                // This is safe because we know the chunk will have been
                // allocated, and the index in that chunk is guaranteed to be
                // less than the size of the chunk.
                unsafe { (*chunk).get_unchecked(index_in_chunk) }
            })
            .filter(|(slot_data, _)| {
                SlotKey::new(slot_data.load(Relaxed)).generation() == key_generation
            })
            .map(|(_, v)| v)
    }

    /// get an iterator of all the entries in the slotmap.
    pub fn entries(&self) -> impl Iterator<Item = (SlotKey, &T)> {
        (0..self.chunk_count_for_reads.load(Relaxed))
            .map(|chunk_index| {
                // This is safe because the range we are iterating over is
                // limitted to the range where we can guarantee the chunks have
                // been allocated.
                let chunk = unsafe { self.chunks.get_unchecked(chunk_index).assume_init_ref() };
                (chunk_index, chunk)
            })
            .flat_map(|(chunk_idx, chunk)| repeat(chunk_idx).zip(chunk.iter().enumerate()))
            .map(|(chunk_idx, (slot_idx, (slot_metadata, value)))| {
                let generation = SlotKey::new(slot_metadata.load(Relaxed)).generation();
                let slot_key = SlotKey::new_from_parts(chunk_idx, slot_idx, generation);
                (slot_key, value)
            })
            .filter(|(slot_key, _)| slot_key.generation() % 2 == 1)
    }
}

impl<T> Drop for SlotMap<T> {
    fn drop(&mut self) {
        for chunk_index in 0..self.chunk_count_for_reads.load(Relaxed) {
            // This is safe because the range we are iterating over is limitted
            // to the range where we can guarantee the chunks have been
            // allocated.
            unsafe {
                self.chunks
                    .get_unchecked_mut(chunk_index)
                    .assume_init_drop();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    fn new_slot_map() -> SlotMap<AtomicU32> {
        SlotMap::new()
    }

    #[test]
    fn test_happy_path() {
        let map = new_slot_map();

        let i_value_1 = 42;
        let i_value_2 = 101;

        // test writing
        let key1 = map
            .try_insert(0, AtomicU32::new(i_value_1))
            .expect("Insert failed");
        let key2 = map
            .try_insert(0, AtomicU32::new(i_value_2))
            .expect("Insert failed");

        // Test reading
        let v1 = map.get(key1).expect("This was just added");
        let v2 = map.get(key2).expect("This was just added");
        assert_eq!(v1.load(Relaxed), i_value_1);
        assert_eq!(v2.load(Relaxed), i_value_2);

        // Test iterating
        for (key, v) in map.entries() {
            if key == key1 {
                assert_eq!(v.load(Relaxed), i_value_1);
            } else if key == key2 {
                assert_eq!(v.load(Relaxed), i_value_2);
            }
        }

        // Test mutating internal state while iterating
        for (_, v) in map.entries() {
            v.fetch_add(1, Relaxed);
        }

        // Test reading after mutating
        let v1 = map.get(key1).expect("This was just added");
        let v2 = map.get(key2).expect("This was just added");
        assert_eq!(v1.load(Relaxed), i_value_1 + 1);
        assert_eq!(v2.load(Relaxed), i_value_2 + 1);
    }

    #[derive(Default, Debug)]
    struct TestDroppable(usize, Option<Arc<AtomicUsize>>);

    impl Drop for TestDroppable {
        fn drop(&mut self) {
            if let Some(drop_count) = &self.1 {
                drop_count.fetch_add(1, Relaxed);
            }
        }
    }

    #[test]
    fn test_drop() {
        let drop_counter = Arc::new(AtomicUsize::default());
        let to_drop_count = 100;
        {
            let map: SlotMap<TestDroppable> = SlotMap::new();

            for i in 0..to_drop_count {
                let _ = map
                    .try_insert(0, TestDroppable(i, Some(Arc::clone(&drop_counter))))
                    .expect("insert failed");
            }
        }

        assert_eq!(to_drop_count, drop_counter.load(Relaxed));
    }

    #[test]
    fn test_thread_safety() {
        let thread_count = 100;
        let insert_count = 10000;

        let drop_counter = Arc::new(AtomicUsize::default());

        // Test basic thread safety by inserting a bunch of values on different
        // threads and ensure that the number dropped equals the number inserted.
        {
            let map: Arc<SlotMap<TestDroppable>> = Arc::new(SlotMap::new());

            (0..thread_count)
                .map(|thread_num| {
                    let map_clone = Arc::clone(&map);
                    let dc_clone = Arc::clone(&drop_counter);
                    thread::spawn(move || {
                        (0..insert_count)
                            .map(|i| {
                                // Do some inserting
                                map_clone
                                    .try_insert(
                                        0,
                                        TestDroppable(
                                            thread_num * insert_count + i,
                                            Some(Arc::clone(&dc_clone)),
                                        ),
                                    )
                                    .expect("Insert failed")
                            })
                            .enumerate()
                            .for_each(|(i, key)| {
                                // And some reading
                                assert_eq!(
                                    Some(thread_num * insert_count + i),
                                    map_clone.get(key).map(|v| v.0)
                                );
                            })
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .for_each(|t| t.join().expect("Failed to join"));
        }

        assert_eq!(thread_count * insert_count, drop_counter.load(SeqCst));
    }

    #[test]
    fn test_insert_after_disable() {
        let map = new_slot_map();

        assert!(map.try_insert(0, AtomicU32::new(1)).is_ok());

        map.stop_inserts_for_partition(0);

        assert!(map.try_insert(0, AtomicU32::new(2)).is_err());

        // Inserting without a partition should still be allowed
        let key = map.insert(AtomicU32::new(3));
        assert_eq!(map.get(key).unwrap().load(SeqCst), 3);
    }
}
