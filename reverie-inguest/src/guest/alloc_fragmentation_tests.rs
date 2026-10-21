/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Capacity regressions on fresh, static instances of the actual Tool heap.
//! These do not construct a 32 MiB arena on the test thread's stack.

use super::*;

#[test]
fn freed_large_block_does_not_become_a_tiny_live_allocation() {
    static HEAP: ToolHeap = ToolHeap::new();
    // Offset zero stays unused; the first aligned payload starts at byte 32.
    // This allocation exhausts the bump range before any free-list reuse.
    let large = HEAP.allocate(Layout::from_size_align(TOOL_HEAP_BYTES - 32, 8).unwrap());
    assert!(!large.is_null(), "initial whole-arena allocation failed");
    assert!(
        HEAP.allocate(Layout::from_size_align(1, 8).unwrap())
            .is_null()
    );
    // SAFETY: large is a live allocation from this isolated heap.
    unsafe { HEAP.deallocate(large) };

    let tiny = HEAP.allocate(Layout::from_size_align(1, 8).unwrap());
    assert!(
        !tiny.is_null(),
        "tiny allocation did not reuse the free block"
    );
    // SAFETY: tiny is live and has one writable byte.
    unsafe { tiny.write(0x3c) };
    let buffer = HEAP.allocate(Layout::from_size_align(32768, 8).unwrap());
    let recovered = !buffer.is_null();
    if recovered {
        assert!(HEAP.contains(buffer));
        assert!(!(buffer as usize..buffer as usize + 32768).contains(&(tiny as usize)));
        // SAFETY: buffer is live and has 32768 writable bytes; tiny is disjoint.
        unsafe {
            buffer.write_bytes(0xa5, 32768);
            assert_eq!(tiny.read(), 0x3c);
            HEAP.deallocate(buffer);
        }
    }
    // SAFETY: tiny remains live even when the second allocation fails.
    unsafe { HEAP.deallocate(tiny) };
    assert!(
        recovered,
        "a one-byte live allocation retained the freed large span; 32768 bytes must still fit"
    );
}

struct LiveAllocation {
    heap: &'static ToolHeap,
    pointer: *mut u8,
    size: usize,
}

impl LiveAllocation {
    fn new(heap: &'static ToolHeap, size: usize, alignment: usize) -> Self {
        let pointer = heap.allocate(Layout::from_size_align(size, alignment).unwrap());
        assert!(!pointer.is_null(), "allocation of {size} bytes failed");
        assert!(heap.contains(pointer));
        assert_eq!(pointer as usize % alignment, 0);
        let end = (pointer as usize).checked_add(size).unwrap();
        assert!(end <= heap.base() as usize + TOOL_HEAP_BYTES);
        Self {
            heap,
            pointer,
            size,
        }
    }

    fn paint_edges(&self, value: u8) {
        let count = self.size.min(64);
        // SAFETY: both edge ranges are within this live allocation.
        unsafe {
            self.pointer.write_bytes(value, count);
            self.pointer
                .add(self.size - count)
                .write_bytes(value, count);
        }
    }

    fn check_edges(&self, value: u8) {
        let count = self.size.min(64);
        for index in 0..count {
            // SAFETY: both reads are within this live allocation.
            unsafe {
                assert_eq!(self.pointer.add(index).read(), value);
                assert_eq!(self.pointer.add(self.size - count + index).read(), value);
            }
        }
    }
}

impl Drop for LiveAllocation {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns one live allocation from its heap.
        unsafe { self.heap.deallocate(self.pointer) };
    }
}

fn assert_disjoint(left: &LiveAllocation, right: &LiveAllocation) {
    let a = left.pointer as usize;
    let b = right.pointer as usize;
    assert!(
        a + left.size <= b || b + right.size <= a,
        "live payload ranges overlap"
    );
}

fn block_remaining_bump(last: &LiveAllocation) -> LiveAllocation {
    let heap = last.heap;
    let payload_end = last.pointer as usize - heap.base() as usize + last.size;
    // Setup only: account for aligned block-header/back-pointer overhead when
    // consuming the remaining bump range. No free-list metadata is inspected.
    let start = align_up(payload_end, align_of::<ToolHeapBlock>()).unwrap();
    let size = TOOL_HEAP_BYTES
        .checked_sub(start)
        .and_then(|remaining| {
            remaining.checked_sub(size_of::<ToolHeapBlock>() + size_of::<usize>())
        })
        .unwrap();
    let blocker = LiveAllocation::new(heap, size, 8);
    blocker.paint_edges(0xb7);
    assert!(
        heap.allocate(Layout::from_size_align(1, 8).unwrap())
            .is_null(),
        "test setup did not exhaust bump space"
    );
    blocker
}

#[test]
fn adjacent_free_blocks_merge_in_predecessor_successor_and_bridge_orders() {
    static HEAPS: [ToolHeap; 3] = [const { ToolHeap::new() }; 3];
    // ABC exercises predecessor merging; CBA successor merging; ACB merges
    // both neighbors when the middle allocation is released last.
    for (heap, order) in HEAPS.iter().zip([[0, 1, 2], [2, 1, 0], [0, 2, 1]]) {
        let lower = LiveAllocation::new(heap, 64, 8);
        lower.paint_edges(0x31);
        let mut blocks = [
            Some(LiveAllocation::new(heap, 4096, 8)),
            Some(LiveAllocation::new(heap, 4096, 8)),
            Some(LiveAllocation::new(heap, 4096, 8)),
        ];
        let upper = LiveAllocation::new(heap, 64, 8);
        upper.paint_edges(0x73);
        let blocker = block_remaining_bump(&upper);
        for index in order {
            drop(blocks[index].take().unwrap());
        }
        // Each individual free payload is only 4096 bytes. Neither live
        // sentinel nor the bump-tail blocker may supply this merged request.
        let merged = LiveAllocation::new(heap, 3 * 4096, 8);
        for other in [&lower, &upper, &blocker] {
            assert_disjoint(&merged, other);
        }
        merged.paint_edges(0xa6);
        lower.check_edges(0x31);
        upper.check_edges(0x73);
        blocker.check_edges(0xb7);
        merged.check_edges(0xa6);
    }
}

#[test]
fn a_live_allocation_separates_nonadjacent_free_blocks() {
    static HEAP: ToolHeap = ToolHeap::new();
    let first = LiveAllocation::new(&HEAP, 4096, 8);
    let bridge = LiveAllocation::new(&HEAP, 64, 8);
    bridge.paint_edges(0x8b);
    let last = LiveAllocation::new(&HEAP, 4096, 8);
    let blocker = block_remaining_bump(&last);
    drop(first);
    drop(last);
    // Enough bytes are free in total, but no contiguous free span can hold
    // this payload. Merging across the live bridge would corrupt its bytes.
    let refused = HEAP.allocate(Layout::from_size_align(8192, 8).unwrap());
    bridge.check_edges(0x8b);
    blocker.check_edges(0xb7);
    assert!(
        refused.is_null(),
        "free spans merged across a live allocation"
    );
}

#[test]
fn repeated_maps_scratch_does_not_pin_large_spans_in_tiny_live_names() {
    static HEAP: ToolHeap = ToolHeap::new();
    let mut names: [Option<LiveAllocation>; 24] = std::array::from_fn(|_| None);
    for index in 0..names.len() {
        let scratch = LiveAllocation::new(&HEAP, 2 * 1024 * 1024, 8);
        for live in names.iter().flatten() {
            assert_disjoint(&scratch, live);
        }
        scratch.paint_edges(0xd4);
        scratch.check_edges(0xd4);
        drop(scratch);
        let name = LiveAllocation::new(&HEAP, 5, 8);
        for live in names.iter().flatten() {
            assert_disjoint(&name, live);
        }
        name.paint_edges(index as u8);
        names[index] = Some(name);
        for (earlier, live) in names.iter().take(index + 1).enumerate() {
            live.as_ref().unwrap().check_edges(earlier as u8);
        }
    }
    drop(names);
    let reused = LiveAllocation::new(&HEAP, 2 * 1024 * 1024, 8);
    reused.paint_edges(0xe5);
    reused.check_edges(0xe5);
}

#[test]
fn odd_payload_neighbors_and_overaligned_reuse_preserve_live_bytes() {
    static HEAP: ToolHeap = ToolHeap::new();
    let first = LiveAllocation::new(&HEAP, 1, 8);
    let second = LiveAllocation::new(&HEAP, 1, 8);
    let aligned = LiveAllocation::new(&HEAP, 257, 4096);
    aligned.paint_edges(0x49);
    let sentinel = LiveAllocation::new(&HEAP, 64, 8);
    sentinel.paint_edges(0x97);
    let blocker = block_remaining_bump(&sentinel);
    drop(first);
    drop(second);
    // Rounded block ends must retain the padding between these adjacent odd
    // allocations, so their combined range can satisfy a larger request.
    let joined = LiveAllocation::new(&HEAP, 16, 8);
    for other in [&aligned, &sentinel, &blocker] {
        assert_disjoint(&joined, other);
    }
    joined.paint_edges(0x25);
    aligned.check_edges(0x49);
    sentinel.check_edges(0x97);
    blocker.check_edges(0xb7);
    drop(aligned);
    let aligned_reused = LiveAllocation::new(&HEAP, 257, 4096);
    for other in [&joined, &sentinel, &blocker] {
        assert_disjoint(&aligned_reused, other);
    }
    aligned_reused.paint_edges(0x58);
    joined.check_edges(0x25);
    sentinel.check_edges(0x97);
    blocker.check_edges(0xb7);
    aligned_reused.check_edges(0x58);
}

#[test]
fn exact_minimum_remainder_is_reusable_and_short_remainder_stays_reserved() {
    static HEAPS: [ToolHeap; 2] = [const { ToolHeap::new() }; 2];
    for (heap, requested) in HEAPS.iter().zip([32, 49]) {
        let original = LiveAllocation::new(heap, 64, 8);
        let sentinel = LiveAllocation::new(heap, 64, 8);
        sentinel.paint_edges(0x69);
        let blocker = block_remaining_bump(&sentinel);
        drop(original);
        let replacement = LiveAllocation::new(heap, requested, 8);
        for other in [&sentinel, &blocker] {
            assert_disjoint(&replacement, other);
        }
        replacement.paint_edges(0xf1);
        let one = heap.allocate(Layout::from_size_align(1, 8).unwrap());
        if requested == 32 {
            // The remaining aligned span is exactly 32 bytes: enough for a
            // header, back-pointer and at least one byte of useful payload.
            assert!(!one.is_null(), "exact minimum remainder was discarded");
            assert!(heap.contains(one));
            assert!(
                !(replacement.pointer as usize..replacement.pointer as usize + requested)
                    .contains(&(one as usize))
            );
            // SAFETY: one is a distinct live one-byte allocation from heap.
            unsafe {
                one.write(0x42);
                assert_eq!(one.read(), 0x42);
                heap.deallocate(one);
            }
        } else {
            // Only eight bytes remain after rounding the 49-byte payload.
            // They cannot safely hold another block and must not be exposed.
            assert!(one.is_null(), "undersized remainder became an allocation");
        }
        replacement.check_edges(0xf1);
        sentinel.check_edges(0x69);
        blocker.check_edges(0xb7);
        drop(replacement);
        let restored = LiveAllocation::new(heap, 64, 8);
        restored.paint_edges(0x7a);
        sentinel.check_edges(0x69);
        blocker.check_edges(0xb7);
        restored.check_edges(0x7a);
    }
}
