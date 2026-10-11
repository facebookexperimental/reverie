//! A caller-owned allocator must remain independent of the LiteInst rlib.

use std::alloc::GlobalAlloc;
use std::alloc::Layout;
use std::alloc::System;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

struct CountingSystem;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every operation preserves System's pointer and layout contract.
unsafe impl GlobalAlloc for CountingSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingSystem = CountingSystem;

reverie_liteinst::declare_legacy_tool_backing!();

fn main() {
    const BYTES: usize = 96 * 1024 * 1024;
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    let mut allocation = Vec::<u8>::new();
    allocation
        .try_reserve_exact(BYTES)
        .expect("96 MiB caller allocation");
    allocation.resize(BYTES, 0xa7);
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    assert!(after > before, "caller allocator was not used");
    assert_eq!(allocation.len(), BYTES);
    for (index, value) in allocation.iter_mut().enumerate() {
        assert_eq!(*value, 0xa7);
        *value = (index as u8).wrapping_mul(31).wrapping_add(9);
    }
    for (index, value) in allocation.iter().enumerate() {
        assert_eq!(*value, (index as u8).wrapping_mul(31).wrapping_add(9));
    }
    assert_eq!(
        reverie_liteinst::allocator_fixture::m1_probe_private(allocation.as_ptr()),
        0,
        "host allocation entered a Tool reserve"
    );
    println!(
        "M1_HOST_CONTROL bytes={BYTES} allocations={} private=0 bytes_ok=1",
        after - before
    );
    std::hint::black_box(&allocation);
}
