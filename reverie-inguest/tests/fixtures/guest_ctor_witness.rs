/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Dynamic constructor witness: a `.init_array` constructor whose
//! first actions are to store a magic value into `WITNESS_SLOT` and
//! to write a marker. The constructor runs inside dynamic-loader
//! initialization, long before `main`, so a host that reads the
//! slot while the fresh image is stopped before release and still
//! finds zero has proof that no loader/libc initialization ran
//! either — the constructor escape class. `main` re-checks the
//! slot, so the store's liveness is proven by the guest itself; the
//! test needs only the slot's link address (the `WITNESS_SLOT`
//! symbol) and the stdout ordering.

use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// The witness slot: zero until the constructor runs.
#[unsafe(no_mangle)]
pub static WITNESS_SLOT: AtomicU64 = AtomicU64::new(0);

const MAGIC: u64 = u64::from_le_bytes(*b"CT0RRAN!");
const MARKER: &[u8] = b"CTOR_RAN\n";

#[used]
#[unsafe(link_section = ".init_array")]
static CTOR: extern "C" fn() = ctor;

extern "C" fn ctor() {
    WITNESS_SLOT.store(MAGIC, Ordering::Relaxed);
    // std is not initialized yet; write the marker with a raw syscall.
    // SAFETY: write(1, MARKER) only reads this image's static bytes.
    // The syscall clobbers RCX/R11, declared below; nothing else is
    // live across it that the ABI promises to preserve.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") 1i64 => _,
            in("rdi") 1i64,
            in("rsi") MARKER.as_ptr(),
            in("rdx") MARKER.len(),
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

fn main() {
    if WITNESS_SLOT.load(Ordering::Relaxed) == MAGIC {
        println!("CTOR_WITNESS_OK");
    } else {
        println!("CTOR_WITNESS_MISSING");
        std::process::exit(3);
    }
}
