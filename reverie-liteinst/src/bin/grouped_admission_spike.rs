/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Standalone protocol-model spike for grouped (per-mapping-generation)
//! code admission. This is not a backend mode and wires into no runtime:
//! it models the admission state machine with raw `mmap`/`mprotect` and a
//! `SIGSEGV` handler so the revocation, entry-closure and concurrent
//! first-fault properties can be witnessed before any gate integration.
//!
//! One mode per process (the refusal modes exit from inside the handler):
//! `admit`, `interior`, `revoke`, `readmit`, `concurrent`.

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("unsupported platform");
    std::process::exit(2);
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use spike::main;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod spike {
    use std::ffi::c_void;
    use std::process;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicU8;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    const PAGE: usize = 4096;
    const GROUP_PAGES: usize = 2;

    const SEALED: u8 = 0;
    const ADMITTING: u8 = 1;
    const ADMITTED: u8 = 2;

    const EXIT_STALE: i32 = 3;
    const EXIT_INTERIOR: i32 = 4;
    const EXIT_FOREIGN: i32 = 90;
    const EXIT_SPURIOUS: i32 = 91;
    const EXIT_STUCK: i32 = 92;

    /// The single modeled group descriptor. `mapping_gen` is bumped by the
    /// (modeled) mapping lifecycle on any remap or alias write; `cert_gen`
    /// is the generation the offline certificate was issued for. Admission
    /// requires the two to agree.
    struct Gate {
        lo: AtomicUsize,
        hi: AtomicUsize,
        state: AtomicU8,
        mapping_gen: AtomicU64,
        cert_gen: AtomicU64,
        faults: AtomicU64,
        admissions: AtomicU64,
        entries: [AtomicUsize; 2],
    }

    static GATE: Gate = Gate {
        lo: AtomicUsize::new(0),
        hi: AtomicUsize::new(0),
        state: AtomicU8::new(SEALED),
        mapping_gen: AtomicU64::new(1),
        cert_gen: AtomicU64::new(1),
        faults: AtomicU64::new(0),
        admissions: AtomicU64::new(0),
        entries: [AtomicUsize::new(0), AtomicUsize::new(0)],
    };

    fn refuse(msg: &[u8], code: i32) -> ! {
        unsafe {
            libc::write(libc::STDERR_FILENO, msg.as_ptr().cast(), msg.len());
            libc::_exit(code);
        }
    }

    extern "C" fn on_segv(_sig: libc::c_int, info: *mut libc::siginfo_t, _ctx: *mut c_void) {
        let addr = unsafe { (*info).si_addr() } as usize;
        let lo = GATE.lo.load(Ordering::Acquire);
        let hi = GATE.hi.load(Ordering::Acquire);
        if addr < lo || addr >= hi {
            refuse(b"R-CODE foreign-fault\n", EXIT_FOREIGN);
        }
        GATE.faults.fetch_add(1, Ordering::Relaxed);
        if GATE.cert_gen.load(Ordering::Acquire) != GATE.mapping_gen.load(Ordering::Acquire) {
            refuse(b"R-CODE stale-generation\n", EXIT_STALE);
        }
        if GATE.state.load(Ordering::Acquire) == ADMITTED {
            // Fault delivered just before a racing winner published RX:
            // retrying the fetch now succeeds.
            return;
        }
        let is_entry = GATE
            .entries
            .iter()
            .any(|e| lo + e.load(Ordering::Relaxed) == addr);
        if !is_entry {
            refuse(b"R-CODE interior-entry\n", EXIT_INTERIOR);
        }
        match GATE
            .state
            .compare_exchange(SEALED, ADMITTING, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                // One permission flip admits the whole group extent.
                let rc = unsafe {
                    libc::mprotect(
                        lo as *mut c_void,
                        hi - lo,
                        libc::PROT_READ | libc::PROT_EXEC,
                    )
                };
                if rc != 0 {
                    refuse(b"R-CODE mprotect-failed\n", EXIT_SPURIOUS);
                }
                GATE.admissions.fetch_add(1, Ordering::Relaxed);
                GATE.state.store(ADMITTED, Ordering::Release);
            }
            Err(_) => {
                // Lost the race: wait for the winner to publish RX.
                for _ in 0..50_000_000u32 {
                    if GATE.state.load(Ordering::Acquire) == ADMITTED {
                        return;
                    }
                    core::hint::spin_loop();
                }
                refuse(b"R-CODE admission-stuck\n", EXIT_STUCK);
            }
        }
    }

    fn install_handler() {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_segv as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()),
                0
            );
        }
    }

    /// Map a two-page group, plant one certified entry per page, seal NX.
    fn setup_group() -> usize {
        let len = PAGE * GROUP_PAGES;
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        // mov eax, 42; ret  /  mov eax, 7; ret
        let stub_a: [u8; 6] = [0xB8, 42, 0, 0, 0, 0xC3];
        let stub_b: [u8; 6] = [0xB8, 7, 0, 0, 0, 0xC3];
        unsafe {
            std::ptr::copy_nonoverlapping(stub_a.as_ptr(), base.cast(), stub_a.len());
            std::ptr::copy_nonoverlapping(
                stub_b.as_ptr(),
                base.byte_add(PAGE).cast(),
                stub_b.len(),
            );
            assert_eq!(libc::mprotect(base, len, libc::PROT_READ), 0);
        }
        let lo = base as usize;
        GATE.lo.store(lo, Ordering::Release);
        GATE.hi.store(lo + len, Ordering::Release);
        GATE.entries[0].store(0, Ordering::Release);
        GATE.entries[1].store(PAGE, Ordering::Release);
        lo
    }

    fn call_at(addr: usize) -> i32 {
        let f: extern "C" fn() -> i32 = unsafe { std::mem::transmute(addr) };
        f()
    }

    /// Model a remap / alias write: bump the mapping generation and
    /// re-seal NX *before* any further execution. The old certificate
    /// (issued for the previous generation) is now stale.
    fn revoke(lo: usize) {
        GATE.mapping_gen.fetch_add(1, Ordering::AcqRel);
        GATE.state.store(SEALED, Ordering::Release);
        let rc = unsafe { libc::mprotect(lo as *mut c_void, PAGE * GROUP_PAGES, libc::PROT_READ) };
        assert_eq!(rc, 0);
    }

    fn report(tag: &str) {
        println!(
            "{tag} faults={} admissions={} mapping_gen={} cert_gen={}",
            GATE.faults.load(Ordering::Relaxed),
            GATE.admissions.load(Ordering::Relaxed),
            GATE.mapping_gen.load(Ordering::Relaxed),
            GATE.cert_gen.load(Ordering::Relaxed),
        );
    }

    pub fn main() {
        let mode = std::env::args().nth(1).unwrap_or_default();
        install_handler();
        let lo = setup_group();
        match mode.as_str() {
            "admit" => {
                assert_eq!(call_at(lo), 42);
                // Second page executes with no second fault: group flip.
                assert_eq!(call_at(lo + PAGE), 7);
                assert_eq!(GATE.faults.load(Ordering::Relaxed), 1);
                assert_eq!(GATE.admissions.load(Ordering::Relaxed), 1);
                report("ADMIT-OK");
            }
            "interior" => {
                // Sealed group, uncertified interior offset: must refuse.
                let _ = call_at(lo + 1);
                eprintln!("interior entry executed");
                process::exit(1);
            }
            "revoke" => {
                assert_eq!(call_at(lo), 42);
                revoke(lo);
                // Stale certificate against the new generation: must refuse.
                let _ = call_at(lo);
                eprintln!("stale generation executed");
                process::exit(1);
            }
            "readmit" => {
                assert_eq!(call_at(lo), 42);
                revoke(lo);
                // A fresh certificate for the current generation re-admits.
                GATE.cert_gen
                    .store(GATE.mapping_gen.load(Ordering::Acquire), Ordering::Release);
                assert_eq!(call_at(lo), 42);
                assert_eq!(GATE.admissions.load(Ordering::Relaxed), 2);
                report("READMIT-OK");
            }
            "bench" => {
                // Per-admission cost: revoke + recertify + fault-admit,
                // per iteration, over the same two-page group.
                assert_eq!(call_at(lo), 42);
                let iters = 2000u32;
                let mut samples = Vec::with_capacity(iters as usize);
                for _ in 0..iters {
                    revoke(lo);
                    GATE.cert_gen
                        .store(GATE.mapping_gen.load(Ordering::Acquire), Ordering::Release);
                    let start = std::time::Instant::now();
                    assert_eq!(call_at(lo), 42);
                    samples.push(start.elapsed().as_nanos() as u64);
                }
                samples.sort_unstable();
                println!(
                    "BENCH admissions={} per-admission fault+grant median_ns={} p90_ns={}",
                    GATE.admissions.load(Ordering::Relaxed),
                    samples[samples.len() / 2],
                    samples[samples.len() * 9 / 10],
                );
            }
            "concurrent" => {
                let barrier = Barrier::new(9);
                std::thread::scope(|scope| {
                    let mut handles = Vec::new();
                    for _ in 0..8 {
                        handles.push(scope.spawn(|| {
                            barrier.wait();
                            call_at(lo)
                        }));
                    }
                    barrier.wait();
                    for handle in handles {
                        assert_eq!(handle.join().unwrap(), 42);
                    }
                });
                assert_eq!(GATE.admissions.load(Ordering::Relaxed), 1);
                report("CONCURRENT-OK");
            }
            _ => {
                eprintln!(
                    "usage: grouped-admission-spike <admit|interior|revoke|readmit|concurrent|bench>"
                );
                process::exit(2);
            }
        }
    }
}
