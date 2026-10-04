/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The unchanged-mapping fence must not wait for a retained kernel operand or
//! for allocation-only mmap file preparation. These controls execute the real
//! Host adapters; they do not change a mapping while the fence is held.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

use futures::FutureExt;

use super::*;

type MmapReadObserver = Rc<dyn Fn()>;

thread_local! {
    static MMAP_READ_OBSERVER: RefCell<Option<MmapReadObserver>> = const { RefCell::new(None) };
}

pub(super) fn observe_mmap_file_read() {
    let observer = MMAP_READ_OBSERVER.with(|slot| slot.borrow().clone());
    if let Some(observer) = observer {
        observer();
    }
}

struct MmapObserverGuard(Option<MmapReadObserver>);

impl MmapObserverGuard {
    fn install(observer: MmapReadObserver) -> Self {
        Self(MMAP_READ_OBSERVER.with(|slot| slot.replace(Some(observer))))
    }
}

impl Drop for MmapObserverGuard {
    fn drop(&mut self) {
        let current = MMAP_READ_OBSERVER.with(|slot| slot.replace(self.0.take()));
        drop(current);
    }
}

struct FutexWaiter {
    handle: Option<JoinHandle<i64>>,
    // Both addresses belong to the retained Mapping until this worker joins.
    original_address: usize,
    requeued_address: usize,
}

impl FutexWaiter {
    fn join(&mut self) -> i64 {
        self.handle.take().unwrap().join().unwrap()
    }
}

impl Drop for FutexWaiter {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // Rescue only: a failing assertion can precede or follow requeue.
            // Wake both possible queues, then retain the real worker through
            // join. Its finite kernel timeout also bounds the pre-queue race.
            for address in [self.original_address, self.requeued_address] {
                // SAFETY: the controller's memory view outlives this guard;
                // the aligned words are inside it, and no layout is changed.
                unsafe {
                    libc::syscall(libc::SYS_futex, address, libc::FUTEX_WAKE, 1);
                }
            }
            let _ = handle.join();
        }
    }
}

#[test]
fn queued_host_futex_retains_operands_while_unchanged_mapping_fence_completes() {
    const WORD: u64 = 0x1_0000;
    const SECOND: u64 = WORD + 4;
    const TIMEOUT: u64 = WORD + 16;
    let started = Instant::now();
    let memory = GuestMemory::new(WORD, PAGE_SIZE as usize).unwrap();
    memory.map_user_range(WORD, PAGE_SIZE, false).unwrap();
    memory.enable_user_access();
    let timeout = libc::timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    // SAFETY: the bytes cover the initialized native timespec passed to the
    // actual host futex adapter, within the retained guest memory allocation.
    let timeout_bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(&timeout).cast::<u8>(),
            std::mem::size_of::<libc::timespec>(),
        )
    };
    memory.write_raw(TIMEOUT, timeout_bytes).unwrap();
    let owners = memory.test_mapping_owners();
    let gate = memory.entry_gate();
    let original_address = memory.host_address() as usize;
    let requeued_address = original_address + (SECOND - WORD) as usize;
    assert_eq!(original_address % std::mem::align_of::<u32>(), 0);
    assert_eq!(requeued_address % std::mem::align_of::<u32>(), 0);
    assert_eq!(owners(), 1);
    let waiting_memory = memory.clone();
    let (finished, completion) = mpsc::channel();
    let mut waiter = FutexWaiter {
        handle: Some(std::thread::spawn(move || {
            let wait_started_at = started.elapsed();
            // Exactly one adapter invocation, with no EINTR or timeout retry.
            let result = futex(
                &waiting_memory,
                &[WORD, libc::FUTEX_WAIT as u64, 0, TIMEOUT, 0, 0],
            );
            // Capture thread-local errno before any timestamp, channel or log
            // operation. The adapter result already preserves a failing host
            // errno; thread_errno is observational and is stale on success.
            // SAFETY: errno_location points to this live thread's errno cell.
            let thread_errno = unsafe { *libc::__errno_location() };
            let wait_returned_at = started.elapsed();
            finished.send(result).unwrap();
            eprintln!(
                "queued-host-futex wait result={result} result_errno={:?} thread_errno={thread_errno} started_at={wait_started_at:?} returned_at={wait_returned_at:?} elapsed={:?}",
                (result < 0).then_some(-result),
                wait_returned_at - wait_started_at,
            );
            result
        })),
        original_address,
        requeued_address,
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    let requeue_started_at = started.elapsed();
    let mut adapter_moves = 0;
    let mut last_move = None;
    let (requeued_at, requeue_errno, destination_observed_at) = loop {
        // Zero wakes, at most one requeue. A positive move proves queue
        // membership at that instant, not persistent sleep at SECOND: Linux
        // may internally retry or restart this same WAIT at its original WORD.
        let moved = futex(
            &memory,
            &[WORD, libc::FUTEX_CMP_REQUEUE as u64, 0, 1, SECOND, 0],
        );
        // SAFETY: errno_location points to this live thread's errno cell.
        let thread_errno = unsafe { *libc::__errno_location() };
        assert!(
            moved == 0 || moved == 1,
            "requeue returned {moved}, thread_errno={thread_errno}, elapsed={:?}",
            started.elapsed(),
        );
        if moved == 1 {
            adapter_moves += 1;
            last_move = Some((started.elapsed(), thread_errno));
        }
        // Independently require the actual destination key, so a broken
        // adapter that translated uaddr2 back to WORD cannot pass. Ordinary
        // same-key CMP_REQUEUE wakes nothing and does not change the key.
        // SAFETY: both aligned operands name SECOND in this live, unchanged
        // Mapping; the controller retains it until the real waiter joins.
        let destination = unsafe {
            libc::syscall(
                libc::SYS_futex,
                requeued_address,
                libc::FUTEX_CMP_REQUEUE,
                0,
                1,
                requeued_address,
                0,
            )
        };
        // SAFETY: errno_location points to this live thread's errno cell.
        let destination_errno = unsafe { *libc::__errno_location() };
        assert!(
            destination == 0 || destination == 1,
            "destination membership returned {destination}, thread_errno={destination_errno}"
        );
        if let (1, Some((requeued_at, requeue_errno))) = (destination, last_move) {
            break (requeued_at, requeue_errno, started.elapsed());
        }
        assert!(
            Instant::now() < deadline,
            "waiter never demonstrated adapter requeue and destination membership"
        );
        std::thread::yield_now();
    };
    assert_eq!(completion.try_recv(), Err(mpsc::TryRecvError::Empty));
    assert!(!waiter.handle.as_ref().unwrap().is_finished());
    // Controller view + waiter view + the retained word. The timeout was
    // copied into host-owned storage before the wait and retains no Mapping.
    // The operand admission tokens have retired; the word remains retained.
    assert_eq!(owners(), 3);
    assert_eq!(gate.test_state().copies, 0);
    assert_eq!(gate.test_state().retained_operands, 1);
    let close_started_at = started.elapsed();
    let closed = gate
        .try_close()
        .unwrap()
        .unwrap()
        .finish()
        .now_or_never()
        .expect("unchanged-mapping fence waited for the kernel futex")
        .unwrap();
    let closed_at = started.elapsed();
    assert!(gate.test_state().closed);
    assert_eq!(gate.test_state().copies, 0);
    assert_eq!(gate.test_state().retained_operands, 1);
    assert_eq!(owners(), 3);
    assert_eq!(completion.try_recv(), Err(mpsc::TryRecvError::Empty));
    assert!(!waiter.handle.as_ref().unwrap().is_finished());
    let reopen_started_at = started.elapsed();
    drop(closed);
    let reopened_at = started.elapsed();
    let wake_started_at = started.elapsed();
    let mut wake_rounds = 0;
    let mut wake = 0;
    let (wake_by_key, wake_errnos) = loop {
        // Reuse the initial two-second deadline; do not renew either this
        // budget or the worker's single five-second kernel WAIT. A retry can
        // briefly leave both queues empty before reenqueuing at WORD.
        assert!(
            Instant::now() < deadline,
            "controller never woke the retained waiter: rounds={wake_rounds}, elapsed={:?}",
            started.elapsed(),
        );
        wake_rounds += 1;
        let mut by_key = [0; 2];
        let mut errnos = [0; 2];
        for (index, address) in [SECOND, WORD].into_iter().enumerate() {
            by_key[index] = futex(&memory, &[address, libc::FUTEX_WAKE as u64, 1, 0, 0, 0]);
            // SAFETY: errno_location points to this live thread's errno cell.
            errnos[index] = unsafe { *libc::__errno_location() };
            assert!(
                by_key[index] == 0 || by_key[index] == 1,
                "wake at {address:#x} returned {}, thread_errno={}",
                by_key[index],
                errnos[index],
            );
            wake += by_key[index];
            assert!(wake <= 1, "more than one retained waiter was woken");
        }
        if wake == 1 {
            assert!(
                Instant::now() < deadline,
                "positive controller wake exceeded the shared admission deadline",
            );
            break (by_key, errnos);
        }
        // A zero-only round is not success. A signal, timeout, or unrelated
        // wake completing WAIT without our positive wake must still fail.
        assert_eq!(
            completion.try_recv(),
            Err(mpsc::TryRecvError::Empty),
            "WAIT completed without a positive controller wake",
        );
        assert!(!waiter.handle.as_ref().unwrap().is_finished());
        std::thread::yield_now();
    };
    let wake_returned_at = started.elapsed();
    eprintln!(
        "queued-host-futex controller original={original_address:#x} second={requeued_address:#x} requeue_started_at={requeue_started_at:?} requeued_at={requeued_at:?} requeue_thread_errno={requeue_errno} adapter_moves={adapter_moves} destination_observed_at={destination_observed_at:?} close_started_at={close_started_at:?} closed_at={closed_at:?} reopen_started_at={reopen_started_at:?} reopened_at={reopened_at:?} wake_started_at={wake_started_at:?} wake_returned_at={wake_returned_at:?} wake_total={wake} wake_rounds={wake_rounds} wake_by_key_second_original={wake_by_key:?} wake_thread_errnos={wake_errnos:?}",
    );
    assert_eq!(wake, 1);
    assert_eq!(completion.recv_timeout(Duration::from_secs(2)).unwrap(), 0);
    let join_started_at = started.elapsed();
    let joined = waiter.join();
    eprintln!(
        "queued-host-futex join result={joined} started_at={join_started_at:?} completed_at={:?}",
        started.elapsed(),
    );
    assert_eq!(joined, 0);
    assert_eq!(owners(), 1);
    assert!(gate.pending_failure().is_none());
    assert_eq!(
        futex(&memory, &[SECOND, libc::FUTEX_WAKE as u64, 1, 0, 0, 0]),
        0
    );
    assert_eq!(
        futex(&memory, &[WORD, libc::FUTEX_WAKE as u64, 1, 0, 0, 0]),
        0
    );
    drop(memory);
    assert_eq!(owners(), 0);
}

#[test]
fn futex_allow_lists_every_supported_command_and_clock_combination() {
    const WORD: u64 = 0x1_0000;
    let memory = GuestMemory::new(WORD, PAGE_SIZE as usize).unwrap();
    memory.enable_user_access();

    let allowed = [
        ("FUTEX_WAIT", libc::FUTEX_WAIT),
        ("FUTEX_WAKE", libc::FUTEX_WAKE),
        ("FUTEX_REQUEUE", libc::FUTEX_REQUEUE),
        ("FUTEX_CMP_REQUEUE", libc::FUTEX_CMP_REQUEUE),
        ("FUTEX_WAKE_OP", libc::FUTEX_WAKE_OP),
        ("FUTEX_LOCK_PI", libc::FUTEX_LOCK_PI),
        ("FUTEX_UNLOCK_PI", libc::FUTEX_UNLOCK_PI),
        ("FUTEX_TRYLOCK_PI", libc::FUTEX_TRYLOCK_PI),
        ("FUTEX_WAIT_BITSET", libc::FUTEX_WAIT_BITSET),
        ("FUTEX_WAKE_BITSET", libc::FUTEX_WAKE_BITSET),
        ("FUTEX_WAIT_REQUEUE_PI", libc::FUTEX_WAIT_REQUEUE_PI),
        ("FUTEX_CMP_REQUEUE_PI", libc::FUTEX_CMP_REQUEUE_PI),
        ("FUTEX_LOCK_PI2", libc::FUTEX_LOCK_PI2),
        (
            "FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME",
            libc::FUTEX_WAIT_BITSET | libc::FUTEX_CLOCK_REALTIME,
        ),
        (
            "FUTEX_WAIT_REQUEUE_PI|FUTEX_CLOCK_REALTIME",
            libc::FUTEX_WAIT_REQUEUE_PI | libc::FUTEX_CLOCK_REALTIME,
        ),
        (
            "FUTEX_LOCK_PI2|FUTEX_CLOCK_REALTIME",
            libc::FUTEX_LOCK_PI2 | libc::FUTEX_CLOCK_REALTIME,
        ),
    ];

    // Every admitted operation must pass both local deny-by-default gates.
    // The aligned but unmapped primary word then supplies one common, bounded
    // oracle: EFAULT proves the adapter did not reject the operation as ENOSYS.
    for (name, operation) in allowed {
        assert_eq!(
            futex(&memory, &[WORD, operation as u64, 0, 0, 0, 0]),
            negative_errno(libc::EFAULT),
            "{name} did not pass the futex allow lists"
        );
    }
}

#[test]
fn matching_futex_wait_observes_copied_finite_timeout() {
    const WORD: u64 = 0x1_0000;
    const SECOND: u64 = WORD + 4;
    const TIMEOUT: u64 = WORD + 16;
    let memory = GuestMemory::new(WORD, PAGE_SIZE as usize).unwrap();
    memory.map_user_range(WORD, PAGE_SIZE, false).unwrap();
    memory.write_raw(WORD, &0_u32.to_ne_bytes()).unwrap();
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    // SAFETY: the bytes cover the initialized native timespec copied by the
    // futex adapter, within this live guest allocation.
    let timeout_bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(&timeout).cast::<u8>(),
            std::mem::size_of::<libc::timespec>(),
        )
    };
    memory.write_raw(TIMEOUT, timeout_bytes).unwrap();
    memory.enable_user_access();

    let original_address = memory.host_address() as usize;
    let waiting_memory = memory.clone();
    let (finished, completion) = mpsc::channel();
    let mut waiter = FutexWaiter {
        handle: Some(std::thread::spawn(move || {
            let result = futex(
                &waiting_memory,
                &[WORD, libc::FUTEX_WAIT as u64, 0, TIMEOUT, 0, 0],
            );
            let _ = finished.send(result);
            result
        })),
        original_address,
        requeued_address: original_address + (SECOND - WORD) as usize,
    };

    // Passing NULL instead of the copied timespec would wait indefinitely. A
    // bounded receive detects that mutation; repeated rescue wakes then close
    // the worker before reporting the failure. The outer test command remains
    // the hard bound for a worker that never reaches the kernel queue.
    let result = match completion.recv_timeout(Duration::from_secs(2)) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => loop {
            // SAFETY: memory and its aligned futex word remain live until the
            // worker is joined below.
            unsafe {
                libc::syscall(libc::SYS_futex, original_address, libc::FUTEX_WAKE, 1);
            }
            match completion.recv_timeout(Duration::from_millis(1)) {
                Ok(rescued) => {
                    assert_eq!(waiter.join(), rescued);
                    panic!(
                        "matching FUTEX_WAIT did not complete within its finite timeout; \
                         rescue returned {rescued}"
                    );
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(error) => panic!("matching FUTEX_WAIT worker disconnected: {error}"),
            }
        },
        Err(error) => panic!("matching FUTEX_WAIT worker disconnected: {error}"),
    };
    assert_eq!(result, negative_errno(libc::ETIMEDOUT));
    assert_eq!(waiter.join(), result);
}

#[test]
fn futex_timeout_import_and_non_pi_word_alignment_follow_linux_fault_order() {
    const BASE: u64 = 0x1_0000;
    const WORD: u64 = BASE;
    const TIMEOUT_PAGE: u64 = BASE + PAGE_SIZE;
    const MAPPED_WORD: u64 = BASE + 2 * PAGE_SIZE;
    const TIMEOUT: u64 = TIMEOUT_PAGE + 64;
    let memory = GuestMemory::new(BASE, 3 * PAGE_SIZE as usize).unwrap();
    memory
        .map_user_range(TIMEOUT_PAGE, PAGE_SIZE, false)
        .unwrap();
    memory
        .map_user_range(MAPPED_WORD, PAGE_SIZE, false)
        .unwrap();
    memory.enable_user_access();

    // do_futex rejects invalid flag combinations and unsupported commands
    // before get_futex_key reaches a misaligned, inaccessible word.
    assert_eq!(
        futex(
            &memory,
            &[
                WORD + 1,
                (libc::FUTEX_WAIT | libc::FUTEX_CLOCK_REALTIME) as u64,
                0,
                0,
                0,
                0,
            ]
        ),
        negative_errno(libc::ENOSYS)
    );
    assert_eq!(
        futex(&memory, &[WORD + 1, 99, 0, 0, 0, 0]),
        negative_errno(libc::ENOSYS)
    );

    // FUTEX_UNLOCK_PI reads the word before key lookup, so an inaccessible,
    // misaligned address faults instead of reaching the alignment check.
    assert_eq!(
        futex(
            &memory,
            &[WORD + 1, libc::FUTEX_UNLOCK_PI as u64, 0, 0, 0, 0]
        ),
        negative_errno(libc::EFAULT)
    );

    // The outer sys_futex timeout import still precedes do_futex validation.
    assert_eq!(
        futex(
            &memory,
            &[
                WORD + 1,
                (libc::FUTEX_WAIT | libc::FUTEX_CLOCK_REALTIME) as u64,
                0,
                1,
                0,
                0,
            ]
        ),
        negative_errno(libc::EFAULT)
    );

    // sys_futex validates a readable timeout before do_futex reaches the
    // aligned but unmapped primary word.
    for malformed in [
        libc::timespec {
            tv_sec: -1,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: -1,
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 1_000_000_000,
        },
    ] {
        let malformed_bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&malformed).cast::<u8>(),
                std::mem::size_of::<libc::timespec>(),
            )
        };
        memory.write_raw(TIMEOUT, malformed_bytes).unwrap();
        for operation in [
            libc::FUTEX_WAIT,
            libc::FUTEX_LOCK_PI,
            libc::FUTEX_WAIT_BITSET,
            libc::FUTEX_WAIT_REQUEUE_PI,
            libc::FUTEX_LOCK_PI2,
        ] {
            assert_eq!(
                futex(&memory, &[WORD, operation as u64, 0, TIMEOUT, 0, 0]),
                negative_errno(libc::EINVAL),
                "operation {operation} must validate its timeout first"
            );
        }
    }

    let valid = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let valid_bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(&valid).cast::<u8>(),
            std::mem::size_of::<libc::timespec>(),
        )
    };
    memory.write_raw(TIMEOUT, valid_bytes).unwrap();

    // This input is EFAULT under either possible PI-word lookup order, so it
    // asserts only that WAIT_REQUEUE_PI retains the adapter's existing
    // translation behavior. PI lookup-order fidelity remains unverified.
    assert_eq!(
        futex(
            &memory,
            &[
                MAPPED_WORD + 1,
                libc::FUTEX_WAIT_REQUEUE_PI as u64,
                0,
                TIMEOUT,
                WORD,
                0,
            ]
        ),
        negative_errno(libc::EFAULT)
    );

    // Natural alignment is rejected before mapping accessibility, for both
    // words of the covered non-PI operations.
    assert_eq!(
        futex(
            &memory,
            &[WORD + 1, libc::FUTEX_WAIT as u64, 0, TIMEOUT, 0, 0]
        ),
        negative_errno(libc::EINVAL)
    );
    assert_eq!(
        futex(
            &memory,
            &[
                MAPPED_WORD,
                libc::FUTEX_CMP_REQUEUE as u64,
                0,
                1,
                WORD + 1,
                0,
            ]
        ),
        negative_errno(libc::EINVAL)
    );
}

#[test]
fn futex_timeout_copy_accepts_unaligned_readonly_cross_page_input() {
    const BASE: u64 = 0x1_0000;
    const WORD: u64 = BASE;
    const TIMEOUT_PAGE: u64 = BASE + PAGE_SIZE;
    const TIMEOUT: u64 = TIMEOUT_PAGE + PAGE_SIZE - 7;
    let memory = GuestMemory::new(BASE, 3 * PAGE_SIZE as usize).unwrap();
    memory.map_user_range(BASE, PAGE_SIZE, false).unwrap();
    memory
        .map_user_range(TIMEOUT_PAGE, 2 * PAGE_SIZE, false)
        .unwrap();
    memory.write_raw(WORD, &1_u32.to_ne_bytes()).unwrap();
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let timeout_bytes = unsafe {
        std::slice::from_raw_parts(
            std::ptr::from_ref(&timeout).cast::<u8>(),
            std::mem::size_of::<libc::timespec>(),
        )
    };
    memory.write_raw(TIMEOUT, timeout_bytes).unwrap();
    memory
        .map_user_permissions(TIMEOUT_PAGE, 2 * PAGE_SIZE, true, false)
        .unwrap();
    memory.enable_user_access();

    // Linux copies a timespec bytewise: it need not be naturally aligned or
    // writable. The mismatched word makes the actual host wait return EAGAIN.
    assert_eq!(
        futex(&memory, &[WORD, libc::FUTEX_WAIT as u64, 0, TIMEOUT, 0, 0]),
        negative_errno(libc::EAGAIN)
    );

    memory
        .map_user_permissions(TIMEOUT_PAGE + PAGE_SIZE, PAGE_SIZE, false, false)
        .unwrap();
    assert_eq!(
        futex(&memory, &[WORD, libc::FUTEX_WAIT as u64, 0, TIMEOUT, 0, 0]),
        negative_errno(libc::EFAULT)
    );
}

struct MmapReader {
    release: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<i64>>,
}

impl MmapReader {
    fn finish(&mut self) -> i64 {
        self.release.take().unwrap().send(()).unwrap();
        self.handle.take().unwrap().join().unwrap()
    }
}

impl Drop for MmapReader {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn allocation_held_mmap_file_read_does_not_hold_unchanged_mapping_fence() {
    let mut state = native_loaded_state(std::path::Path::new("/"));
    let expected_address = state.mmap_base;
    let memory = GuestMemory::new(0, state.mmap_limit as usize).unwrap();
    memory.enable_user_access();
    let expected: Vec<u8> = (0..PAGE_SIZE).map(|i| (i * 17 + 3) as u8).collect();
    // SAFETY: the fixed name is nul-terminated. A successful returned fd is
    // immediately owned by File and follows the ordinary mmap read path.
    let raw = unsafe { libc::memfd_create(c"entry-mmap-wait".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(
        raw >= 0,
        "memfd_create: {}",
        std::io::Error::last_os_error()
    );
    let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
    file.write_all(&expected).unwrap();
    let fd = insert_file_with_flags(&mut state, file, false, None);
    assert_eq!(fd, 3);
    let gate = memory.entry_gate();
    let owners = memory.test_mapping_owners();
    let mut reading_memory = memory.clone();
    let reads = Arc::new(AtomicUsize::new(0));
    let reader_reads = reads.clone();
    let (prepared, preparation) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (completed, completion) = mpsc::channel();
    let mut reader = MmapReader {
        release: Some(release),
        handle: Some(std::thread::spawn(move || {
            let _observer = MmapObserverGuard::install(Rc::new(move || {
                assert_eq!(reader_reads.fetch_add(1, Ordering::SeqCst), 0);
                prepared.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(5)).unwrap();
            }));
            // This wrapper owns the actual allocation_guard through mmap's
            // file.read_at loop, and only later performs admitted byte copies.
            let result = match execute_basic_syscall(
                &mut reading_memory,
                &mut state,
                &SyscallRequest::new(
                    libc::SYS_mmap as u64,
                    [
                        0,
                        PAGE_SIZE,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        libc::MAP_PRIVATE as u64,
                        fd as u64,
                        0,
                    ],
                ),
            ) {
                SyscallAction::Continue {
                    result,
                    segment: None,
                } => result,
                _ => panic!("mmap did not retain its ordinary syscall disposition"),
            };
            completed.send(result).unwrap();
            result
        })),
    };
    preparation.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(completion.try_recv(), Err(mpsc::TryRecvError::Empty));
    assert!(!reader.handle.as_ref().unwrap().is_finished());
    // The wrapper's extra owner is still live with its allocation guard.
    assert_eq!(owners(), 3);
    assert_eq!(gate.test_state().copies, 0);
    let closed = gate
        .try_close()
        .unwrap()
        .unwrap()
        .finish()
        .now_or_never()
        .expect("fence waited for allocation-held file preparation")
        .unwrap();
    assert!(gate.test_state().closed);
    assert_eq!(gate.test_state().copies, 0);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(completion.try_recv(), Err(mpsc::TryRecvError::Empty));
    // Reopen before releasing the actual file read and demanding the later
    // reservation/population completion; those byte copies need admission.
    drop(closed);
    assert_eq!(reader.finish(), expected_address as i64);
    assert_eq!(
        completion.recv_timeout(Duration::from_secs(2)).unwrap(),
        expected_address as i64
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_eq!(owners(), 1);
    let mut actual = vec![0; PAGE_SIZE as usize];
    memory.user().read(expected_address, &mut actual).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(
        memory.reservation_kind(expected_address),
        Some(RegionKind::Mmap)
    );
    assert!(gate.pending_failure().is_none());
    drop(memory);
    assert_eq!(owners(), 0);
}
