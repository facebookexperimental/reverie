/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::sync::mpsc;
use std::task::Context;
use std::time::Duration;
use std::time::Instant;

use futures::FutureExt;

use super::*;

const WAIT: Duration = Duration::from_secs(5);
const BASE: u64 = 0x1000;
const LENGTH: usize = 1024 * 1024 + PAGE_SIZE;

// Release every controlled host wait before joining, including during an
// assertion's unwind. No worker waits for the controller to finish close.
#[derive(Default)]
struct Workers {
    releases: Vec<mpsc::Sender<()>>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

impl Workers {
    fn spawn<T: Send + 'static>(
        &mut self,
        body: impl FnOnce() -> T + Send + 'static,
    ) -> mpsc::Receiver<T> {
        let (send, receive) = mpsc::channel();
        self.handles.push(std::thread::spawn(move || {
            let result = body();
            let _ = send.send(result);
        }));
        receive
    }

    fn join(&mut self) {
        while let Some(handle) = self.handles.last() {
            let deadline = Instant::now() + WAIT;
            while !handle.is_finished() {
                assert!(Instant::now() < deadline, "snapshot worker did not return");
                std::thread::yield_now();
            }
            self.handles.pop().unwrap().join().unwrap();
        }
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        for release in self.releases.drain(..) {
            let _ = release.send(());
        }
        for handle in self.handles.drain(..) {
            let result = handle.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn memory() -> (GuestMemory, Vec<u8>) {
    let memory = GuestMemory::new(BASE, LENGTH).unwrap();
    let expected: Vec<_> = (0..LENGTH).map(|offset| (offset % 251) as u8).collect();
    memory.write_raw(BASE, &expected).unwrap();
    (memory, expected)
}

fn wait_for_copy(gate: &crate::entry::EntryGate, minimum: usize) {
    let deadline = Instant::now() + WAIT;
    loop {
        // This takes the real admission mutex after Condvar::wait released it.
        // It cannot observe merely a thread launched before copy_blocking.
        let state = gate.test_state();
        if state.copy_waiters.len() >= minimum {
            assert_eq!(state.copy_waiters.len(), minimum);
            assert!(state.copy_waits >= state.copy_waiters.len());
            assert_eq!(state.copies, 0);
            assert!(!state.open);
            return;
        }
        assert!(
            Instant::now() < deadline,
            "copy did not wait on the closed gate"
        );
        std::thread::yield_now();
    }
}

fn assert_snapshot(snapshot: &GuestMemory, expected: &[u8], source: &GuestMemory) {
    assert!(!Arc::ptr_eq(&snapshot.entry_gate(), &source.entry_gate()));
    assert_ne!(snapshot.host_address(), source.host_address());
    let mut bytes = vec![0xff; expected.len()];
    snapshot.read_raw(BASE, &mut bytes).unwrap();
    assert_eq!(bytes, expected);
}

fn admitted_copy_case(user: bool) {
    let (memory, expected) = memory();
    let gate = memory.entry_gate();
    let mut workers = Workers::default();
    let (held, hold_observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    workers.releases.push(release.clone());
    let source = memory.clone();
    let snapshot = workers.spawn(move || {
        source.snapshot_with_sparse_copy(|source, destination, length| {
            held.send(()).unwrap();
            released.recv_timeout(WAIT).unwrap();
            copy_sparse_file(source, destination, length)
        })
    });
    hold_observed.recv_timeout(WAIT).unwrap();
    assert!(matches!(
        memory.mapping.slice.backing.host_access.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    assert_eq!(gate.test_state().copies, 0);

    let (contended, contention) = mpsc::channel();
    let mut reader = memory.clone();
    reader.test_backing_contention = Some(Arc::new(move || {
        contended.send(()).unwrap();
    }));
    let read = workers.spawn(move || {
        let mut bytes = vec![0xff; LENGTH];
        let result = if user {
            reader.user().read(BASE, &mut bytes)
        } else {
            reader.read_raw(BASE, &mut bytes)
        };
        result.map(|()| bytes)
    });
    contention.recv_timeout(WAIT).unwrap();
    assert_eq!(gate.test_state().copies, 1);
    let mut closing = Box::pin(gate.try_close().unwrap().unwrap().finish());
    assert!(
        closing
            .as_mut()
            .poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
            .is_pending(),
        "the actual admitted read still depends on the held backing lock"
    );
    assert!(!gate.test_state().closed);
    assert!(matches!(read.try_recv(), Err(mpsc::TryRecvError::Empty)));

    // An independent observer releases the host operation without waiting for
    // either the admitted reader or the incomplete close. The close future is
    // retained across this release rather than dropped to manufacture progress.
    let observed_gate = gate.clone();
    let (observe, observation) = mpsc::channel();
    workers.releases.push(observe.clone());
    let observer = workers.spawn(move || {
        observation.recv_timeout(WAIT).unwrap();
        let state = observed_gate.test_state();
        assert_eq!(state.copies, 1);
        assert!(!state.open);
        assert!(!state.closed);
        release.send(()).unwrap();
    });
    observe.send(()).unwrap();
    observer.recv_timeout(WAIT).unwrap();
    assert_eq!(read.recv_timeout(WAIT).unwrap().unwrap(), expected);
    let closed = closing
        .now_or_never()
        .expect("finished admitted read must release this same close")
        .unwrap();
    assert_eq!(gate.test_state().copies, 0);
    assert!(gate.test_state().closed);
    // A sparse-copy fallback may itself be waiting for fresh source admission.
    // Reopen before awaiting its full constructor or any worker join.
    drop(closed);
    let snapshot = snapshot.recv_timeout(WAIT).unwrap().unwrap();
    assert_snapshot(&snapshot, &expected, &memory);
    assert!(gate.pending_failure().is_none());
    workers.join();
}

#[test]
fn sparse_host_operation_keeps_close_pending_for_admitted_raw_read() {
    admitted_copy_case(false);
}

#[test]
fn sparse_host_operation_keeps_close_pending_for_admitted_user_read() {
    admitted_copy_case(true);
}

fn no_admitted_copy_case(force_fallback: bool) {
    let (memory, expected) = memory();
    let gate = memory.entry_gate();
    let mut workers = Workers::default();
    let (held, hold_observed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    workers.releases.push(release.clone());
    let (host_returned, host_return) = mpsc::channel();
    let source = memory.clone();
    let snapshot = workers.spawn(move || {
        source.snapshot_with_sparse_copy(|source, destination, length| {
            // SAFETY: duplicate the actual snapshot destination descriptor so
            // the controller can inspect the deliberately dirty prefix without
            // inventing a Mapping or bypassing a production short-copy token.
            let duplicate = unsafe { libc::fcntl(destination, libc::F_DUPFD_CLOEXEC, 0) };
            assert!(duplicate >= 0);
            let duplicate = unsafe { OwnedFd::from_raw_fd(duplicate) };
            held.send(duplicate).unwrap();
            released.recv_timeout(WAIT).unwrap();
            let result = if force_fallback {
                let dirty = [0xa5_u8; 257];
                // SAFETY: the actual snapshot helper owns both backing locks;
                // this fd write is the injected partial host operation.
                assert_eq!(
                    unsafe { libc::pwrite(destination, dirty.as_ptr().cast(), dirty.len(), 0) },
                    dirty.len() as isize
                );
                Err(io::Error::other(
                    "partial sparse copy requires full fallback",
                ))
            } else {
                copy_sparse_file(source, destination, length)
            };
            host_returned.send(result.is_ok()).unwrap();
            result
        })
    });
    let destination = hold_observed.recv_timeout(WAIT).unwrap();
    assert_eq!(gate.test_state().copies, 0);
    let closed = gate
        .try_close()
        .unwrap()
        .unwrap()
        .finish()
        .now_or_never()
        .expect("the held sparse fd operation is not a short-copy lease")
        .unwrap();
    assert!(gate.test_state().closed);
    assert!(matches!(
        snapshot.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    let reader = memory.clone();
    let read = workers.spawn(move || {
        let mut bytes = vec![0xff; LENGTH];
        reader.user().read(BASE, &mut bytes).map(|()| bytes)
    });
    wait_for_copy(&gate, 1);
    assert!(matches!(read.try_recv(), Err(mpsc::TryRecvError::Empty)));
    release.send(()).unwrap();
    let sparse_succeeded = host_return.recv_timeout(WAIT).unwrap();
    if !sparse_succeeded {
        // One external reader and the real first fallback read are both denied.
        wait_for_copy(&gate, 2);
        assert!(matches!(
            snapshot.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
    if force_fallback {
        assert!(!sparse_succeeded);
        let mut prefix = [0_u8; 258];
        // SAFETY: this owned fd is the actual destination. The observed denied
        // fallback has not acquired any source copy token or written bytes.
        assert_eq!(
            unsafe {
                libc::pread(
                    destination.as_raw_fd(),
                    prefix.as_mut_ptr().cast(),
                    prefix.len(),
                    0,
                )
            },
            prefix.len() as isize
        );
        assert_eq!(&prefix[..257], &[0xa5_u8; 257]);
        assert_eq!(prefix[257], 0);
    }
    assert!(gate.test_state().closed);
    assert_eq!(gate.test_state().copies, 0);
    drop(closed);
    assert_eq!(read.recv_timeout(WAIT).unwrap().unwrap(), expected);
    let snapshot = snapshot.recv_timeout(WAIT).unwrap().unwrap();
    assert_snapshot(&snapshot, &expected, &memory);
    assert!(gate.pending_failure().is_none());
    workers.join();
}

#[test]
fn sparse_host_operation_without_admitted_copy_allows_close() {
    no_admitted_copy_case(false);
}

#[test]
fn partial_sparse_fallback_waits_for_reopen_and_overwrites_full_destination() {
    no_admitted_copy_case(true);
}
