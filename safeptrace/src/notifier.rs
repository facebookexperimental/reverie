/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! # Making `ptrace` async
//!
//! Getting asynchronous notifications for a tree of child processes is tricky.
//! The common way is to just call `waitpid(-1)` in the tracer process and let
//! that scoop up every event for every child of the current process. This is
//! what `strace` and `rr` do to receive `ptrace` stop events. The problem is
//! that we shouldn't do something like that in a library like Reverie since we
//! don't know what other (untraced) processes the user has spawned. Calling
//! `waitpid(-1)` will consume and "steal" exit events from processes we aren't
//! actively tracing.
//!
//! The best solution would be one where we can wait on all child processes of a
//! specific subtree.
//!
//! ## Failed ideas
//!
//!  1. As an initial dumb implementation, we simply called `waitid` on all child
//!     processes one by one in a round-robin fashion until an event was finally
//!     received. While it worked, this wasn't the best solution for two reasons:
//!     (1) it uses a lot of CPU which starves the guest of CPU resources and
//!     slows everything down to a crawl, and (2) it didn't allow us to receive
//!     `PTRACE_EVENT_EXIT` events out-of-band which is necessary for canceling
//!     pending futures in the event a guest process is suddenly killed.
//!  2. Polling `pidfd_open(2)` descriptors does not report ptrace stops, so it
//!     cannot replace the per-tracee blocking waiter. The waiter does use
//!     `waitid(P_PIDFD)` to bind every status consumption to one exact kernel
//!     task lifetime rather than a reusable numeric PID.
//!  3. Using `tokio::task::spawn_blocking` to simply call `waitid()` on the
//!     process we're interested in works, but is about twice as slow as (1)
//!     because of the overhead of locking a mutex and shuffling bits of data
//!     in/out of the Tokio thread pool.
//!  4. Process groups sound like the ideal solution, but it is possible for a
//!     process to escape a process group by simply calling `setpgid(2)`. Thus,
//!     such a solution would need to be aware of all calls to `setpgid` and
//!     `setsid` to perform proper bookkeeping and maintain an internal set of
//!     process groups.
//!  5. We could fork off a child process that calls `waitpid(-1)`, which then
//!     sends events back to the tracer process via a pipe. The forked process
//!     would need to call `prctl` with `PR_SET_CHILD_SUBREAPER` so that orphaned
//!     processes don't escape the process tree. This is similar to [what Bazel
//!     does](https://jmmv.dev/2019/11/bazel-process-wrapper.html) to keep track
//!     of the process tree of a build rule. Unfortunately, this won't work
//!     because `ptrace` must be only be called by the *thread* that spawned the
//!     initial process.
//!
//! ## Current implementation
//!
//! Currently, we spawn one thread per guest thread who each call `waitid` in a
//! loop on an individual thread/process ID. The nice thing about this is that we
//! can receive `PTRACE_EVENT_EXIT` events "out-of-band" and use that to cancel
//! any futures that may be pending in a tool's `handle_syscall_event`. This
//! approach also avoids the overhead of shuffling events through Tokio's
//! blocking thread pool. (An `AtomicI32` plus a small persistent waker slot can
//! be used instead.) The downside of this approach is that we
//! can end up spawning a lot of guest threads.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::collections::hash_map::Entry;
use std::fs;
use std::fs::OpenOptions;
use std::future::Future;
use std::hash::Hash;
use std::hash::Hasher;
use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::pin::Pin;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Barrier;
use std::sync::LazyLock;
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
#[cfg(test)]
use std::sync::mpsc;
use std::task::Context;
use std::task::Poll;
use std::task::RawWakerVTable;
use std::task::Waker;
use std::thread;
use std::thread::JoinHandle;
#[cfg(test)]
use std::thread::ThreadId;
use std::time::Duration;
use std::time::Instant;

use nix::sys::wait::WaitPidFlag;
use parking_lot::Condvar;
use parking_lot::Mutex;
use parking_lot::MutexGuard;

use super::Errno;
use super::Error;
use super::Pid;
use super::Running;
use super::Stopped;
use super::TraceeToken;
use super::Wait;
use super::waitid;

static NOTIFIER: LazyLock<Notifier> = LazyLock::new(Notifier::new);

#[cfg(test)]
static CAPTURE_ERRORS: LazyLock<Mutex<HashMap<Pid, Errno>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static CAPTURE_PERSISTENT_ERRORS: LazyLock<Mutex<HashMap<Pid, Errno>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static FORCE_RAW_CLAIM_REGISTRATION_RACE: LazyLock<Mutex<HashMap<Pid, ()>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SPAWN_WORKER_ERRORS: LazyLock<Mutex<HashMap<Pid, i32>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SPAWN_WORKER_COUNTS: LazyLock<Mutex<HashMap<Pid, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static PIDFD_OPEN_ERRORS: LazyLock<Mutex<HashMap<Pid, Errno>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static PIDFD_LIVENESS_ERRORS: LazyLock<Mutex<HashMap<Pid, VecDeque<Errno>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
struct EventCapturePause {
    captured: Arc<Barrier>,
    resume: Arc<Barrier>,
}

#[cfg(test)]
#[derive(Debug)]
struct BoundedTestPause {
    captured: mpsc::SyncSender<()>,
    resume: mpsc::Receiver<()>,
}

#[cfg(test)]
#[derive(Debug)]
struct ExactTestMember {
    pid: Pid,
    pidfd: OwnedFd,
    phase: ExactCleanupPhase,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactCleanupPhase {
    NeedsSignal,
    NeedsReap,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct PendingExactRegistration {
    pid: Pid,
    error: Errno,
}

#[cfg(test)]
#[derive(Debug)]
struct NewChildDecodePause {
    captured: mpsc::SyncSender<()>,
    resume: mpsc::Receiver<()>,
    members: Arc<Mutex<Vec<ExactTestMember>>>,
    registration_error: Arc<Mutex<Option<PendingExactRegistration>>>,
    pidfd_open_error: Arc<Mutex<Option<Errno>>>,
}

#[cfg(test)]
static EVENT_CAPTURE_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static CURRENT_OR_NEW_CAPTURE_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SPAWN_FAILURE_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static PRE_REGISTRATION_REAP_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SYNC_WAIT_CLAIM_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SYNC_HANDLE_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static CLEANUP_OWNER_CLAIM_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static CLEANUP_CANCEL_SIGNAL_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SYNC_STATUS_PUBLICATION_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SYNC_RETURN_COMMIT_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static CAPTURE_AFTER_FIRST_SNAPSHOT_PAUSES: LazyLock<Mutex<HashMap<Pid, EventCapturePause>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static SYNC_DECODE_CAPTURE_ERRORS: LazyLock<Mutex<HashMap<Pid, Errno>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static CAPTURE_THREAD_ERRORS: LazyLock<Mutex<HashMap<ThreadId, VecDeque<Errno>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
pub(super) fn inject_capture_error_for_current_thread(error: Errno) {
    CAPTURE_THREAD_ERRORS
        .lock()
        .entry(thread::current().id())
        .or_default()
        .push_back(error);
}

#[cfg(test)]
pub(super) fn inject_sync_decode_capture_error(pid: Pid, error: Errno) {
    SYNC_DECODE_CAPTURE_ERRORS.lock().insert(pid, error);
}

#[cfg(test)]
pub(super) fn pause_sync_new_child_decode(handle: &EventHandle) {
    if let Some(pause) = handle.event().new_child_decode_pause.lock().take()
        && pause.captured.send(()).is_ok()
    {
        let _ = pause.resume.recv();
    }
}

#[cfg(test)]
pub(super) fn register_new_child_for_test_cleanup(
    handle: &EventHandle,
    child: Pid,
) -> Result<(), Errno> {
    let mut slot = handle.event().new_child_decode_pause.lock();
    let Some(pause) = slot.as_mut() else {
        return Ok(());
    };
    let injected = pause.pidfd_open_error.lock().take();
    let pidfd = match injected.map_or_else(|| open_thread_pidfd(child), Err) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            *pause.registration_error.lock() = Some(PendingExactRegistration { pid: child, error });
            return Err(error);
        }
    };
    pause.members.lock().push(ExactTestMember {
        pid: child,
        pidfd,
        phase: ExactCleanupPhase::NeedsSignal,
    });
    Ok(())
}

/// A place-holder status used to indicate that no status has been set.
const INVALID_STATUS: i32 = -1;

/// The notifier worker found that the PID is no longer a waitable child.
const ECHILD_STATUS: i32 = -2;

/// No `PTRACE_EVENT_EXIT` outcome has been published yet.
const EXIT_PENDING: i32 = 0;

/// The tracee entered `PTRACE_EVENT_EXIT`; this observation remains latched.
const EXIT_STOPPED: i32 = 1;

/// The tracee became terminal without an observed `PTRACE_EVENT_EXIT`.
const EXIT_ECHILD: i32 = 2;

const EXIT_CAP_PENDING: u8 = 0;
const EXIT_CAP_AVAILABLE: u8 = 1;
const EXIT_CAP_CLAIMED: u8 = 2;
const EXIT_CAP_EXPIRED: u8 = 3;
const EXIT_CAP_FINALIZING: u8 = 4;

const WORKER_NOT_STARTED: i32 = 0;
const WORKER_STARTING: i32 = 1;
const WORKER_RUNNING: i32 = 2;
const WORKER_FINISHING: i32 = 3;
const WORKER_DONE: i32 = 4;

const WAIT_OWNER_NONE: u8 = 0;
const WAIT_OWNER_SYNC: u8 = 1;
const WAIT_OWNER_NOTIFIER: u8 = 2;
const WAIT_OWNER_SYNC_RETURNING: u8 = 3;
const WAIT_OWNER_NOTIFIER_RETURNING: u8 = 4;

/// A newly forked TRACEME child can change TracerPid between the two procfs
/// snapshots used to bind its exact pidfd identity. Retry that finite
/// transition without ever falling back to a numeric wait.
const SYNC_IDENTITY_CAPTURE_RETRIES: usize = 8;

/// The number we get when in a PTRACE_EVENT_EXIT stop.
const PTRACE_EVENT_EXIT_STOP: i32 = (libc::PTRACE_EVENT_EXIT << 16) | (libc::SIGTRAP << 8) | 0x7f;

#[derive(Debug, Default)]
struct WakerSlot {
    waker: Mutex<Option<Waker>>,
    data: AtomicPtr<()>,
    vtable: AtomicPtr<RawWakerVTable>,
}

impl WakerSlot {
    /// Keeps one task registered across all status events for a PID.
    fn register(&self, waker: &Waker) -> bool {
        let data = waker.data().cast_mut();
        let vtable = std::ptr::from_ref(waker.vtable()).cast_mut();
        // The stored waker keeps its data identity live, so this pair cannot
        // be reused for a different task while it remains in the slot.

        if self.data.load(Ordering::Acquire) == data
            && self.vtable.load(Ordering::Relaxed) == vtable
        {
            return false;
        }

        let mut slot = self.waker.lock();
        if slot
            .as_ref()
            .is_some_and(|registered| registered.will_wake(waker))
        {
            return false;
        }

        *slot = Some(waker.clone());
        self.vtable.store(vtable, Ordering::Relaxed);
        // Publish data last so an Acquire match also observes the vtable.
        self.data.store(data, Ordering::Release);
        true
    }

    fn wake(&self) {
        let waker = self.waker.lock().as_ref().cloned();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[derive(Debug, Default)]
struct ExitWaiter {
    waker: WakerSlot,
}

#[derive(Debug, Default)]
struct ExitWaiters {
    waiters: Mutex<Vec<Weak<ExitWaiter>>>,
}

impl ExitWaiters {
    fn register(&self, waiter: &Arc<ExitWaiter>, waker: &Waker) {
        waiter.waker.register(waker);
        let weak = Arc::downgrade(waiter);
        let mut waiters = self.waiters.lock();
        waiters.retain(|registered| registered.strong_count() != 0);
        if !waiters.iter().any(|registered| registered.ptr_eq(&weak)) {
            waiters.push(weak);
        }
    }

    fn wake_all(&self) {
        let live = {
            let mut waiters = self.waiters.lock();
            let mut live = Vec::with_capacity(waiters.len());
            waiters.retain(|waiter| {
                if let Some(waiter) = waiter.upgrade() {
                    live.push(waiter);
                    true
                } else {
                    false
                }
            });
            live
        };
        for waiter in live {
            waiter.waker.wake();
        }
    }
}

#[derive(Debug)]
struct Event {
    /// Cancellation-safe weak registrations for every pending exit waiter.
    exit_waiters: ExitWaiters,

    /// Serializes the two-phase exit-stop publication with terminal
    /// finalization. The notifier worker normally supplies statuses in order,
    /// but unstarted-completion paths may publish ECHILD independently.
    exit_publication: Mutex<()>,

    /// Waker for regular status events.
    status_waker: WakerSlot,

    /// Ordered regular statuses plus a retained terminal publication.
    status: Mutex<StatusState>,

    /// Wakes synchronous cancellation cleanup when a status is published.
    status_changed: Condvar,

    /// Independently retained `PTRACE_EVENT_EXIT` publication. Keeping this
    /// separate prevents a following final wait status from stealing the exit
    /// event from a held [`ExitFuture`].
    exit_status: AtomicI32,

    /// Linear claim for the one stopped-state capability represented by this
    /// exact Event generation's retained exit-stop observation.
    exit_capability: AtomicU8,

    /// Last notifier registration error. Resource/read failures are retryable
    /// and must not be collapsed into terminal ECHILD.
    registration_error: Mutex<Option<Errno>>,

    /// Monotonic activity state owned by this exact Event generation.
    worker_state: AtomicI32,
    worker_done_lock: Mutex<()>,
    worker_done_changed: Condvar,

    /// Serializes kernel wait-status ownership before either synchronous
    /// fallback/capture or notifier registration can inspect mutable state.
    cleanup_cancel_requested: AtomicBool,
    cleanup_claim_waiters: AtomicUsize,
    wait_owner: AtomicU8,
    wait_owner_lock: Mutex<()>,
    wait_owner_changed: Condvar,

    #[cfg(test)]
    new_child_decode_pause: Mutex<Option<NewChildDecodePause>>,
    #[cfg(test)]
    cleanup_return_pause: Mutex<Option<BoundedTestPause>>,
}

#[derive(Debug)]
struct StatusState {
    pending: VecDeque<i32>,
    terminal: i32,
}

struct StatusReservation<'a> {
    status: i32,
    state: Option<MutexGuard<'a, StatusState>>,
}

enum StatusReturn<T> {
    Returned(T),
    Cancelled(i32),
}

struct ReturnTransaction<'a> {
    event: &'a Event,
    returning_owner: u8,
    rollback_owner: u8,
    completed: bool,
}

impl ReturnTransaction<'_> {
    fn commit(mut self, final_owner: u8) {
        let _guard = self.event.wait_owner_lock.lock();
        self.event
            .wait_owner
            .compare_exchange(
                self.returning_owner,
                final_owner,
                Ordering::Release,
                Ordering::Acquire,
            )
            .expect("status return ownership changed before commit");
        self.completed = true;
        self.event.wait_owner_changed.notify_all();
    }
}

impl Drop for ReturnTransaction<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let _guard = self.event.wait_owner_lock.lock();
        self.event
            .wait_owner
            .compare_exchange(
                self.returning_owner,
                self.rollback_owner,
                Ordering::Release,
                Ordering::Acquire,
            )
            .expect("status return ownership changed before rollback");
        self.event.wait_owner_changed.notify_all();
    }
}

enum ReturnTransactionStart<'a> {
    Begun(ReturnTransaction<'a>),
    Cancelled,
}

struct SyncWaitOwner<'a> {
    event: &'a Event,
    released: bool,
}

impl SyncWaitOwner<'_> {
    fn decode_status_return<T>(
        &mut self,
        _pid: Pid,
        reservation: StatusReservation<'_>,
        decode: impl FnOnce(i32) -> Result<T, Error>,
    ) -> Result<StatusReturn<T>, Error> {
        let transaction = match self.event.begin_status_return(
            reservation.status,
            WAIT_OWNER_SYNC,
            WAIT_OWNER_SYNC_RETURNING,
        ) {
            ReturnTransactionStart::Begun(transaction) => transaction,
            ReturnTransactionStart::Cancelled => {
                return Ok(StatusReturn::Cancelled(reservation.status));
            }
        };
        #[cfg(test)]
        if let Some(pause) = SYNC_RETURN_COMMIT_PAUSES.lock().remove(&_pid) {
            pause.captured.wait();
            pause.resume.wait();
        }
        let decoded = decode(reservation.status)?;
        reservation.commit();
        transaction.commit(WAIT_OWNER_NONE);
        self.released = true;
        Ok(StatusReturn::Returned(decoded))
    }
}

impl Drop for SyncWaitOwner<'_> {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let _guard = self.event.wait_owner_lock.lock();
        self.event
            .wait_owner
            .compare_exchange(
                WAIT_OWNER_SYNC,
                WAIT_OWNER_NONE,
                Ordering::Release,
                Ordering::Acquire,
            )
            .expect("synchronous wait ownership changed before release");
        self.event.wait_owner_changed.notify_all();
    }
}

enum SyncWaitOwnership<'a> {
    Claimed(SyncWaitOwner<'a>),
    Notifier,
}

struct NotifierWaitOwner<'a> {
    event: &'a Event,
    committed: bool,
}

impl NotifierWaitOwner<'_> {
    fn commit(mut self) {
        self.committed = true;
        self.event.notify_wait_owner_change();
    }
}

impl Drop for NotifierWaitOwner<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let _guard = self.event.wait_owner_lock.lock();
        self.event
            .wait_owner
            .compare_exchange(
                WAIT_OWNER_NOTIFIER,
                WAIT_OWNER_NONE,
                Ordering::Release,
                Ordering::Acquire,
            )
            .expect("notifier wait ownership changed before rollback");
        self.event.wait_owner_changed.notify_all();
    }
}

enum NotifierWaitOwnership<'a> {
    Claimed(NotifierWaitOwner<'a>),
    Existing,
}

#[cfg(test)]
enum CancellableNotifierWaitOwnership<'a> {
    Claimed(NotifierWaitOwner<'a>),
    Synchronous,
    Existing,
    Returning,
}

impl StatusReservation<'_> {
    fn commit(mut self) {
        if let Some(state) = self.state.as_mut() {
            let committed = state.pending.pop_front();
            debug_assert_eq!(committed, Some(self.status));
        }
    }
}

impl Event {
    pub fn new() -> Self {
        Self {
            exit_waiters: ExitWaiters::default(),
            exit_publication: Mutex::new(()),
            status_waker: WakerSlot::default(),
            status: Mutex::new(StatusState {
                pending: VecDeque::new(),
                terminal: INVALID_STATUS,
            }),
            status_changed: Condvar::new(),
            exit_status: AtomicI32::new(EXIT_PENDING),
            exit_capability: AtomicU8::new(EXIT_CAP_PENDING),
            registration_error: Mutex::new(None),
            worker_state: AtomicI32::new(WORKER_NOT_STARTED),
            worker_done_lock: Mutex::new(()),
            worker_done_changed: Condvar::new(),
            cleanup_cancel_requested: AtomicBool::new(false),
            cleanup_claim_waiters: AtomicUsize::new(0),
            wait_owner: AtomicU8::new(WAIT_OWNER_NONE),
            wait_owner_lock: Mutex::new(()),
            wait_owner_changed: Condvar::new(),
            #[cfg(test)]
            new_child_decode_pause: Mutex::new(None),
            #[cfg(test)]
            cleanup_return_pause: Mutex::new(None),
        }
    }

    fn expire_unclaimed_exit_capability(&self) -> bool {
        loop {
            let state = self.exit_capability.load(Ordering::Acquire);
            match state {
                EXIT_CAP_PENDING | EXIT_CAP_AVAILABLE => {
                    let replacement = if state == EXIT_CAP_PENDING {
                        EXIT_CAP_FINALIZING
                    } else {
                        EXIT_CAP_EXPIRED
                    };
                    if self
                        .exit_capability
                        .compare_exchange(state, replacement, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        return state == EXIT_CAP_PENDING;
                    }
                }
                EXIT_CAP_CLAIMED | EXIT_CAP_EXPIRED => return false,
                EXIT_CAP_FINALIZING => std::hint::spin_loop(),
                state => unreachable!("invalid exit capability state {state}"),
            }
        }
    }

    fn prepare_exit_capability_for_cleanup(&self, owns_claimed: bool) -> Result<(), Errno> {
        loop {
            let state = self.exit_capability.load(Ordering::Acquire);
            match state {
                EXIT_CAP_PENDING | EXIT_CAP_AVAILABLE => {
                    if self
                        .exit_capability
                        .compare_exchange(
                            state,
                            EXIT_CAP_EXPIRED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.exit_waiters.wake_all();
                        return Ok(());
                    }
                }
                EXIT_CAP_CLAIMED if owns_claimed => {
                    if self
                        .exit_capability
                        .compare_exchange(
                            EXIT_CAP_CLAIMED,
                            EXIT_CAP_EXPIRED,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        self.exit_waiters.wake_all();
                        return Ok(());
                    }
                }
                EXIT_CAP_CLAIMED => return Err(Errno::EALREADY),
                EXIT_CAP_EXPIRED => return Ok(()),
                EXIT_CAP_FINALIZING => std::hint::spin_loop(),
                state => unreachable!("invalid exit capability state {state}"),
            }
        }
    }

    fn publish_exit_stop(&self, between_status_and_capability: impl FnOnce()) {
        // Publish STOPPED first. A waiter that observes this half-published
        // state is already registered and returns Pending until AVAILABLE is
        // released and wake_all runs below.
        let publication = self.exit_publication.lock();
        let previous = self.exit_status.compare_exchange(
            EXIT_PENDING,
            EXIT_STOPPED,
            Ordering::Release,
            Ordering::Acquire,
        );
        debug_assert!(matches!(
            previous,
            Ok(EXIT_PENDING) | Err(EXIT_STOPPED | EXIT_ECHILD)
        ));
        if previous.is_ok() {
            between_status_and_capability();
            let capability = self.exit_capability.compare_exchange(
                EXIT_CAP_PENDING,
                EXIT_CAP_AVAILABLE,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            // Cleanup may expire the capability during the publication gap.
            // Terminal finalization cannot interleave because it takes the
            // same exit_publication lock.
            debug_assert!(matches!(
                capability,
                Ok(EXIT_CAP_PENDING) | Err(EXIT_CAP_EXPIRED)
            ));
        }
        drop(publication);
        self.status_changed.notify_all();
        self.exit_waiters.wake_all();
    }

    fn publish_terminal_exit_state(&self) {
        let _publication = self.exit_publication.lock();
        // Expire an unclaimed capability before terminal status or ECHILD
        // becomes visible. CLAIMED is already a non-duplicating state.
        let finalizing = self.expire_unclaimed_exit_capability();
        let _ = self.exit_status.compare_exchange(
            EXIT_PENDING,
            EXIT_ECHILD,
            Ordering::Release,
            Ordering::Acquire,
        );
        if finalizing {
            self.exit_capability
                .compare_exchange(
                    EXIT_CAP_FINALIZING,
                    EXIT_CAP_EXPIRED,
                    Ordering::Release,
                    Ordering::Acquire,
                )
                .expect("terminal exit-capability publication changed");
        }
    }

    /// Replaces the status and notifies the notifier of the change. Returns the
    /// old status if there was one.
    pub fn update(&self, status: i32) -> Option<i32> {
        if status == PTRACE_EVENT_EXIT_STOP {
            self.publish_exit_stop(|| {});
            return None;
        }

        let terminal = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
        if terminal {
            self.publish_terminal_exit_state();
        }
        let mut state = self.status.lock();
        let previous = if terminal {
            let previous = state.terminal;
            if previous == INVALID_STATUS || previous == ECHILD_STATUS {
                state.terminal = status;
            } else {
                debug_assert_eq!(previous, status, "terminal publication changed");
            }
            previous
        } else {
            let previous = state.pending.back().copied().unwrap_or(INVALID_STATUS);
            state.pending.push_back(status);
            previous
        };
        drop(state);
        self.status_changed.notify_all();
        if terminal {
            // A terminal publication resolves both waiter classes. ExitFuture
            // observes either the retained exit stop or typed ECHILD, while
            // WaitFuture retains the exact final status.
            self.status_waker.wake();
            self.exit_waiters.wake_all();
        } else {
            self.status_waker.wake();
        }

        (previous != INVALID_STATUS).then_some(previous)
    }

    fn update_sync_status(&self, status: i32) {
        if status != PTRACE_EVENT_EXIT_STOP {
            self.update(status);
            return;
        }

        // A synchronous wait directly returns this stopped capability. Keep
        // the raw stop rollback-safe in the regular FIFO without separately
        // minting an ExitFuture capability for the same consumed status.
        let mut state = self.status.lock();
        state.pending.push_back(status);
        drop(state);
        self.status_changed.notify_all();
        self.status_waker.wake();
    }

    /// Publishes a terminal `ECHILD` observation to every kind of waiter.
    fn mark_echild(&self) {
        self.publish_terminal_exit_state();
        let mut state = self.status.lock();
        if state.terminal == INVALID_STATUS {
            state.terminal = ECHILD_STATUS;
        }
        drop(state);
        self.status_changed.notify_all();
        self.status_waker.wake();
        self.exit_waiters.wake_all();
    }

    fn is_terminal(&self) -> bool {
        self.status.lock().terminal != INVALID_STATUS
    }

    /// Reserves the next status without removing a fallibly decoded FIFO front.
    fn poll_status_reservation(&self, waker: &Waker) -> Poll<Result<StatusReservation<'_>, Errno>> {
        // Register the waker *before* checking the status to avoid a race condition.
        self.status_waker.register(waker);

        let state = self.status.lock();
        if let Some(status) = state.pending.front().copied() {
            return Poll::Ready(Ok(StatusReservation {
                status,
                state: Some(state),
            }));
        }
        match state.terminal {
            INVALID_STATUS => Poll::Pending,
            ECHILD_STATUS => Poll::Ready(Err(Errno::ECHILD)),
            status => {
                // Final status is immutable so old state generations retain
                // the actual exit code or terminating signal after removal.
                Poll::Ready(Ok(StatusReservation {
                    status,
                    state: None,
                }))
            }
        }
    }

    #[cfg(test)]
    fn poll_status(&self, waker: &Waker) -> Poll<Result<i32, Errno>> {
        match self.poll_status_reservation(waker) {
            Poll::Ready(Ok(reservation)) => {
                let status = reservation.status;
                reservation.commit();
                Poll::Ready(Ok(status))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn wait_pending_status(&self, timeout: Duration) -> Option<MutexGuard<'_, StatusState>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut state = self.status.lock();
        loop {
            if !state.pending.is_empty() {
                return Some(state);
            }
            if state.terminal != INVALID_STATUS {
                return None;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            self.status_changed.wait_for(&mut state, remaining);
        }
    }

    fn pending_is_empty(&self) -> bool {
        self.status.lock().pending.is_empty()
    }

    fn notify_wait_owner_change(&self) {
        let _guard = self.wait_owner_lock.lock();
        self.wait_owner_changed.notify_all();
    }

    /// Linearizes a typed status return before decoding can acquire the PID
    /// registry, inspect procfs, or lock a newly materialized child Event.
    /// The owner mutex is deliberately released before decode; cleanup treats
    /// RETURNING as a transaction in flight and waits for this RAII guard to
    /// commit or restore the prior owner.
    fn begin_status_return(
        &self,
        status: i32,
        current_owner: u8,
        returning_owner: u8,
    ) -> ReturnTransactionStart<'_> {
        let _guard = self.wait_owner_lock.lock();
        if !libc::WIFEXITED(status)
            && !libc::WIFSIGNALED(status)
            && (self.cleanup_cancel_requested.load(Ordering::Acquire)
                || self.cleanup_claim_waiters.load(Ordering::Acquire) != 0)
        {
            return ReturnTransactionStart::Cancelled;
        }
        self.wait_owner
            .compare_exchange(
                current_owner,
                returning_owner,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .expect("status return began under the wrong wait owner");
        ReturnTransactionStart::Begun(ReturnTransaction {
            event: self,
            returning_owner,
            rollback_owner: current_owner,
            completed: false,
        })
    }

    fn claim_sync_wait(&self) -> Result<SyncWaitOwnership<'_>, Errno> {
        let mut guard = self.wait_owner_lock.lock();
        loop {
            match self.wait_owner.load(Ordering::Acquire) {
                WAIT_OWNER_NONE => {
                    self.wait_owner
                        .compare_exchange(
                            WAIT_OWNER_NONE,
                            WAIT_OWNER_SYNC,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .expect("wait owner changed while serialized");
                    return Ok(SyncWaitOwnership::Claimed(SyncWaitOwner {
                        event: self,
                        released: false,
                    }));
                }
                WAIT_OWNER_NOTIFIER => match self.worker_state.load(Ordering::Acquire) {
                    WORKER_NOT_STARTED | WORKER_STARTING => {
                        self.wait_owner_changed.wait(&mut guard)
                    }
                    WORKER_RUNNING | WORKER_FINISHING | WORKER_DONE => {
                        return Ok(SyncWaitOwnership::Notifier);
                    }
                    state => unreachable!("invalid worker state {state}"),
                },
                WAIT_OWNER_SYNC => return Err(Errno::EBUSY),
                WAIT_OWNER_SYNC_RETURNING | WAIT_OWNER_NOTIFIER_RETURNING => {
                    self.wait_owner_changed.wait(&mut guard)
                }
                owner => unreachable!("invalid wait owner {owner}"),
            }
        }
    }

    fn claim_notifier_wait(&self) -> NotifierWaitOwnership<'_> {
        let mut guard = self.wait_owner_lock.lock();
        loop {
            match self.wait_owner.load(Ordering::Acquire) {
                WAIT_OWNER_NONE => {
                    self.wait_owner
                        .compare_exchange(
                            WAIT_OWNER_NONE,
                            WAIT_OWNER_NOTIFIER,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .expect("wait owner changed while serialized");
                    return NotifierWaitOwnership::Claimed(NotifierWaitOwner {
                        event: self,
                        committed: false,
                    });
                }
                WAIT_OWNER_SYNC | WAIT_OWNER_SYNC_RETURNING | WAIT_OWNER_NOTIFIER_RETURNING => {
                    self.wait_owner_changed.wait(&mut guard)
                }
                WAIT_OWNER_NOTIFIER => match self.worker_state.load(Ordering::Acquire) {
                    WORKER_NOT_STARTED | WORKER_STARTING => {
                        self.wait_owner_changed.wait(&mut guard)
                    }
                    WORKER_RUNNING | WORKER_FINISHING | WORKER_DONE => {
                        return NotifierWaitOwnership::Existing;
                    }
                    state => unreachable!("invalid worker state {state}"),
                },
                owner => unreachable!("invalid wait owner {owner}"),
            }
        }
    }

    #[cfg(test)]
    fn try_claim_cancellable_notifier_wait(&self) -> CancellableNotifierWaitOwnership<'_> {
        let _guard = self.wait_owner_lock.lock();
        match self.wait_owner.load(Ordering::Acquire) {
            WAIT_OWNER_NONE => {
                self.cleanup_cancel_requested.store(true, Ordering::Release);
                self.wait_owner
                    .compare_exchange(
                        WAIT_OWNER_NONE,
                        WAIT_OWNER_NOTIFIER,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .expect("wait owner changed while serialized");
                CancellableNotifierWaitOwnership::Claimed(NotifierWaitOwner {
                    event: self,
                    committed: false,
                })
            }
            WAIT_OWNER_SYNC => {
                self.cleanup_cancel_requested.store(true, Ordering::Release);
                CancellableNotifierWaitOwnership::Synchronous
            }
            WAIT_OWNER_NOTIFIER => {
                self.cleanup_cancel_requested.store(true, Ordering::Release);
                CancellableNotifierWaitOwnership::Existing
            }
            WAIT_OWNER_SYNC_RETURNING | WAIT_OWNER_NOTIFIER_RETURNING => {
                self.cleanup_claim_waiters.fetch_add(1, Ordering::Release);
                CancellableNotifierWaitOwnership::Returning
            }
            owner => unreachable!("invalid wait owner {owner}"),
        }
    }

    fn decode_status_return<T>(
        &self,
        reservation: StatusReservation<'_>,
        decode: impl FnOnce(i32) -> Result<T, Error>,
    ) -> Result<StatusReturn<T>, Error> {
        let transaction = match self.begin_status_return(
            reservation.status,
            WAIT_OWNER_NOTIFIER,
            WAIT_OWNER_NOTIFIER_RETURNING,
        ) {
            ReturnTransactionStart::Begun(transaction) => transaction,
            ReturnTransactionStart::Cancelled => {
                return Ok(StatusReturn::Cancelled(reservation.status));
            }
        };
        let decoded = decode(reservation.status)?;
        reservation.commit();
        transaction.commit(WAIT_OWNER_NOTIFIER);
        Ok(StatusReturn::Returned(decoded))
    }

    fn wait_status_reservation_sync(&self) -> Result<StatusReservation<'_>, Errno> {
        let mut state = self.status.lock();
        loop {
            if let Some(status) = state.pending.front().copied() {
                return Ok(StatusReservation {
                    status,
                    state: Some(state),
                });
            }
            match state.terminal {
                INVALID_STATUS => self.status_changed.wait(&mut state),
                ECHILD_STATUS => return Err(Errno::ECHILD),
                status => {
                    return Ok(StatusReservation {
                        status,
                        state: None,
                    });
                }
            }
        }
    }

    fn try_status_reservation_sync(&self) -> Option<Result<StatusReservation<'_>, Errno>> {
        let state = self.status.lock();
        if let Some(status) = state.pending.front().copied() {
            return Some(Ok(StatusReservation {
                status,
                state: Some(state),
            }));
        }
        match state.terminal {
            INVALID_STATUS => None,
            ECHILD_STATUS => Some(Err(Errno::ECHILD)),
            status => Some(Ok(StatusReservation {
                status,
                state: None,
            })),
        }
    }

    fn try_terminal_reservation_sync(&self) -> Option<Result<StatusReservation<'_>, Errno>> {
        let state = self.status.lock();
        match state.terminal {
            INVALID_STATUS => None,
            ECHILD_STATUS => Some(Err(Errno::ECHILD)),
            status => Some(Ok(StatusReservation {
                status,
                state: None,
            })),
        }
    }

    fn finish_sync_terminal(&self) {
        if self.try_begin_unstarted_completion() {
            self.mark_worker_done();
        } else {
            debug_assert_eq!(self.worker_state.load(Ordering::Acquire), WORKER_DONE);
        }
    }

    #[cfg(test)]
    fn wait_for_sync_owner_release(&self, timeout: Duration) -> bool {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut guard = self.wait_owner_lock.lock();
        loop {
            if !matches!(
                self.wait_owner.load(Ordering::Acquire),
                WAIT_OWNER_SYNC | WAIT_OWNER_SYNC_RETURNING
            ) {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            self.wait_owner_changed.wait_for(&mut guard, remaining);
        }
    }

    #[cfg(test)]
    fn wait_for_return_and_claim_cancellable_notifier(
        &self,
        timeout: Duration,
    ) -> Option<CancellableNotifierWaitOwnership<'_>> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut guard = self.wait_owner_lock.lock();
        loop {
            match self.wait_owner.load(Ordering::Acquire) {
                WAIT_OWNER_SYNC_RETURNING | WAIT_OWNER_NOTIFIER_RETURNING => {}
                WAIT_OWNER_NONE => {
                    self.cleanup_cancel_requested.store(true, Ordering::Release);
                    let previous = self.cleanup_claim_waiters.fetch_sub(1, Ordering::AcqRel);
                    debug_assert_ne!(previous, 0);
                    self.wait_owner
                        .compare_exchange(
                            WAIT_OWNER_NONE,
                            WAIT_OWNER_NOTIFIER,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .expect("wait owner changed while serialized");
                    return Some(CancellableNotifierWaitOwnership::Claimed(
                        NotifierWaitOwner {
                            event: self,
                            committed: false,
                        },
                    ));
                }
                WAIT_OWNER_SYNC => {
                    self.cleanup_cancel_requested.store(true, Ordering::Release);
                    let previous = self.cleanup_claim_waiters.fetch_sub(1, Ordering::AcqRel);
                    debug_assert_ne!(previous, 0);
                    return Some(CancellableNotifierWaitOwnership::Synchronous);
                }
                WAIT_OWNER_NOTIFIER => {
                    self.cleanup_cancel_requested.store(true, Ordering::Release);
                    let previous = self.cleanup_claim_waiters.fetch_sub(1, Ordering::AcqRel);
                    debug_assert_ne!(previous, 0);
                    return Some(CancellableNotifierWaitOwnership::Existing);
                }
                owner => unreachable!("invalid wait owner {owner}"),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let previous = self.cleanup_claim_waiters.fetch_sub(1, Ordering::AcqRel);
                debug_assert_ne!(previous, 0);
                return None;
            }
            self.wait_owner_changed.wait_for(&mut guard, remaining);
        }
    }

    fn try_begin_worker_start(&self) -> bool {
        let started = self
            .worker_state
            .compare_exchange(
                WORKER_NOT_STARTED,
                WORKER_STARTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if started {
            self.notify_wait_owner_change();
        }
        started
    }

    fn mark_worker_running(&self) {
        self.worker_state
            .compare_exchange(
                WORKER_STARTING,
                WORKER_RUNNING,
                Ordering::Release,
                Ordering::Acquire,
            )
            .expect("worker start state changed before publication");
        self.notify_wait_owner_change();
    }

    fn rollback_worker_start(&self) {
        self.worker_state
            .compare_exchange(
                WORKER_STARTING,
                WORKER_NOT_STARTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .expect("failed worker start state changed before rollback");
        self.notify_wait_owner_change();
    }

    fn worker_is_running(&self) -> bool {
        self.worker_state.load(Ordering::Acquire) == WORKER_RUNNING
    }

    fn try_begin_unstarted_completion(&self) -> bool {
        let finishing = self
            .worker_state
            .compare_exchange(
                WORKER_NOT_STARTED,
                WORKER_FINISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if finishing {
            self.notify_wait_owner_change();
        }
        finishing
    }

    fn mark_worker_done(&self) {
        let previous = self.worker_state.swap(WORKER_DONE, Ordering::AcqRel);
        debug_assert!(matches!(previous, WORKER_RUNNING | WORKER_FINISHING));
        self.worker_done_changed.notify_all();
        self.notify_wait_owner_change();
    }

    fn wait_worker_done(&self, timeout: Duration) -> bool {
        if self.worker_state.load(Ordering::Acquire) == WORKER_DONE {
            return true;
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        let mut guard = self.worker_done_lock.lock();
        loop {
            if self.worker_state.load(Ordering::Acquire) == WORKER_DONE {
                return true;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            self.worker_done_changed.wait_for(&mut guard, remaining);
        }
    }

    /// Polls the event to check if there is a new status ready to be consumed.
    pub fn poll_exit(&self, waiter: &Arc<ExitWaiter>, waker: &Waker) -> Poll<Result<(), Errno>> {
        // Register before checking publication to avoid a lost wake. The weak
        // Event registration is pruned automatically if this future is dropped.
        self.exit_waiters.register(waiter, waker);

        loop {
            match self.exit_status.load(Ordering::Acquire) {
                EXIT_STOPPED => match self.exit_capability.load(Ordering::Acquire) {
                    EXIT_CAP_AVAILABLE => {
                        if self
                            .exit_capability
                            .compare_exchange(
                                EXIT_CAP_AVAILABLE,
                                EXIT_CAP_CLAIMED,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            )
                            .is_ok()
                        {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    EXIT_CAP_CLAIMED | EXIT_CAP_EXPIRED => {
                        return Poll::Ready(Err(Errno::EALREADY));
                    }
                    EXIT_CAP_PENDING | EXIT_CAP_FINALIZING => return Poll::Pending,
                    state => unreachable!("invalid exit capability state {state}"),
                },
                EXIT_ECHILD => return Poll::Ready(Err(Errno::ECHILD)),
                EXIT_PENDING => match self.exit_capability.load(Ordering::Acquire) {
                    EXIT_CAP_PENDING | EXIT_CAP_FINALIZING => return Poll::Pending,
                    EXIT_CAP_AVAILABLE => {
                        // AVAILABLE is released after STOPPED. Re-read after
                        // the Acquire so a stale first status load cannot miss
                        // a publication whose wake already happened. Keep
                        // Pending only for the defensively modeled old order.
                        match self.exit_status.load(Ordering::Acquire) {
                            EXIT_PENDING => return Poll::Pending,
                            EXIT_STOPPED | EXIT_ECHILD => continue,
                            state => unreachable!("invalid exit publication state {state}"),
                        }
                    }
                    EXIT_CAP_CLAIMED => return Poll::Ready(Err(Errno::EALREADY)),
                    EXIT_CAP_EXPIRED => {
                        // Acquiring EXPIRED observes the finalizer's prior
                        // ECHILD release when expiration came from terminal
                        // publication. Re-read because the first status load
                        // may predate it.
                        return match self.exit_status.load(Ordering::Acquire) {
                            EXIT_ECHILD => Poll::Ready(Err(Errno::ECHILD)),
                            EXIT_PENDING | EXIT_STOPPED => Poll::Ready(Err(Errno::EALREADY)),
                            state => unreachable!("invalid exit publication state {state}"),
                        };
                    }
                    state => unreachable!("unpublished exit capability state {state}"),
                },
                state => unreachable!("invalid exit publication state {state}"),
            }
        }
    }
}

/// One immutable notifier generation carried by typed tracee states.
#[derive(Debug)]
struct EventGeneration {
    event: Arc<Event>,
    identity: OnceLock<Arc<WorkerIdentity>>,
    authoritative: OnceLock<EventHandle>,
}

#[derive(Clone, Debug)]
pub(super) struct EventHandle(Arc<EventGeneration>);

impl EventHandle {
    pub(super) fn new() -> Self {
        Self(Arc::new(EventGeneration {
            event: Arc::new(Event::new()),
            identity: OnceLock::new(),
            authoritative: OnceLock::new(),
        }))
    }

    fn with_identity(identity: Arc<WorkerIdentity>) -> Self {
        let handle = Self::new();
        handle
            .0
            .identity
            .set(identity)
            .expect("fresh event generation identity is unset");
        handle
    }

    pub(super) fn current_or_new(pid: Pid) -> Result<Self, Errno> {
        NOTIFIER.current_or_new(pid)
    }

    pub(super) fn current_or_error(pid: Pid) -> Self {
        match Self::current_or_new(pid) {
            Ok(handle) => handle,
            Err(error) => {
                let handle = Self::new();
                *handle.event().registration_error.lock() = Some(error);
                handle
            }
        }
    }

    fn event(&self) -> &Arc<Event> {
        &self.resolved().0.event
    }

    fn identity(&self) -> Option<&Arc<WorkerIdentity>> {
        self.resolved().0.identity.get()
    }

    fn bind_identity(&self, identity: Arc<WorkerIdentity>) -> Result<(), Arc<WorkerIdentity>> {
        self.resolved().0.identity.set(identity)
    }

    fn resolved(&self) -> &Self {
        let mut current = self;
        while let Some(authoritative) = current.0.authoritative.get() {
            current = authoritative;
        }
        current
    }

    fn resolved_handle(&self) -> Self {
        self.resolved().clone()
    }

    fn chain_contains(&self, generation: &Arc<EventGeneration>) -> bool {
        let mut current = self;
        loop {
            if Arc::ptr_eq(&current.0, generation) {
                return true;
            }
            let Some(authoritative) = current.0.authoritative.get() else {
                return false;
            };
            current = authoritative;
        }
    }

    /// Redirects this requested generation to the registry's authoritative
    /// generation. The registry mutex serializes production adoption; this
    /// additional lock makes the primitive independently cycle-free under
    /// racing test or future call sites.
    fn adopt_authoritative(&self, authoritative: &Self) -> Result<Self, Errno> {
        static ADOPTION_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

        let _adoption = ADOPTION_LOCK.lock();
        let authoritative = authoritative.resolved_handle();
        if authoritative.chain_contains(&self.0) {
            if Arc::ptr_eq(&authoritative.0, &self.0) {
                return Ok(authoritative);
            }
            return Err(Errno::ELOOP);
        }
        match self.0.authoritative.set(authoritative.clone()) {
            Ok(()) => Ok(authoritative),
            Err(_) => {
                let selected = self.resolved_handle();
                if Arc::ptr_eq(&selected.0, &authoritative.0) {
                    Ok(selected)
                } else {
                    Err(Errno::EALREADY)
                }
            }
        }
    }
}

impl PartialEq for EventHandle {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for EventHandle {}

impl Hash for EventHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).hash(state);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerProcSnapshot {
    tgid: Pid,
    tracer_pid: Pid,
    start_time: u64,
}

impl WorkerProcSnapshot {
    fn same_process_generation(&self, other: &Self) -> bool {
        self.tgid == other.tgid && self.start_time == other.start_time
    }
}

/// Immutable procfs generation bound to one notifier worker.
#[derive(Debug)]
struct WorkerIdentity {
    pid: Pid,
    snapshot: WorkerProcSnapshot,
    pidfd: OwnedFd,
    proc_dir: OwnedFd,
    proc_inode: u64,
}

impl WorkerIdentity {
    fn capture(pid: Pid) -> Result<Self, Errno> {
        #[cfg(test)]
        if let Some(error) = CAPTURE_PERSISTENT_ERRORS.lock().get(&pid).copied() {
            return Err(error);
        }
        #[cfg(test)]
        if let Some(error) = CAPTURE_ERRORS.lock().remove(&pid) {
            return Err(error);
        }
        #[cfg(test)]
        {
            let thread = thread::current().id();
            let mut errors = CAPTURE_THREAD_ERRORS.lock();
            if let Some(error) = errors.get_mut(&thread).and_then(VecDeque::pop_front) {
                if errors.get(&thread).is_some_and(VecDeque::is_empty) {
                    errors.remove(&thread);
                }
                return Err(error);
            }
        }
        // Ordinary direct children have TracerPid 0 and are still valid
        // waitpid targets. TracerPid is mutable attachment state within the
        // exact pidfd/procfs generation; only a currently tracer-owned task may
        // turn ECHILD into a transient retry below.
        Self::capture_process(pid)
    }

    fn capture_process(pid: Pid) -> Result<Self, Errno> {
        let before = worker_proc_snapshot(pid).map_err(io_errno)?;
        #[cfg(test)]
        if let Some(pause) = CAPTURE_AFTER_FIRST_SNAPSHOT_PAUSES.lock().remove(&pid) {
            pause.captured.wait();
            pause.resume.wait();
        }
        let pidfd = open_thread_pidfd(pid)?;
        let proc_dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(format!("/proc/{pid}"))
            .map_err(io_errno)?;
        let proc_inode = proc_dir.metadata().map_err(io_errno)?.ino();
        let after = worker_proc_snapshot(pid).map_err(io_errno)?;
        let current_inode = fs::metadata(format!("/proc/{pid}"))
            .map_err(io_errno)?
            .ino();
        if !before.same_process_generation(&after) || current_inode != proc_inode {
            return Err(Errno::ESRCH);
        }

        Ok(Self {
            pid,
            snapshot: after,
            pidfd,
            proc_dir: proc_dir.into(),
            proc_inode,
        })
    }

    /// Returns true only while this exact procfs generation remains attached
    /// to a live thread in this tracer process.
    fn is_active_tracee(&self) -> bool {
        self.is_same_process_generation()
            && worker_proc_snapshot(self.pid).ok().is_some_and(|current| {
                current.same_process_generation(&self.snapshot)
                    && tracer_is_current(current.tracer_pid)
            })
    }

    fn is_same_process_generation(&self) -> bool {
        let Ok(current) = worker_proc_snapshot(self.pid) else {
            return false;
        };
        current.same_process_generation(&self.snapshot)
            && fd_inode(&self.proc_dir).ok() == Some(self.proc_inode)
            && fs::metadata(format!("/proc/{}", self.pid))
                .ok()
                .map(|metadata| metadata.ino())
                == Some(self.proc_inode)
    }

    fn same_generation(&self, other: &Self) -> bool {
        self.pid == other.pid
            && self.snapshot.same_process_generation(&other.snapshot)
            && self.proc_inode == other.proc_inode
    }

    fn same_live_generation(&self, other: &Self) -> Result<bool, Errno> {
        if !self.same_generation(other) {
            return Ok(false);
        }
        Ok(self.pidfd_is_live()? && other.pidfd_is_live()?)
    }

    fn pidfd_is_live(&self) -> Result<bool, Errno> {
        #[cfg(test)]
        {
            let mut errors = PIDFD_LIVENESS_ERRORS.lock();
            if let Some(error) = errors.get_mut(&self.pid).and_then(VecDeque::pop_front) {
                if errors.get(&self.pid).is_some_and(VecDeque::is_empty) {
                    errors.remove(&self.pid);
                }
                return Err(error);
            }
        }
        pidfd_is_live(&self.pidfd)
    }
}

fn open_thread_pidfd(pid: Pid) -> Result<OwnedFd, Errno> {
    #[cfg(test)]
    if let Some(error) = PIDFD_OPEN_ERRORS.lock().remove(&pid) {
        return Err(error);
    }

    open_thread_pidfd_kernel(pid)
}

fn open_thread_pidfd_kernel(pid: Pid) -> Result<OwnedFd, Errno> {
    // PIDFD_THREAD has the same value as O_EXCL. It binds a pidfd to the exact
    // TID rather than silently projecting a non-leader onto its thread group.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), libc::O_EXCL) } as i32;
    if fd == -1 {
        Err(io_errno(io::Error::last_os_error()))
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn pidfd_is_live(pidfd: &OwnedFd) -> Result<bool, Errno> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = io_errno(io::Error::last_os_error());
    if error == Errno::ESRCH {
        Ok(false)
    } else {
        Err(error)
    }
}

struct PendingWorker {
    start: std::sync::mpsc::SyncSender<()>,
    _handle: JoinHandle<()>,
}

impl PendingWorker {
    fn start(self) {
        self.start
            .send(())
            .expect("new notifier worker dropped its start gate");
    }
}

fn spawn_worker(
    pid: Pid,
    event: Arc<Event>,
    identity: Arc<WorkerIdentity>,
) -> io::Result<PendingWorker> {
    #[cfg(test)]
    if let Some(error) = SPAWN_WORKER_ERRORS.lock().remove(&pid) {
        if let Some(pause) = SPAWN_FAILURE_PAUSES.lock().remove(&pid) {
            pause.captured.wait();
            pause.resume.wait();
        }
        return Err(io::Error::from_raw_os_error(error));
    }
    let (start, wait_for_start) = std::sync::mpsc::sync_channel(1);
    let handle = thread::Builder::new()
        .name(format!("guest-{}", pid))
        .spawn(move || {
            if wait_for_start.recv().is_ok() {
                worker_thread(pid, event, identity);
            }
        })?;
    #[cfg(test)]
    {
        *SPAWN_WORKER_COUNTS.lock().entry(pid).or_default() += 1;
    }
    Ok(PendingWorker {
        start,
        _handle: handle,
    })
}

/// Waits on one exact kernel task lifetime and returns its lossless raw status.
/// Returns `None` once that pidfd is no longer waitable. There is deliberately
/// no numeric-PID fallback after identity capture.
fn wait_pidfd_status(identity: &WorkerIdentity) -> Option<i32> {
    let flags = WaitPidFlag::from_bits_retain(
        WaitPidFlag::WEXITED.bits() | WaitPidFlag::WSTOPPED.bits() | libc::__WALL,
    );
    loop {
        let result = waitid::waitpidfd(identity.pidfd.as_raw_fd(), flags);

        return match result {
            Ok(status) => Some(status.unwrap()),
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => None,
            Err(err) => {
                panic!(
                    "waitid(P_PIDFD, {}) failed unexpectedly: {}",
                    identity.pid, err
                )
            }
        };
    }
}

/// A worker thread that simply wakes a future when a process changes state.
fn worker_thread(pid: Pid, event: Arc<Event>, identity: Arc<WorkerIdentity>) {
    let mut retrying_echild = false;
    loop {
        // Revalidate before retrying a transient ECHILD. The pidfd keeps the
        // wait bound to this exact task even if its numeric TID is later reused.
        if retrying_echild && !identity.is_active_tracee() {
            event.mark_echild();
            break;
        }
        let Some(status) = wait_pidfd_status(&identity) else {
            if identity.is_active_tracee() {
                // A newborn auto-attached ptrace child can briefly exist with
                // this exact procfs generation before its first wait status
                // becomes visible. ECHILD is transient only in that window.
                retrying_echild = true;
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            // Publish before unregistering so held and newly registered late
            // waiters both receive a typed terminal result instead of hanging.
            event.mark_echild();
            break;
        };
        retrying_echild = false;
        event.update(status);

        // Try to avoid reaching an ECHILD error by terminating the loop on the
        // last event.
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            break;
        }
    }
    event.mark_worker_done();
    // The worker owns terminal registry cleanup. A WaitFuture may be dropped
    // before the final status is polled, and leaving cleanup to that future
    // would retain a stale event if the kernel later reuses this PID.
    NOTIFIER.remove(pid, &event);
}

fn try_replay_sync_terminal(pid: Pid, handle: &EventHandle) -> Option<Result<Wait, Error>> {
    let handle = handle.resolved_handle();
    let event = handle.event();
    let reservation = event.try_terminal_reservation_sync()?;
    Some(match reservation {
        Err(error) => Err(error.into()),
        Ok(reservation) => Wait::from_raw_with_token(
            pid,
            reservation.status,
            TraceeToken::from_event(handle.clone()),
        ),
    })
}

fn resume_cancelled_sync_status(pid: Pid, status: i32) -> Result<(), Error> {
    if !libc::WIFSTOPPED(status) {
        return Ok(());
    }
    match nix::sys::ptrace::cont(pid.into(), None) {
        Ok(()) => Ok(()),
        // An untraced job-control stop needs no resume for the already-pending
        // exact-pidfd SIGKILL to terminate it.
        // SIGKILL can advance an exit-stopped task before PTRACE_CONT reaches
        // it; the exact pidfd wait below still observes the terminal status.
        Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(nix::errno::Errno::EIO) if status != PTRACE_EVENT_EXIT_STOP => Ok(()),
        Err(error) => Err(Errno::new(error as i32).into()),
    }
}

/// Performs a synchronous typed wait under the PID generation's registry
/// authority and atomic Event wait-owner claim. A losing synchronous caller
/// consumes the notifier FIFO instead of issuing a second kernel wait.
pub(super) fn wait_sync(pid: Pid, token: TraceeToken) -> Result<Wait, Error> {
    let flags = WaitPidFlag::from_bits_retain(
        WaitPidFlag::WEXITED.bits() | WaitPidFlag::WSTOPPED.bits() | libc::__WALL,
    );
    let requested = token.event().resolved_handle();
    // A retained same-generation result remains authoritative even after the
    // procfs task and registry entry have disappeared.
    if let Some(replayed) = try_replay_sync_terminal(pid, &requested) {
        return replayed;
    }
    let handle = match NOTIFIER.sync_handle(pid, &requested) {
        Ok(handle) => handle,
        Err(error) => {
            if let Some(replayed) = try_replay_sync_terminal(pid, &requested) {
                return replayed;
            }
            return Err(error.into());
        }
    };
    let token = TraceeToken::from_event(handle);
    #[cfg(test)]
    if let Some(pause) = SYNC_HANDLE_PAUSES.lock().remove(&pid) {
        pause.captured.wait();
        pause.resume.wait();
    }

    loop {
        let handle = token.event().resolved_handle();
        let event = Arc::clone(handle.event());
        match event.claim_sync_wait()? {
            SyncWaitOwnership::Notifier => {
                let reservation = event.wait_status_reservation_sync()?;
                match event.decode_status_return(reservation, |status| {
                    Wait::from_raw_with_token(pid, status, TraceeToken::from_event(handle))
                })? {
                    StatusReturn::Returned(decoded) => return Ok(decoded),
                    StatusReturn::Cancelled(_) => return Err(Errno::ECANCELED.into()),
                }
            }
            SyncWaitOwnership::Claimed(mut owner) => {
                if !Arc::ptr_eq(token.event().event(), &event) {
                    drop(owner);
                    continue;
                }
                #[cfg(test)]
                if let Some(pause) = SYNC_WAIT_CLAIM_PAUSES.lock().remove(&pid) {
                    pause.captured.wait();
                    pause.resume.wait();
                }
                let mut cancelling = false;
                if let Some(reservation) = event.try_status_reservation_sync() {
                    let reservation = reservation?;
                    match owner.decode_status_return(pid, reservation, |status| {
                        Wait::from_raw_with_token(
                            pid,
                            status,
                            TraceeToken::from_event(handle.clone()),
                        )
                    })? {
                        StatusReturn::Returned(decoded) => return Ok(decoded),
                        StatusReturn::Cancelled(status) => {
                            resume_cancelled_sync_status(pid, status)?;
                            cancelling = true;
                        }
                    }
                }
                loop {
                    let status = loop {
                        let Some(identity) = handle.identity() else {
                            NOTIFIER.remove(pid, &event);
                            return Err(Errno::EIO.into());
                        };
                        if identity.pid != pid {
                            NOTIFIER.remove(pid, &event);
                            return Err(Errno::ESRCH.into());
                        }
                        let result = waitid::waitpidfd(identity.pidfd.as_raw_fd(), flags);
                        match result {
                            Ok(Some(status)) => break status,
                            Ok(None) => {
                                unreachable!("blocking synchronous wait returned no status")
                            }
                            Err(Errno::EINTR) => {}
                            Err(error) => {
                                if error == Errno::ECHILD {
                                    event.mark_echild();
                                    event.finish_sync_terminal();
                                }
                                NOTIFIER.remove(pid, &event);
                                return Err(error.into());
                            }
                        }
                    };
                    event.update_sync_status(status);
                    #[cfg(test)]
                    if let Some(pause) = SYNC_STATUS_PUBLICATION_PAUSES.lock().remove(&pid) {
                        pause.captured.wait();
                        pause.resume.wait();
                    }
                    if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                        event.finish_sync_terminal();
                        NOTIFIER.remove(pid, &event);
                        if cancelling {
                            drop(owner);
                            return Wait::from_raw_with_token(
                                pid,
                                status,
                                TraceeToken::from_event(handle),
                            );
                        }
                    }
                    #[cfg(test)]
                    if let Some(error) = SYNC_DECODE_CAPTURE_ERRORS.lock().remove(&pid) {
                        inject_capture_error_for_current_thread(error);
                    }
                    let reservation = event
                        .try_status_reservation_sync()
                        .expect("published synchronous status is immediately reservable")?;
                    match owner.decode_status_return(pid, reservation, |reserved_status| {
                        Wait::from_raw_with_token(
                            pid,
                            reserved_status,
                            TraceeToken::from_event(handle.clone()),
                        )
                    })? {
                        StatusReturn::Returned(decoded) => return Ok(decoded),
                        StatusReturn::Cancelled(reserved_status) => {
                            resume_cancelled_sync_status(pid, reserved_status)?;
                            cancelling = true;
                        }
                    }
                }
            }
        }
    }
}

fn worker_process_start_time(pid: Pid) -> std::io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed stat"))?
        .1;
    fields
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "missing starttime"))?
        .parse()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn worker_status_pid(status: &str, name: &str) -> std::io::Result<Pid> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|value| value.trim().parse::<i32>().ok())
        .map(Pid::from_raw)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("missing or malformed {name}"),
            )
        })
}

fn worker_proc_snapshot(pid: Pid) -> std::io::Result<WorkerProcSnapshot> {
    let start_time = worker_process_start_time(pid)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let snapshot = WorkerProcSnapshot {
        tgid: worker_status_pid(&status, "Tgid:")?,
        tracer_pid: worker_status_pid(&status, "TracerPid:")?,
        start_time,
    };
    if worker_process_start_time(pid)? != start_time {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "tracee identity changed while reading procfs",
        ));
    }
    Ok(snapshot)
}

fn tracer_is_current(tracer_pid: Pid) -> bool {
    tracer_pid.as_raw() > 0
        && std::path::Path::new(&format!("/proc/self/task/{tracer_pid}")).exists()
}

fn fd_inode(fd: &OwnedFd) -> std::io::Result<u64> {
    fs::metadata(format!("/proc/self/fd/{}", fd.as_raw_fd())).map(|metadata| metadata.ino())
}

fn io_errno(error: std::io::Error) -> Errno {
    Errno::new(error.raw_os_error().unwrap_or(libc::EIO))
}

#[derive(Debug)]
struct NotifierEntry {
    handle: EventHandle,
    identity: Arc<WorkerIdentity>,
}

#[cfg(test)]
enum RawCleanupClaim {
    Won,
    Existing(EventHandle),
    Lost,
}

enum EventRegistration {
    Registered(EventHandle),
    Adopted,
}

#[cfg(test)]
enum CancellableEventRegistration {
    Registered,
    Synchronous(Arc<Event>),
    ReturningTimedOut,
    Busy,
}

struct Notifier {
    /// Mapping of numeric PIDs to their validated current proc generation.
    pids: Mutex<HashMap<Pid, NotifierEntry>>,
}

impl Notifier {
    /// Creates the notifier.
    pub fn new() -> Self {
        let pids = Mutex::new(HashMap::new());
        Notifier { pids }
    }

    fn capture_identity(&self, pid: Pid) -> Result<Arc<WorkerIdentity>, Errno> {
        WorkerIdentity::capture(pid).map(Arc::new)
    }

    fn current_or_new(&self, pid: Pid) -> Result<EventHandle, Errno> {
        loop {
            let current = self.capture_identity(pid)?;
            if !current.is_same_process_generation() {
                continue;
            }
            #[cfg(test)]
            if let Some(pause) = CURRENT_OR_NEW_CAPTURE_PAUSES.lock().remove(&pid) {
                pause.captured.wait();
                pause.resume.wait();
            }

            let mut pids = self.pids.lock();
            // This exact kernel-lifetime check is the commit linearization
            // point. It is a pidfd syscall, not a long procfs read under the
            // global registry lock. A later reap/reuse cannot retarget the
            // pidfd-bound handle or worker.
            if !current.pidfd_is_live()? {
                drop(pids);
                continue;
            }
            if let Some(occupied) = pids.get(&pid)
                && occupied.identity.same_live_generation(&current)?
            {
                return Ok(occupied.handle.clone());
            }
            match pids.entry(pid) {
                Entry::Occupied(mut occupied) => {
                    let handle = EventHandle::with_identity(Arc::clone(&current));
                    occupied.insert(NotifierEntry {
                        handle: handle.clone(),
                        identity: current,
                    });
                    return Ok(handle);
                }
                Entry::Vacant(_) => {
                    let handle = EventHandle::with_identity(Arc::clone(&current));
                    // A typed state may still use synchronous wait. Defer registry
                    // insertion until async notification or terminal cleanup is
                    // actually requested.
                    return Ok(handle);
                }
            }
        }
    }

    /// Resolves one PID generation to its process-global wait authority before
    /// a synchronous caller can claim or enter the kernel wait.
    fn sync_handle(&self, pid: Pid, requested: &EventHandle) -> Result<EventHandle, Errno> {
        let mut capture_retries = 0;
        loop {
            let current = match self.capture_identity(pid) {
                Err(Errno::ENOENT | Errno::ESRCH)
                    if capture_retries < SYNC_IDENTITY_CAPTURE_RETRIES =>
                {
                    capture_retries += 1;
                    thread::yield_now();
                    continue;
                }
                result => result?,
            };
            if !current.is_same_process_generation() {
                continue;
            }
            match requested.identity() {
                Some(bound) if !bound.same_live_generation(&current)? => {
                    return Err(Errno::ECHILD);
                }
                Some(_) => {}
                None => {
                    if let Err(bound) = requested.bind_identity(Arc::clone(&current))
                        && !bound.same_live_generation(&current)?
                    {
                        return Err(Errno::ECHILD);
                    }
                }
            }

            let mut pids = self.pids.lock();
            if !current.pidfd_is_live()? {
                drop(pids);
                continue;
            }
            if let Some(occupied) = pids.get(&pid)
                && occupied.identity.same_live_generation(&current)?
            {
                return requested.adopt_authoritative(&occupied.handle);
            }
            pids.insert(
                pid,
                NotifierEntry {
                    handle: requested.clone(),
                    identity: current,
                },
            );
            return Ok(requested.resolved_handle());
        }
    }

    #[cfg(test)]
    fn current_registered(&self, pid: Pid) -> Result<Option<EventHandle>, Errno> {
        loop {
            let current = match self.capture_identity(pid) {
                Ok(current) => current,
                Err(Errno::ENOENT | Errno::ESRCH) => return Ok(None),
                Err(error) => return Err(error),
            };
            if !current.is_same_process_generation() {
                continue;
            }
            let pids = self.pids.lock();
            if !current.pidfd_is_live()? {
                drop(pids);
                continue;
            }
            return match pids.get(&pid) {
                Some(occupied) if occupied.identity.same_live_generation(&current)? => {
                    Ok(Some(occupied.handle.clone()))
                }
                _ => Ok(None),
            };
        }
    }

    #[cfg(test)]
    fn registered_sync_handle(
        &self,
        pid: Pid,
        exact_pidfd: &OwnedFd,
    ) -> Result<Option<EventHandle>, Errno> {
        if !pidfd_is_live(exact_pidfd)? {
            return Ok(None);
        }
        let pids = self.pids.lock();
        let Some(occupied) = pids.get(&pid) else {
            return Ok(None);
        };
        if !matches!(
            occupied.handle.event().wait_owner.load(Ordering::Acquire),
            WAIT_OWNER_SYNC | WAIT_OWNER_SYNC_RETURNING
        ) || !pidfd_is_live(&occupied.identity.pidfd)?
        {
            return Ok(None);
        }

        // Two live pidfds for the same numeric pid cannot name different
        // generations. This exact-pidfd fallback is intentionally limited to
        // an active synchronous owner, where capture may be unavailable and
        // cleanup must cancel the waiter before retrying registration.
        Ok(Some(occupied.handle.clone()))
    }

    fn resolve_echild(&self, pid: Pid, handle: &EventHandle) -> EventHandle {
        let handle = handle.resolved_handle();
        let event = Arc::clone(handle.event());
        // STARTING, raw cleanup claim, and registry insertion/removal all hold
        // this lock. A resolver can therefore never mistake an unpublished or
        // rolled-back worker start for a stable nonterminal Event.
        let mut pids = self.pids.lock();
        if event.worker_is_running() {
            return handle;
        }
        if event.try_begin_unstarted_completion() {
            // Publish the terminal result before completion becomes visible.
            event.mark_echild();
            event.mark_worker_done();
            if pids
                .get(&pid)
                .is_some_and(|current| Arc::ptr_eq(current.handle.event(), &event))
            {
                pids.remove(&pid);
            }
        }
        handle
    }

    fn record_registration_error(handle: &EventHandle, error: Errno) {
        *handle.event().registration_error.lock() = Some(error);
    }

    /// Registers the exact event generation carried by a typed state.
    fn event(&self, pid: Pid, handle: &EventHandle) -> Result<EventHandle, Errno> {
        loop {
            let requested = Arc::clone(handle.event());
            let owner = match requested.claim_notifier_wait() {
                NotifierWaitOwnership::Existing => return Ok(handle.resolved_handle()),
                NotifierWaitOwnership::Claimed(owner) => owner,
            };
            if !Arc::ptr_eq(handle.event(), &requested) {
                drop(owner);
                continue;
            }
            match self.event_with_owner(pid, handle, &requested, owner)? {
                EventRegistration::Registered(handle) => return Ok(handle),
                EventRegistration::Adopted => {}
            }
        }
    }

    #[cfg(test)]
    fn try_event_for_cleanup(
        &self,
        pid: Pid,
        handle: &EventHandle,
        return_deadline: Instant,
    ) -> Result<CancellableEventRegistration, Errno> {
        loop {
            let requested = Arc::clone(handle.event());
            let mut ownership = requested.try_claim_cancellable_notifier_wait();
            if matches!(ownership, CancellableNotifierWaitOwnership::Returning) {
                if let Some(pause) = requested.cleanup_return_pause.lock().take()
                    && pause.captured.send(()).is_ok()
                {
                    let _ = pause.resume.recv();
                }
                let return_timeout = return_deadline.saturating_duration_since(Instant::now());
                ownership = match requested
                    .wait_for_return_and_claim_cancellable_notifier(return_timeout)
                {
                    Some(ownership) => ownership,
                    None => return Ok(CancellableEventRegistration::ReturningTimedOut),
                };
            }
            let owner = match ownership {
                CancellableNotifierWaitOwnership::Synchronous => {
                    return Ok(CancellableEventRegistration::Synchronous(Arc::clone(
                        &requested,
                    )));
                }
                CancellableNotifierWaitOwnership::Existing => {
                    return match requested.worker_state.load(Ordering::Acquire) {
                        WORKER_RUNNING | WORKER_FINISHING | WORKER_DONE => {
                            Ok(CancellableEventRegistration::Registered)
                        }
                        WORKER_NOT_STARTED | WORKER_STARTING => {
                            Ok(CancellableEventRegistration::Busy)
                        }
                        state => unreachable!("invalid worker state {state}"),
                    };
                }
                CancellableNotifierWaitOwnership::Returning => {
                    unreachable!("return wait completed without a stable ownership state")
                }
                CancellableNotifierWaitOwnership::Claimed(owner) => owner,
            };
            if !Arc::ptr_eq(handle.event(), &requested) {
                drop(owner);
                continue;
            }
            match self.event_with_owner(pid, handle, &requested, owner)? {
                EventRegistration::Registered(_) => {
                    return Ok(CancellableEventRegistration::Registered);
                }
                EventRegistration::Adopted => {}
            }
        }
    }

    fn event_with_owner(
        &self,
        pid: Pid,
        handle: &EventHandle,
        requested: &Arc<Event>,
        owner: NotifierWaitOwner<'_>,
    ) -> Result<EventRegistration, Errno> {
        if requested.is_terminal() {
            owner.commit();
            return Ok(EventRegistration::Registered(handle.resolved_handle()));
        }

        // Event-local RUNNING is the ownership proof. Registry replacement is
        // allowed while an old typed state still awaits its own worker, and
        // that old worker must not consult the replacement generation or
        // recapture /proc before publishing its final status.
        if requested.worker_is_running() {
            owner.commit();
            return Ok(EventRegistration::Registered(handle.resolved_handle()));
        }

        loop {
            let current = match self.capture_identity(pid) {
                Ok(identity) => identity,
                Err(Errno::ENOENT | Errno::ESRCH) => {
                    let resolved = self.resolve_echild(pid, handle);
                    owner.commit();
                    return Ok(EventRegistration::Registered(resolved));
                }
                Err(error) => {
                    Self::record_registration_error(handle, error);
                    return Err(error);
                }
            };

            if !current.is_same_process_generation() {
                continue;
            }
            match handle.identity() {
                Some(bound) => match bound.same_live_generation(&current) {
                    Ok(true) => {}
                    Ok(false) => {
                        let resolved = self.resolve_echild(pid, handle);
                        owner.commit();
                        return Ok(EventRegistration::Registered(resolved));
                    }
                    Err(error) => {
                        Self::record_registration_error(handle, error);
                        return Err(error);
                    }
                },
                None => {
                    if let Err(bound) = handle.bind_identity(Arc::clone(&current)) {
                        match bound.same_live_generation(&current) {
                            Ok(true) => {}
                            Ok(false) => {
                                let resolved = self.resolve_echild(pid, handle);
                                owner.commit();
                                return Ok(EventRegistration::Registered(resolved));
                            }
                            Err(error) => {
                                Self::record_registration_error(handle, error);
                                return Err(error);
                            }
                        }
                    }
                }
            }
            #[cfg(test)]
            if let Some(pause) = EVENT_CAPTURE_PAUSES.lock().remove(&pid) {
                pause.captured.wait();
                pause.resume.wait();
            }

            let mut pids = self.pids.lock();
            match current.pidfd_is_live() {
                Ok(true) => {}
                Ok(false) => {
                    drop(pids);
                    let resolved = self.resolve_echild(pid, handle);
                    owner.commit();
                    return Ok(EventRegistration::Registered(resolved));
                }
                Err(error) => {
                    Self::record_registration_error(handle, error);
                    return Err(error);
                }
            }
            match requested.worker_state.load(Ordering::Acquire) {
                WORKER_FINISHING | WORKER_DONE => {
                    owner.commit();
                    return Ok(EventRegistration::Registered(handle.resolved_handle()));
                }
                WORKER_RUNNING => {
                    owner.commit();
                    return Ok(EventRegistration::Registered(handle.resolved_handle()));
                }
                WORKER_STARTING => {
                    unreachable!("worker STARTING publication escaped the registry lock")
                }
                WORKER_NOT_STARTED => {}
                state => unreachable!("invalid worker state {state}"),
            }
            let mut worker_identity = None;
            let event_handle = match pids.entry(pid) {
                Entry::Occupied(occupied) if occupied.get().handle == *handle => {
                    match occupied.get().identity.same_live_generation(&current) {
                        Ok(true) => {}
                        Ok(false) => {
                            drop(pids);
                            let resolved = self.resolve_echild(pid, handle);
                            owner.commit();
                            return Ok(EventRegistration::Registered(resolved));
                        }
                        Err(error) => {
                            Self::record_registration_error(handle, error);
                            return Err(error);
                        }
                    }
                    if requested.try_begin_worker_start() {
                        worker_identity = Some(Arc::clone(&occupied.get().identity));
                    }
                    handle.clone()
                }
                Entry::Occupied(mut occupied) => {
                    match occupied.get().identity.same_live_generation(&current) {
                        Ok(true) => {
                            let authoritative = occupied.get().handle.clone();
                            drop(pids);
                            handle.adopt_authoritative(&authoritative)?;
                            drop(owner);
                            return Ok(EventRegistration::Adopted);
                        }
                        Ok(false) => {}
                        Err(error) => {
                            Self::record_registration_error(handle, error);
                            return Err(error);
                        }
                    }
                    occupied.insert(NotifierEntry {
                        handle: handle.clone(),
                        identity: Arc::clone(&current),
                    });
                    if requested.try_begin_worker_start() {
                        worker_identity = Some(current);
                    }
                    handle.clone()
                }
                Entry::Vacant(vacant) => {
                    vacant.insert(NotifierEntry {
                        handle: handle.clone(),
                        identity: Arc::clone(&current),
                    });
                    if requested.try_begin_worker_start() {
                        worker_identity = Some(current);
                    }
                    handle.clone()
                }
            };
            let pending_worker = if let Some(identity) = worker_identity {
                match spawn_worker(pid, Arc::clone(event_handle.event()), Arc::clone(&identity)) {
                    Ok(worker) => {
                        requested.mark_worker_running();
                        Some(worker)
                    }
                    Err(error) => {
                        requested.rollback_worker_start();
                        if pids.get(&pid).is_some_and(|entry| {
                            entry.handle == *handle && entry.identity.same_generation(&identity)
                        }) {
                            pids.remove(&pid);
                        }
                        let error = io_errno(error);
                        Self::record_registration_error(handle, error);
                        return Err(error);
                    }
                }
            } else {
                None
            };
            *requested.registration_error.lock() = None;
            drop(pids);
            if let Some(worker) = pending_worker {
                worker.start();
            }
            owner.commit();
            return Ok(EventRegistration::Registered(event_handle));
        }
    }

    /// Removes a completed PID without disturbing a reused PID's event.
    fn remove(&self, pid: Pid, event: &Arc<Event>) {
        let mut pids = self.pids.lock();
        if pids
            .get(&pid)
            .is_some_and(|current| Arc::ptr_eq(current.handle.event(), event))
        {
            pids.remove(&pid);
        }
    }

    #[cfg(test)]
    fn try_claim_unstarted_raw_cleanup(
        &self,
        pid: Pid,
        handle: &EventHandle,
    ) -> Result<RawCleanupClaim, Errno> {
        loop {
            let mut pids = self.pids.lock();
            if let Some(current) = pids.get(&pid)
                && current.handle != *handle
            {
                let current_handle = current.handle.clone();
                let current_identity = Arc::clone(&current.identity);
                drop(pids);
                let live = current_identity.pidfd_is_live()?;
                pids = self.pids.lock();
                if !pids.get(&pid).is_some_and(|entry| {
                    entry.handle == current_handle
                        && entry.identity.same_generation(&current_identity)
                }) {
                    drop(pids);
                    continue;
                }
                if live {
                    return Ok(RawCleanupClaim::Existing(current_handle));
                }
                pids.remove(&pid);
            }

            drop(pids);
            let event = Arc::clone(handle.event());
            let owner = match event.claim_notifier_wait() {
                NotifierWaitOwnership::Existing => return Ok(RawCleanupClaim::Lost),
                NotifierWaitOwnership::Claimed(owner) => owner,
            };
            if !Arc::ptr_eq(handle.event(), &event) {
                drop(owner);
                continue;
            }
            pids = self.pids.lock();
            if pids
                .get(&pid)
                .is_some_and(|current| current.handle != *handle)
            {
                drop(pids);
                drop(owner);
                continue;
            }
            if !event.try_begin_unstarted_completion() {
                drop(owner);
                return Ok(RawCleanupClaim::Lost);
            }
            if pids
                .get(&pid)
                .is_some_and(|current| current.handle == *handle)
            {
                pids.remove(&pid);
            }
            owner.commit();
            return Ok(RawCleanupClaim::Won);
        }
    }
}

impl Drop for Notifier {
    fn drop(&mut self) {
        // All guests should have exited by now.
        let pids = self.pids.lock();
        assert_eq!(
            pids.len(),
            0,
            "Some tracees have not exited yet:\n{:#?}",
            pids
        );
    }
}

/// A synchronous acknowledgment that a PID's notifier worker has observed a
/// terminal state and removed its registry entry.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-270): Trigger 2: review the public generation-bound
// terminal-cleanup acknowledgment contract.
pub struct TerminalCleanup {
    pid: Pid,
    event: EventHandle,
}

impl TerminalCleanup {
    pub(super) fn new(pid: Pid, token: &TraceeToken) -> Self {
        let cleanup = Self::new_unregistered(pid, token);
        let _ = cleanup.ensure_registered();
        cleanup
    }

    fn new_unregistered(pid: Pid, token: &TraceeToken) -> Self {
        let event = token.event().clone();
        Self { pid, event }
    }

    /// Retries notifier registration and returns the exact capture/open error.
    pub fn ensure_registered(&self) -> Result<(), Errno> {
        NOTIFIER.event(self.pid, &self.event).map(drop)
    }

    #[cfg(test)]
    fn try_ensure_registered_for_cleanup(
        &self,
        return_deadline: Instant,
    ) -> Result<CancellableEventRegistration, Errno> {
        NOTIFIER.try_event_for_cleanup(self.pid, &self.event, return_deadline)
    }

    /// Returns the last typed notifier registration error, if any.
    pub fn registration_error(&self) -> Option<Errno> {
        *self.event.event().registration_error.lock()
    }

    #[cfg(test)]
    fn try_claim_unstarted_raw_cleanup(&self) -> Result<RawCleanupClaim, Errno> {
        NOTIFIER.try_claim_unstarted_raw_cleanup(self.pid, &self.event)
    }

    #[cfg(test)]
    fn finish_unstarted_raw_cleanup(&self) {
        let event = self.event.event();
        event.mark_echild();
        event.mark_worker_done();
        NOTIFIER.remove(self.pid, event);
    }

    /// Returns true when both handles carry the same immutable Event generation.
    pub fn same_generation(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.event.event(), other.event.event())
    }

    /// Waits up to `timeout` for the notifier worker to unregister this PID.
    ///
    /// This does not call `waitpid`: after notifier registration, the worker
    /// thread remains the sole owner of wait statuses for the PID.
    pub fn wait(&self, timeout: Duration) -> bool {
        self.event.event().wait_worker_done(timeout)
    }

    /// Reserves the oldest queued nonterminal state after cancellation.
    ///
    /// This is a cancellation-only escape hatch for the ptracer thread that
    /// owns this exact event generation. The FIFO front remains present and
    /// unavailable to other consumers until [`PendingStatusReservation::commit`].
    /// Dropping the reservation performs an allocation-free rollback without
    /// changing FIFO order.
    pub fn reserve_pending_for_cleanup(
        &self,
        timeout: Duration,
    ) -> Option<PendingStatusReservation<'_>> {
        let state = self.event.event().wait_pending_status(timeout)?;
        let status = *state
            .pending
            .front()
            .expect("pending cleanup reservation requires a FIFO front");
        Some(PendingStatusReservation {
            pid: self.pid,
            status,
            event: self.event.resolved(),
            state,
        })
    }

    /// Returns true when no nonterminal status remains queued.
    pub fn pending_is_empty(&self) -> bool {
        self.event.event().pending_is_empty()
    }

    /// Returns true when this exact event observed a ptrace exit stop.
    pub fn exit_stop_observed(&self) -> bool {
        self.event.event().exit_status.load(Ordering::Acquire) == EXIT_STOPPED
    }

    /// Revokes any not-yet-claimed exit-stop capability before cancellation
    /// cleanup performs a raw ptrace transition.
    ///
    /// Returns [`Errno::EALREADY`] rather than advancing behind a capability
    /// already minted as [`Stopped`].
    pub fn revoke_unclaimed_exit_stop(&self) -> Result<(), Errno> {
        self.event
            .event()
            .prepare_exit_capability_for_cleanup(false)
    }

    /// Transfers a previously claimed exit-stop capability to cancellation
    /// cleanup and revokes all future claims.
    ///
    /// # Safety
    ///
    /// The caller must prove exclusive ownership of the exact stopped tracee
    /// generation and that the previously returned [`Stopped`] value has been
    /// destroyed or transferred to the cleanup path. Revocation cannot make an
    /// independently retained `Stopped` value safe.
    pub unsafe fn revoke_owned_exit_stop(&self) -> Result<(), Errno> {
        self.event.event().prepare_exit_capability_for_cleanup(true)
    }
}

/// A rollback-safe reservation of one exact-generation notifier FIFO front.
#[must_use = "drop rolls the reservation back; call commit after ownership is stored"]
pub struct PendingStatusReservation<'a> {
    pid: Pid,
    status: i32,
    event: &'a EventHandle,
    state: MutexGuard<'a, StatusState>,
}

impl PendingStatusReservation<'_> {
    /// Decodes the reserved status without removing it from the FIFO.
    pub fn decode(&self) -> Result<Wait, Error> {
        Wait::from_raw_with_token(
            self.pid,
            self.status,
            TraceeToken::from_event(self.event.clone()),
        )
    }

    /// Removes the reserved front after all associated ownership is durable.
    pub fn commit(mut self) {
        let committed = self.state.pending.pop_front();
        debug_assert_eq!(committed, Some(self.status));
    }
}

/// A future representing a process state change.
pub struct WaitFuture {
    running: Running,
}

impl WaitFuture {
    pub(super) fn new(running: Running) -> Self {
        Self { running }
    }
}

impl Future for WaitFuture {
    type Output = Result<Wait, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let pid = this.running.pid();
        let event_handle = match NOTIFIER.event(pid, this.running.token().event()) {
            Ok(event) => event,
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        let event = event_handle.event();
        let reservation = match futures::ready!(event.poll_status_reservation(cx.waker())) {
            Ok(reservation) => reservation,
            Err(errno) => return Poll::Ready(Err(errno.into())),
        };
        match event.decode_status_return(reservation, |status| {
            Wait::from_raw_with_token(pid, status, TraceeToken::from_event(event_handle.clone()))
        }) {
            Ok(StatusReturn::Returned(decoded)) => Poll::Ready(Ok(decoded)),
            Ok(StatusReturn::Cancelled(_)) => Poll::Ready(Err(Errno::ECANCELED.into())),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

/// A future representing PTRACE_EVENT_EXIT. The future resolves when the process
/// receives a PTRACE_EVENT_EXIT. A process can receive this event at any time,
/// even when in another ptrace stop state.
///
/// The next state after this should be the final exit status.
/// Exactly one future for an immutable Event generation can claim and return
/// the stopped-state capability. Duplicate or re-polled futures return
/// [`Errno::EALREADY`]. An unclaimed capability also expires before terminal
/// publication or cancellation cleanup advances the tracee; terminal status
/// remains independently retained for ordinary waiters.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-270): Trigger 2: review the public typed-error
// ExitFuture contract and retained exit-stop generation semantics.
pub struct ExitFuture {
    pid: Pid,
    event: EventHandle,
    waiter: Arc<ExitWaiter>,
}

impl ExitFuture {
    pub(super) fn new(pid: Pid, token: &TraceeToken) -> Self {
        Self {
            pid,
            event: token.event().clone(),
            waiter: Arc::new(ExitWaiter::default()),
        }
    }
}

impl Future for ExitFuture {
    type Output = Result<Stopped, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let event_handle = match NOTIFIER.event(this.pid, &this.event) {
            Ok(event) => event,
            Err(error) => return Poll::Ready(Err(error.into())),
        };
        let event = event_handle.event();
        match futures::ready!(event.poll_exit(&this.waiter, cx.waker())) {
            Ok(()) => Poll::Ready(Ok(Stopped::from_token(
                this.pid,
                TraceeToken::from_event(event_handle),
            ))),
            Err(errno) => Poll::Ready(Err(errno.into())),
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::hash_map::DefaultHasher;
    use std::env;
    use std::io;
    use std::io::Read;
    use std::io::Write;
    use std::mem;
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::process::Output;
    use std::process::Stdio;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::mpsc;
    use std::task::Wake;
    use std::thread::JoinHandle;
    use std::time::Duration;

    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::ForkResult;
    use nix::unistd::Pid;
    use nix::unistd::fork;

    use super::*;
    use crate::Options;

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);

    impl Wake for WakeCounter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn handle_hash(handle: &EventHandle) -> u64 {
        let mut hasher = DefaultHasher::new();
        handle.hash(&mut hasher);
        hasher.finish()
    }

    const SUBPROCESS_POLL_INTERVAL: Duration = Duration::from_millis(5);
    const SUBPROCESS_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);
    const PID_NAMESPACE_TEST_TIMEOUT: Duration = Duration::from_secs(5);
    const TRACEE_WAIT_TIMEOUT: Duration = Duration::from_secs(2);
    const REGISTRATION_RETRY_TIMEOUT: Duration = Duration::from_millis(100);

    #[derive(Debug)]
    struct BoundedSubprocess {
        output: Output,
        timed_out: bool,
    }

    fn kill_process_group(process_group: i32) -> io::Result<()> {
        let result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if fd == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn pidfd_send_signal(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn pidfd_exited(pidfd: &OwnedFd) -> io::Result<bool> {
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result == 1 && pollfd.revents & libc::POLLIN != 0)
        }
    }

    struct PipeDrain {
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<io::Result<Vec<u8>>>>,
    }

    impl PipeDrain {
        fn is_finished(&self) -> bool {
            self.thread.as_ref().is_none_or(JoinHandle::is_finished)
        }

        fn stop_and_join(&mut self) -> io::Result<Vec<u8>> {
            self.stop.store(true, Ordering::Release);
            self.join()
        }

        fn join(&mut self) -> io::Result<Vec<u8>> {
            self.thread
                .take()
                .expect("pipe reader joined twice")
                .join()
                .map_err(|_| io::Error::other("exact-test pipe reader panicked"))?
        }
    }

    impl Drop for PipeDrain {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn drain_pipe<R>(mut pipe: R) -> io::Result<PipeDrain>
    where
        R: Read + AsRawFd + Send + 'static,
    {
        let flags = unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_GETFL) };
        if flags == -1
            || unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                == -1
        {
            return Err(io::Error::last_os_error());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 8192];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => return Ok(bytes),
                    Ok(read) => bytes.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        if reader_stop.load(Ordering::Acquire) {
                            return Ok(bytes);
                        }
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => return Err(error),
                }
            }
        });
        Ok(PipeDrain {
            stop,
            thread: Some(thread),
        })
    }

    struct ChildProcessGroup {
        child: std::process::Child,
        pidfd: OwnedFd,
        process_group: i32,
        reaped: bool,
    }

    impl ChildProcessGroup {
        fn new(mut child: std::process::Child) -> io::Result<Self> {
            let process_group = child.id() as i32;
            let pidfd = match pidfd_open(process_group) {
                Ok(pidfd) => pidfd,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
            Ok(Self {
                child,
                pidfd,
                process_group,
                reaped: false,
            })
        }

        fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
            let status = self.child.wait()?;
            self.reaped = true;
            Ok(status)
        }

        fn terminate_group(&self) -> io::Result<()> {
            kill_process_group(self.process_group)?;
            Ok(())
        }
    }

    impl Drop for ChildProcessGroup {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = kill_process_group(self.process_group);
                let _ = self.child.wait();
                self.reaped = true;
            }
        }
    }

    fn run_exact_test_bounded(
        inner: &str,
        environment: &[(&str, &str)],
        pid_namespace: bool,
        timeout: Duration,
    ) -> io::Result<BoundedSubprocess> {
        const PROJECT_REAPED_PGID: &str = "SAFEPTRACE_PROJECT_REAPED_PGID";
        let projected_reaped_pgid = environment
            .iter()
            .find_map(|(name, value)| (*name == PROJECT_REAPED_PGID).then_some(*value))
            .map(str::parse::<i32>)
            .transpose()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let test_binary = env::current_exe()?;
        let mut command = if pid_namespace {
            let mut command = Command::new("unshare");
            command.args([
                "--user",
                "--map-root-user",
                "--pid",
                "--fork",
                "--mount-proc",
            ]);
            command.arg(test_binary);
            command
        } else {
            Command::new(test_binary)
        };
        command
            .args(["--exact", inner, "--nocapture"])
            .envs(environment.iter().copied())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);

        let mut group = ChildProcessGroup::new(command.spawn()?)?;
        let mut stdout = drain_pipe(
            group
                .child
                .stdout
                .take()
                .expect("bounded child stdout pipe"),
        )?;
        let mut stderr = match drain_pipe(
            group
                .child
                .stderr
                .take()
                .expect("bounded child stderr pipe"),
        ) {
            Ok(stderr) => stderr,
            Err(error) => {
                let _ = group.terminate_group();
                let _ = stdout.stop_and_join();
                let _ = group.wait();
                return Err(error);
            }
        };
        let deadline = Instant::now() + timeout;
        let timed_out = loop {
            if pidfd_exited(&group.pidfd)? {
                break false;
            }
            if Instant::now() >= deadline {
                group.terminate_group()?;
                break true;
            }
            thread::sleep(SUBPROCESS_POLL_INTERVAL);
        };

        let drain_deadline = Instant::now() + SUBPROCESS_DRAIN_TIMEOUT;
        while !stdout.is_finished() || !stderr.is_finished() {
            if Instant::now() >= drain_deadline {
                break;
            }
            thread::sleep(SUBPROCESS_POLL_INTERVAL);
        }
        let drain_timed_out = !stdout.is_finished() || !stderr.is_finished();
        if drain_timed_out {
            // The unreaped leader pins both its PID and same-valued PGID, so
            // this cannot target a recycled process group.
            group.terminate_group()?;
        }

        let stdout_result = if timed_out || drain_timed_out {
            stdout.stop_and_join()
        } else {
            stdout.join()
        };
        let stderr_result = if timed_out || drain_timed_out {
            stderr.stop_and_join()
        } else {
            stderr.join()
        };
        // Reap last. No code below may signal the bare PID or PGID.
        let status = group.wait()?;
        if let Some(projected_reaped_pgid) = projected_reaped_pgid {
            // Test-only projection: any error cleanup below must respect
            // `reaped` and leave this potentially recycled PGID untouched.
            group.process_group = projected_reaped_pgid;
        }
        let stdout = stdout_result?;
        let stderr = stderr_result?;
        if projected_reaped_pgid.is_some() {
            return Err(io::Error::other(
                "injected exact-test reader failure after leader reap",
            ));
        }
        if drain_timed_out {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "exact-test pipes stayed open after leader exit; status={status}; stdout={}; stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                ),
            ));
        }
        Ok(BoundedSubprocess {
            output: Output {
                status,
                stdout,
                stderr,
            },
            timed_out,
        })
    }

    fn run_exact_in_pid_namespace_bounded(
        inner: &str,
        environment: &[(&str, &str)],
    ) -> Option<Output> {
        match run_exact_test_bounded(inner, environment, true, PID_NAMESPACE_TEST_TIMEOUT) {
            Ok(result) if result.timed_out => panic!(
                "PID-namespace exact test exceeded {:?}:\nstdout:\n{}\nstderr:\n{}",
                PID_NAMESPACE_TEST_TIMEOUT,
                String::from_utf8_lossy(&result.output.stdout),
                String::from_utf8_lossy(&result.output.stderr),
            ),
            Ok(result) => Some(result.output),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => panic!("failed to run bounded PID-namespace exact test: {error}"),
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum ExactReuseOutcome {
        Exercised,
        Unavailable,
    }

    fn classify_exact_reuse_output(
        output: Option<&Output>,
        exercised_marker: &str,
        unavailable_marker: &str,
    ) -> Result<ExactReuseOutcome, String> {
        let Some(output) = output else {
            // `unshare` is absent on this host.
            return Ok(ExactReuseOutcome::Unavailable);
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let exercised = stdout.contains(exercised_marker);
        let unavailable = stdout.contains(unavailable_marker);

        if output.status.success() {
            return match (exercised, unavailable) {
                (true, false) => Ok(ExactReuseOutcome::Exercised),
                (false, true) => Ok(ExactReuseOutcome::Unavailable),
                _ => Err(format!(
                    "successful exact test emitted ambiguous/missing outcome marker; status={}; stdout:\n{stdout}\nstderr:\n{stderr}",
                    output.status
                )),
            };
        }

        let known_unshare_denial = stderr.lines().any(|line| {
            matches!(
                line,
                "unshare: unshare failed: Operation not permitted"
                    | "unshare: write failed /proc/self/uid_map: Operation not permitted"
            )
        });
        if known_unshare_denial && !exercised && !unavailable {
            Ok(ExactReuseOutcome::Unavailable)
        } else {
            Err(format!(
                "exact-test subprocess failed; status={}; stdout:\n{stdout}\nstderr:\n{stderr}",
                output.status
            ))
        }
    }

    fn waitpid_status_bounded(pid: Pid, flags: i32, timeout: Duration) -> io::Result<i32> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid.as_raw(), &mut status, flags | libc::WNOHANG) };
            if waited == pid.as_raw() {
                return Ok(status);
            }
            if waited == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("waitpid({pid}) exceeded {timeout:?}"),
                ));
            }
            thread::sleep(SUBPROCESS_POLL_INTERVAL);
        }
    }

    fn stopped_tracee_bounded(pid: Pid) -> io::Result<Stopped> {
        let status = waitpid_status_bounded(pid, libc::WUNTRACED, TRACEE_WAIT_TIMEOUT)?;
        if !libc::WIFSTOPPED(status) {
            return Err(io::Error::other(format!(
                "tracee {pid} reached non-stop status {status:#x}"
            )));
        }
        if libc::WSTOPSIG(status) != libc::SIGSTOP {
            return Err(io::Error::other(format!(
                "tracee {pid} stopped with signal {} instead of SIGSTOP",
                libc::WSTOPSIG(status)
            )));
        }
        Ok(Stopped::new_unchecked(pid.into()))
    }

    fn reap_tracee_bounded(pid: Pid) -> io::Result<()> {
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match waitpid_status_bounded(pid, libc::__WALL, remaining) {
                Ok(status) if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) => return Ok(()),
                Ok(status) if libc::WIFSTOPPED(status) => {
                    let _ = nix::sys::ptrace::cont(pid, None);
                }
                Ok(status) => {
                    return Err(io::Error::other(format!(
                        "tracee {pid} cleanup reached unexpected status {status:#x}"
                    )));
                }
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                    if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                        return Ok(());
                    }
                }
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("tracee {pid} survived bounded cleanup"),
                ));
            }
            thread::sleep(SUBPROCESS_POLL_INTERVAL);
        }
    }

    fn reap_tracee_pidfd_bounded(pid: Pid, pidfd: &OwnedFd) -> io::Result<()> {
        let flags = WaitPidFlag::from_bits_retain(
            WaitPidFlag::WEXITED.bits()
                | WaitPidFlag::WSTOPPED.bits()
                | WaitPidFlag::WCONTINUED.bits()
                | WaitPidFlag::WNOHANG.bits()
                | libc::__WALL,
        );
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        loop {
            match waitid::waitid(waitid::IdType::Pidfd(pidfd.as_raw_fd()), flags) {
                Ok(WaitStatus::Exited(waited, _) | WaitStatus::Signaled(waited, _, _)) => {
                    assert_eq!(waited, pid, "pidfd reaped a different tracee");
                    return Ok(());
                }
                Ok(
                    WaitStatus::Stopped(waited, _)
                    | WaitStatus::PtraceEvent(waited, _, _)
                    | WaitStatus::PtraceSyscall(waited),
                ) => {
                    assert_eq!(waited, pid, "pidfd observed a different tracee stop");
                    // The exact pidfd-reported stop pins this numeric PID until
                    // the following transition completes.
                    nix::sys::ptrace::cont(pid, None).map_err(|error| {
                        io::Error::other(format!("resume pidfd-bound cleanup stop: {error}"))
                    })?;
                }
                Ok(WaitStatus::StillAlive | WaitStatus::Continued(_)) => {}
                Err(Errno::EINTR) => continue,
                // The exact pidfd has already been reaped. Never fall through
                // to a numeric wait that could bind a replacement PID.
                Err(Errno::ECHILD) => return Ok(()),
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "waitid(P_PIDFD) cleanup failed: {error}"
                    )));
                }
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("pidfd cleanup for tracee {pid} timed out"),
                ));
            }
            thread::sleep(SUBPROCESS_POLL_INTERVAL);
        }
    }

    enum TraceeCleanupOwnership {
        PreRegistration,
        NotifierOwned {
            terminal: TerminalCleanup,
            owns_claimed_exit: bool,
            raw_cleanup_claimed: bool,
            raw_cleanup_finishes_event: bool,
            cleanup_signal_sent: bool,
        },
    }

    enum CleanupWaitOwner {
        Notifier,
        Raw { finish_event: bool },
        TerminalAck,
        Authoritative(TerminalCleanup),
    }

    struct TraceeCleanupGuard {
        pid: Pid,
        pidfd: OwnedFd,
        ownership: TraceeCleanupOwnership,
        armed: bool,
    }

    impl TraceeCleanupGuard {
        fn new(pid: Pid) -> io::Result<Self> {
            Ok(Self {
                pid,
                pidfd: pidfd_open(pid.as_raw())?,
                ownership: TraceeCleanupOwnership::PreRegistration,
                armed: true,
            })
        }

        /// Transfers wait-status ownership before the first registration
        /// attempt. Raw waitpid cleanup is forbidden after this transition,
        /// including when proc-generation capture fails.
        fn store_terminal(&mut self, candidate: TerminalCleanup) -> io::Result<()> {
            match &self.ownership {
                TraceeCleanupOwnership::PreRegistration => {
                    self.ownership = TraceeCleanupOwnership::NotifierOwned {
                        terminal: candidate,
                        owns_claimed_exit: false,
                        raw_cleanup_claimed: false,
                        raw_cleanup_finishes_event: false,
                        cleanup_signal_sent: false,
                    };
                }
                TraceeCleanupOwnership::NotifierOwned { terminal, .. } => {
                    if terminal.pid != candidate.pid || !terminal.same_generation(&candidate) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "cleanup guard cannot bind a different notifier generation",
                        ));
                    }
                }
            }
            Ok(())
        }

        fn bind_terminal(&mut self, candidate: TerminalCleanup) -> io::Result<()> {
            self.store_terminal(candidate)?;
            self.terminal()
                .expect("notifier ownership transition stores terminal cleanup")
                .ensure_registered()
                .map_err(|error| io::Error::other(format!("register cleanup notifier: {error}")))
        }

        fn bind_notifier(&mut self, stopped: &Stopped) -> io::Result<()> {
            self.bind_terminal(TerminalCleanup::new_unregistered(stopped.0, &stopped.1))
        }

        fn bind_running_notifier(&mut self, running: &Running) -> io::Result<()> {
            self.bind_terminal(TerminalCleanup::new_unregistered(running.0, &running.1))
        }

        fn terminal(&self) -> Option<&TerminalCleanup> {
            match &self.ownership {
                TraceeCleanupOwnership::PreRegistration => None,
                TraceeCleanupOwnership::NotifierOwned { terminal, .. } => Some(terminal),
            }
        }

        /// Constructs ExitFuture only after guard ownership has moved to the
        /// same immutable notifier generation.
        fn exit_event(&mut self, stopped: &Stopped) -> io::Result<ExitFuture> {
            self.bind_notifier(stopped)?;
            Ok(stopped.exit_event())
        }

        /// Records transfer of the exact exit-stop capability immediately
        /// after ExitFuture returns it.
        fn mark_claimed_exit(&mut self) {
            let TraceeCleanupOwnership::NotifierOwned {
                owns_claimed_exit, ..
            } = &mut self.ownership
            else {
                panic!("exit capability claimed before notifier ownership transition");
            };
            *owns_claimed_exit = true;
        }

        fn disarm(&mut self) {
            self.armed = false;
        }

        fn cleanup_before_registration(pid: Pid, pidfd: &OwnedFd) -> io::Result<()> {
            match pidfd_send_signal(pidfd, libc::SIGKILL) {
                Ok(()) => {
                    if let Some(pause) = PRE_REGISTRATION_REAP_PAUSES.lock().remove(&pid.into()) {
                        pause.captured.wait();
                        pause.resume.wait();
                    }
                    reap_tracee_pidfd_bounded(pid, pidfd)
                }
                // A dead/reaped pidfd cannot refer to a recycled numeric PID.
                // In particular, do not fall through to waitpid(self.pid).
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
                Err(error) => Err(error),
            }
        }

        fn acquire_cleanup_wait_owner(
            pid: Pid,
            pidfd: &OwnedFd,
            terminal: &TerminalCleanup,
            signal_sent: &mut bool,
        ) -> io::Result<CleanupWaitOwner> {
            let authoritative =
                match NOTIFIER.current_registered(pid.into()) {
                    Ok(Some(authoritative)) => Some(authoritative),
                    Ok(None) | Err(_) => NOTIFIER
                        .registered_sync_handle(pid.into(), pidfd)
                        .map_err(|error| {
                            io::Error::other(format!(
                                "resolve exact-pidfd synchronous cleanup authority: {error}"
                            ))
                        })?,
                };
            if let Some(authoritative) = authoritative {
                terminal
                    .event
                    .adopt_authoritative(&authoritative)
                    .map_err(|error| {
                        io::Error::other(format!("adopt cleanup wait authority: {error}"))
                    })?;
            }
            if let Some(pause) = CLEANUP_OWNER_CLAIM_PAUSES.lock().remove(&pid.into()) {
                pause.captured.wait();
                pause.resume.wait();
            }

            let deadline = Instant::now() + REGISTRATION_RETRY_TIMEOUT;
            let return_deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
            let last_error = loop {
                match terminal.try_ensure_registered_for_cleanup(return_deadline) {
                    Ok(CancellableEventRegistration::Registered) => {
                        return match terminal.event.event().worker_state.load(Ordering::Acquire) {
                            WORKER_RUNNING => Ok(CleanupWaitOwner::Notifier),
                            WORKER_FINISHING | WORKER_DONE => Ok(CleanupWaitOwner::TerminalAck),
                            state => Err(io::Error::other(format!(
                                "successful cleanup registration retained worker state {state}"
                            ))),
                        };
                    }
                    Ok(CancellableEventRegistration::Synchronous(event)) => {
                        if !*signal_sent {
                            match pidfd_send_signal(pidfd, libc::SIGKILL) {
                                Ok(()) => *signal_sent = true,
                                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                                    *signal_sent = true;
                                }
                                Err(error) => return Err(error),
                            }
                        }
                        if let Some(pause) = CLEANUP_CANCEL_SIGNAL_PAUSES.lock().remove(&pid.into())
                        {
                            pause.captured.wait();
                            pause.resume.wait();
                        }
                        if !event.wait_for_sync_owner_release(TRACEE_WAIT_TIMEOUT) {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "synchronous wait owner did not release after exact pidfd cancellation",
                            ));
                        }
                    }
                    Ok(CancellableEventRegistration::ReturningTimedOut) => {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "typed status return transactions starved cleanup past its deadline",
                        ));
                    }
                    Ok(CancellableEventRegistration::Busy) if Instant::now() < deadline => {
                        thread::sleep(SUBPROCESS_POLL_INTERVAL);
                    }
                    Ok(CancellableEventRegistration::Busy) => break Errno::EBUSY,
                    Err(_) if Instant::now() < deadline => {
                        thread::sleep(SUBPROCESS_POLL_INTERVAL);
                    }
                    Err(error) => break error,
                }
            };

            // Deterministically force registration to win immediately before
            // the raw-owner CAS. This models the only meaningful CAS loss.
            if FORCE_RAW_CLAIM_REGISTRATION_RACE
                .lock()
                .remove(&pid.into())
                .is_some()
            {
                CAPTURE_PERSISTENT_ERRORS.lock().remove(&pid.into());
                match terminal
                    .try_ensure_registered_for_cleanup(Instant::now() + TRACEE_WAIT_TIMEOUT)
                {
                    Ok(CancellableEventRegistration::Registered) => {}
                    Ok(CancellableEventRegistration::Synchronous(_)) => {
                        return Err(io::Error::other(
                            "forced cleanup registration race found a synchronous owner",
                        ));
                    }
                    Ok(CancellableEventRegistration::ReturningTimedOut) => {
                        return Err(io::Error::other(
                            "forced cleanup registration race timed out behind a returning owner",
                        ));
                    }
                    Ok(CancellableEventRegistration::Busy) => {
                        return Err(io::Error::other(
                            "forced cleanup registration race remained unpublished",
                        ));
                    }
                    Err(error) => {
                        return Err(io::Error::other(format!(
                            "force cleanup registration race: {error}"
                        )));
                    }
                }
            }

            match terminal
                .try_claim_unstarted_raw_cleanup()
                .map_err(|error| {
                    io::Error::other(format!("claim exact raw cleanup owner: {error}"))
                })? {
                RawCleanupClaim::Won => {
                    return Ok(CleanupWaitOwner::Raw { finish_event: true });
                }
                RawCleanupClaim::Existing(event) => {
                    return Ok(CleanupWaitOwner::Authoritative(TerminalCleanup {
                        pid: terminal.pid,
                        event,
                    }));
                }
                RawCleanupClaim::Lost => {}
            }

            let event = terminal.event.event();
            match event.worker_state.load(Ordering::Acquire) {
                WORKER_RUNNING => Ok(CleanupWaitOwner::Notifier),
                // Another raw owner or synthetic completion won. This guard
                // must never infer raw-wait ownership from a state it did not
                // install; it waits only for that owner's terminal ack.
                WORKER_FINISHING | WORKER_DONE => Ok(CleanupWaitOwner::TerminalAck),
                state => Err(io::Error::other(format!(
                    "cleanup registration remained {last_error} and raw-owner CAS lost in state {state}"
                ))),
            }
        }

        fn cleanup_with_notifier(
            pid: Pid,
            pidfd: &OwnedFd,
            terminal: &TerminalCleanup,
            owns_claimed_exit: bool,
            signal_sent: &mut bool,
        ) -> io::Result<()> {
            if !*signal_sent {
                match pidfd_send_signal(pidfd, libc::SIGKILL) {
                    Ok(()) => *signal_sent = true,
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                        *signal_sent = true;
                        if terminal.wait(TRACEE_WAIT_TIMEOUT) {
                            return Ok(());
                        }
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("notifier for dead tracee {pid} did not finish"),
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }

            if owns_claimed_exit {
                // SAFETY: `mark_claimed_exit` is called immediately after the
                // unique Stopped capability is returned, and this guard is its
                // sole cancellation owner in these exact-lifetime tests.
                unsafe { terminal.revoke_owned_exit_stop() }
            } else {
                terminal.revoke_unclaimed_exit_stop()
            }
            .map_err(|error| io::Error::other(format!("revoke exit capability: {error}")))?;

            let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
            let mut exit_stop_resumed = false;
            loop {
                if terminal.wait(Duration::ZERO) {
                    return Ok(());
                }
                if terminal.exit_stop_observed() && !exit_stop_resumed {
                    nix::sys::ptrace::cont(pid, None).map_err(|error| {
                        io::Error::other(format!("resume cleanup exit stop: {error}"))
                    })?;
                    exit_stop_resumed = true;
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("notifier cleanup for tracee {pid} timed out"),
                    ));
                }
                thread::sleep(SUBPROCESS_POLL_INTERVAL);
            }
        }

        fn cleanup_with_raw_wait(
            pid: Pid,
            pidfd: &OwnedFd,
            terminal: &TerminalCleanup,
            finish_event: bool,
            signal_sent: &mut bool,
        ) -> io::Result<()> {
            if !*signal_sent {
                match pidfd_send_signal(pidfd, libc::SIGKILL) {
                    Ok(()) => *signal_sent = true,
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                        *signal_sent = true;
                    }
                    Err(error) => return Err(error),
                }
            }
            reap_tracee_pidfd_bounded(pid, pidfd)?;
            if finish_event {
                terminal.finish_unstarted_raw_cleanup();
            } else if !terminal.wait(TRACEE_WAIT_TIMEOUT) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "synthetic notifier completion did not finish after exact raw reap",
                ));
            }
            Ok(())
        }

        fn cleanup_with_terminal_ack(
            pidfd: &OwnedFd,
            terminal: &TerminalCleanup,
            signal_sent: &mut bool,
        ) -> io::Result<()> {
            if terminal.wait(TRACEE_WAIT_TIMEOUT) {
                return Ok(());
            }

            // The winning owner failed to acknowledge within its bound. Do
            // not steal waitpid ownership; only ensure the exact pidfd target
            // is no longer live before surfacing the invariant failure.
            if !*signal_sent {
                match pidfd_send_signal(pidfd, libc::SIGKILL) {
                    Ok(()) => *signal_sent = true,
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                        *signal_sent = true;
                    }
                    Err(error) => return Err(error),
                }
            }
            let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
            loop {
                if terminal.wait(Duration::ZERO) {
                    return Ok(());
                }
                if pidfd_exited(pidfd)? {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cleanup owner omitted terminal acknowledgment after tracee exit",
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "cleanup owner left the exact pidfd target live",
                    ));
                }
                thread::sleep(SUBPROCESS_POLL_INTERVAL);
            }
        }

        fn cleanup(&mut self) -> io::Result<()> {
            if !self.armed {
                return Ok(());
            }
            if matches!(self.ownership, TraceeCleanupOwnership::PreRegistration) {
                Self::cleanup_before_registration(self.pid, &self.pidfd)?;
                self.armed = false;
                return Ok(());
            }

            let needs_owner = matches!(
                self.ownership,
                TraceeCleanupOwnership::NotifierOwned {
                    raw_cleanup_claimed: false,
                    ..
                }
            );
            if needs_owner {
                let TraceeCleanupOwnership::NotifierOwned {
                    terminal,
                    cleanup_signal_sent,
                    ..
                } = &mut self.ownership
                else {
                    unreachable!()
                };
                match Self::acquire_cleanup_wait_owner(
                    self.pid,
                    &self.pidfd,
                    terminal,
                    cleanup_signal_sent,
                )? {
                    CleanupWaitOwner::Notifier => {
                        let TraceeCleanupOwnership::NotifierOwned {
                            terminal,
                            owns_claimed_exit,
                            cleanup_signal_sent,
                            ..
                        } = &mut self.ownership
                        else {
                            unreachable!()
                        };
                        Self::cleanup_with_notifier(
                            self.pid,
                            &self.pidfd,
                            terminal,
                            *owns_claimed_exit,
                            cleanup_signal_sent,
                        )?;
                        self.armed = false;
                        return Ok(());
                    }
                    CleanupWaitOwner::Raw { finish_event } => {
                        let TraceeCleanupOwnership::NotifierOwned {
                            raw_cleanup_claimed,
                            raw_cleanup_finishes_event,
                            ..
                        } = &mut self.ownership
                        else {
                            unreachable!()
                        };
                        *raw_cleanup_claimed = true;
                        *raw_cleanup_finishes_event = finish_event;
                    }
                    CleanupWaitOwner::TerminalAck => {
                        let TraceeCleanupOwnership::NotifierOwned {
                            terminal,
                            cleanup_signal_sent,
                            ..
                        } = &mut self.ownership
                        else {
                            unreachable!()
                        };
                        Self::cleanup_with_terminal_ack(
                            &self.pidfd,
                            terminal,
                            cleanup_signal_sent,
                        )?;
                        self.armed = false;
                        return Ok(());
                    }
                    CleanupWaitOwner::Authoritative(authoritative) => {
                        let TraceeCleanupOwnership::NotifierOwned {
                            terminal,
                            owns_claimed_exit,
                            ..
                        } = &mut self.ownership
                        else {
                            unreachable!()
                        };
                        *terminal = authoritative;
                        *owns_claimed_exit = false;
                        return self.cleanup();
                    }
                }
            }

            let TraceeCleanupOwnership::NotifierOwned {
                terminal,
                raw_cleanup_claimed: true,
                raw_cleanup_finishes_event,
                cleanup_signal_sent,
                ..
            } = &mut self.ownership
            else {
                unreachable!("cleanup wait ownership must be resolved")
            };
            Self::cleanup_with_raw_wait(
                self.pid,
                &self.pidfd,
                terminal,
                *raw_cleanup_finishes_event,
                cleanup_signal_sent,
            )?;
            self.armed = false;
            Ok(())
        }
    }

    impl Drop for TraceeCleanupGuard {
        fn drop(&mut self) {
            let _ = self.cleanup();
        }
    }

    #[test]
    fn stale_cleanup_guard_pid_projection_cannot_signal_replacement() {
        let (old_pid, mut old_cleanup) =
            spawn_stopped_process(None).expect("spawn old cleanup generation");
        pidfd_send_signal(&old_cleanup.pidfd, libc::SIGKILL)
            .expect("signal old generation through pidfd");
        reap_tracee_bounded(old_pid).expect("reap old cleanup generation");

        let (replacement_pid, replacement_cleanup) =
            spawn_stopped_process(None).expect("spawn replacement cleanup generation");
        // Project the stale numeric identity onto a live process. The pidfd
        // must remain authoritative during Drop/unwind.
        old_cleanup.pid = replacement_pid;
        drop(old_cleanup);

        assert_eq!(
            unsafe { libc::kill(replacement_pid.as_raw(), 0) },
            0,
            "stale cleanup guard signaled a live replacement"
        );
        reap_stopped_process(replacement_cleanup);
    }

    #[test]
    fn fallback_guard_unwind_does_not_orphan_stopped_child() {
        let identity = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&identity);
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let (pid, _cleanup) =
                spawn_stopped_process(None).expect("spawn guarded fallback child");
            *captured.lock() = Some(
                WorkerIdentity::capture_process(pid.into())
                    .expect("capture guarded fallback child"),
            );
            panic!("exercise fallback unwind cleanup");
        }));
        assert!(unwind.is_err());
        let identity = identity
            .lock()
            .take()
            .expect("fallback panic captured child identity");
        assert!(
            !identity.is_same_process_generation(),
            "fallback panic orphaned its stopped child"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cleanup_guard_transitions_before_first_exit_future_poll() {
        let (_, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn notifier-owned cleanup tracee");
        stopped
            .setoptions(Options::PTRACE_O_TRACEEXIT)
            .expect("enable notifier-owned cleanup exit stop");
        let mut exit = Box::pin(
            cleanup
                .exit_event(&stopped)
                .expect("bind cleanup guard before ExitFuture poll"),
        );
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned { .. }
        ));

        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert_eq!(exit.as_mut().poll(&mut context), Poll::Pending);
        drop(exit);

        cleanup
            .cleanup()
            .expect("notifier-owned cleanup after canceled ExitFuture");
        assert!(!cleanup.armed);
    }

    #[test]
    fn registration_is_reused_across_status_events() {
        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&counter));
        let event = Event::new();

        assert_eq!(event.poll_status(&waker), Poll::Pending);
        assert_eq!(event.poll_status(&waker), Poll::Pending);

        let stopped = (libc::SIGSTOP << 8) | 0x7f;
        assert_eq!(event.update(stopped), None);
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(stopped)));
        assert!(!event.status_waker.register(&waker));
    }

    #[test]
    fn bounded_test_subprocess_kills_and_reaps_hung_inner() {
        const HANG: &str = "SAFEPTRACE_BOUNDED_INNER_HANG";
        if env::var_os(HANG).is_some() {
            println!("BOUNDED_INNER_HANG_READY");
            io::stdout().flush().expect("flush hang marker");
            loop {
                thread::park();
            }
        }

        let inner = "notifier::test::bounded_test_subprocess_kills_and_reaps_hung_inner";
        let started = Instant::now();
        let result =
            run_exact_test_bounded(inner, &[(HANG, "1")], false, Duration::from_millis(100))
                .expect("run deliberately hung exact-test subprocess");

        assert!(result.timed_out, "hung subprocess unexpectedly completed");
        assert!(
            String::from_utf8_lossy(&result.output.stdout).contains("BOUNDED_INNER_HANG_READY"),
            "hung subprocess output was not drained concurrently: {result:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "hung subprocess cleanup exceeded its external bound"
        );
    }

    #[test]
    fn drain_failure_after_reap_never_signals_projected_reused_pgid() {
        const SENTINEL: &str = "SAFEPTRACE_PGID_SENTINEL_INNER";
        const PROJECT_REAPED_PGID: &str = "SAFEPTRACE_PROJECT_REAPED_PGID";
        if env::var_os(SENTINEL).is_some() {
            loop {
                thread::park();
            }
        }
        if env::var_os(PROJECT_REAPED_PGID).is_some() {
            println!("PROJECTED_REAPED_PGID_INNER_COMPLETE");
            return;
        }

        let inner = "notifier::test::drain_failure_after_reap_never_signals_projected_reused_pgid";
        let mut sentinel_command = Command::new(env::current_exe().expect("current test binary"));
        sentinel_command
            .args(["--exact", inner, "--nocapture"])
            .env(SENTINEL, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut sentinel = ChildProcessGroup::new(
            sentinel_command
                .spawn()
                .expect("spawn projected-PGID sentinel"),
        )
        .expect("open projected-PGID sentinel pidfd");
        let projected_pgid = sentinel.process_group.to_string();

        let error = run_exact_test_bounded(
            inner,
            &[(PROJECT_REAPED_PGID, projected_pgid.as_str())],
            false,
            PID_NAMESPACE_TEST_TIMEOUT,
        )
        .expect_err("injected post-reap reader failure must surface");
        assert!(
            error
                .to_string()
                .contains("injected exact-test reader failure"),
            "{error}"
        );
        assert!(
            !pidfd_exited(&sentinel.pidfd).expect("poll projected-PGID sentinel"),
            "post-reap error cleanup signaled a recycled process group"
        );

        sentinel
            .terminate_group()
            .expect("terminate projected-PGID sentinel");
        sentinel.wait().expect("reap projected-PGID sentinel");
    }

    #[test]
    fn exact_new_child_cleanup_never_signals_projected_reused_pgid() {
        const SENTINEL: &str = "SAFEPTRACE_NEW_CHILD_PGID_SENTINEL";
        if env::var_os(SENTINEL).is_some() {
            loop {
                thread::park();
            }
        }

        let mut old_command = Command::new("/bin/true");
        old_command.process_group(0);
        let mut old = ChildProcessGroup::new(
            old_command
                .spawn()
                .expect("spawn old exact-cleanup group leader"),
        )
        .expect("open old exact-cleanup leader pidfd");
        let old_pid = old.process_group;
        let stale_pidfd = old
            .pidfd
            .try_clone()
            .expect("clone stale exact-cleanup pidfd");
        old.wait().expect("reap old exact-cleanup leader");

        let inner = "notifier::test::exact_new_child_cleanup_never_signals_projected_reused_pgid";
        let mut sentinel_command = Command::new(env::current_exe().expect("current test binary"));
        sentinel_command
            .args(["--exact", inner, "--nocapture"])
            .env(SENTINEL, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut sentinel = ChildProcessGroup::new(
            sentinel_command
                .spawn()
                .expect("spawn exact-cleanup projected-PGID sentinel"),
        )
        .expect("open exact-cleanup sentinel pidfd");

        let mut stale_guard = ExactNewChildCleanupGuard {
            projected_pgid: Pid::from_raw(sentinel.process_group),
            event: EventHandle::new(),
            members: Arc::new(Mutex::new(vec![ExactTestMember {
                pid: crate::Pid::from_raw(old_pid),
                pidfd: stale_pidfd,
                phase: ExactCleanupPhase::NeedsSignal,
            }])),
            registration_error: Arc::new(Mutex::new(None)),
            pidfd_open_error: Arc::new(Mutex::new(None)),
            signal_errors: HashMap::new(),
            reap_errors: HashMap::new(),
            armed: true,
        };
        stale_guard
            .cleanup()
            .expect("stale exact cleanup ignores projected numeric PGID");
        assert!(
            !pidfd_exited(&sentinel.pidfd).expect("poll exact-cleanup sentinel"),
            "stale exact cleanup signaled the projected replacement process group"
        );

        sentinel
            .terminate_group()
            .expect("terminate exact-cleanup sentinel");
        sentinel.wait().expect("reap exact-cleanup sentinel");
    }

    #[test]
    fn exact_reuse_nonzero_inner_is_a_hard_failure() {
        const FAIL: &str = "SAFEPTRACE_EXACT_REUSE_FAIL_INNER";
        if env::var_os(FAIL).is_some() {
            println!("ACTUAL_PID_REUSE_UNAVAILABLE");
            io::stdout().flush().expect("flush misleading marker");
            std::process::exit(23);
        }

        let inner = "notifier::test::exact_reuse_nonzero_inner_is_a_hard_failure";
        let result =
            run_exact_test_bounded(inner, &[(FAIL, "1")], false, PID_NAMESPACE_TEST_TIMEOUT)
                .expect("run nonzero exact-test subprocess");
        assert!(!result.timed_out);
        let error = classify_exact_reuse_output(
            Some(&result.output),
            "ACTUAL_PID_REUSE_EXERCISED",
            "ACTUAL_PID_REUSE_UNAVAILABLE",
        )
        .expect_err("nonzero inner test must not become an unavailable fallback");
        assert!(error.contains("status=exit status: 23"), "{error}");
    }

    #[test]
    fn exact_reuse_classifier_accepts_only_known_uid_map_denial() {
        let output = Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"unshare: write failed /proc/self/uid_map: Operation not permitted\n".to_vec(),
        };
        assert_eq!(
            classify_exact_reuse_output(
                Some(&output),
                "ACTUAL_PID_REUSE_EXERCISED",
                "ACTUAL_PID_REUSE_UNAVAILABLE",
            ),
            Ok(ExactReuseOutcome::Unavailable)
        );

        let nearby = Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: Vec::new(),
            stderr: b"unshare: write failed /proc/self/uid_map: Input/output error\n".to_vec(),
        };
        assert!(
            classify_exact_reuse_output(
                Some(&nearby),
                "ACTUAL_PID_REUSE_EXERCISED",
                "ACTUAL_PID_REUSE_UNAVAILABLE",
            )
            .is_err(),
            "nearby non-permission uid_map failure became an unavailable fallback"
        );
    }

    #[test]
    fn registration_updates_when_the_executor_changes_wakers() {
        let slot = WakerSlot::default();
        let first = Waker::from(Arc::new(WakeCounter::default()));
        let second_counter = Arc::new(WakeCounter::default());
        let second = Waker::from(Arc::clone(&second_counter));

        assert!(slot.register(&first));
        assert!(!slot.register(&first));
        assert!(slot.register(&second));
        slot.wake();
        assert_eq!(second_counter.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn exit_event_code() {
        assert_eq!(
            WaitStatus::from_raw(Pid::from_raw(42), PTRACE_EVENT_EXIT_STOP),
            Ok(WaitStatus::PtraceEvent(
                Pid::from_raw(42),
                Signal::SIGTRAP,
                libc::PTRACE_EVENT_EXIT
            ))
        );
    }

    #[test]
    fn held_unclaimed_exit_waiter_expires_before_terminal_publication() {
        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&counter));
        let event = Event::new();
        let waiter = Arc::new(ExitWaiter::default());

        assert_eq!(event.poll_exit(&waiter, &waker), Poll::Pending);
        event.update(PTRACE_EVENT_EXIT_STOP);
        event.update(42 << 8);

        assert_eq!(
            event.poll_exit(&waiter, &waker),
            Poll::Ready(Err(Errno::EALREADY))
        );
        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(42 << 8)));
    }

    #[test]
    fn exit_stop_capability_is_single_claim_while_terminal_status_fans_out() {
        let waker = Waker::from(Arc::new(WakeCounter::default()));
        let event = Event::new();
        let winner = Arc::new(ExitWaiter::default());
        let duplicate = Arc::new(ExitWaiter::default());

        event.update(PTRACE_EVENT_EXIT_STOP);
        assert_eq!(event.poll_exit(&winner, &waker), Poll::Ready(Ok(())));
        assert_eq!(
            event.poll_exit(&duplicate, &waker),
            Poll::Ready(Err(Errno::EALREADY)),
            "one Event generation minted two exit-stop capabilities"
        );

        event.update(42 << 8);
        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(42 << 8)));
        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(42 << 8)));
        assert_eq!(
            event.poll_exit(&winner, &waker),
            Poll::Ready(Err(Errno::EALREADY))
        );
    }

    #[test]
    fn cleanup_requires_exclusive_transfer_of_claimed_exit_stop() {
        let waker = Waker::from(Arc::new(WakeCounter::default()));
        let event = Event::new();
        let waiter = Arc::new(ExitWaiter::default());

        event.update(PTRACE_EVENT_EXIT_STOP);
        assert_eq!(event.poll_exit(&waiter, &waker), Poll::Ready(Ok(())));
        assert_eq!(
            event.prepare_exit_capability_for_cleanup(false),
            Err(Errno::EALREADY)
        );
        event
            .prepare_exit_capability_for_cleanup(true)
            .expect("exclusive cleanup transfer rejected claimed exit stop");
        assert_eq!(
            event.poll_exit(&waiter, &waker),
            Poll::Ready(Err(Errno::EALREADY))
        );
    }

    #[test]
    fn simultaneous_exit_waiters_are_all_woken_for_one_claim() {
        for claim_a_first in [true, false] {
            let counter_a = Arc::new(WakeCounter::default());
            let counter_b = Arc::new(WakeCounter::default());
            let waker_a = Waker::from(Arc::clone(&counter_a));
            let waker_b = Waker::from(Arc::clone(&counter_b));
            let event = Event::new();
            let waiter_a = Arc::new(ExitWaiter::default());
            let waiter_b = Arc::new(ExitWaiter::default());

            assert_eq!(event.poll_exit(&waiter_a, &waker_a), Poll::Pending);
            assert_eq!(event.poll_exit(&waiter_b, &waker_b), Poll::Pending);
            event.update(PTRACE_EVENT_EXIT_STOP);

            assert_eq!(counter_a.0.load(Ordering::SeqCst), 1);
            assert_eq!(counter_b.0.load(Ordering::SeqCst), 1);
            let (winner, winner_waker, duplicate, duplicate_waker) = if claim_a_first {
                (&waiter_a, &waker_a, &waiter_b, &waker_b)
            } else {
                (&waiter_b, &waker_b, &waiter_a, &waker_a)
            };
            assert_eq!(event.poll_exit(winner, winner_waker), Poll::Ready(Ok(())));
            assert_eq!(
                event.poll_exit(duplicate, duplicate_waker),
                Poll::Ready(Err(Errno::EALREADY))
            );
        }
    }

    #[test]
    fn exit_waiter_retries_capability_before_status_publication() {
        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&counter));
        let event = Event::new();
        let waiter = Arc::new(ExitWaiter::default());

        // Deterministically model the Round 12 publication order between its
        // two atomic writes. A poll in this gap must remain retryable.
        event
            .exit_capability
            .store(EXIT_CAP_AVAILABLE, Ordering::Release);
        assert_eq!(event.poll_exit(&waiter, &waker), Poll::Pending);

        event.exit_status.store(EXIT_STOPPED, Ordering::Release);
        event.exit_waiters.wake_all();
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert_eq!(event.poll_exit(&waiter, &waker), Poll::Ready(Ok(())));
    }

    #[test]
    fn exit_waiter_retries_forced_status_before_capability_publication() {
        let counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&counter));
        let event = Arc::new(Event::new());
        let waiter = Arc::new(ExitWaiter::default());
        let (paused_tx, paused_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let publisher_event = Arc::clone(&event);

        let publisher = thread::spawn(move || {
            publisher_event.publish_exit_stop(|| {
                paused_tx.send(()).expect("report exit publication gap");
                resume_rx.recv().expect("resume exit publication");
            });
        });
        paused_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("exit publication did not reach forced gap");

        assert_eq!(event.exit_status.load(Ordering::Acquire), EXIT_STOPPED);
        assert_eq!(
            event.exit_capability.load(Ordering::Acquire),
            EXIT_CAP_PENDING
        );
        assert_eq!(event.poll_exit(&waiter, &waker), Poll::Pending);

        resume_tx.send(()).expect("release exit publication");
        publisher.join().expect("join exit publisher");
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        assert_eq!(event.poll_exit(&waiter, &waker), Poll::Ready(Ok(())));
    }

    #[test]
    fn terminal_finalization_waits_for_exit_capability_publication() {
        let event = Arc::new(Event::new());
        let waiter = Arc::new(ExitWaiter::default());
        let waker = Waker::from(Arc::new(WakeCounter::default()));
        let (paused_tx, paused_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let publisher_event = Arc::clone(&event);
        let publisher = thread::spawn(move || {
            publisher_event.publish_exit_stop(|| {
                paused_tx.send(()).expect("report exit publication gap");
                resume_rx.recv().expect("resume exit publication");
            });
        });
        paused_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("exit publication did not reach forced gap");

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let finalizer_event = Arc::clone(&event);
        let finalizer = thread::spawn(move || {
            started_tx.send(()).expect("report terminal attempt");
            finalizer_event.update(42 << 8);
            done_tx.send(()).expect("report terminal completion");
        });
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("terminal finalizer did not start");
        assert_eq!(
            done_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout),
            "terminal publication interleaved the exit-stop atomic gap"
        );

        resume_tx.send(()).expect("release exit publication");
        publisher.join().expect("join exit publisher");
        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("terminal finalizer stayed blocked");
        finalizer.join().expect("join terminal finalizer");

        assert_eq!(event.exit_status.load(Ordering::Acquire), EXIT_STOPPED);
        assert_eq!(
            event.exit_capability.load(Ordering::Acquire),
            EXIT_CAP_EXPIRED
        );
        assert_eq!(
            event.poll_exit(&waiter, &waker),
            Poll::Ready(Err(Errno::EALREADY))
        );
        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(42 << 8)));
    }

    #[test]
    fn cancelled_last_exit_waiter_does_not_orphan_first_waiter() {
        let counter_a = Arc::new(WakeCounter::default());
        let counter_b = Arc::new(WakeCounter::default());
        let waker_a = Waker::from(Arc::clone(&counter_a));
        let waker_b = Waker::from(Arc::clone(&counter_b));
        let event = Event::new();
        let waiter_a = Arc::new(ExitWaiter::default());
        let waiter_b = Arc::new(ExitWaiter::default());

        assert_eq!(event.poll_exit(&waiter_a, &waker_a), Poll::Pending);
        assert_eq!(event.poll_exit(&waiter_b, &waker_b), Poll::Pending);
        drop(waiter_b);
        event.update(PTRACE_EVENT_EXIT_STOP);

        assert_eq!(counter_a.0.load(Ordering::SeqCst), 1);
        assert_eq!(counter_b.0.load(Ordering::SeqCst), 0);
        assert_eq!(event.poll_exit(&waiter_a, &waker_a), Poll::Ready(Ok(())));
        event.update(42 << 8);
        assert_eq!(event.poll_status(&waker_a), Poll::Ready(Ok(42 << 8)));
        assert_eq!(event.poll_status(&waker_a), Poll::Ready(Ok(42 << 8)));
    }

    #[test]
    fn terminal_status_remains_available_to_late_waiters() {
        let waker = Waker::from(Arc::new(WakeCounter::default()));

        for terminal in [42 << 8, Signal::SIGILL as i32] {
            let event = Event::new();
            let waiter = Arc::new(ExitWaiter::default());
            event.update(PTRACE_EVENT_EXIT_STOP);
            event.update(terminal);

            assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(terminal)));
            assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(terminal)));
            assert_eq!(
                event.poll_exit(&waiter, &waker),
                Poll::Ready(Err(Errno::EALREADY))
            );
        }
    }

    #[test]
    fn queued_stop_precedes_monotonic_terminal_status() {
        let waker = Waker::from(Arc::new(WakeCounter::default()));
        let event = Event::new();
        let stopped = (Signal::SIGSTOP as i32) << 8 | 0x7f;
        let terminal = 42 << 8;

        event.update(stopped);
        event.update(terminal);

        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(stopped)));
        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(terminal)));
        assert_eq!(event.poll_status(&waker), Poll::Ready(Ok(terminal)));
    }

    #[test]
    fn failed_cleanup_decode_preserves_fifo_front_for_retry() {
        let pid = Pid::from_raw(i32::MAX - 31);
        let handle = EventHandle::new();
        let child_event = (libc::PTRACE_EVENT_FORK << 16) | (libc::SIGTRAP << 8) | 0x7f;
        handle.event().update(child_event);
        let cleanup = TerminalCleanup {
            pid: pid.into(),
            event: handle,
        };

        let reservation = cleanup
            .reserve_pending_for_cleanup(Duration::ZERO)
            .expect("reserve child-event FIFO front");
        assert!(reservation.decode().is_err(), "fake child event decoded");
        drop(reservation);
        let retry = cleanup
            .reserve_pending_for_cleanup(Duration::ZERO)
            .expect("decode failure removed FIFO front");
        assert_eq!(retry.status, child_event);
    }

    #[test]
    fn worker_completion_does_not_hide_pending_cleanup_status() {
        let pid = Pid::from_raw(i32::MAX - 32);
        let handle = EventHandle::new();
        let stopped = (Signal::SIGSTOP as i32) << 8 | 0x7f;
        handle.event().update(stopped);
        assert!(handle.event().try_begin_worker_start());
        handle.event().mark_worker_running();
        handle.event().mark_worker_done();
        let cleanup = TerminalCleanup {
            pid: pid.into(),
            event: handle,
        };

        assert!(cleanup.wait(Duration::ZERO));
        assert!(!cleanup.pending_is_empty());
    }

    #[test]
    fn authoritative_adoption_is_cycle_free_and_preserves_handle_hash() {
        let first = EventHandle::new();
        let second = EventHandle::new();
        let first_hash = handle_hash(&first);
        let second_hash = handle_hash(&second);
        let start = Arc::new(Barrier::new(3));

        let first_racer = first.clone();
        let second_target = second.clone();
        let first_start = Arc::clone(&start);
        let forward = thread::spawn(move || {
            first_start.wait();
            first_racer.adopt_authoritative(&second_target)
        });
        let second_racer = second.clone();
        let first_target = first.clone();
        let second_start = Arc::clone(&start);
        let reverse = thread::spawn(move || {
            second_start.wait();
            second_racer.adopt_authoritative(&first_target)
        });
        start.wait();
        forward.join().expect("join forward adoption").unwrap();
        reverse.join().expect("join reverse adoption").unwrap();

        assert!(Arc::ptr_eq(first.event(), second.event()));
        assert_ne!(first, second, "stable token identity must not be rewritten");
        assert_eq!(handle_hash(&first), first_hash);
        assert_eq!(handle_hash(&second), second_hash);

        let rejected = EventHandle::new();
        let adopted = if first.0.authoritative.get().is_some() {
            &first
        } else {
            &second
        };
        assert_eq!(
            adopted.adopt_authoritative(&rejected),
            Err(Errno::EALREADY),
            "an adopted handle cannot be redirected to a second authority"
        );
        assert!(Arc::ptr_eq(first.event(), second.event()));
    }

    #[test]
    fn terminal_cleanup_removes_stale_pid_registration() {
        let pid = Pid::from_raw(i32::MAX - 17);
        let running = Running::new(pid.into());
        let cleanup = running.terminal_cleanup();
        let old_event = cleanup.event.clone();

        assert!(cleanup.wait(Duration::from_secs(1)));
        let replacement_handle = EventHandle::new();
        let replacement = NOTIFIER
            .event(pid.into(), &replacement_handle)
            .expect("resolve absent replacement");
        assert!(
            !Arc::ptr_eq(old_event.event(), replacement.event()),
            "terminal cleanup retained a stale PID registry entry"
        );
    }

    #[test]
    fn terminal_cleanup_surfaces_and_retries_typed_capture_error() {
        let (pid, mut child_cleanup) =
            spawn_stopped_process(None).expect("spawn capture-error child");
        CAPTURE_ERRORS.lock().insert(pid.into(), Errno::EMFILE);

        let running = Running::new(pid.into());
        let error = child_cleanup
            .bind_running_notifier(&running)
            .expect_err("first notifier registration must surface EMFILE");
        assert!(error.to_string().contains("EMFILE"), "{error}");
        assert!(matches!(
            child_cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned { .. }
        ));
        let cleanup = child_cleanup
            .terminal()
            .expect("failed registration retains notifier ownership");
        assert_eq!(cleanup.registration_error(), Some(Errno::EMFILE));
        assert!(!cleanup.wait(Duration::ZERO));
        cleanup
            .ensure_registered()
            .expect("retry notifier registration after EMFILE");
        assert_eq!(cleanup.registration_error(), None);

        pidfd_send_signal(&child_cleanup.pidfd, libc::SIGKILL)
            .expect("signal capture-error child through pidfd");
        assert!(cleanup.wait(Duration::from_secs(1)));
        child_cleanup.disarm();
        assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
    }

    #[test]
    fn unsupported_pidfd_thread_fails_closed_before_registration() {
        for error in [Errno::EINVAL, Errno::ENOSYS] {
            let (pid, cleanup) =
                spawn_stopped_process(None).expect("spawn unsupported-pidfd child");
            let running = Running::new(pid.into());
            let terminal = TerminalCleanup::new_unregistered(pid.into(), &running.1);
            PIDFD_OPEN_ERRORS.lock().insert(pid.into(), error);

            assert_eq!(terminal.ensure_registered(), Err(error));
            assert_eq!(terminal.registration_error(), Some(error));
            assert_eq!(
                terminal.event.event().worker_state.load(Ordering::Acquire),
                WORKER_NOT_STARTED
            );
            assert!(!NOTIFIER.pids.lock().contains_key(&pid.into()));
            assert_eq!(
                terminal.event.event().wait_owner.load(Ordering::Acquire),
                WAIT_OWNER_NONE,
                "failed registration must release wait ownership"
            );

            reap_stopped_process(cleanup);
        }
    }

    #[test]
    fn pidfd_liveness_errors_are_typed_across_owner_paths() {
        let (lookup_pid, lookup_cleanup) =
            spawn_stopped_process(None).expect("spawn liveness lookup child");
        PIDFD_LIVENESS_ERRORS
            .lock()
            .entry(lookup_pid.into())
            .or_default()
            .push_back(Errno::EPERM);
        assert!(matches!(
            EventHandle::current_or_new(lookup_pid.into()),
            Err(Errno::EPERM)
        ));
        reap_stopped_process(lookup_cleanup);

        let (event_pid, event_cleanup) =
            spawn_stopped_process(None).expect("spawn liveness event child");
        let event_running = Running::new(event_pid.into());
        let event_terminal = TerminalCleanup::new_unregistered(event_pid.into(), &event_running.1);
        PIDFD_LIVENESS_ERRORS
            .lock()
            .entry(event_pid.into())
            .or_default()
            .push_back(Errno::EINVAL);
        assert_eq!(event_terminal.ensure_registered(), Err(Errno::EINVAL));
        assert_eq!(event_terminal.registration_error(), Some(Errno::EINVAL));
        reap_stopped_process(event_cleanup);

        let (raw_pid, mut raw_cleanup) =
            spawn_stopped_process(None).expect("spawn liveness raw-claim child");
        let authoritative_running = Running::new(raw_pid.into());
        let authoritative = authoritative_running.terminal_cleanup();
        let competing_running = Running::new(raw_pid.into());
        let competing = TerminalCleanup::new_unregistered(raw_pid.into(), &competing_running.1);
        PIDFD_LIVENESS_ERRORS
            .lock()
            .entry(raw_pid.into())
            .or_default()
            .push_back(Errno::EBADF);
        assert!(matches!(
            competing.try_claim_unstarted_raw_cleanup(),
            Err(Errno::EBADF)
        ));
        raw_cleanup
            .store_terminal(authoritative)
            .expect("bind raw-claim cleanup to authoritative worker");
        raw_cleanup
            .cleanup()
            .expect("cleanup liveness raw-claim child");
    }

    #[test]
    fn synchronous_wait_claim_blocks_and_wakes_registration() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn sync-first wait-owner child");
        let synchronous_running = Running::new(pid.into());
        let notifier_running = Running::new(pid.into());
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &notifier_running.1);
        let claimed = Arc::new(Barrier::new(2));
        let resume_wait = Arc::new(Barrier::new(2));
        SYNC_WAIT_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&claimed),
                resume: Arc::clone(&resume_wait),
            },
        );
        let synchronous = thread::spawn(move || synchronous_running.wait());
        claimed.wait();

        let (registered_tx, registered_rx) = mpsc::channel();
        let registration = thread::spawn(move || {
            let result = terminal.ensure_registered();
            registered_tx
                .send(())
                .expect("report sync-first registration completion");
            (result, terminal)
        });
        thread::sleep(Duration::from_millis(20));
        assert!(
            registered_rx.try_recv().is_err(),
            "registration bypassed the synchronous wait-owner claim"
        );

        resume_wait.wait();
        nix::sys::signal::kill(pid, Signal::SIGCONT).expect("resume sync-first child");
        assert!(matches!(
            synchronous.join().expect("join synchronous wait"),
            Ok(Wait::Exited(waited, crate::ExitStatus::Exited(0))) if waited == pid.into()
        ));
        registered_rx
            .recv_timeout(TRACEE_WAIT_TIMEOUT)
            .expect("registration was not woken after synchronous wait release");
        let (result, terminal) = registration.join().expect("join blocked registration");
        result.expect("registration retries after synchronous wait release");
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        cleanup.disarm();
    }

    #[test]
    fn synchronous_wait_losing_to_notifier_consumes_event_fifo() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn notifier-first wait-owner child");
        let notifier_running = Running::new(pid.into());
        let terminal = TerminalCleanup::new_unregistered(pid.into(), &notifier_running.1);
        terminal
            .ensure_registered()
            .expect("register notifier-first worker");

        let synchronous_running = Running::new(pid.into());
        let canonicalized = Arc::new(Barrier::new(2));
        let resume_wait = Arc::new(Barrier::new(2));
        SYNC_HANDLE_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&canonicalized),
                resume: Arc::clone(&resume_wait),
            },
        );
        let synchronous = thread::spawn(move || synchronous_running.wait());
        canonicalized.wait();
        nix::sys::signal::kill(pid, Signal::SIGCONT).expect("resume notifier-first child");
        resume_wait.wait();
        let observed = synchronous
            .join()
            .expect("join notifier-owned synchronous wait");
        assert!(
            matches!(
                observed,
                Ok(Wait::Exited(waited, crate::ExitStatus::Exited(0))) if waited == pid.into()
            ),
            "unexpected notifier-owned synchronous wait: {observed:?}"
        );
        assert!(terminal.wait(TRACEE_WAIT_TIMEOUT));
        cleanup.disarm();
    }

    #[test]
    fn distinct_raw_claim_adopts_synchronous_registry_owner() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn sync-versus-raw owner child");
        let synchronous_running = Running::new(pid.into());
        let claimed = Arc::new(Barrier::new(2));
        let resume_wait = Arc::new(Barrier::new(2));
        SYNC_WAIT_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&claimed),
                resume: Arc::clone(&resume_wait),
            },
        );
        let synchronous = thread::spawn(move || synchronous_running.wait());
        claimed.wait();

        let raw_running = Running::new(pid.into());
        let raw = TerminalCleanup::new_unregistered(pid.into(), &raw_running.1);
        let authoritative = match raw
            .try_claim_unstarted_raw_cleanup()
            .expect("resolve distinct raw claim")
        {
            RawCleanupClaim::Existing(authoritative) => authoritative,
            _ => panic!("distinct raw claim did not adopt synchronous authority"),
        };
        assert!(Arc::ptr_eq(
            authoritative.event(),
            NOTIFIER
                .pids
                .lock()
                .get(&pid.into())
                .expect("synchronous registry authority")
                .handle
                .event()
        ));

        resume_wait.wait();
        nix::sys::signal::kill(pid, Signal::SIGCONT).expect("resume sync-versus-raw child");
        assert!(
            synchronous
                .join()
                .expect("join sync-versus-raw wait")
                .is_ok()
        );
        cleanup.disarm();
    }

    #[test]
    fn cleanup_cancels_distinct_synchronous_owner_before_registration() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn cleanup-versus-sync child");
        let synchronous_running = Running::new(pid.into());
        let claimed = Arc::new(Barrier::new(2));
        let resume_wait = Arc::new(Barrier::new(2));
        SYNC_WAIT_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&claimed),
                resume: Arc::clone(&resume_wait),
            },
        );
        let synchronous = thread::spawn(move || synchronous_running.wait());
        claimed.wait();

        let cleanup_running = Running::new(pid.into());
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(
                pid.into(),
                &cleanup_running.1,
            ))
            .expect("store distinct cleanup Event");
        let cleaning = thread::spawn(move || {
            let result = cleanup.cleanup();
            (result, cleanup)
        });
        thread::sleep(Duration::from_millis(20));
        resume_wait.wait();

        assert!(matches!(
            synchronous.join().expect("join cancelled synchronous wait"),
            Ok(Wait::Exited(waited, crate::ExitStatus::Signaled(Signal::SIGKILL, _)))
                if waited == pid.into()
        ));
        let (result, cleanup) = cleaning.join().expect("join distinct cleanup");
        result.expect("cleanup waits for synchronous owner release");
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                raw_cleanup_claimed: false,
                cleanup_signal_sent: true,
                ..
            }
        ));
    }

    #[test]
    fn cleanup_claim_catches_sync_started_after_authority_resolution() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn cleanup claim-race child");
        let running = Running::new(pid.into());
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("store claim-race cleanup Event");

        let cleanup_ready = Arc::new(Barrier::new(2));
        let resume_cleanup = Arc::new(Barrier::new(2));
        CLEANUP_OWNER_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&cleanup_ready),
                resume: Arc::clone(&resume_cleanup),
            },
        );
        let sync_claimed = Arc::new(Barrier::new(2));
        let resume_sync = Arc::new(Barrier::new(2));
        SYNC_WAIT_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&sync_claimed),
                resume: Arc::clone(&resume_sync),
            },
        );
        let cancel_sent = Arc::new(Barrier::new(2));
        let resume_cancel = Arc::new(Barrier::new(2));
        CLEANUP_CANCEL_SIGNAL_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&cancel_sent),
                resume: Arc::clone(&resume_cancel),
            },
        );

        let cleaning = thread::spawn(move || {
            let result = cleanup.cleanup();
            (result, cleanup)
        });
        cleanup_ready.wait();
        let synchronous = thread::spawn(move || running.wait());
        sync_claimed.wait();
        resume_cleanup.wait();
        cancel_sent.wait();
        resume_cancel.wait();
        resume_sync.wait();

        assert!(matches!(
            synchronous.join().expect("join claim-race synchronous wait"),
            Ok(Wait::Exited(waited, crate::ExitStatus::Signaled(Signal::SIGKILL, _)))
                if waited == pid.into()
        ));
        let (result, cleanup) = cleaning.join().expect("join claim-race cleanup");
        result.expect("serialized cleanup claim cancels late synchronous owner");
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                cleanup_signal_sent: true,
                ..
            }
        ));
    }

    #[test]
    fn regular_stop_return_commit_precedes_late_cleanup_cancellation() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn regular return-race child");
        let running = Running::new(pid.into());
        let retained = running.1.event().clone();
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("store regular return-race Event");
        retained.event().update((libc::SIGSTOP << 8) | 0x7f);

        let return_decided = Arc::new(Barrier::new(2));
        let resume_return = Arc::new(Barrier::new(2));
        SYNC_RETURN_COMMIT_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&return_decided),
                resume: Arc::clone(&resume_return),
            },
        );
        let cleanup_ready = Arc::new(Barrier::new(2));
        let resume_cleanup = Arc::new(Barrier::new(2));
        CLEANUP_OWNER_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&cleanup_ready),
                resume: Arc::clone(&resume_cleanup),
            },
        );

        let synchronous = thread::spawn(move || {
            matches!(
                running.wait(),
                Ok(Wait::Stopped(_, crate::Event::Signal(Signal::SIGSTOP)))
            )
        });
        return_decided.wait();
        let cleaning = thread::spawn(move || {
            let result = cleanup.cleanup();
            (result, cleanup)
        });
        cleanup_ready.wait();
        resume_cleanup.wait();
        thread::yield_now();
        resume_return.wait();

        assert!(
            synchronous.join().expect("join regular return decision"),
            "cleanup cancelled a regular stop after its return decision"
        );
        let (result, _cleanup) = cleaning.join().expect("join regular return cleanup");
        result.expect("cleanup after regular return ownership handoff");
    }

    #[test]
    fn exit_stop_return_commit_precedes_late_cleanup_cancellation() {
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn exit return-race tracee");
        stopped
            .setoptions(Options::PTRACE_O_TRACEEXIT)
            .expect("enable exit return-race stop");
        let running = stopped
            .resume(None)
            .expect("resume exit return-race tracee");
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("store exit return-race Event");

        let return_decided = Arc::new(Barrier::new(2));
        let resume_return = Arc::new(Barrier::new(2));
        SYNC_RETURN_COMMIT_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&return_decided),
                resume: Arc::clone(&resume_return),
            },
        );
        let cleanup_ready = Arc::new(Barrier::new(2));
        let resume_cleanup = Arc::new(Barrier::new(2));
        CLEANUP_OWNER_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&cleanup_ready),
                resume: Arc::clone(&resume_cleanup),
            },
        );

        let coordinator = thread::spawn(move || {
            return_decided.wait();
            let cleaning = thread::spawn(move || {
                let result = cleanup.cleanup();
                (result, cleanup)
            });
            cleanup_ready.wait();
            resume_cleanup.wait();
            thread::yield_now();
            resume_return.wait();
            cleaning.join().expect("join exit return cleanup")
        });

        let (exit_stopped, event) = running
            .wait()
            .expect("exit stop return decision")
            .assume_stopped();
        assert_eq!(event, crate::Event::Exit);
        let _running = exit_stopped
            .resume(None)
            .expect("resume returned exit-stop capability");
        let (result, _cleanup) = coordinator.join().expect("join exit return coordinator");
        result.expect("cleanup after exit return ownership handoff");
    }

    #[test]
    fn decode_error_rolls_back_return_transaction_and_wakes_cleanup() {
        let pid: crate::Pid = Pid::this().into();
        let event = Arc::new(Event::new());
        event.update((libc::SIGSTOP << 8) | 0x7f);
        let return_begun = Arc::new(Barrier::new(2));
        let resume_decode = Arc::new(Barrier::new(2));
        SYNC_RETURN_COMMIT_PAUSES.lock().insert(
            pid,
            EventCapturePause {
                captured: Arc::clone(&return_begun),
                resume: Arc::clone(&resume_decode),
            },
        );

        let (first_claim_tx, first_claim_rx) = mpsc::channel();
        let (retry_tx, retry_rx) = mpsc::channel();
        let (decoded_tx, decoded_rx) = mpsc::channel();
        let (release_owner_tx, release_owner_rx) = mpsc::channel();
        thread::scope(|scope| {
            let decoding_event = Arc::clone(&event);
            scope.spawn(move || {
                let mut owner = match decoding_event
                    .claim_sync_wait()
                    .expect("claim rollback-test synchronous owner")
                {
                    SyncWaitOwnership::Claimed(owner) => owner,
                    SyncWaitOwnership::Notifier => {
                        panic!("rollback test unexpectedly found notifier")
                    }
                };
                let reservation = decoding_event
                    .try_status_reservation_sync()
                    .expect("rollback status is present")
                    .expect("rollback status is valid");
                let result: Result<StatusReturn<()>, Error> =
                    owner.decode_status_return(pid, reservation, |_| Err(Errno::EIO.into()));
                decoded_tx
                    .send(result)
                    .expect("report decode-error rollback");
                release_owner_rx
                    .recv()
                    .expect("retain restored synchronous owner for cleanup retry");
            });

            return_begun.wait();
            assert_eq!(
                event.wait_owner.load(Ordering::Acquire),
                WAIT_OWNER_SYNC_RETURNING
            );
            let cleanup_event = Arc::clone(&event);
            scope.spawn(move || {
                let returning = matches!(
                    cleanup_event.try_claim_cancellable_notifier_wait(),
                    CancellableNotifierWaitOwnership::Returning
                );
                first_claim_tx
                    .send(returning)
                    .expect("report in-flight return claim");
                let synchronous = matches!(
                    cleanup_event
                        .wait_for_return_and_claim_cancellable_notifier(TRACEE_WAIT_TIMEOUT),
                    Some(CancellableNotifierWaitOwnership::Synchronous)
                );
                retry_tx
                    .send(synchronous)
                    .expect("report rolled-back synchronous claim");
            });

            assert!(
                first_claim_rx
                    .recv_timeout(TRACEE_WAIT_TIMEOUT)
                    .expect("cleanup did not observe RETURNING")
            );
            assert!(!event.cleanup_cancel_requested.load(Ordering::Acquire));
            resume_decode.wait();
            assert!(matches!(
                decoded_rx
                    .recv_timeout(TRACEE_WAIT_TIMEOUT)
                    .expect("decode error did not complete"),
                Err(Error::Errno(Errno::EIO))
            ));
            assert!(
                retry_rx
                    .recv_timeout(TRACEE_WAIT_TIMEOUT)
                    .expect("cleanup was not woken by rollback")
            );
            assert!(event.cleanup_cancel_requested.load(Ordering::Acquire));
            release_owner_tx
                .send(())
                .expect("release restored synchronous owner");
        });
        assert_eq!(event.wait_owner.load(Ordering::Acquire), WAIT_OWNER_NONE);
        assert_eq!(
            event.status.lock().pending.front().copied(),
            Some((libc::SIGSTOP << 8) | 0x7f),
            "decode error consumed the rollback-safe FIFO reservation"
        );
    }

    #[test]
    fn pending_cleanup_claim_prevents_repeated_return_starvation() {
        let event = Arc::new(Event::new());
        event
            .wait_owner
            .store(WAIT_OWNER_NOTIFIER, Ordering::Release);
        let stopped = (libc::SIGSTOP << 8) | 0x7f;
        let transaction = match event.begin_status_return(
            stopped,
            WAIT_OWNER_NOTIFIER,
            WAIT_OWNER_NOTIFIER_RETURNING,
        ) {
            ReturnTransactionStart::Begun(transaction) => transaction,
            ReturnTransactionStart::Cancelled => panic!("first return was unexpectedly cancelled"),
        };

        let (observed_tx, observed_rx) = mpsc::channel();
        let cleanup_event = Arc::clone(&event);
        let cleanup = thread::spawn(move || {
            assert!(matches!(
                cleanup_event.try_claim_cancellable_notifier_wait(),
                CancellableNotifierWaitOwnership::Returning
            ));
            observed_tx
                .send(())
                .expect("report pending cleanup return claim");
            matches!(
                cleanup_event.wait_for_return_and_claim_cancellable_notifier(TRACEE_WAIT_TIMEOUT),
                Some(CancellableNotifierWaitOwnership::Existing)
            )
        });
        observed_rx
            .recv_timeout(TRACEE_WAIT_TIMEOUT)
            .expect("cleanup did not register its RETURNING claim");
        assert_eq!(event.cleanup_claim_waiters.load(Ordering::Acquire), 1);

        transaction.commit(WAIT_OWNER_NOTIFIER);
        for _ in 0..64 {
            assert!(matches!(
                event.begin_status_return(
                    stopped,
                    WAIT_OWNER_NOTIFIER,
                    WAIT_OWNER_NOTIFIER_RETURNING,
                ),
                ReturnTransactionStart::Cancelled
            ));
            thread::yield_now();
        }
        assert!(cleanup.join().expect("join pending cleanup claimant"));
        assert!(event.cleanup_cancel_requested.load(Ordering::Acquire));
        assert_eq!(event.cleanup_claim_waiters.load(Ordering::Acquire), 0);
        assert_eq!(
            event.wait_owner.load(Ordering::Acquire),
            WAIT_OWNER_NOTIFIER
        );
    }

    #[test]
    fn chained_returning_adoption_preserves_cleanup_deadline() {
        let first = EventHandle::new();
        let second = EventHandle::new();
        first
            .event()
            .wait_owner
            .store(WAIT_OWNER_SYNC, Ordering::Release);
        second
            .event()
            .wait_owner
            .store(WAIT_OWNER_SYNC, Ordering::Release);
        let stopped = (libc::SIGSTOP << 8) | 0x7f;
        let first_return = match first.event().begin_status_return(
            stopped,
            WAIT_OWNER_SYNC,
            WAIT_OWNER_SYNC_RETURNING,
        ) {
            ReturnTransactionStart::Begun(transaction) => transaction,
            ReturnTransactionStart::Cancelled => panic!("first chained return was cancelled"),
        };
        let second_return = match second.event().begin_status_return(
            stopped,
            WAIT_OWNER_SYNC,
            WAIT_OWNER_SYNC_RETURNING,
        ) {
            ReturnTransactionStart::Begun(transaction) => transaction,
            ReturnTransactionStart::Cancelled => panic!("second chained return was cancelled"),
        };

        let deadline = Instant::now() + Duration::from_millis(150);
        let started = Instant::now();
        let cleanup_handle = first.clone();
        let cleanup = thread::spawn(move || {
            NOTIFIER.try_event_for_cleanup(Pid::this().into(), &cleanup_handle, deadline)
        });
        let claim_deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        while first.event().cleanup_claim_waiters.load(Ordering::Acquire) == 0 {
            assert!(
                Instant::now() < claim_deadline,
                "cleanup did not wait on first RETURNING generation"
            );
            thread::yield_now();
        }
        first
            .adopt_authoritative(&second)
            .expect("chain cleanup handle to second RETURNING generation");
        thread::sleep(Duration::from_millis(100));
        first_return.commit(WAIT_OWNER_NONE);

        let result = cleanup.join().expect("join chained RETURNING cleanup");
        assert!(matches!(
            result,
            Ok(CancellableEventRegistration::ReturningTimedOut)
        ));
        assert!(
            started.elapsed() < Duration::from_millis(220),
            "adoption reset the absolute cleanup deadline: {:?}",
            started.elapsed()
        );
        drop(second_return);
        assert_eq!(
            second.event().cleanup_claim_waiters.load(Ordering::Acquire),
            0
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn new_child_decode_return_precedes_cleanup_for_fork_vfork_and_clone() {
        for repetition in 0..8 {
            for child_op in [
                crate::ChildOp::Fork,
                crate::ChildOp::Vfork,
                crate::ChildOp::Clone,
            ] {
                let mut race = start_new_child_return_race(child_op, WAIT_OWNER_SYNC_RETURNING)
                    .unwrap_or_else(|error| {
                        panic!("sync repetition {repetition} start {child_op:?}: {error}")
                    });
                let wait = race
                    .running
                    .take()
                    .expect("sync race waiter")
                    .wait()
                    .unwrap_or_else(|error| {
                        panic!("sync repetition {repetition} wait {child_op:?}: {error}")
                    });
                finish_new_child_return_race(child_op, race, wait).unwrap_or_else(|error| {
                    panic!("sync repetition {repetition} finish {child_op:?}: {error}")
                });
            }
        }
        for repetition in 0..8 {
            for child_op in [
                crate::ChildOp::Fork,
                crate::ChildOp::Vfork,
                crate::ChildOp::Clone,
            ] {
                let mut race = start_new_child_return_race(child_op, WAIT_OWNER_NOTIFIER_RETURNING)
                    .unwrap_or_else(|error| {
                        panic!("async repetition {repetition} start {child_op:?}: {error}")
                    });
                let wait = race
                    .running
                    .take()
                    .expect("async race waiter")
                    .next_state()
                    .await
                    .unwrap_or_else(|error| {
                        panic!("async repetition {repetition} wait {child_op:?}: {error}")
                    });
                finish_new_child_return_race(child_op, race, wait).unwrap_or_else(|error| {
                    panic!("async repetition {repetition} finish {child_op:?}: {error}")
                });
            }
        }
    }

    #[test]
    fn cleanup_cancellation_retains_pending_regular_stop_until_terminal() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn pending-stop cancellation child");
        let running = Running::new(pid.into());
        let retained = running.1.event().clone();
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("store pending-stop cleanup Event");

        let sync_claimed = Arc::new(Barrier::new(2));
        let resume_sync = Arc::new(Barrier::new(2));
        SYNC_WAIT_CLAIM_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&sync_claimed),
                resume: Arc::clone(&resume_sync),
            },
        );
        let cancel_sent = Arc::new(Barrier::new(2));
        let resume_cancel = Arc::new(Barrier::new(2));
        CLEANUP_CANCEL_SIGNAL_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&cancel_sent),
                resume: Arc::clone(&resume_cancel),
            },
        );

        let synchronous = thread::spawn(move || running.wait());
        sync_claimed.wait();
        let stopped = (libc::SIGSTOP << 8) | 0x7f;
        retained.event().update(stopped);
        let cleaning = thread::spawn(move || {
            let result = cleanup.cleanup();
            (result, cleanup)
        });
        cancel_sent.wait();
        resume_cancel.wait();
        resume_sync.wait();

        assert!(matches!(
            synchronous.join().expect("join pending-stop synchronous wait"),
            Ok(Wait::Exited(waited, crate::ExitStatus::Signaled(Signal::SIGKILL, _)))
                if waited == pid.into()
        ));
        let (result, cleanup) = cleaning.join().expect("join pending-stop cleanup");
        result.expect("pending-stop cleanup reaches terminal state");
        assert_eq!(
            retained.event().status.lock().pending.front().copied(),
            Some(stopped),
            "cancellation consumed the pending regular stop instead of transferring it"
        );
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                cleanup_signal_sent: true,
                ..
            }
        ));
    }

    #[test]
    fn cleanup_cancellation_retains_exit_stop_and_sync_returns_terminal() {
        let (pid, stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn exit-stop cancellation tracee");
        stopped
            .setoptions(Options::PTRACE_O_TRACEEXIT)
            .expect("enable cancellation exit stop");
        let running = stopped
            .resume(None)
            .expect("resume cancellation exit tracee");
        let retained = running.1.event().clone();
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("store exit-stop cleanup Event");

        let status_published = Arc::new(Barrier::new(2));
        let resume_status = Arc::new(Barrier::new(2));
        SYNC_STATUS_PUBLICATION_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&status_published),
                resume: Arc::clone(&resume_status),
            },
        );
        let cancel_sent = Arc::new(Barrier::new(2));
        let resume_cancel = Arc::new(Barrier::new(2));
        CLEANUP_CANCEL_SIGNAL_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&cancel_sent),
                resume: Arc::clone(&resume_cancel),
            },
        );

        let coordinator = thread::spawn(move || {
            status_published.wait();
            let cleaning = thread::spawn(move || {
                let result = cleanup.cleanup();
                (result, cleanup)
            });
            cancel_sent.wait();
            resume_cancel.wait();
            resume_status.wait();
            cleaning.join().expect("join exit-stop cleanup")
        });

        // Keep ptrace resume on the same thread that spawned the TRACEME
        // child; the coordinator owns only cancellation and exact-pidfd kill.
        let observed = running.wait();
        assert!(
            matches!(observed, Ok(Wait::Exited(waited, _)) if waited == pid.into()),
            "cancelled synchronous exit-stop returned {observed:?}"
        );
        let (result, _cleanup) = coordinator.join().expect("join exit-stop coordinator");
        result.expect("exit-stop cancellation reaches terminal state");
        assert_eq!(
            retained.event().status.lock().pending.front().copied(),
            Some(PTRACE_EVENT_EXIT_STOP),
            "cancellation consumed or duplicated the retained exit stop"
        );
        assert_eq!(
            retained.event().exit_capability.load(Ordering::Acquire),
            EXIT_CAP_EXPIRED,
            "synchronous cancellation minted an ExitFuture capability"
        );
    }

    #[test]
    fn synchronous_late_wait_replays_terminal_after_reap() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn late terminal replay child");
        let running = Running::new(pid.into());
        let retry = Running::from_token(pid.into(), running.1.clone());
        pidfd_send_signal(&cleanup.pidfd, libc::SIGKILL)
            .expect("signal late terminal replay child");

        let first = running.wait().expect("consume exact terminal status");
        let late = retry
            .wait()
            .expect("replay retained terminal after procfs disappearance");
        assert!(matches!(
            (&first, &late),
            (
                Wait::Exited(first_pid, crate::ExitStatus::Signaled(Signal::SIGKILL, _)),
                Wait::Exited(late_pid, crate::ExitStatus::Signaled(Signal::SIGKILL, _))
            ) if *first_pid == pid.into() && *late_pid == pid.into()
        ));
        cleanup.disarm();
    }

    #[test]
    fn persistent_registration_failure_claims_exact_raw_cleanup() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn failed-bind cleanup child");
        let identity = WorkerIdentity::capture_process(pid.into())
            .expect("capture failed-bind cleanup generation");
        CAPTURE_PERSISTENT_ERRORS
            .lock()
            .insert(pid.into(), Errno::EMFILE);
        let running = Running::new(pid.into());

        cleanup
            .bind_running_notifier(&running)
            .expect_err("inject persistent notifier registration failure");
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned { .. }
        ));
        cleanup
            .cleanup()
            .expect("persistent failure falls back to exact raw cleanup");
        CAPTURE_PERSISTENT_ERRORS.lock().remove(&pid.into());
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                raw_cleanup_claimed: true,
                cleanup_signal_sent: true,
                ..
            }
        ));

        assert!(
            !identity.is_same_process_generation(),
            "persistent notifier registration failure orphaned its child"
        );
    }

    #[test]
    fn persistent_registration_failure_drop_reaps_child() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn persistent-drop cleanup child");
        let identity = WorkerIdentity::capture_process(pid.into())
            .expect("capture persistent-drop cleanup generation");
        CAPTURE_PERSISTENT_ERRORS
            .lock()
            .insert(pid.into(), Errno::EIO);
        let running = Running::new(pid.into());

        cleanup
            .bind_running_notifier(&running)
            .expect_err("inject persistent Drop registration failure");
        drop(cleanup);
        CAPTURE_PERSISTENT_ERRORS.lock().remove(&pid.into());

        assert!(
            !identity.is_same_process_generation(),
            "persistent registration failure was ignored by Drop"
        );
    }

    #[test]
    fn registration_winning_raw_claim_race_uses_notifier_cleanup() {
        let (pid, mut cleanup) = spawn_stopped_process(None).expect("spawn CAS-loss cleanup child");
        let identity = WorkerIdentity::capture_process(pid.into())
            .expect("capture CAS-loss cleanup generation");
        CAPTURE_PERSISTENT_ERRORS
            .lock()
            .insert(pid.into(), Errno::EMFILE);
        FORCE_RAW_CLAIM_REGISTRATION_RACE
            .lock()
            .insert(pid.into(), ());
        let running = Running::new(pid.into());

        cleanup
            .bind_running_notifier(&running)
            .expect_err("inject CAS-loss registration failure");
        cleanup
            .cleanup()
            .expect("CAS loss transfers cleanup to notifier worker");
        CAPTURE_PERSISTENT_ERRORS.lock().remove(&pid.into());
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                raw_cleanup_claimed: false,
                ..
            }
        ));
        assert_eq!(
            cleanup
                .terminal()
                .expect("CAS-loss terminal cleanup")
                .event
                .event()
                .worker_state
                .load(Ordering::Acquire),
            WORKER_DONE
        );
        assert!(
            !identity.is_same_process_generation(),
            "notifier-owned CAS-loss cleanup orphaned its child"
        );
    }

    #[test]
    fn second_guard_cannot_infer_raw_wait_ownership() {
        let (pid, mut winner) = spawn_stopped_process(None).expect("spawn two-guard cleanup child");
        let mut loser = TraceeCleanupGuard::new(pid).expect("open loser guard pidfd");
        let identity = WorkerIdentity::capture_process(pid.into())
            .expect("capture two-guard cleanup generation");
        let running = Running::new(pid.into());
        winner
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("store winner terminal generation");
        loser
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("store loser terminal generation");
        assert!(matches!(
            winner
                .terminal()
                .expect("winner terminal")
                .try_claim_unstarted_raw_cleanup(),
            Ok(RawCleanupClaim::Won)
        ));
        let TraceeCleanupOwnership::NotifierOwned {
            raw_cleanup_claimed,
            raw_cleanup_finishes_event,
            ..
        } = &mut winner.ownership
        else {
            unreachable!()
        };
        *raw_cleanup_claimed = true;
        *raw_cleanup_finishes_event = true;

        let mut loser_signal_sent = false;
        let loser_owner = TraceeCleanupGuard::acquire_cleanup_wait_owner(
            pid,
            &loser.pidfd,
            loser.terminal().expect("loser terminal"),
            &mut loser_signal_sent,
        )
        .expect("loser observes winner state");
        assert!(matches!(loser_owner, CleanupWaitOwner::TerminalAck));

        winner.cleanup().expect("winner performs exact raw cleanup");
        loser
            .cleanup()
            .expect("loser observes terminal acknowledgment");
        assert!(matches!(
            loser.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                raw_cleanup_claimed: false,
                ..
            }
        ));
        assert!(
            !identity.is_same_process_generation(),
            "two-guard cleanup left its child generation live"
        );
    }

    #[test]
    fn reaped_pidfd_esrch_never_waits_on_projected_replacement() {
        let (old_pid, mut old_cleanup) =
            spawn_stopped_process(None).expect("spawn ESRCH old generation");
        let running = Running::new(old_pid.into());
        old_cleanup
            .store_terminal(TerminalCleanup::new_unregistered(
                old_pid.into(),
                &running.1,
            ))
            .expect("store ESRCH old terminal");
        assert!(matches!(
            old_cleanup
                .terminal()
                .expect("ESRCH old terminal")
                .try_claim_unstarted_raw_cleanup(),
            Ok(RawCleanupClaim::Won)
        ));
        let TraceeCleanupOwnership::NotifierOwned {
            raw_cleanup_claimed,
            raw_cleanup_finishes_event,
            ..
        } = &mut old_cleanup.ownership
        else {
            unreachable!()
        };
        *raw_cleanup_claimed = true;
        *raw_cleanup_finishes_event = true;

        pidfd_send_signal(&old_cleanup.pidfd, libc::SIGKILL).expect("signal ESRCH old generation");
        reap_tracee_pidfd_bounded(old_pid, &old_cleanup.pidfd)
            .expect("pidfd-reap ESRCH old generation");
        let (replacement_pid, replacement_cleanup) =
            spawn_stopped_process(None).expect("spawn ESRCH replacement generation");
        old_cleanup.pid = replacement_pid;

        old_cleanup
            .cleanup()
            .expect("reaped pidfd cleanup avoids numeric replacement wait");
        assert_eq!(
            unsafe { libc::kill(replacement_pid.as_raw(), 0) },
            0,
            "ESRCH cleanup touched the projected replacement"
        );
        reap_stopped_process(replacement_cleanup);
    }

    fn pre_registration_cleanup_never_reaps_reused_pid(requested_pid: Option<i32>) -> bool {
        let Some((old_pid, mut old_cleanup)) = spawn_stopped_process(requested_pid) else {
            return false;
        };
        let captured = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        PRE_REGISTRATION_REAP_PAUSES.lock().insert(
            old_pid.into(),
            EventCapturePause {
                captured: Arc::clone(&captured),
                resume: Arc::clone(&resume),
            },
        );
        let cleanup = thread::spawn(move || old_cleanup.cleanup());
        captured.wait();
        reap_tracee_bounded(old_pid).expect("competing owner reaps old pre-registration child");
        thread::sleep(Duration::from_millis(20));

        let Some((replacement_pid, replacement_cleanup)) = spawn_stopped_process(requested_pid)
        else {
            resume.wait();
            let _ = cleanup.join();
            return false;
        };
        resume.wait();
        let cleanup_result = cleanup.join().expect("join pre-registration cleanup");
        let replacement_live = unsafe { libc::kill(replacement_pid.as_raw(), 0) } == 0;
        reap_stopped_process(replacement_cleanup);
        cleanup_result.expect("exact old pidfd reap must not wait on replacement PID");
        assert!(replacement_live, "old cleanup touched the replacement PID");
        true
    }

    #[test]
    fn pre_registration_cleanup_uses_exact_pidfd_after_competing_reap() {
        const INNER: &str = "SAFEPTRACE_PRE_REG_REAP_REUSE_INNER";
        if env::var_os(INNER).is_some() {
            if pre_registration_cleanup_never_reaps_reused_pid(Some(100)) {
                println!("ACTUAL_PRE_REG_REAP_REUSE_EXERCISED");
            } else {
                println!("ACTUAL_PRE_REG_REAP_REUSE_UNAVAILABLE");
            }
            return;
        }

        let inner =
            "notifier::test::pre_registration_cleanup_uses_exact_pidfd_after_competing_reap";
        let actual_reuse = run_exact_in_pid_namespace_bounded(inner, &[(INNER, "1")]);
        match classify_exact_reuse_output(
            actual_reuse.as_ref(),
            "ACTUAL_PRE_REG_REAP_REUSE_EXERCISED",
            "ACTUAL_PRE_REG_REAP_REUSE_UNAVAILABLE",
        )
        .unwrap_or_else(|error| panic!("actual pre-registration reuse regression failed: {error}"))
        {
            ExactReuseOutcome::Exercised => return,
            ExactReuseOutcome::Unavailable => {}
        }

        assert!(pre_registration_cleanup_never_reaps_reused_pid(None));
    }

    #[test]
    fn registration_claim_after_capture_excludes_raw_cleanup() {
        let (old_pid, mut old_cleanup) =
            spawn_stopped_process(None).expect("spawn delayed-registration old generation");
        let running = Running::new(old_pid.into());
        old_cleanup
            .store_terminal(TerminalCleanup::new_unregistered(
                old_pid.into(),
                &running.1,
            ))
            .expect("store delayed-registration terminal");
        let delayed = TerminalCleanup::new_unregistered(old_pid.into(), &running.1);
        let raw = TerminalCleanup::new_unregistered(old_pid.into(), &running.1);
        let captured = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        EVENT_CAPTURE_PAUSES.lock().insert(
            old_pid.into(),
            EventCapturePause {
                captured: Arc::clone(&captured),
                resume: Arc::clone(&resume),
            },
        );
        let registration = thread::spawn(move || delayed.ensure_registered());
        captured.wait();

        let (raw_tx, raw_rx) = mpsc::channel();
        let raw_claim = thread::spawn(move || {
            let claim = raw.try_claim_unstarted_raw_cleanup();
            raw_tx.send(()).expect("report raw-claim completion");
            claim
        });
        thread::sleep(Duration::from_millis(20));
        assert!(matches!(raw_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));

        resume.wait();
        registration
            .join()
            .expect("join delayed registration")
            .expect("terminal delayed registration returns exact Event");
        raw_rx
            .recv_timeout(TRACEE_WAIT_TIMEOUT)
            .expect("raw claim was not woken after registration publication");
        assert!(matches!(
            raw_claim.join().expect("join excluded raw claim"),
            Ok(RawCleanupClaim::Lost)
        ));
        old_cleanup
            .cleanup()
            .expect("notifier owner cleans delayed-registration child");
    }

    #[test]
    fn worker_spawn_failure_rolls_back_registry_and_cleanup_retries() {
        let (pid, mut cleanup) = spawn_stopped_process(None).expect("spawn worker-failure child");
        let identity =
            WorkerIdentity::capture_process(pid.into()).expect("capture worker-failure generation");
        let running = Running::new(pid.into());
        SPAWN_WORKER_ERRORS.lock().insert(pid.into(), libc::EAGAIN);

        let error = cleanup
            .bind_running_notifier(&running)
            .expect_err("inject notifier worker spawn failure");
        assert!(error.to_string().contains("EAGAIN"), "{error}");
        let terminal = cleanup.terminal().expect("spawn-failure terminal");
        assert_eq!(
            terminal.event.event().worker_state.load(Ordering::Acquire),
            WORKER_NOT_STARTED
        );
        assert!(
            !NOTIFIER
                .pids
                .lock()
                .get(&pid.into())
                .is_some_and(|entry| entry.handle == terminal.event)
        );

        cleanup
            .cleanup()
            .expect("spawn-failure cleanup retries registration");
        assert!(
            !identity.is_same_process_generation(),
            "worker spawn failure orphaned its child"
        );
    }

    #[test]
    fn echild_resolver_waits_for_starting_spawn_rollback() {
        let (pid, cleanup) = spawn_stopped_process(None).expect("spawn STARTING rollback child");
        let running = Running::new(pid.into());
        let starter = TerminalCleanup::new_unregistered(pid.into(), &running.1);
        let resolver = TerminalCleanup::new_unregistered(pid.into(), &running.1);
        let spawn_paused = Arc::new(Barrier::new(2));
        let resume_spawn = Arc::new(Barrier::new(2));
        SPAWN_WORKER_ERRORS.lock().insert(pid.into(), libc::EAGAIN);
        SPAWN_FAILURE_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&spawn_paused),
                resume: Arc::clone(&resume_spawn),
            },
        );
        let starting = thread::spawn(move || starter.ensure_registered());
        spawn_paused.wait();

        let resolver_started = Arc::new(Barrier::new(2));
        let resolver_entered = Arc::clone(&resolver_started);
        let resolving = thread::spawn(move || {
            inject_capture_error_for_current_thread(Errno::ENOENT);
            resolver_entered.wait();
            resolver.ensure_registered()
        });
        resolver_started.wait();
        thread::sleep(Duration::from_millis(20));
        resume_spawn.wait();

        assert_eq!(
            starting.join().expect("join failed STARTING spawn"),
            Err(Errno::EAGAIN)
        );
        resolving
            .join()
            .expect("join STARTING ECHILD resolver")
            .expect("resolver completes rolled-back Event");
        assert_eq!(
            running
                .1
                .event()
                .event()
                .worker_state
                .load(Ordering::Acquire),
            WORKER_DONE
        );
        assert!(!NOTIFIER.pids.lock().contains_key(&pid.into()));
        reap_stopped_process(cleanup);
    }

    #[test]
    fn delayed_current_or_new_cannot_overwrite_replacement_entry() {
        let (old_pid, old_cleanup) =
            spawn_stopped_process(None).expect("spawn delayed lookup old generation");
        let captured = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        CURRENT_OR_NEW_CAPTURE_PAUSES.lock().insert(
            old_pid.into(),
            EventCapturePause {
                captured: Arc::clone(&captured),
                resume: Arc::clone(&resume),
            },
        );
        let lookup = thread::spawn(move || EventHandle::current_or_new(old_pid.into()));
        captured.wait();
        reap_stopped_process(old_cleanup);

        let (replacement_pid, replacement_cleanup) =
            spawn_stopped_process(None).expect("spawn delayed lookup replacement");
        let mut replacement_identity = WorkerIdentity::capture_process(replacement_pid.into())
            .expect("capture delayed lookup replacement");
        replacement_identity.pid = old_pid.into();
        let replacement_identity = Arc::new(replacement_identity);
        let replacement_handle = EventHandle::with_identity(Arc::clone(&replacement_identity));
        assert!(replacement_handle.event().try_begin_worker_start());
        replacement_handle.event().mark_worker_running();
        NOTIFIER.pids.lock().insert(
            old_pid.into(),
            NotifierEntry {
                handle: replacement_handle.clone(),
                identity: replacement_identity,
            },
        );
        resume.wait();
        assert!(lookup.join().expect("join delayed current_or_new").is_err());
        assert!(
            NOTIFIER
                .pids
                .lock()
                .get(&old_pid.into())
                .is_some_and(|entry| entry.handle == replacement_handle)
        );
        assert_eq!(
            replacement_handle
                .event()
                .worker_state
                .load(Ordering::Acquire),
            WORKER_RUNNING
        );
        NOTIFIER.pids.lock().remove(&old_pid.into());
        replacement_handle.event().mark_echild();
        replacement_handle.event().mark_worker_done();
        reap_stopped_process(replacement_cleanup);
    }

    fn delayed_current_or_new_revalidates_after_pid_reuse(requested_pid: Option<i32>) -> bool {
        let Some((old_pid, old_cleanup)) = spawn_stopped_process(requested_pid) else {
            return false;
        };
        let captured = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        CURRENT_OR_NEW_CAPTURE_PAUSES.lock().insert(
            old_pid.into(),
            EventCapturePause {
                captured: Arc::clone(&captured),
                resume: Arc::clone(&resume),
            },
        );
        let lookup = thread::spawn(move || EventHandle::current_or_new(old_pid.into()));
        captured.wait();

        reap_stopped_process(old_cleanup);
        thread::sleep(Duration::from_millis(20));
        let Some((replacement_pid, replacement_cleanup)) = spawn_stopped_process(requested_pid)
        else {
            resume.wait();
            let _ = lookup.join();
            return false;
        };
        resume.wait();

        let selected = lookup.join().expect("join post-validation lookup");
        if replacement_pid == old_pid {
            let selected = selected.expect("recapture exact reused PID generation");
            assert!(
                selected
                    .identity()
                    .is_some_and(|identity| identity.is_same_process_generation()),
                "post-validation lookup returned the reaped PID generation"
            );
        } else {
            assert_eq!(
                selected.expect_err("reaped PID lookup must not return a stale handle"),
                Errno::ENOENT
            );
        }
        assert_eq!(
            unsafe { libc::kill(replacement_pid.as_raw(), 0) },
            0,
            "stale lookup touched the replacement generation"
        );
        reap_stopped_process(replacement_cleanup);
        true
    }

    #[test]
    fn current_or_new_linearizes_after_validation_before_pid_reuse() {
        const INNER: &str = "SAFEPTRACE_LOOKUP_REUSE_INNER";
        if env::var_os(INNER).is_some() {
            if delayed_current_or_new_revalidates_after_pid_reuse(Some(100)) {
                println!("ACTUAL_LOOKUP_PID_REUSE_EXERCISED");
            } else {
                println!("ACTUAL_LOOKUP_PID_REUSE_UNAVAILABLE");
            }
            return;
        }

        let inner = "notifier::test::current_or_new_linearizes_after_validation_before_pid_reuse";
        let actual_reuse = run_exact_in_pid_namespace_bounded(inner, &[(INNER, "1")]);
        match classify_exact_reuse_output(
            actual_reuse.as_ref(),
            "ACTUAL_LOOKUP_PID_REUSE_EXERCISED",
            "ACTUAL_LOOKUP_PID_REUSE_UNAVAILABLE",
        )
        .unwrap_or_else(|error| panic!("actual lookup PID-reuse regression failed: {error}"))
        {
            ExactReuseOutcome::Exercised => return,
            ExactReuseOutcome::Unavailable => {}
        }

        assert!(delayed_current_or_new_revalidates_after_pid_reuse(None));
    }

    fn delayed_event_never_rebinds_after_pid_reuse(requested_pid: Option<i32>) -> bool {
        let Some((old_pid, old_cleanup)) = spawn_stopped_process(requested_pid) else {
            return false;
        };
        let running = Running::new(old_pid.into());
        let terminal = TerminalCleanup::new_unregistered(old_pid.into(), &running.1);
        let captured = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        EVENT_CAPTURE_PAUSES.lock().insert(
            old_pid.into(),
            EventCapturePause {
                captured: Arc::clone(&captured),
                resume: Arc::clone(&resume),
            },
        );
        let registration = thread::spawn(move || {
            terminal.ensure_registered()?;
            Ok::<_, Errno>(terminal)
        });
        captured.wait();

        reap_stopped_process(old_cleanup);
        thread::sleep(Duration::from_millis(20));
        let Some((replacement_pid, replacement_cleanup)) = spawn_stopped_process(requested_pid)
        else {
            resume.wait();
            let _ = registration.join();
            return false;
        };
        resume.wait();

        let terminal = registration
            .join()
            .expect("join post-validation registration")
            .expect("stale registration resolves its bound Event");
        let completed_without_replacement = terminal.wait(Duration::from_millis(50));
        let replacement_live = unsafe { libc::kill(replacement_pid.as_raw(), 0) } == 0;
        reap_stopped_process(replacement_cleanup);
        assert!(
            completed_without_replacement,
            "stale registration rebound its Event to the replacement generation"
        );
        assert!(
            replacement_live,
            "stale registration touched the replacement"
        );
        assert!(!NOTIFIER.pids.lock().contains_key(&old_pid.into()));
        true
    }

    #[test]
    fn event_linearizes_after_validation_before_pid_reuse() {
        const INNER: &str = "SAFEPTRACE_EVENT_REUSE_INNER";
        if env::var_os(INNER).is_some() {
            if delayed_event_never_rebinds_after_pid_reuse(Some(100)) {
                println!("ACTUAL_EVENT_PID_REUSE_EXERCISED");
            } else {
                println!("ACTUAL_EVENT_PID_REUSE_UNAVAILABLE");
            }
            return;
        }

        let inner = "notifier::test::event_linearizes_after_validation_before_pid_reuse";
        let actual_reuse = run_exact_in_pid_namespace_bounded(inner, &[(INNER, "1")]);
        match classify_exact_reuse_output(
            actual_reuse.as_ref(),
            "ACTUAL_EVENT_PID_REUSE_EXERCISED",
            "ACTUAL_EVENT_PID_REUSE_UNAVAILABLE",
        )
        .unwrap_or_else(|error| panic!("actual event PID-reuse regression failed: {error}"))
        {
            ExactReuseOutcome::Exercised => return,
            ExactReuseOutcome::Unavailable => {}
        }

        assert!(delayed_event_never_rebinds_after_pid_reuse(None));
    }

    #[test]
    fn distinct_event_guard_uses_live_registry_worker() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn distinct-Event cleanup child");
        let identity = WorkerIdentity::capture_process(pid.into())
            .expect("capture distinct-Event cleanup generation");
        let authoritative_running = Running::new(pid.into());
        let authoritative = authoritative_running.terminal_cleanup();
        let competing_running = Running::new(pid.into());
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(
                pid.into(),
                &competing_running.1,
            ))
            .expect("store competing cleanup Event");
        assert!(
            !cleanup
                .terminal()
                .expect("competing terminal")
                .same_generation(&authoritative)
        );
        assert_eq!(
            SPAWN_WORKER_COUNTS.lock().get(&pid.into()).copied(),
            Some(1),
            "authoritative registration starts exactly one worker"
        );

        cleanup
            .cleanup()
            .expect("competing guard adopts authoritative worker");
        assert!(
            cleanup
                .terminal()
                .expect("adopted authoritative terminal")
                .same_generation(&authoritative)
        );
        assert!(matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                raw_cleanup_claimed: false,
                ..
            }
        ));
        assert_eq!(
            SPAWN_WORKER_COUNTS.lock().remove(&pid.into()),
            Some(1),
            "competing Event must not start a second worker"
        );
        assert!(
            !identity.is_same_process_generation(),
            "competing Event raw-waited alongside the registry worker"
        );
    }

    #[test]
    fn registry_replacement_does_not_terminalize_running_old_event() {
        let (pid, child_cleanup) =
            spawn_stopped_process(None).expect("spawn old active registry tracee");
        let identity = Arc::new(
            WorkerIdentity::capture_process(pid.into()).expect("capture old active generation"),
        );
        let old_handle = EventHandle::with_identity(Arc::clone(&identity));
        assert!(old_handle.event().try_begin_worker_start());
        old_handle.event().mark_worker_running();
        NOTIFIER.pids.lock().insert(
            pid.into(),
            NotifierEntry {
                handle: old_handle.clone(),
                identity: Arc::clone(&identity),
            },
        );
        let replacement = EventHandle::with_identity(Arc::clone(&identity));
        NOTIFIER.pids.lock().insert(
            pid.into(),
            NotifierEntry {
                handle: replacement,
                identity,
            },
        );

        NOTIFIER.resolve_echild(pid.into(), &old_handle);
        let terminal = old_handle.event().status.lock().terminal;
        NOTIFIER.pids.lock().remove(&pid.into());
        reap_stopped_process(child_cleanup);

        assert_eq!(
            terminal, INVALID_STATUS,
            "registry replacement terminalized an Event with its own active worker"
        );
    }

    #[test]
    fn running_old_event_bypasses_replacement_capture_failure() {
        let (pid, child_cleanup) =
            spawn_stopped_process(None).expect("spawn old event fast-path tracee");
        let identity = Arc::new(
            WorkerIdentity::capture_process(pid.into()).expect("capture old event generation"),
        );
        let old_handle = EventHandle::with_identity(Arc::clone(&identity));
        assert!(old_handle.event().try_begin_worker_start());
        old_handle.event().mark_worker_running();
        let replacement = EventHandle::with_identity(Arc::clone(&identity));
        NOTIFIER.pids.lock().insert(
            pid.into(),
            NotifierEntry {
                handle: replacement,
                identity,
            },
        );

        inject_capture_error_for_current_thread(Errno::EMFILE);
        let selected = NOTIFIER
            .event(pid.into(), &old_handle)
            .expect("running old Event must not recapture replacement identity");
        assert!(matches!(
            NOTIFIER.capture_identity(pid.into()),
            Err(Errno::EMFILE)
        ));

        NOTIFIER.pids.lock().remove(&pid.into());
        reap_stopped_process(child_cleanup);
        assert!(
            Arc::ptr_eq(selected.event(), old_handle.event()),
            "replacement registry entry displaced the old Event worker"
        );
    }

    #[test]
    fn registered_exit_stop_survives_procfs_disappearance_until_final_status() {
        let (pid, child_cleanup) =
            spawn_stopped_process(None).expect("spawn exiting notifier tracee");
        let identity = Arc::new(
            WorkerIdentity::capture_process(pid.into()).expect("capture notifier generation"),
        );
        let handle = EventHandle::with_identity(Arc::clone(&identity));
        handle.event().update(PTRACE_EVENT_EXIT_STOP);
        assert!(handle.event().try_begin_worker_start());
        handle.event().mark_worker_running();
        NOTIFIER.pids.lock().insert(
            pid.into(),
            NotifierEntry {
                handle: handle.clone(),
                identity,
            },
        );

        reap_stopped_process(child_cleanup);
        NOTIFIER
            .event(pid.into(), &handle)
            .expect("reuse exact registered notifier generation");
        let terminal = Signal::SIGKILL as i32;
        handle.event().update(terminal);
        let waker = Waker::from(Arc::new(WakeCounter::default()));
        let observed = handle.event().poll_status(&waker);
        NOTIFIER.pids.lock().remove(&pid.into());

        assert_eq!(
            observed,
            Poll::Ready(Ok(terminal)),
            "procfs disappearance replaced the old worker's final status with ECHILD"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pre_traceme_snapshot_does_not_synthesize_echild_for_live_generation() {
        let (pid, _stopped, mut cleanup) =
            spawn_traced_process(None).expect("spawn pre-TRACEME snapshot tracee");
        let mut identity =
            WorkerIdentity::capture_process(pid.into()).expect("capture live traced generation");
        assert!(tracer_is_current(identity.snapshot.tracer_pid));
        identity.snapshot.tracer_pid = crate::Pid::from_raw(0);
        assert!(
            identity.is_active_tracee(),
            "mutable TracerPid transition changed immutable process generation"
        );

        let handle = EventHandle::with_identity(Arc::new(identity));
        cleanup
            .store_terminal(TerminalCleanup {
                pid: pid.into(),
                event: handle.clone(),
            })
            .expect("store pre-TRACEME Event generation");
        let stopped = Stopped::from_token(pid.into(), TraceeToken::from_event(handle));
        let exited = stopped
            .resume(None)
            .expect("resume pre-TRACEME snapshot tracee")
            .next_state()
            .await
            .expect("live generation became synthetic ECHILD");
        assert_eq!(exited.assume_exited().1, crate::ExitStatus::Exited(42));
        cleanup.disarm();
    }

    #[test]
    fn capture_accepts_tracer_attachment_during_identity_snapshot() {
        let (pid, mut cleanup) =
            spawn_stopped_process(None).expect("spawn capture-transition child");
        let first_snapshot = Arc::new(Barrier::new(2));
        let resume_capture = Arc::new(Barrier::new(2));
        CAPTURE_AFTER_FIRST_SNAPSHOT_PAUSES.lock().insert(
            pid.into(),
            EventCapturePause {
                captured: Arc::clone(&first_snapshot),
                resume: Arc::clone(&resume_capture),
            },
        );

        let capturing = thread::spawn(move || WorkerIdentity::capture_process(pid.into()));
        first_snapshot.wait();
        nix::sys::ptrace::seize(pid, Options::empty())
            .expect("attach tracer between identity snapshots");
        resume_capture.wait();
        let identity = capturing
            .join()
            .expect("join capture-transition thread")
            .expect("TracerPid transition changed process generation");
        assert!(
            tracer_is_current(identity.snapshot.tracer_pid),
            "capture did not normalize to the post-attachment TracerPid"
        );
        cleanup.cleanup().expect("cleanup capture-transition child");
    }

    fn retained_nonterminal_rejects_replacement(requested_pid: Option<i32>) -> bool {
        let Some((old_pid, mut old_cleanup)) = spawn_stopped_process(requested_pid) else {
            return false;
        };
        let old_running = Running::new(old_pid.into());
        let old_handle = old_running.1.event().clone();
        old_handle
            .bind_identity(Arc::new(
                WorkerIdentity::capture_process(old_pid.into())
                    .expect("capture retained-stop old generation"),
            ))
            .expect("bind retained-stop old identity");
        old_handle.event().update((libc::SIGSTOP << 8) | 0x7f);
        old_cleanup
            .cleanup()
            .expect("reap retained-stop old generation");

        let Some((replacement_pid, replacement_cleanup)) = spawn_stopped_process(requested_pid)
        else {
            return false;
        };
        let projected = Running::from_token(replacement_pid.into(), old_running.1);
        assert!(
            matches!(
                projected.wait(),
                Err(Error::Errno(Errno::ECHILD | Errno::ESRCH))
            ),
            "old nonterminal FIFO status replayed as a replacement-PID capability"
        );
        reap_stopped_process(replacement_cleanup);
        true
    }

    #[test]
    fn retained_nonterminal_is_not_replayed_for_pid_reuse_projection() {
        const INNER: &str = "SAFEPTRACE_RETAINED_STOP_REUSE_INNER";
        if env::var_os(INNER).is_some() {
            if retained_nonterminal_rejects_replacement(Some(100)) {
                println!("ACTUAL_RETAINED_STOP_REUSE_EXERCISED");
            } else {
                println!("ACTUAL_RETAINED_STOP_REUSE_UNAVAILABLE");
            }
            return;
        }

        let inner = "notifier::test::retained_nonterminal_is_not_replayed_for_pid_reuse_projection";
        let actual_reuse = run_exact_in_pid_namespace_bounded(inner, &[(INNER, "1")]);
        match classify_exact_reuse_output(
            actual_reuse.as_ref(),
            "ACTUAL_RETAINED_STOP_REUSE_EXERCISED",
            "ACTUAL_RETAINED_STOP_REUSE_UNAVAILABLE",
        )
        .unwrap_or_else(|error| panic!("actual retained-stop reuse regression failed: {error}"))
        {
            ExactReuseOutcome::Exercised => return,
            ExactReuseOutcome::Unavailable => {}
        }

        assert!(retained_nonterminal_rejects_replacement(None));
    }

    struct NewChildReturnRace {
        pid: Pid,
        running: Option<Running>,
        parent_identity: WorkerIdentity,
        coordinator: JoinHandle<(io::Result<()>, TraceeCleanupGuard)>,
        exact_cleanup: ExactNewChildCleanupGuard,
    }

    struct ExactNewChildCleanupGuard {
        projected_pgid: Pid,
        event: EventHandle,
        members: Arc<Mutex<Vec<ExactTestMember>>>,
        registration_error: Arc<Mutex<Option<PendingExactRegistration>>>,
        pidfd_open_error: Arc<Mutex<Option<Errno>>>,
        signal_errors: HashMap<crate::Pid, VecDeque<Errno>>,
        reap_errors: HashMap<crate::Pid, VecDeque<Errno>>,
        armed: bool,
    }

    impl ExactNewChildCleanupGuard {
        const DROP_CLEANUP_ATTEMPTS: usize = 3;

        fn new(projected_pgid: Pid, event: EventHandle) -> io::Result<Self> {
            let leader: crate::Pid = projected_pgid.into();
            let pidfd = open_thread_pidfd(leader).map_err(|error| {
                io::Error::other(format!(
                    "open exact fixture leader {projected_pgid} pidfd: {error}"
                ))
            })?;
            Ok(Self {
                projected_pgid,
                event,
                members: Arc::new(Mutex::new(vec![ExactTestMember {
                    pid: leader,
                    pidfd,
                    phase: ExactCleanupPhase::NeedsSignal,
                }])),
                registration_error: Arc::new(Mutex::new(None)),
                pidfd_open_error: Arc::new(Mutex::new(None)),
                signal_errors: HashMap::new(),
                reap_errors: HashMap::new(),
                armed: true,
            })
        }

        fn disarm_completed(&mut self) -> io::Result<()> {
            if let Some(pending) = *self.registration_error.lock() {
                return Err(io::Error::other(format!(
                    "cannot disarm with pending exact registration for {}: {}",
                    pending.pid, pending.error
                )));
            }
            let members = self.members.lock();
            for member in members.iter() {
                if !pidfd_exited(&member.pidfd)? {
                    return Err(io::Error::other(format!(
                        "cannot disarm live exact member {} in phase {:?}",
                        member.pid, member.phase
                    )));
                }
            }
            drop(members);
            self.members.lock().clear();
            self.armed = false;
            Ok(())
        }

        fn inject_signal_error(&mut self, pid: crate::Pid, error: Errno) {
            self.signal_errors.entry(pid).or_default().push_back(error);
        }

        fn inject_reap_error(&mut self, pid: crate::Pid, error: Errno) {
            self.reap_errors.entry(pid).or_default().push_back(error);
        }

        fn inject_pidfd_open_error(&self, error: Errno) {
            *self.pidfd_open_error.lock() = Some(error);
        }

        fn install_new_child_decode_pause(
            &self,
            captured: mpsc::SyncSender<()>,
            resume: mpsc::Receiver<()>,
        ) {
            *self.event.event().new_child_decode_pause.lock() = Some(NewChildDecodePause {
                captured,
                resume,
                members: Arc::clone(&self.members),
                registration_error: Arc::clone(&self.registration_error),
                pidfd_open_error: Arc::clone(&self.pidfd_open_error),
            });
        }

        fn take_injected_error(
            errors: &mut HashMap<crate::Pid, VecDeque<Errno>>,
            pid: crate::Pid,
        ) -> Option<Errno> {
            let error = errors.get_mut(&pid).and_then(VecDeque::pop_front);
            if errors.get(&pid).is_some_and(VecDeque::is_empty) {
                errors.remove(&pid);
            }
            error
        }

        fn cleanup_error(&self, failures: &[String]) -> io::Error {
            let retained = self
                .members
                .lock()
                .iter()
                .map(|member| format!("{}:{:?}", member.pid, member.phase))
                .collect::<Vec<_>>()
                .join(", ");
            let pending = (*self.registration_error.lock())
                .map(|pending| format!("{}:{}", pending.pid, pending.error))
                .unwrap_or_else(|| "none".to_owned());
            io::Error::other(format!(
                "exact fixture cleanup for projected PGID {} failed; retained=[{}]; pending_registration={}; {}",
                self.projected_pgid,
                retained,
                pending,
                failures.join("; ")
            ))
        }

        fn cleanup(&mut self) -> io::Result<()> {
            if !self.armed {
                return Ok(());
            }
            self.event.event().new_child_decode_pause.lock().take();
            self.event.event().cleanup_return_pause.lock().take();

            let mut failures = Vec::new();
            let pending_registration = *self.registration_error.lock();
            if let Some(pending) = pending_registration {
                match open_thread_pidfd(pending.pid) {
                    Ok(pidfd) => {
                        self.members.lock().push(ExactTestMember {
                            pid: pending.pid,
                            pidfd,
                            phase: ExactCleanupPhase::NeedsSignal,
                        });
                        self.registration_error.lock().take();
                    }
                    Err(error) => {
                        *self.registration_error.lock() = Some(PendingExactRegistration {
                            pid: pending.pid,
                            error,
                        });
                        failures.push(format!(
                            "retry NewChild exact pidfd registration for {} after {}: {}",
                            pending.pid, pending.error, error
                        ));
                    }
                }
            }
            let registration_retry_failed = self.registration_error.lock().is_some();
            if registration_retry_failed {
                // The stopped parent remains the authority that pins the
                // numeric child reported by GETEVENTMSG. Do not signal or reap
                // that parent until the child has its own exact pidfd.
                return Err(self.cleanup_error(&failures));
            }

            let members = mem::take(&mut *self.members.lock());
            let mut retained = Vec::new();
            for mut member in members {
                if member.phase == ExactCleanupPhase::NeedsSignal {
                    let signal = Self::take_injected_error(&mut self.signal_errors, member.pid)
                        .map_or_else(
                            || pidfd_send_signal(&member.pidfd, libc::SIGKILL),
                            |error| Err(io::Error::from_raw_os_error(error.into_raw())),
                        );
                    match signal {
                        Ok(()) => member.phase = ExactCleanupPhase::NeedsReap,
                        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                            member.phase = ExactCleanupPhase::NeedsReap;
                        }
                        Err(error) => {
                            failures.push(format!(
                                "signal exact member {} through pidfd: {error}",
                                member.pid
                            ));
                            retained.push(member);
                            continue;
                        }
                    }
                }

                let reap = Self::take_injected_error(&mut self.reap_errors, member.pid)
                    .map_or_else(
                        || {
                            let pid = Pid::from_raw(member.pid.as_raw());
                            reap_tracee_pidfd_bounded(pid, &member.pidfd)
                        },
                        |error| Err(io::Error::from_raw_os_error(error.into_raw())),
                    );
                if let Err(error) = reap {
                    failures.push(format!("reap exact member {}: {error}", member.pid));
                    retained.push(member);
                }
            }
            self.members.lock().extend(retained);

            if failures.is_empty()
                && self.registration_error.lock().is_none()
                && self.members.lock().is_empty()
            {
                self.armed = false;
                Ok(())
            } else {
                Err(self.cleanup_error(&failures))
            }
        }

        fn emergency_cleanup_without_injection(&mut self) -> io::Result<()> {
            if !self.armed {
                return Ok(());
            }
            self.event.event().new_child_decode_pause.lock().take();
            self.event.event().cleanup_return_pause.lock().take();

            let mut failures = Vec::new();
            if let Some(pending) = *self.registration_error.lock() {
                match open_thread_pidfd_kernel(pending.pid) {
                    Ok(pidfd) => {
                        self.members.lock().push(ExactTestMember {
                            pid: pending.pid,
                            pidfd,
                            phase: ExactCleanupPhase::NeedsSignal,
                        });
                        self.registration_error.lock().take();
                    }
                    Err(error) => {
                        *self.registration_error.lock() = Some(PendingExactRegistration {
                            pid: pending.pid,
                            error,
                        });
                        failures.push(format!(
                            "emergency exact pidfd registration for {} after {}: {}",
                            pending.pid, pending.error, error
                        ));
                    }
                }
            }
            let registration_failed = self.registration_error.lock().is_some();
            if registration_failed {
                return Err(self.cleanup_error(&failures));
            }

            let members = mem::take(&mut *self.members.lock());
            let mut retained = Vec::new();
            for member in members {
                let signal = pidfd_send_signal(&member.pidfd, libc::SIGKILL);
                let signal_succeeded = match signal {
                    Ok(()) => true,
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => true,
                    Err(error) => {
                        failures.push(format!(
                            "emergency signal exact member {} through pidfd: {error}",
                            member.pid
                        ));
                        false
                    }
                };
                let pid = Pid::from_raw(member.pid.as_raw());
                match reap_tracee_pidfd_bounded(pid, &member.pidfd) {
                    Ok(()) if signal_succeeded => {}
                    Ok(()) => {
                        // Exact reap proves the member is gone even if the
                        // preceding signal syscall reported an error.
                        failures.retain(|failure| {
                            !failure.starts_with(&format!(
                                "emergency signal exact member {} ",
                                member.pid
                            ))
                        });
                    }
                    Err(error) => {
                        failures.push(format!(
                            "emergency reap exact member {}: {error}",
                            member.pid
                        ));
                        retained.push(member);
                    }
                }
            }
            self.members.lock().extend(retained);
            if self.members.lock().is_empty()
                && self.registration_error.lock().is_none()
                && failures.is_empty()
            {
                self.armed = false;
                Ok(())
            } else {
                Err(self.cleanup_error(&failures))
            }
        }
    }

    impl Drop for ExactNewChildCleanupGuard {
        fn drop(&mut self) {
            let mut retry_failures = Vec::new();
            for attempt in 1..=Self::DROP_CLEANUP_ATTEMPTS {
                match self.cleanup() {
                    Ok(()) => return,
                    Err(error) => retry_failures.push(format!("attempt {attempt}: {error}")),
                }
                if attempt < Self::DROP_CLEANUP_ATTEMPTS {
                    thread::sleep(SUBPROCESS_POLL_INTERVAL);
                }
            }
            match self.emergency_cleanup_without_injection() {
                Ok(()) => return,
                Err(error) => retry_failures.push(format!("emergency: {error}")),
            }
            let terminal = self.cleanup_error(&retry_failures);
            eprintln!(
                "NewChild fixture exact cleanup remained armed after bounded retries and emergency cleanup: {terminal}"
            );
            // This is test-only fixture code. Returning would drop the exact
            // pidfds and make an orphan invisible to the harness. Traced
            // members have PTRACE_O_EXITKILL; exec'd untraced members install
            // PDEATHSIG before execution. Abort only after direct, uninjected
            // pidfd SIGKILL/reap has also failed.
            std::process::abort();
        }
    }

    fn spawn_exact_cleanup_member() -> (Pid, WorkerIdentity, ExactNewChildCleanupGuard) {
        // Use an exec'd child with closed stdio instead of direct fork. These
        // tests run beside exact-subprocess pipe tests, and a fork-only child
        // would inherit their write ends until cleanup, making EOF scheduling
        // dependent under the default-parallel harness.
        let mut command = Command::new("/bin/sleep");
        command
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = command.spawn().expect("spawn exact-cleanup member");
        let pid = Pid::from_raw(child.id() as i32);
        let mut guard =
            ExactNewChildCleanupGuard::new(pid, EventHandle::new()).unwrap_or_else(|error| {
                let _ = child.kill();
                let _ = child.wait();
                panic!("open exact-cleanup member guard: {error}");
            });
        let identity = WorkerIdentity::capture_process(pid.into()).unwrap_or_else(|error| {
            guard.cleanup().unwrap_or_else(|cleanup_error| {
                panic!("capture exact-cleanup member identity: {error}; cleanup: {cleanup_error}")
            });
            panic!("capture exact-cleanup member identity: {error}");
        });
        drop(child);
        (pid, identity, guard)
    }

    #[test]
    fn exact_new_child_cleanup_signal_failure_retains_authority_for_retry() {
        let (pid, identity, mut guard) = spawn_exact_cleanup_member();
        guard.inject_signal_error(pid.into(), Errno::EIO);

        let error = guard
            .cleanup()
            .expect_err("injected exact signal failure must fail cleanup");
        assert!(error.to_string().contains("signal exact member"), "{error}");
        assert!(guard.armed);
        {
            let members = guard.members.lock();
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].pid, pid.into());
            assert_eq!(members[0].phase, ExactCleanupPhase::NeedsSignal);
            assert!(
                !pidfd_exited(&members[0].pidfd).expect("poll retained exact member"),
                "signal failure unexpectedly lost the live member"
            );
        }

        guard.cleanup().expect("retry exact signal cleanup");
        assert!(!guard.armed);
        assert!(guard.members.lock().is_empty());
        wait_generation_retired_bounded(&identity, "retried exact signal cleanup")
            .expect("no orphan after exact signal retry");
    }

    #[test]
    fn exact_new_child_cleanup_reap_failure_resumes_without_duplicate_signal() {
        let (pid, identity, mut guard) = spawn_exact_cleanup_member();
        guard.inject_reap_error(pid.into(), Errno::EIO);

        let error = guard
            .cleanup()
            .expect_err("injected exact reap failure must fail cleanup");
        assert!(error.to_string().contains("reap exact member"), "{error}");
        assert!(guard.armed);
        {
            let members = guard.members.lock();
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].pid, pid.into());
            assert_eq!(members[0].phase, ExactCleanupPhase::NeedsReap);
        }

        // If retry regresses to the signal phase, this injected error makes it
        // fail. A NeedsReap member must only repeat the exact pidfd reap.
        guard.inject_signal_error(pid.into(), Errno::EIO);
        guard.cleanup().expect("retry exact reap cleanup");
        assert!(!guard.armed);
        assert!(guard.members.lock().is_empty());
        wait_generation_retired_bounded(&identity, "retried exact reap cleanup")
            .expect("no orphan after exact reap retry");
    }

    fn assert_unwind_retries_exact_member_cleanup(
        inject: impl FnOnce(&mut ExactNewChildCleanupGuard, crate::Pid),
        context: &str,
    ) {
        let (pid, identity, mut guard) = spawn_exact_cleanup_member();
        inject(&mut guard, pid.into());
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = guard;
            panic!("exercise exact cleanup Drop during unwind");
        }));
        assert!(unwind.is_err(), "fixture panic unexpectedly returned");
        wait_generation_retired_bounded(&identity, context)
            .unwrap_or_else(|error| panic!("{context} left an exact member alive: {error}"));
    }

    #[test]
    fn exact_cleanup_drop_retries_one_shot_signal_failure_during_unwind() {
        assert_unwind_retries_exact_member_cleanup(
            |guard, pid| guard.inject_signal_error(pid, Errno::EIO),
            "unwind retry after exact signal failure",
        );
    }

    #[test]
    fn exact_cleanup_drop_retries_one_shot_reap_failure_during_unwind() {
        assert_unwind_retries_exact_member_cleanup(
            |guard, pid| guard.inject_reap_error(pid, Errno::EIO),
            "unwind retry after exact reap failure",
        );
    }

    #[test]
    fn exact_cleanup_drop_emergency_bypasses_persistent_test_signal_failures() {
        assert_unwind_retries_exact_member_cleanup(
            |guard, pid| {
                for _ in 0..ExactNewChildCleanupGuard::DROP_CLEANUP_ATTEMPTS {
                    guard.inject_signal_error(pid, Errno::EIO);
                }
            },
            "uninjected emergency cleanup after persistent test signal failures",
        );
    }

    #[test]
    fn exact_cleanup_drop_retries_registration_failure_during_unwind() {
        let child_op = crate::ChildOp::Clone;
        let (pid, stopped, mut cleanup) =
            spawn_new_child_tracee(child_op).expect("spawn unwind registration-failure tracee");
        let parent_identity = WorkerIdentity::capture_process(pid.into())
            .expect("capture unwind registration-failure parent");
        let parent_event = stopped.1.event().clone();
        let exact_cleanup = ExactNewChildCleanupGuard::new(pid, parent_event)
            .expect("construct unwind exact guard while parent is stopped");
        let (captured_tx, captured_rx) = mpsc::sync_channel(1);
        let (_resume_tx, resume_rx) = mpsc::channel();
        exact_cleanup.inject_pidfd_open_error(Errno::EMFILE);
        exact_cleanup.install_new_child_decode_pause(captured_tx, resume_rx);

        let running = stopped
            .resume(None)
            .expect("resume unwind registration-failure parent after guard install");
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("bind unwind registration-failure parent cleanup");
        let error = running
            .wait()
            .expect_err("pidfd-open injection must abort NewChild materialization");
        assert!(matches!(error, Error::Errno(Errno::EMFILE)), "{error:?}");
        assert!(captured_rx.try_recv().is_err());
        let pending = (*exact_cleanup.registration_error.lock())
            .expect("unwind registration failure must remain retryable");
        let child_pid = pending.pid;
        let child_identity = WorkerIdentity::capture_process(child_pid)
            .expect("capture unwind registration-failure child");
        PIDFD_OPEN_ERRORS.lock().insert(child_pid, Errno::ENFILE);

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _exact_cleanup = exact_cleanup;
            panic!("exercise registration retry during exact cleanup Drop");
        }));
        assert!(unwind.is_err(), "fixture panic unexpectedly returned");
        cleanup.disarm();
        wait_generation_retired_bounded(
            &parent_identity,
            "unwind retry after parent registration failure",
        )
        .expect("registration unwind retry left parent alive");
        wait_generation_retired_bounded(
            &child_identity,
            &format!("unwind retry after child {child_pid} registration failure"),
        )
        .expect("registration unwind retry left child alive");
    }

    #[test]
    fn new_child_pidfd_open_failure_precedes_materialization_and_cleanup_retries() {
        let child_op = crate::ChildOp::Clone;
        let (pid, stopped, mut cleanup) =
            spawn_new_child_tracee(child_op).expect("spawn pidfd-open failure tracee");
        let parent_identity = WorkerIdentity::capture_process(pid.into())
            .expect("capture pidfd-open failure parent identity");
        let parent_event = stopped.1.event().clone();
        let mut exact_cleanup = ExactNewChildCleanupGuard::new(pid, parent_event)
            .expect("construct exact guard while parent is stopped");
        let (captured_tx, captured_rx) = mpsc::sync_channel(1);
        let (_resume_tx, resume_rx) = mpsc::channel();
        exact_cleanup.inject_pidfd_open_error(Errno::EMFILE);
        exact_cleanup.install_new_child_decode_pause(captured_tx, resume_rx);

        let running = stopped
            .resume(None)
            .expect("resume pidfd-open failure parent after guard install");
        cleanup
            .store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))
            .expect("bind pidfd-open failure parent cleanup");
        let error = running
            .wait()
            .expect_err("pidfd-open failure must abort NewChild decoding");
        assert!(matches!(error, Error::Errno(Errno::EMFILE)), "{error:?}");
        assert!(
            captured_rx.try_recv().is_err(),
            "NewChild materialization pause ran after exact registration failed"
        );
        let pending = (*exact_cleanup.registration_error.lock())
            .expect("failed child registration must remain retryable");
        assert_eq!(pending.error, Errno::EMFILE);
        assert_ne!(pending.pid.as_raw(), pid.as_raw());
        let child_pid = pending.pid;
        let child_identity = WorkerIdentity::capture_process(child_pid)
            .expect("capture failed-registration child identity before cleanup retry");
        PIDFD_OPEN_ERRORS.lock().insert(child_pid, Errno::ENFILE);
        let retry_error = exact_cleanup
            .cleanup()
            .expect_err("second pidfd-open failure must retain the stopped parent authority");
        assert!(
            retry_error
                .to_string()
                .contains("retry NewChild exact pidfd registration"),
            "{retry_error}"
        );
        assert!(exact_cleanup.armed);
        assert!(parent_identity.is_same_process_generation());
        assert!(child_identity.is_same_process_generation());
        assert_eq!(
            (*exact_cleanup.registration_error.lock())
                .expect("failed retry remains registered")
                .error,
            Errno::ENFILE
        );
        {
            let members = exact_cleanup.members.lock();
            assert_eq!(members.len(), 1);
            assert_eq!(members[0].pid, pid.into());
            assert_eq!(members[0].phase, ExactCleanupPhase::NeedsSignal);
        }
        exact_cleanup
            .cleanup()
            .expect("exact cleanup retries child pidfd registration");
        assert!(!exact_cleanup.armed);
        assert!(exact_cleanup.members.lock().is_empty());
        assert!(exact_cleanup.registration_error.lock().is_none());
        cleanup.disarm();
        wait_generation_retired_bounded(&parent_identity, "pidfd-open failure parent")
            .expect("no parent orphan after pidfd-open registration retry");
        wait_generation_retired_bounded(
            &child_identity,
            &format!("pidfd-open failure child {child_pid}"),
        )
        .expect("no child orphan after pidfd-open registration retry");
    }

    fn start_new_child_return_race(
        child_op: crate::ChildOp,
        expected_return_owner: u8,
    ) -> io::Result<NewChildReturnRace> {
        let (pid, stopped, mut cleanup) = spawn_new_child_tracee(child_op)?;
        let parent_identity = WorkerIdentity::capture_process(pid.into()).map_err(|error| {
            io::Error::other(format!(
                "capture {child_op:?} parent {pid} identity: {error}"
            ))
        })?;
        let parent_event = stopped.1.event().clone();
        let exact_cleanup = ExactNewChildCleanupGuard::new(pid, parent_event.clone())?;
        let (child_materialized_tx, child_materialized_rx) = mpsc::sync_channel(0);
        let (resume_return_tx, resume_return_rx) = mpsc::channel();
        exact_cleanup.install_new_child_decode_pause(child_materialized_tx, resume_return_rx);
        let running = stopped
            .resume(None)
            .map_err(|error| io::Error::other(format!("resume {child_op:?} parent: {error}")))?;
        cleanup.store_terminal(TerminalCleanup::new_unregistered(pid.into(), &running.1))?;
        // The waiter remains on its ptracer thread. Only the cleanup contender
        // runs here while GETEVENTMSG, child materialization, and typed return
        // execute in the synchronous call or WaitFuture poll.
        let coordinator = thread::spawn(move || {
            if let Err(error) = child_materialized_rx.recv_timeout(TRACEE_WAIT_TIMEOUT) {
                let cleanup_result = cleanup.cleanup();
                return (
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "{child_op:?} decode did not materialize within bound: {error}; cleanup: {cleanup_result:?}"
                        ),
                    )),
                    cleanup,
                );
            }
            assert_eq!(
                parent_event.event().wait_owner.load(Ordering::Acquire),
                expected_return_owner,
                "{child_op:?} decoded outside its return transaction"
            );

            let (cleanup_saw_return_tx, cleanup_saw_return_rx) = mpsc::sync_channel(0);
            let (resume_cleanup_tx, resume_cleanup_rx) = mpsc::channel();
            *parent_event.event().cleanup_return_pause.lock() = Some(BoundedTestPause {
                captured: cleanup_saw_return_tx,
                resume: resume_cleanup_rx,
            });
            let cleaning = thread::spawn(move || {
                let result = cleanup.cleanup();
                (result, cleanup)
            });
            if let Err(error) = cleanup_saw_return_rx.recv_timeout(TRACEE_WAIT_TIMEOUT) {
                parent_event.event().cleanup_return_pause.lock().take();
                drop(cleanup_saw_return_rx);
                let _ = resume_return_tx.send(());
                let (cleanup_result, cleanup) = cleaning.join().expect("join failed cleanup race");
                return (
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!(
                            "{child_op:?} cleanup did not observe RETURNING: {error}; cleanup: {cleanup_result:?}"
                        ),
                    )),
                    cleanup,
                );
            }
            assert!(
                !parent_event
                    .event()
                    .cleanup_cancel_requested
                    .load(Ordering::Acquire),
                "{child_op:?} cleanup cancelled after typed return had begun"
            );
            resume_cleanup_tx
                .send(())
                .expect("resume cleanup RETURNING observation");
            resume_return_tx
                .send(())
                .expect("resume NewChild return transaction");
            cleaning.join().expect("join new-child cleanup")
        });

        Ok(NewChildReturnRace {
            pid,
            running: Some(running),
            parent_identity,
            coordinator,
            exact_cleanup,
        })
    }

    fn wait_generation_retired_bounded(identity: &WorkerIdentity, context: &str) -> io::Result<()> {
        let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
        loop {
            if !identity.is_same_process_generation() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let status = fs::read_to_string(format!("/proc/{}/status", identity.pid))
                    .unwrap_or_else(|error| format!("unavailable: {error}"));
                let status = status
                    .lines()
                    .filter(|line| {
                        line.starts_with("State:")
                            || line.starts_with("Tgid:")
                            || line.starts_with("TracerPid:")
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                let pidfd_live = identity.pidfd_is_live();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{context}: generation {} remained live; pidfd={pidfd_live:?}; proc=[{status}]",
                        identity.pid
                    ),
                ));
            }
            thread::sleep(SUBPROCESS_POLL_INTERVAL);
        }
    }

    fn finish_new_child_return_race(
        child_op: crate::ChildOp,
        mut race: NewChildReturnRace,
        wait: Wait,
    ) -> io::Result<()> {
        let (parent, event) = wait.assume_stopped();
        let child = match event {
            crate::Event::NewChild(observed, child) if observed == child_op => child,
            event => {
                return Err(io::Error::other(format!(
                    "expected {child_op:?} event, got {event:?}"
                )));
            }
        };
        if parent.pid() != race.pid.into() {
            return Err(io::Error::other(format!(
                "{child_op:?} returned parent {} instead of {}",
                parent.pid(),
                race.pid
            )));
        }
        drop(parent);

        let child_pid = Pid::from_raw(child.pid().as_raw());
        let child_identity = WorkerIdentity::capture_process(child.pid()).map_err(|error| {
            io::Error::other(format!(
                "capture materialized {child_op:?} child {child_pid}: {error}"
            ))
        })?;
        reap_new_child_bounded(child)?;
        let (cleanup_result, cleanup) = race
            .coordinator
            .join()
            .map_err(|_| io::Error::other(format!("{child_op:?} cleanup coordinator panicked")))?;
        cleanup_result?;
        if !matches!(
            cleanup.ownership,
            TraceeCleanupOwnership::NotifierOwned {
                cleanup_signal_sent: true,
                ..
            }
        ) {
            return Err(io::Error::other(format!(
                "{child_op:?} parent cleanup did not send its exact cancellation signal"
            )));
        }
        wait_generation_retired_bounded(
            &race.parent_identity,
            &format!("{child_op:?} parent cleanup"),
        )?;
        wait_generation_retired_bounded(
            &child_identity,
            &format!("{child_op:?} child {child_pid} reap"),
        )?;
        race.exact_cleanup.disarm_completed()?;
        Ok(())
    }

    fn new_child_trace_option(child_op: crate::ChildOp) -> Options {
        Options::PTRACE_O_EXITKILL
            | match child_op {
                crate::ChildOp::Fork => Options::PTRACE_O_TRACEFORK,
                crate::ChildOp::Vfork => Options::PTRACE_O_TRACEVFORK,
                crate::ChildOp::Clone => Options::PTRACE_O_TRACECLONE,
            }
    }

    fn spawn_new_child_tracee(
        child_op: crate::ChildOp,
    ) -> io::Result<(Pid, Stopped, TraceeCleanupGuard)> {
        match unsafe { fork() }.map_err(io::Error::other)? {
            ForkResult::Parent { child } => {
                let mut cleanup = TraceeCleanupGuard::new(child).inspect_err(|_| {
                    let _ = unsafe { libc::kill(child.as_raw(), libc::SIGKILL) };
                    let _ = reap_tracee_bounded(child);
                })?;
                let mut running = match Running::seize(
                    child.into(),
                    new_child_trace_option(child_op),
                ) {
                    Ok(running) => running,
                    Err(error) => {
                        let snapshot = worker_proc_snapshot(child.into());
                        let cleanup_result = cleanup.cleanup();
                        return Err(io::Error::other(format!(
                            "seize {child_op:?} parent {child}: {error}; snapshot: {snapshot:?}; cleanup: {cleanup_result:?}"
                        )));
                    }
                };
                let stopped = loop {
                    match running.wait() {
                        Ok(Wait::Stopped(stopped, crate::Event::Stop))
                        | Ok(Wait::Stopped(stopped, crate::Event::Signal(Signal::SIGSTOP))) => {
                            break stopped;
                        }
                        Ok(Wait::Stopped(stopped, crate::Event::Signal(signal))) => {
                            running = stopped.resume(Some(signal)).map_err(io::Error::other)?;
                        }
                        Ok(Wait::Stopped(stopped, _)) => {
                            running = stopped.resume(None).map_err(io::Error::other)?;
                        }
                        Ok(Wait::Exited(_, status)) => {
                            cleanup.disarm();
                            return Err(io::Error::other(format!(
                                "{child_op:?} parent {child} exited before initial stop: {status:?}"
                            )));
                        }
                        Err(error) => {
                            let cleanup_result = cleanup.cleanup();
                            return Err(io::Error::other(format!(
                                "wait {child_op:?} parent {child} initial stop: {error}; cleanup: {cleanup_result:?}"
                            )));
                        }
                    }
                };
                Ok((child, stopped, cleanup))
            }
            ForkResult::Child => {
                if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
                    unsafe { libc::_exit(125) };
                }
                let flags = match child_op {
                    crate::ChildOp::Fork => libc::SIGCHLD,
                    crate::ChildOp::Vfork => libc::CLONE_VFORK | libc::SIGCHLD,
                    crate::ChildOp::Clone => 0,
                };
                let result = unsafe {
                    libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize)
                };
                if result == 0 {
                    unsafe { libc::_exit(0) };
                }
                unsafe { libc::_exit(i32::from(result == -1)) };
            }
        }
    }

    fn reap_new_child_bounded(child: Running) -> io::Result<()> {
        let child_pid = Pid::from_raw(child.pid().as_raw());
        let child_pidfd = pidfd_open(child_pid.as_raw())?;
        let wait_bounded = |running: Running| -> Result<Wait, Error> {
            let pid = running.0;
            let token = running.1;
            let flags = WaitPidFlag::from_bits_retain(
                WaitPidFlag::WEXITED.bits()
                    | WaitPidFlag::WSTOPPED.bits()
                    | WaitPidFlag::WNOHANG.bits()
                    | libc::__WALL,
            );
            let deadline = Instant::now() + TRACEE_WAIT_TIMEOUT;
            loop {
                match waitid::waitpidfd(child_pidfd.as_raw_fd(), flags) {
                    Ok(Some(status)) => {
                        return Wait::from_raw_with_token(pid, status, token);
                    }
                    Ok(None) | Err(Errno::EINTR) => {}
                    Err(error) => return Err(error.into()),
                }
                if Instant::now() >= deadline {
                    return Err(Errno::ETIMEDOUT.into());
                }
                thread::sleep(SUBPROCESS_POLL_INTERVAL);
            }
        };

        let first = match wait_bounded(child) {
            Ok(wait) => wait,
            Err(error) => {
                let _ = pidfd_send_signal(&child_pidfd, libc::SIGKILL);
                let cleanup = reap_tracee_pidfd_bounded(child_pid, &child_pidfd);
                return Err(io::Error::other(format!(
                    "bounded initial child {child_pid} wait: {error}; cleanup: {cleanup:?}"
                )));
            }
        };
        let (stopped, event) = first.assume_stopped();
        if !matches!(
            event,
            crate::Event::Stop | crate::Event::Signal(Signal::SIGSTOP)
        ) {
            let _ = pidfd_send_signal(&child_pidfd, libc::SIGKILL);
            let cleanup = reap_tracee_pidfd_bounded(child_pid, &child_pidfd);
            return Err(io::Error::other(format!(
                "unexpected initial child event: {event:?}; cleanup: {cleanup:?}"
            )));
        }
        let running = match stopped.resume(None) {
            Ok(running) => running,
            Err(error) => {
                let _ = pidfd_send_signal(&child_pidfd, libc::SIGKILL);
                let cleanup = reap_tracee_pidfd_bounded(child_pid, &child_pidfd);
                return Err(io::Error::other(format!(
                    "resume child {child_pid}: {error}; cleanup: {cleanup:?}"
                )));
            }
        };
        let (_, exit) = match wait_bounded(running) {
            Ok(wait) => wait.assume_exited(),
            Err(Error::Errno(Errno::ETIMEDOUT)) => {
                pidfd_send_signal(&child_pidfd, libc::SIGKILL)?;
                let cleanup = reap_tracee_pidfd_bounded(child_pid, &child_pidfd);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("child {child_pid} did not exit within bound; cleanup: {cleanup:?}"),
                ));
            }
            Err(error) => {
                let _ = pidfd_send_signal(&child_pidfd, libc::SIGKILL);
                let cleanup = reap_tracee_pidfd_bounded(child_pid, &child_pidfd);
                return Err(io::Error::other(format!(
                    "bounded child {child_pid} exit wait: {error}; cleanup: {cleanup:?}"
                )));
            }
        };
        if exit != crate::ExitStatus::Exited(0) {
            return Err(io::Error::other(format!("unexpected child exit: {exit:?}")));
        }
        Ok(())
    }

    fn spawn_traced_process(
        requested_pid: Option<i32>,
    ) -> Option<(Pid, Stopped, TraceeCleanupGuard)> {
        let child = if let Some(requested_pid) = requested_pid {
            #[repr(C)]
            #[derive(Default)]
            struct CloneArgs {
                flags: u64,
                pidfd: u64,
                child_tid: u64,
                parent_tid: u64,
                exit_signal: u64,
                stack: u64,
                stack_size: u64,
                tls: u64,
                set_tid: u64,
                set_tid_size: u64,
                cgroup: u64,
            }

            let mut set_tid = requested_pid as u64;
            let args = CloneArgs {
                exit_signal: libc::SIGCHLD as u64,
                set_tid: std::ptr::from_mut(&mut set_tid) as u64,
                set_tid_size: 1,
                ..CloneArgs::default()
            };
            let result = unsafe {
                libc::syscall(
                    libc::SYS_clone3,
                    std::ptr::from_ref(&args),
                    mem::size_of::<CloneArgs>(),
                )
            };
            if result == -1 {
                return None;
            }
            if result == 0 {
                crate::traceme_and_stop().expect("TRACEME requested-PID child");
                unsafe { libc::_exit(42) };
            }
            Pid::from_raw(result as i32)
        } else {
            match unsafe { fork() }.expect("fork duplicate-exit tracee") {
                ForkResult::Parent { child } => child,
                ForkResult::Child => {
                    crate::traceme_and_stop().expect("TRACEME duplicate-exit child");
                    unsafe { libc::_exit(42) };
                }
            }
        };

        let mut cleanup = TraceeCleanupGuard::new(child).unwrap_or_else(|error| {
            let _ = unsafe { libc::kill(child.as_raw(), libc::SIGKILL) };
            let _ = reap_tracee_bounded(child);
            panic!("open duplicate-exit tracee pidfd: {error}");
        });
        let stopped = stopped_tracee_bounded(child).unwrap_or_else(|error| {
            cleanup
                .cleanup()
                .unwrap_or_else(|cleanup_error| panic!("{error}; cleanup: {cleanup_error}"));
            panic!("wait duplicate-exit initial stop: {error}");
        });
        Some((child, stopped, cleanup))
    }

    async fn duplicate_exit_waiter_rejects_replacement(requested_pid: Option<i32>) -> bool {
        let Some((old_pid, old_stopped, mut old_cleanup)) = spawn_traced_process(requested_pid)
        else {
            return false;
        };
        old_stopped
            .setoptions(Options::PTRACE_O_TRACEEXIT)
            .expect("enable exit stop for duplicate waiter");
        // Register then cancel one waiter while the tracee is still stopped.
        // A Pending poll must not consume the Event capability.
        let mut cancelled = Box::pin(
            old_cleanup
                .exit_event(&old_stopped)
                .expect("bind duplicate-waiter cleanup to notifier"),
        );
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert_eq!(cancelled.as_mut().poll(&mut context), Poll::Pending);
        drop(cancelled);

        let winner = old_cleanup
            .exit_event(&old_stopped)
            .expect("create winner on bound notifier generation");
        let duplicate = old_cleanup
            .exit_event(&old_stopped)
            .expect("create duplicate on bound notifier generation");
        let late = old_cleanup
            .exit_event(&old_stopped)
            .expect("create late waiter on bound notifier generation");
        old_stopped
            .resume(None)
            .expect("resume old duplicate-waiter tracee");

        let exit_stopped = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, winner)
            .await
            .expect("old exit-stop winner timed out")
            .expect("claim old exit-stop capability");
        old_cleanup.mark_claimed_exit();
        assert_eq!(
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, duplicate)
                .await
                .expect("old duplicate ExitFuture timed out"),
            Err(Error::Errno(Errno::EALREADY))
        );
        let final_wait = exit_stopped
            .resume(None)
            .expect("resume claimed old exit stop");
        let final_wait = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, final_wait.next_state())
            .await
            .expect("old claimed exit final status timed out")
            .expect("wait old final status");
        old_cleanup.disarm();
        assert_eq!(
            final_wait.assume_exited(),
            (old_pid.into(), crate::ExitStatus::Exited(42))
        );

        thread::sleep(Duration::from_millis(20));
        let Some((replacement_pid, replacement, mut replacement_cleanup)) =
            spawn_traced_process(requested_pid)
        else {
            return false;
        };
        if requested_pid.is_some() {
            assert_eq!(
                replacement_pid, old_pid,
                "clone3 did not reuse requested PID"
            );
        }

        assert_eq!(
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, late)
                .await
                .expect("late old ExitFuture timed out"),
            Err(Error::Errno(Errno::EALREADY))
        );
        replacement
            .getregs()
            .expect("late old waiter touched the stopped replacement");
        replacement_cleanup
            .bind_notifier(&replacement)
            .expect("bind replacement cleanup to notifier");
        let replacement = replacement.resume(None).expect("resume replacement tracee");
        let replacement = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, replacement.next_state())
            .await
            .expect("replacement final status timed out")
            .expect("wait replacement tracee");
        replacement_cleanup.disarm();
        assert_eq!(
            replacement.assume_exited(),
            (replacement_pid.into(), crate::ExitStatus::Exited(42))
        );
        true
    }

    async fn unclaimed_exit_waiter_expires_before_cleanup_replacement(
        requested_pid: Option<i32>,
    ) -> bool {
        let Some((old_pid, old_stopped, mut old_cleanup)) = spawn_traced_process(requested_pid)
        else {
            return false;
        };
        old_stopped
            .setoptions(Options::PTRACE_O_TRACEEXIT)
            .expect("enable exit stop for cleanup expiration");
        let mut late = Box::pin(
            old_cleanup
                .exit_event(&old_stopped)
                .expect("bind unclaimed cleanup to notifier"),
        );
        let terminal = old_cleanup
            .terminal()
            .expect("bound unclaimed cleanup terminal");
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        assert_eq!(late.as_mut().poll(&mut context), Poll::Pending);
        old_stopped
            .resume(None)
            .expect("resume unclaimed exit-stop tracee");

        let deadline = Instant::now() + Duration::from_secs(1);
        while !terminal.exit_stop_observed() {
            assert!(
                Instant::now() < deadline,
                "unclaimed cleanup tracee did not reach exit stop"
            );
            thread::yield_now();
        }
        terminal
            .revoke_unclaimed_exit_stop()
            .expect("cleanup failed to expire unclaimed exit stop");
        nix::sys::ptrace::cont(old_pid, None).expect("raw cleanup resume old exit stop");
        assert!(
            terminal.wait(Duration::from_secs(1)),
            "cleanup notifier did not publish old final status"
        );
        old_cleanup.disarm();

        thread::sleep(Duration::from_millis(20));
        let Some((replacement_pid, replacement, mut replacement_cleanup)) =
            spawn_traced_process(requested_pid)
        else {
            return false;
        };
        if requested_pid.is_some() {
            assert_eq!(
                replacement_pid, old_pid,
                "clone3 did not reuse cleanup test PID"
            );
        }

        assert_eq!(
            tokio::time::timeout(TRACEE_WAIT_TIMEOUT, late)
                .await
                .expect("late unclaimed ExitFuture timed out"),
            Err(Error::Errno(Errno::EALREADY))
        );
        replacement
            .getregs()
            .expect("late unclaimed waiter touched the stopped replacement");
        replacement_cleanup
            .bind_notifier(&replacement)
            .expect("bind cleanup replacement to notifier");
        let replacement = replacement
            .resume(None)
            .expect("resume cleanup replacement tracee");
        let replacement = tokio::time::timeout(TRACEE_WAIT_TIMEOUT, replacement.next_state())
            .await
            .expect("cleanup replacement final status timed out")
            .expect("wait cleanup replacement tracee");
        replacement_cleanup.disarm();
        assert_eq!(
            replacement.assume_exited(),
            (replacement_pid.into(), crate::ExitStatus::Exited(42))
        );
        true
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exit_waiters_never_target_reused_pid_after_claim_or_cleanup() {
        const INNER: &str = "SAFEPTRACE_EXIT_REUSE_INNER";
        if env::var_os(INNER).is_some() {
            if duplicate_exit_waiter_rejects_replacement(Some(100)).await
                && unclaimed_exit_waiter_expires_before_cleanup_replacement(Some(100)).await
            {
                println!("ACTUAL_EXIT_PID_REUSE_EXERCISED");
            } else {
                println!("ACTUAL_EXIT_PID_REUSE_UNAVAILABLE");
            }
            return;
        }

        let inner = "notifier::test::exit_waiters_never_target_reused_pid_after_claim_or_cleanup";
        let actual_reuse = run_exact_in_pid_namespace_bounded(inner, &[(INNER, "1")]);
        match classify_exact_reuse_output(
            actual_reuse.as_ref(),
            "ACTUAL_EXIT_PID_REUSE_EXERCISED",
            "ACTUAL_EXIT_PID_REUSE_UNAVAILABLE",
        )
        .unwrap_or_else(|error| panic!("actual exit PID-reuse regression failed: {error}"))
        {
            ExactReuseOutcome::Exercised => return,
            ExactReuseOutcome::Unavailable => {}
        }

        // Restricted runners may deny user namespaces or clone3(set_tid).
        // Still use two real kernel-created generations and prove the late
        // duplicate cannot mint a second stopped capability.
        assert!(duplicate_exit_waiter_rejects_replacement(None).await);
        assert!(unclaimed_exit_waiter_expires_before_cleanup_replacement(None).await);
    }

    fn spawn_stopped_process(requested_pid: Option<i32>) -> Option<(Pid, TraceeCleanupGuard)> {
        let child = if let Some(requested_pid) = requested_pid {
            #[repr(C)]
            #[derive(Default)]
            struct CloneArgs {
                flags: u64,
                pidfd: u64,
                child_tid: u64,
                parent_tid: u64,
                exit_signal: u64,
                stack: u64,
                stack_size: u64,
                tls: u64,
                set_tid: u64,
                set_tid_size: u64,
                cgroup: u64,
            }

            let mut set_tid = requested_pid as u64;
            let args = CloneArgs {
                exit_signal: libc::SIGCHLD as u64,
                set_tid: std::ptr::from_mut(&mut set_tid) as u64,
                set_tid_size: 1,
                ..CloneArgs::default()
            };
            let result = unsafe {
                libc::syscall(
                    libc::SYS_clone3,
                    std::ptr::from_ref(&args),
                    mem::size_of::<CloneArgs>(),
                )
            };
            if result == -1 {
                return None;
            }
            if result == 0 {
                let _ = nix::sys::signal::raise(Signal::SIGSTOP);
                unsafe { libc::_exit(0) };
            }
            Pid::from_raw(result as i32)
        } else {
            match unsafe { fork() }.expect("fork replacement-generation tracee") {
                ForkResult::Parent { child } => child,
                ForkResult::Child => {
                    let _ = nix::sys::signal::raise(Signal::SIGSTOP);
                    unsafe { libc::_exit(0) };
                }
            }
        };

        let mut cleanup = TraceeCleanupGuard::new(child).unwrap_or_else(|error| {
            let _ = unsafe { libc::kill(child.as_raw(), libc::SIGKILL) };
            let _ = reap_tracee_bounded(child);
            panic!("open replacement-generation pidfd: {error}");
        });
        let status = waitpid_status_bounded(child, libc::WUNTRACED, TRACEE_WAIT_TIMEOUT)
            .unwrap_or_else(|error| {
                let cleanup_result = cleanup.cleanup();
                panic!("wait replacement-generation tracee: {error}; cleanup: {cleanup_result:?}")
            });
        assert!(libc::WIFSTOPPED(status));
        Some((child, cleanup))
    }

    fn reap_stopped_process(mut cleanup: TraceeCleanupGuard) {
        cleanup.cleanup().expect("bounded stopped-process cleanup");
    }

    fn assert_live_replacement_rejected(first_pid: Option<i32>) -> bool {
        let Some((old_pid, old_cleanup)) = spawn_stopped_process(first_pid) else {
            return false;
        };
        let old_identity = WorkerIdentity::capture_process(old_pid.into())
            .expect("capture old notifier worker generation");
        assert!(old_identity.is_same_process_generation());
        reap_stopped_process(old_cleanup);

        // starttime is measured in clock ticks. Keep the two real generations
        // distinct even on fast machines where procfs could otherwise report
        // the same tick.
        thread::sleep(Duration::from_millis(20));

        let Some((new_pid, new_cleanup)) = spawn_stopped_process(first_pid) else {
            return false;
        };
        let new_identity = WorkerIdentity::capture_process(new_pid.into())
            .expect("capture replacement notifier worker generation");
        assert!(new_identity.is_same_process_generation());
        assert!(
            !old_identity.is_same_process_generation(),
            "an ECHILD worker accepted a live replacement proc generation"
        );
        // The production ECHILD decision is stricter still: it also requires
        // the bound TracerPid to remain one of this process's live threads.
        assert!(!old_identity.is_active_tracee());
        reap_stopped_process(new_cleanup);
        true
    }

    #[test]
    fn worker_echild_rejects_live_replacement_generation() {
        const INNER: &str = "SAFEPTRACE_ACTUAL_REUSE_INNER";
        if env::var_os(INNER).is_some() {
            if assert_live_replacement_rejected(Some(100)) {
                println!("ACTUAL_PID_REUSE_EXERCISED");
            } else {
                println!("ACTUAL_PID_REUSE_UNAVAILABLE");
            }
            return;
        }

        // Reinvoke this exact test in a fresh user/PID namespace.
        // `clone3(set_tid)` there deterministically reuses PID 100 for two
        // different, real procfs generations.
        let inner = "notifier::test::worker_echild_rejects_live_replacement_generation";
        let actual_reuse = run_exact_in_pid_namespace_bounded(inner, &[(INNER, "1")]);
        match classify_exact_reuse_output(
            actual_reuse.as_ref(),
            "ACTUAL_PID_REUSE_EXERCISED",
            "ACTUAL_PID_REUSE_UNAVAILABLE",
        )
        .unwrap_or_else(|error| panic!("actual worker PID-reuse regression failed: {error}"))
        {
            ExactReuseOutcome::Exercised => return,
            ExactReuseOutcome::Unavailable => {}
        }

        // Restricted CI runners may prohibit user namespaces or clone3
        // set_tid. Still exercise the exact generation predicate with two live,
        // kernel-created proc generations; the old O_PATH fd/starttime must
        // reject the replacement even though its numeric PID cannot be forced.
        assert!(assert_live_replacement_rejected(None));
    }

    #[test]
    fn registry_rejects_terminal_event_after_actual_pid_reuse() {
        const INNER: &str = "SAFEPTRACE_REGISTRY_REUSE_INNER";
        if env::var_os(INNER).is_some() {
            let Some((old_pid, old_cleanup)) = spawn_stopped_process(Some(100)) else {
                println!("ACTUAL_REGISTRY_PID_REUSE_UNAVAILABLE");
                return;
            };
            let old_identity = Arc::new(
                WorkerIdentity::capture_process(old_pid.into())
                    .expect("capture old registry generation"),
            );
            let old_handle = EventHandle::with_identity(Arc::clone(&old_identity));
            NOTIFIER.pids.lock().insert(
                old_pid.into(),
                NotifierEntry {
                    handle: old_handle.clone(),
                    identity: old_identity,
                },
            );
            assert!(old_handle.event().try_begin_unstarted_completion());
            old_handle.event().mark_echild();
            old_handle.event().mark_worker_done();
            reap_stopped_process(old_cleanup);
            thread::sleep(Duration::from_millis(20));

            let Some((new_pid, new_cleanup)) = spawn_stopped_process(Some(100)) else {
                NOTIFIER.pids.lock().remove(&old_pid.into());
                println!("ACTUAL_REGISTRY_PID_REUSE_UNAVAILABLE");
                return;
            };
            let selected = EventHandle::current_or_new(new_pid.into())
                .expect("select replacement registry generation");
            assert_ne!(
                selected, old_handle,
                "registry rebound a reused numeric PID to the old terminal Event"
            );
            NOTIFIER.pids.lock().remove(&new_pid.into());
            reap_stopped_process(new_cleanup);
            println!("ACTUAL_REGISTRY_PID_REUSE_EXERCISED");
            return;
        }

        let inner = "notifier::test::registry_rejects_terminal_event_after_actual_pid_reuse";
        let actual_reuse = run_exact_in_pid_namespace_bounded(inner, &[(INNER, "1")]);
        match classify_exact_reuse_output(
            actual_reuse.as_ref(),
            "ACTUAL_REGISTRY_PID_REUSE_EXERCISED",
            "ACTUAL_REGISTRY_PID_REUSE_UNAVAILABLE",
        )
        .unwrap_or_else(|error| panic!("actual registry PID-reuse regression failed: {error}"))
        {
            ExactReuseOutcome::Exercised => return,
            ExactReuseOutcome::Unavailable => {}
        }

        // Hosted CI may prohibit user namespaces. Project two distinct real
        // kernel generations onto the same numeric registry key while keeping
        // the old O_PATH fd, starttime, TGID, and inode. This exercises the
        // production replacement path without accepting a numeric-only match.
        assert_projected_registry_reuse_rejected();
    }

    fn assert_projected_registry_reuse_rejected() {
        let (old_pid, old_cleanup) =
            spawn_stopped_process(None).expect("spawn old projected generation");
        let mut old_identity = WorkerIdentity::capture_process(old_pid.into())
            .expect("capture old projected generation");
        reap_stopped_process(old_cleanup);
        thread::sleep(Duration::from_millis(20));

        let (new_pid, new_cleanup) =
            spawn_stopped_process(None).expect("spawn new projected generation");
        old_identity.pid = new_pid.into();
        let old_identity = Arc::new(old_identity);
        let old_handle = EventHandle::with_identity(Arc::clone(&old_identity));
        assert!(old_handle.event().try_begin_unstarted_completion());
        old_handle.event().mark_echild();
        old_handle.event().mark_worker_done();
        NOTIFIER.pids.lock().insert(
            new_pid.into(),
            NotifierEntry {
                handle: old_handle.clone(),
                identity: old_identity,
            },
        );

        let selected = EventHandle::current_or_new(new_pid.into())
            .expect("select projected replacement registry generation");
        assert_ne!(
            selected, old_handle,
            "registry selected a terminal Event using only the projected numeric PID"
        );
        NOTIFIER.pids.lock().remove(&new_pid.into());
        reap_stopped_process(new_cleanup);
    }

    #[test]
    fn registry_rejects_projected_pid_reuse_without_user_namespaces() {
        assert_projected_registry_reuse_rejected();
    }
}
