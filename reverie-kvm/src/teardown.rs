/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Deferred physical destruction of a backend's VM.
//!
//! Closing a VM fd destroys the VM in the kernel (`kvm_destroy_vm`), whose
//! MMU teardown waits for an RCU grace period. That wait is tens of
//! milliseconds on a busy many-CPU host and has nothing to do with the
//! guest: every guest-visible effect of a process's or thread's exit is
//! already published before its backend drops. A backend with a
//! [`VmTeardownSink`] installed therefore hands duplicates of its vCPU and
//! VM fds to the sink at drop, after its logical teardown (worker
//! cancellation and joins) has run on the dropping thread. The dropping
//! thread's own closes then only drop file references; the sink's closes
//! are the last ones and run the kernel destroy wherever the sink chooses.
//!
//! If duplicating a descriptor fails, or the sink panics, the backend's
//! fields drop as they would without a sink and destroy the VM on the
//! dropping thread. Deferral can degrade to synchronous destruction; it
//! cannot leak a VM, because some close is always the last one.
//!
//! The thread reaper here is also safe in a host-fork copy of a run (a
//! process made by `fork()` from a paused template): `fork()` copies
//! only the calling thread, so the workers do not exist in the copy,
//! but their queue does. The reaper records the process its workers
//! were spawned in and, on first use in a different process, spawns a
//! fresh pool that keeps draining that queue — each process's closes
//! drop only its own descriptor references, and the kernel destroy
//! still runs at whichever close is globally last. If no worker can
//! spawn in the copy, descriptors close inline instead. Without this,
//! a copy adopting into the copied queue would wait forever for
//! workers that are not there.
//!
//! The reaper's consumer is the claude-multiverse timelines lane
//! (minibeads epic `dh-wibks8`; archive `rrnewton/hermit
//! archive/multiverse-20261118`): its long-lived template processes
//! host-fork paused copies whose guest children exit inside the copy
//! and would otherwise pay a grace period per child exit on the
//! dropping thread. The Hermit CLI itself does not use the reaper —
//! it installs a helper-process sink, because a process that is about
//! to exit gains nothing from in-process threads — so until the
//! multiverse lane wires the reaper into its template lifecycle, the
//! fork-recovery paths here are exercised by this module's tests.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::Once;
use std::sync::Weak;

use crate::Error;
use crate::Result;
use crate::error::ErrorExt;

/// Where a dropped backend's VM fds go to be closed last.
///
/// The backend calls this once per VM, from its drop, after logical
/// teardown. The descriptors are close-on-exec duplicates of the backend's
/// vCPU and VM fds. The sink must:
///
/// - close `vcpu` before `vm` (the backend's own field drop order);
/// - eventually close both, whatever else fails — dropping them unclosed
///   is impossible for [`OwnedFd`], so holding them forever is the only
///   way to break this, and a VM held past its run is a leak;
/// - not panic (the backend catches a panic and falls back to destroying
///   the VM on the dropping thread, but nothing is reported to the sink).
///
/// It may block, for backpressure: a bounded sink that blocks when full
/// degenerates to synchronous teardown under overload rather than holding
/// unbounded guest memory in undestroyed VMs.
pub trait VmTeardownSink: Send + Sync {
    fn adopt_vm(&self, vcpu: OwnedFd, vm: OwnedFd);

    /// As [`Self::adopt_vm`], plus a `hold` the sink must drop only
    /// after both descriptors are closed. The backend passes a clone
    /// of the VM's guest-memory handle: while the VM is still alive,
    /// unmapping that memory in the dropping process makes the kernel
    /// zap the VM's page tables synchronously on the dropping thread,
    /// putting much of the destroy cost back where deferral was
    /// supposed to move it from (measured; the race decides whether a
    /// given drop pays it). Keeping one clone alive past the destroy
    /// — dropped by whichever thread or process observes the closes
    /// complete — makes the unmap always follow the destroy.
    ///
    /// The default suits a sink that closes both descriptors before
    /// `adopt_vm` returns: the hold then drops right here, already
    /// after the closes. An asynchronous sink must override this and
    /// drop the hold only once its closes have completed; on any
    /// failure path where the descriptors were not adopted, dropping
    /// the hold immediately is still correct, because the backend's
    /// own field drops then run the destroy.
    fn adopt_vm_with_hold(&self, vcpu: OwnedFd, vm: OwnedFd, hold: Box<dyn std::any::Any + Send>) {
        self.adopt_vm(vcpu, vm);
        drop(hold);
    }
}

/// A close-on-exec duplicate of `fd`, for handing to a [`VmTeardownSink`].
pub(crate) fn dup_cloexec(fd: RawFd) -> std::io::Result<OwnedFd> {
    // SAFETY: `fd` is a live descriptor owned by the caller; a successful
    // F_DUPFD_CLOEXEC returns a new descriptor this call uniquely owns.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above, `dup` is a fresh descriptor owned by this call.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

/// Concurrent closes overlap their kernel RCU grace-period waits, so a
/// small pool destroys a fork-heavy run's VMs much faster than one thread
/// could, without unbounded thread creation.
const TEARDOWN_WORKERS: usize = 4;

/// Bundles queued behind the workers before [`VmTeardownSink::adopt_vm`]
/// blocks. Each bundle keeps one guest memory's pinned pages alive, so the
/// queue is bounded; the workers' in-flight bundles are additional.
const MAX_QUEUED_BUNDLES: usize = 32;

struct Bundle {
    vcpu: OwnedFd,
    vm: OwnedFd,
    /// Dropped by the worker after both closes, so the guest memory
    /// it keeps alive unmaps only once the VM is destroyed.
    hold: Option<Box<dyn std::any::Any + Send>>,
}

#[derive(Default)]
struct State {
    queue: VecDeque<Bundle>,
    adopted: u64,
    destroyed: u64,
    handles: usize,
    /// Process the live workers were spawned in (0 before any spawn).
    /// A host-fork copy has a different pid and none of those workers;
    /// first use there spawns a fresh pool (see the module docs).
    worker_pid: libc::pid_t,
    /// No worker could spawn in `worker_pid`; closes run inline there.
    workers_failed: bool,
}

fn current_pid() -> libc::pid_t {
    // SAFETY: getpid takes no arguments and touches no memory.
    unsafe { libc::getpid() }
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    work: Condvar,
    space: Condvar,
    idle: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn wait<'a>(&self, condvar: &Condvar, state: MutexGuard<'a, State>) -> MutexGuard<'a, State> {
        condvar
            .wait(state)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Every live reaper's shared state, for the atfork handlers below.
/// Weak, so registration never keeps a reaper (or its workers) alive.
static FORK_REGISTRY: Mutex<Vec<Weak<Shared>>> = Mutex::new(Vec::new());
static FORK_HANDLERS: Once = Once::new();

/// One queue lock held across a fork, with the `Arc` that keeps its
/// `Shared` alive. Field order matters: the guard unlocks before the
/// `Arc` can drop.
struct HeldForkGuard {
    _guard: Option<MutexGuard<'static, State>>,
    _shared: Arc<Shared>,
}

thread_local! {
    /// Queue locks taken by `atfork_prepare` on this (forking) thread,
    /// released by the parent/child handler on the same thread.
    static FORK_HELD: RefCell<Vec<HeldForkGuard>> = const { RefCell::new(Vec::new()) };
    static FORK_REGISTRY_HELD: RefCell<Option<MutexGuard<'static, Vec<Weak<Shared>>>>> =
        const { RefCell::new(None) };
}

fn lock_registry() -> MutexGuard<'static, Vec<Weak<Shared>>> {
    FORK_REGISTRY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Locks every live reaper's queue before the fork copies memory, so
/// no copy can inherit a queue mutex whose owner thread was not
/// copied: that mutex would stay locked forever in the copy, and its
/// first adoption would deadlock. Workers parked on a condvar have
/// released the mutex and need nothing.
extern "C" fn atfork_prepare() {
    let mut registry = lock_registry();
    registry.retain(|shared| shared.strong_count() > 0);
    let live: Vec<Arc<Shared>> = registry.iter().filter_map(Weak::upgrade).collect();
    FORK_REGISTRY_HELD.with(|held| *held.borrow_mut() = Some(registry));
    FORK_HELD.with(|held| {
        let mut held = held.borrow_mut();
        for shared in live {
            if held
                .iter()
                .any(|held| std::ptr::eq(Arc::as_ptr(&held._shared), Arc::as_ptr(&shared)))
            {
                continue;
            }
            // SAFETY: the accompanying `Arc` in the same entry keeps
            // `shared` alive until after the guard drops.
            let shared_ref: &'static Shared = unsafe { &*Arc::as_ptr(&shared) };
            held.push(HeldForkGuard {
                _guard: Some(shared_ref.lock()),
                _shared: shared,
            });
        }
    });
}

fn atfork_release() {
    FORK_HELD.with(|held| held.borrow_mut().clear());
    FORK_REGISTRY_HELD.with(|held| {
        let _ = held.borrow_mut().take();
    });
}

extern "C" fn atfork_parent() {
    atfork_release();
}

extern "C" fn atfork_child() {
    // The forking thread is the copied guards' owner here, exactly as
    // in the parent; releasing is the same operation in both.
    atfork_release();
}

/// Registers the atfork handlers (once per process) and this reaper
/// in their registry. glibc runs the handlers for `libc::fork`, and
/// they survive into forked copies, whose copied registry still
/// names their copied shared states.
fn register_for_atfork(shared: &Arc<Shared>) {
    FORK_HANDLERS.call_once(|| {
        // SAFETY: the three handlers are plain functions that only
        // lock and unlock the mutexes above on the forking thread.
        unsafe {
            libc::pthread_atfork(
                Some(atfork_prepare),
                Some(atfork_parent),
                Some(atfork_child),
            );
        }
    });
    lock_registry().push(Arc::downgrade(shared));
}

#[cfg(test)]
type WorkerPopHook = Arc<dyn Fn(*const Shared) + Send + Sync>;

#[cfg(test)]
static WORKER_POP_HOOK: Mutex<Option<WorkerPopHook>> = Mutex::new(None);

fn teardown_worker(shared: Arc<Shared>) {
    loop {
        let bundle = {
            let mut state = shared.lock();
            // Stamp the process this worker is actually running in. A
            // thread-restoring host fork (raw clone, no atfork handlers)
            // resumes this worker in the copy under a new pid; the stamp
            // tells a racing `ensure_workers` there that a live pool
            // already exists in this process, so it does not spawn a
            // second one draining the same queue.
            let pid = current_pid();
            if state.worker_pid != pid {
                state.worker_pid = pid;
                shared.idle.notify_all();
            }
            loop {
                if let Some(bundle) = state.queue.pop_front() {
                    #[cfg(test)]
                    if let Some(hook) = WORKER_POP_HOOK
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone()
                    {
                        // Still holding the queue lock: the fork test
                        // parks the worker here, mid-critical-section.
                        hook(Arc::as_ptr(&shared));
                    }
                    shared.space.notify_all();
                    break bundle;
                }
                // No handle remains, so no bundle can still arrive.
                if state.handles == 0 {
                    return;
                }
                state = shared.wait(&shared.work, state);
            }
        };
        // Field order in the backend: the vCPU fd closes before the VM fd.
        // Dropping an OwnedFd closes it; the VM close runs the kernel
        // destroy this thread exists to absorb. The hold drops last,
        // after the destroy it was kept alive past.
        drop(bundle.vcpu);
        drop(bundle.vm);
        drop(bundle.hold);
        let mut state = shared.lock();
        // Capped at `adopted`: a fork copy may already have reconciled
        // this bundle as lost (see `ensure_workers`) before a restored
        // worker finished closing it here.
        if state.destroyed < state.adopted {
            state.destroyed = state.destroyed.saturating_add(1);
        }
        shared.idle.notify_all();
    }
}

/// Spawns up to [`TEARDOWN_WORKERS`] workers for `shared`, detaching
/// them: a worker stops on its own once no handle remains and the queue
/// is empty, so nothing needs their join handles. Returns how many
/// spawned and the first spawn error, if any.
fn spawn_workers(shared: &Arc<Shared>) -> (usize, Option<std::io::Error>) {
    let mut spawned = 0;
    let mut first_error = None;
    for _ in 0..TEARDOWN_WORKERS {
        match crate::failure::spawn_owned(
            crate::supervisor_thread::builder().name("reverie-kvm-vm-teardown".into()),
            shared.clone(),
            teardown_worker,
        ) {
            Ok(_handle) => spawned += 1,
            Err((error, _)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    (spawned, first_error)
}

/// A [`VmTeardownSink`] that closes adopted VM fds on a small pool of
/// dedicated threads (`reverie-kvm-vm-teardown`).
///
/// This suits a process that keeps running after a run ends. A process
/// that is about to exit gains less: process exit closes any descriptor
/// the pool has not reached yet, in the exiting process. Such an embedder
/// can implement [`VmTeardownSink`] itself and hand the descriptors to a
/// longer-lived owner.
///
/// A host-fork copy of a process holding a reaper may keep using it:
/// the first adoption or wait in the copy spawns fresh workers there
/// (the template's workers were not copied), and any bundles the queue
/// held at the fork are drained by whichever process reaches them. If
/// no worker can spawn in the copy, its adoptions close inline.
pub struct VmTeardownReaper {
    shared: Arc<Shared>,
}

impl VmTeardownReaper {
    /// Spawns the teardown worker threads.
    pub fn new() -> Result<Self> {
        let shared = Arc::new(Shared::default());
        {
            let mut state = shared.lock();
            state.handles = 1;
            state.worker_pid = current_pid();
        }
        register_for_atfork(&shared);
        let (spawned, error) = spawn_workers(&shared);
        if let Some(error) = error {
            // Construction is all-or-nothing. No handle escapes, so any
            // workers that did spawn stop once they see no handle and an
            // empty queue.
            {
                let mut state = shared.lock();
                state.handles = 0;
                state.workers_failed = spawned == 0;
            }
            shared.work.notify_all();
            return Err(Error::from(error).cleanup("VM teardown worker spawn"));
        }
        Ok(Self { shared })
    }

    /// Whether workers are running in this process, spawning them first
    /// if this is a host-fork copy whose template's workers were not
    /// copied. A partial pool still counts: one worker drains the queue.
    fn ensure_workers(&self) -> bool {
        let pid = current_pid();
        let mut state = self.shared.lock();
        if state.worker_pid == pid {
            return !state.workers_failed;
        }
        // A thread-restoring host fork (raw clone, no atfork handlers)
        // resumes the recorded workers in this process; they just have
        // not looped since the restore to re-stamp `worker_pid`. Wake
        // them and briefly give one the chance, so this does not spawn
        // a second pool draining the same queue alongside the restored
        // one. The grace is paid once, on first use in a copy whose
        // workers really are gone (plain fork): there the stamp never
        // arrives and the spawn below follows.
        self.shared.work.notify_all();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(2);
        while state.worker_pid != pid {
            let Some(remaining) = deadline.checked_duration_since(std::time::Instant::now()) else {
                break;
            };
            let (guard, _timed_out) = self
                .shared
                .idle
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
        }
        if state.worker_pid == pid {
            return !state.workers_failed;
        }
        // First use in a forked copy (or, if a reaper was somehow made
        // without `new`, in any process): the recorded workers belong
        // to the other process. The queue and counts carry over as-is.
        // The state lock is held across the spawn so concurrent first
        // uses in the copy serialize on this one attempt; the new
        // workers simply block on the lock until it is released.
        //
        // Reconcile bundles a template worker had already popped at
        // the fork: that thread was not copied, so nobody here will
        // close them or count them destroyed, and waiting for them
        // would hang. Their descriptor copies in this process close
        // at its exit at the latest (and the template's own workers
        // close the template's copies), so counting them destroyed
        // here keeps this copy's waits truthful about its own work.
        let lost = state
            .adopted
            .saturating_sub(state.destroyed)
            .saturating_sub(state.queue.len() as u64);
        state.destroyed = state.destroyed.saturating_add(lost);
        state.worker_pid = pid;
        state.workers_failed = false;
        let (spawned, _error) = spawn_workers(&self.shared);
        if spawned == 0 {
            state.workers_failed = true;
            return false;
        }
        true
    }

    /// Blocks until every bundle adopted so far has been destroyed.
    /// Bundles adopted concurrently with the wait may or may not be
    /// included; callers that need a quiescent point stop adopting first
    /// (a finished run has no backend left to drop).
    ///
    /// In a process where no worker can run, this drains the queue on
    /// the calling thread instead of waiting for workers that are not
    /// there.
    pub fn wait_idle(&self) {
        if !self.ensure_workers() {
            loop {
                let bundle = {
                    let mut state = self.shared.lock();
                    match state.queue.pop_front() {
                        Some(bundle) => bundle,
                        None => {
                            assert_eq!(
                                state.adopted, state.destroyed,
                                "VM teardown queue empty with undestroyed bundles"
                            );
                            return;
                        }
                    }
                };
                drop(bundle.vcpu);
                drop(bundle.vm);
                let mut state = self.shared.lock();
                state.destroyed = state.destroyed.saturating_add(1);
            }
        }
        let mut state = self.shared.lock();
        while !(state.queue.is_empty() && state.adopted == state.destroyed) {
            state = self.shared.wait(&self.shared.idle, state);
        }
    }

    /// Bundles adopted and destroyed so far. Equal counts with an empty
    /// queue (as [`Self::wait_idle`] establishes) prove no adopted VM is
    /// still alive.
    pub fn counts(&self) -> (u64, u64) {
        let state = self.shared.lock();
        (state.adopted, state.destroyed)
    }
}

impl Clone for VmTeardownReaper {
    fn clone(&self) -> Self {
        let mut state = self.shared.lock();
        state.handles = state.handles.saturating_add(1);
        drop(state);
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for VmTeardownReaper {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.handles = state.handles.saturating_sub(1);
        self.shared.work.notify_all();
    }
}

impl VmTeardownReaper {
    fn adopt_bundle(&self, bundle: Bundle) {
        if !self.ensure_workers() {
            // No worker can run in this process (spawn refused, e.g. in
            // a host-fork copy): close inline, in the sink's order, and
            // count the bundle so `counts` and `wait_idle` stay truthful.
            drop(bundle.vcpu);
            drop(bundle.vm);
            drop(bundle.hold);
            let mut state = self.shared.lock();
            state.adopted = state.adopted.saturating_add(1);
            state.destroyed = state.destroyed.saturating_add(1);
            self.shared.idle.notify_all();
            return;
        }
        // Kept outside the queue until space is certain, so the wait for
        // space cannot lose the bundle.
        let mut bundle = Some(bundle);
        let mut state = self.shared.lock();
        while state.queue.len() >= MAX_QUEUED_BUNDLES {
            state = self.shared.wait(&self.shared.space, state);
        }
        state
            .queue
            .push_back(bundle.take().expect("bundle taken before adoption"));
        state.adopted = state.adopted.saturating_add(1);
        self.shared.work.notify_one();
    }
}

impl VmTeardownSink for VmTeardownReaper {
    fn adopt_vm(&self, vcpu: OwnedFd, vm: OwnedFd) {
        self.adopt_bundle(Bundle {
            vcpu,
            vm,
            hold: None,
        });
    }

    fn adopt_vm_with_hold(&self, vcpu: OwnedFd, vm: OwnedFd, hold: Box<dyn std::any::Any + Send>) {
        self.adopt_bundle(Bundle {
            vcpu,
            vm,
            hold: Some(hold),
        });
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, reason = "tests may make threads freely")]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;

    /// A pipe whose read end reports EOF once both adopted write ends —
    /// standing in for a vCPU fd and a VM fd — have been closed.
    fn pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` is a valid two-element array for pipe2 to fill.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: pipe2 just created both descriptors for this call.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn is_eof(fd: &OwnedFd) -> bool {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: `poll` is one valid pollfd for the duration of the call.
        let ready = unsafe { libc::poll(&mut poll, 1, 0) };
        ready == 1 && poll.revents & libc::POLLHUP != 0
    }

    /// `is_eof` with a deadline, for positive checks: a parallel test
    /// between fork and exec transiently holds a duplicate of every
    /// pipe write end in this process, so EOF can lag the closes these
    /// tests own by that exec window. A genuinely leaked duplicate
    /// still fails, at the deadline.
    fn wait_eof(fd: &OwnedFd) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = deadline
                .saturating_duration_since(std::time::Instant::now())
                .as_millis();
            // SAFETY: `poll` is one valid pollfd for the duration of the call.
            let ready =
                unsafe { libc::poll(&mut poll, 1, i32::try_from(timeout).unwrap_or(i32::MAX)) };
            if ready == 1 && poll.revents & libc::POLLHUP != 0 {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
        }
    }

    #[test]
    fn adopted_descriptors_are_closed_by_wait_idle() {
        let reaper = VmTeardownReaper::new().expect("spawn teardown workers");
        let (read_a, write_a) = pipe();
        let (read_b, write_b) = pipe();
        assert!(!is_eof(&read_a));
        reaper.adopt_vm(write_a, write_b);
        reaper.wait_idle();
        assert_eq!(reaper.counts(), (1, 1));
        assert!(wait_eof(&read_a), "vcpu stand-in still open");
        assert!(wait_eof(&read_b), "vm stand-in still open");
    }

    /// The hold is dropped with the bundle's destroy: by the time the
    /// reaper reports idle, a hold given at adoption is gone.
    #[test]
    fn hold_drops_with_the_destroy() {
        struct Flag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let reaper = VmTeardownReaper::new().expect("spawn teardown workers");
        let (_read_a, write_a) = pipe();
        let (_read_b, write_b) = pipe();
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        reaper.adopt_vm_with_hold(
            write_a,
            write_b,
            Box::new(Flag(std::sync::Arc::clone(&dropped))),
        );
        reaper.wait_idle();
        assert_eq!(reaper.counts(), (1, 1));
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst),
            "hold not dropped after the reaper drained"
        );
    }

    #[test]
    fn more_bundles_than_the_queue_bound_all_complete() {
        let reaper = VmTeardownReaper::new().expect("spawn teardown workers");
        let bundles = (MAX_QUEUED_BUNDLES * 2 + TEARDOWN_WORKERS) as u64;
        let mut readers = Vec::new();
        for _ in 0..bundles {
            let (read_a, write_a) = pipe();
            let (read_b, write_b) = pipe();
            readers.push((read_a, read_b));
            reaper.adopt_vm(write_a, write_b);
        }
        reaper.wait_idle();
        assert_eq!(reaper.counts(), (bundles, bundles));
        for (read_a, read_b) in &readers {
            assert!(wait_eof(read_a) && wait_eof(read_b));
        }
    }

    /// The anon-inode name of one open descriptor, if it is still open.
    fn fd_target(fd: RawFd) -> Option<String> {
        std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .ok()?
            .to_str()
            .map(str::to_owned)
    }

    #[derive(Default)]
    struct RecordingSink {
        bundles: Mutex<Vec<(OwnedFd, OwnedFd)>>,
    }

    impl VmTeardownSink for RecordingSink {
        fn adopt_vm(&self, vcpu: OwnedFd, vm: OwnedFd) {
            self.bundles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((vcpu, vm));
        }
    }

    /// A dropped backend hands the sink live duplicates: the VM stays
    /// open in the sink after the backend is gone, and closing the
    /// sink's copies is what finally removes it. Descriptor numbers are
    /// checked individually so parallel tests creating their own VMs
    /// cannot disturb this one.
    #[test]
    fn backend_drop_defers_vm_close_to_the_sink() {
        let sink = Arc::new(RecordingSink::default());
        {
            let mut backend = crate::KvmBackend::new(16 * 1024 * 1024)
                .expect("the deferred-teardown test requires /dev/kvm");
            backend.set_vm_teardown_sink(Some(sink.clone()));
        }
        let (vcpu_fd, vm_fd) = {
            let bundles = sink
                .bundles
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(bundles.len(), 1);
            (bundles[0].0.as_raw_fd(), bundles[0].1.as_raw_fd())
        };
        // The backend is gone; both adopted descriptors are still open,
        // so no destroy ran on the dropping thread.
        let vcpu_target = fd_target(vcpu_fd).expect("adopted vcpu fd closed early");
        let vm_target = fd_target(vm_fd).expect("adopted vm fd closed early");
        assert!(vcpu_target.contains("kvm"), "vcpu fd target: {vcpu_target}");
        assert!(vm_target.contains("kvm-vm"), "vm fd target: {vm_target}");
        // Closing the adopted copies is the last close: the VM goes away.
        sink.bundles
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        assert!(
            fd_target(vm_fd).is_none_or(|target| !target.contains("kvm-vm")),
            "vm fd still open after the sink closed it"
        );
    }

    /// A host-fork copy holds the reaper's queue and counts but none of
    /// its workers (fork copies only the calling thread). Adoption in
    /// the copy must spawn fresh workers there and close the bundle;
    /// the parent's reaper and counts are untouched.
    #[test]
    fn reaper_restarts_workers_in_forked_child() {
        let reaper = VmTeardownReaper::new().expect("spawn teardown workers");
        let (read_a, write_a) = pipe();
        let (read_b, write_b) = pipe();
        reaper.adopt_vm(write_a, write_b);
        reaper.wait_idle();
        assert_eq!(reaper.counts(), (1, 1));
        assert!(wait_eof(&read_a) && wait_eof(&read_b));

        // Adopted only in the child. The parent closes its copies of the
        // write ends right after the fork, so the child's readers can
        // reach EOF there; the verdict rides on the child's counts,
        // which only move when a worker in the child closed a bundle.
        let (read_c, write_c) = pipe();
        let (read_d, write_d) = pipe();
        let mut write_c = Some(write_c);
        let mut write_d = Some(write_d);
        // SAFETY: the child touches only the reaper and these pipes,
        // then _exits without unwinding into the test harness; alarm
        // bounds a hang (adoption waiting for workers that are not
        // there) as a killed child, which the parent reports.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: alarm and _exit take only integer arguments.
            unsafe { libc::alarm(15) };
            let write_c = write_c.take().expect("child write end");
            let write_d = write_d.take().expect("child write end");
            let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                reaper.adopt_vm(write_c, write_d);
                reaper.wait_idle();
                if reaper.counts() != (2, 2) {
                    return false;
                }
                // EOF also needs the parent's copies closed, which it
                // does right after the fork; poll briefly for that.
                for _ in 0..500 {
                    if is_eof(&read_c) && is_eof(&read_d) {
                        return true;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                false
            }));
            // SAFETY: terminate the child immediately with the verdict.
            unsafe { libc::_exit(if verdict.unwrap_or(false) { 0 } else { 1 }) };
        }
        drop(write_c);
        drop(write_d);
        let mut status = 0;
        // SAFETY: wait for the exact child created above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status),
            "fork child did not exit normally (status {status:#x}); a hang ends in SIGALRM"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "fork child could not restart the reaper workers"
        );
        // The child's adoption was its own copy of the counts.
        assert_eq!(reaper.counts(), (1, 1));
    }

    /// A fork that lands while a worker holds the queue lock must not
    /// leave the child's copy of that lock held forever (the worker
    /// thread was not copied). The hook parks the worker inside the
    /// pop critical section; the atfork prepare handler has to wait
    /// it out before the copy is taken, and the child's first
    /// adoption then has to finish within its alarm bound.
    #[test]
    fn fork_while_worker_holds_queue_lock_does_not_deadlock_child() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering;

        let reaper = VmTeardownReaper::new().expect("spawn teardown workers");
        let entered = Arc::new(AtomicBool::new(false));
        let once = Arc::new(AtomicBool::new(false));
        {
            let entered = Arc::clone(&entered);
            let once = Arc::clone(&once);
            let target = Arc::as_ptr(&reaper.shared) as usize;
            let hook: WorkerPopHook = Arc::new(move |shared| {
                if shared as usize == target && !once.swap(true, Ordering::SeqCst) {
                    entered.store(true, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
            });
            *WORKER_POP_HOOK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
        }
        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                *WORKER_POP_HOOK
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            }
        }
        let _clear = ClearHook;

        // One bundle for a worker to pop and park on, one adopted
        // only in the child (as in the restart test above).
        let (_read_a, write_a) = pipe();
        let (_read_b, write_b) = pipe();
        reaper.adopt_vm(write_a, write_b);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !entered.load(Ordering::SeqCst) {
            assert!(
                std::time::Instant::now() < deadline,
                "worker never entered the pop critical section"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let (read_c, write_c) = pipe();
        let (read_d, write_d) = pipe();
        let mut write_c = Some(write_c);
        let mut write_d = Some(write_d);
        // SAFETY: as in the restart test — the child touches only the
        // reaper and these pipes, then _exits; alarm bounds the hang
        // this test exists to catch (a copied locked queue mutex).
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            // SAFETY: alarm and _exit take only integer arguments.
            unsafe { libc::alarm(15) };
            let write_c = write_c.take().expect("child write end");
            let write_d = write_d.take().expect("child write end");
            let verdict = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                reaper.adopt_vm(write_c, write_d);
                reaper.wait_idle();
                reaper.counts() == (2, 2) && wait_eof(&read_c) && wait_eof(&read_d)
            }));
            // SAFETY: terminate the child immediately with the verdict.
            unsafe { libc::_exit(if verdict.unwrap_or(false) { 0 } else { 1 }) };
        }
        drop(write_c);
        drop(write_d);
        let mut status = 0;
        // SAFETY: wait for the exact child created above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status),
            "fork child did not exit normally (status {status:#x}); a hang ends in SIGALRM"
        );
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "fork child's first adoption deadlocked or failed"
        );
        // The parent's own reaper is unaffected and drains normally.
        reaper.wait_idle();
        assert_eq!(reaper.counts(), (1, 1));
    }

    /// The thread reaper as the installed sink: once it reports idle,
    /// its destroyed count proves both closes completed.
    #[test]
    fn backend_drop_with_thread_reaper_leaves_no_vm() {
        let reaper = VmTeardownReaper::new().expect("spawn teardown workers");
        {
            let mut backend = crate::KvmBackend::new(16 * 1024 * 1024)
                .expect("the deferred-teardown test requires /dev/kvm");
            backend.set_vm_teardown_sink(Some(Arc::new(reaper.clone())));
        }
        reaper.wait_idle();
        assert_eq!(reaper.counts(), (1, 1));
    }
}
