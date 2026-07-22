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
//!  2. Using `pidfd_open(2)` to receive events over file descriptors would be
//!     great, but `ptrace` events are not receivable with `pidfd`. This might
//!     change in the future, but there is currently no motivation among Linux
//!     devs to implement support for that. (Folks hate the complexity of ptrace
//!     and are fearful of introducing new security vulnerabilities.)
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
use std::collections::hash_map::Entry;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::RawWakerVTable;
use std::task::Waker;
use std::thread;
use std::thread::JoinHandle;

use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;
use parking_lot::Mutex;

use super::Errno;
use super::Error;
use super::Pid;
use super::Running;
use super::Stopped;
use super::Wait;
use super::waitid;

static NOTIFIER: LazyLock<Notifier> = LazyLock::new(Notifier::new);

/// A place-holder status used to indicate that no status has been set.
const INVALID_STATUS: i32 = -1;

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

#[derive(Debug)]
struct Event {
    /// Waker for exit events.
    exit_waker: WakerSlot,

    /// Waker for regular status events.
    status_waker: WakerSlot,

    /// The raw status. A status of `-1` indicates that no status has been set
    /// yet.
    status: AtomicI32,
}

impl Event {
    pub fn new() -> Self {
        Self {
            exit_waker: WakerSlot::default(),
            status_waker: WakerSlot::default(),
            status: AtomicI32::new(INVALID_STATUS),
        }
    }

    /// Replaces the status and notifies the notifier of the change. Returns the
    /// old status if there was one.
    pub fn update(&self, status: i32) -> Option<i32> {
        let previous = self.status.swap(status, Ordering::SeqCst);

        if status == PTRACE_EVENT_EXIT_STOP {
            self.exit_waker.wake();
        } else {
            self.status_waker.wake();
        }

        if previous == INVALID_STATUS {
            None
        } else {
            Some(previous)
        }
    }

    /// Polls the event to check if there is a new status ready to be consumed.
    pub fn poll_status(&self, waker: &Waker) -> Poll<i32> {
        // Register the waker *before* checking the status to avoid a race condition.
        self.status_waker.register(waker);

        // Only modify the status if we're *not* in a PTRACE_EVENT_EXIT stop.
        // TODO: Think really hard and relax the ordering.
        let status = self
            .status
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |prev| {
                if prev == INVALID_STATUS || prev == PTRACE_EVENT_EXIT_STOP {
                    // Don't update if we're exiting or if there is no status to
                    // be consumed.
                    None
                } else {
                    // Reset the value to indicate it has been consumed.
                    Some(INVALID_STATUS)
                }
            });

        match status {
            Ok(status) => Poll::Ready(status),
            Err(_) => {
                // There is either no status available or the guest is exiting.
                Poll::Pending
            }
        }
    }

    /// Polls the event to check if there is a new status ready to be consumed.
    pub fn poll_exit(&self, waker: &Waker) -> Poll<()> {
        // Register the waker *before* checking the status to avoid a race condition.
        self.exit_waker.register(waker);

        // Only reset the status if we're in a PTRACE_EVENT_EXIT.
        // TODO: Think really hard and relax the ordering.
        let status = self.status.compare_exchange(
            PTRACE_EVENT_EXIT_STOP,
            INVALID_STATUS,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );

        match status {
            Ok(_) => Poll::Ready(()),
            Err(_) => Poll::Pending,
        }
    }
}

fn spawn_worker(pid: Pid, event: Arc<Event>) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("guest-{}", pid))
        .spawn(move || worker_thread(pid, event))
        .expect("failed to spawn thread")
}

/// Waits on a process and returns the raw status. Returns `None` if the process
/// does not exist.
fn wait(pid: Pid) -> Option<i32> {
    loop {
        let result = waitid::waitpid(pid.into(), WaitPidFlag::WEXITED | WaitPidFlag::WSTOPPED);

        return match result {
            Ok(status) => Some(status.unwrap()),
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => None,
            Err(err) => {
                // No other errors should be possible because we handled EINTR
                // and ECHILD. EINVAL only happens when using the API
                // incorrectly.
                panic!("waitid::waitpid({}) failed unexpectedly: {}", pid, err)
            }
        };
    }
}

/// A worker thread that simply wakes a future when a process changes state.
fn worker_thread(pid: Pid, event: Arc<Event>) {
    while let Some(status) = wait(pid) {
        if let Some(old_status) = event.update(status) {
            if status != PTRACE_EVENT_EXIT_STOP && !libc::WIFEXITED(status) {
                panic!(
                    "Got unexpected event: Event {:?} replaced {:?}",
                    WaitStatus::from_raw(pid.into(), status),
                    WaitStatus::from_raw(pid.into(), old_status),
                );
            }
        }

        // Try to avoid reaching an ECHILD error by terminating the loop on the
        // last event.
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            break;
        }
    }
}

struct Notifier {
    /// Mapping of pids to wakers.
    pids: Mutex<HashMap<Pid, Arc<Event>>>,
}

impl Notifier {
    /// Creates the notifier.
    pub fn new() -> Self {
        let pids = Mutex::new(HashMap::new());
        Notifier { pids }
    }

    /// Gets the event state for a PID, creating its notifier thread if needed.
    fn event(&self, pid: Pid) -> Arc<Event> {
        // Check if there is a worker thread associated with this PID and create
        // one if there isn't.
        let mut pids = self.pids.lock();
        match pids.entry(pid) {
            Entry::Occupied(occupied) => Arc::clone(occupied.get()),
            Entry::Vacant(vacant) => {
                let event = Arc::new(Event::new());
                vacant.insert(event.clone());
                spawn_worker(pid, Arc::clone(&event));
                event
            }
        }
    }

    /// Removes a completed PID without disturbing a reused PID's event.
    fn remove(&self, pid: Pid, event: &Arc<Event>) {
        let mut pids = self.pids.lock();
        if pids
            .get(&pid)
            .is_some_and(|current| Arc::ptr_eq(current, event))
        {
            pids.remove(&pid);
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

/// A future representing a process state change.
pub struct WaitFuture {
    running: Running,
    event: Option<Arc<Event>>,
}

impl WaitFuture {
    pub(super) fn new(running: Running) -> Self {
        Self {
            running,
            event: None,
        }
    }
}

impl Future for WaitFuture {
    type Output = Result<Wait, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let pid = this.running.pid();
        let event = this.event.get_or_insert_with(|| NOTIFIER.event(pid));
        let status = futures::ready!(event.poll_status(cx.waker()));

        // This should be the last event. Remove the PID so a future reuse can
        // create a fresh notifier thread.
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            NOTIFIER.remove(pid, event);
        }

        Poll::Ready(Wait::from_raw(pid, status))
    }
}

/// A future representing PTRACE_EVENT_EXIT. The future resolves when the process
/// receives a PTRACE_EVENT_EXIT. A process can receive this event at any time,
/// even when in another ptrace stop state.
///
/// The next state after this should be the final exit status.
pub struct ExitFuture {
    pid: Pid,
    event: Option<Arc<Event>>,
}

impl ExitFuture {
    pub(super) fn new(pid: Pid) -> Self {
        Self { pid, event: None }
    }
}

impl Future for ExitFuture {
    type Output = Stopped;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();
        let event = this.event.get_or_insert_with(|| NOTIFIER.event(this.pid));
        futures::ready!(event.poll_exit(cx.waker()));
        Poll::Ready(Stopped::new_unchecked(this.pid))
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::Pid;

    use super::*;

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
        assert_eq!(event.poll_status(&waker), Poll::Ready(stopped));
        assert!(!event.status_waker.register(&waker));
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
}
