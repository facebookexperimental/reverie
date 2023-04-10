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
//! approach also avoids the overhead of `tokio::task::spawn_blocking` by not
//! locking a `Mutex` each time an event is received. (An `AtomicI32` plus an
//! `AtomicWaker` can be used instead.) The downside of this approach is that we
//! can end up spawning a lot of guest threads.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;
use std::thread;
use std::thread::JoinHandle;

use futures::task::AtomicWaker;
use lazy_static::lazy_static;
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::WaitStatus;
use parking_lot::Mutex;

use super::waitid;
use super::Errno;
use super::Error;
use super::Pid;
use super::Running;
use super::Stopped;
use super::Wait;

lazy_static! {
    static ref NOTIFIER: Notifier = Notifier::new();
}

/// A place-holder status used to indicate that no status has been set.
const INVALID_STATUS: i32 = -1;

/// The number we get when in a PTRACE_EVENT_EXIT stop.
const PTRACE_EVENT_EXIT_STOP: i32 = (libc::PTRACE_EVENT_EXIT << 16) | (libc::SIGTRAP << 8) | 0x7f;

#[derive(Debug)]
struct Event {
    /// Waker for exit events.
    exit_waker: AtomicWaker,

    /// Waker for regular status events.
    status_waker: AtomicWaker,

    /// The raw status. A status of `-1` indicates that no status has been set
    /// yet.
    status: AtomicI32,
}

impl Event {
    pub fn new() -> Self {
        Self {
            exit_waker: AtomicWaker::new(),
            status_waker: AtomicWaker::new(),
            status: AtomicI32::new(INVALID_STATUS),
        }
    }

    pub fn from_exit_waker(waker: &Waker) -> Self {
        let me = Self::new();
        me.exit_waker.register(waker);
        me
    }

    pub fn from_status_waker(waker: &Waker) -> Self {
        let me = Self::new();
        me.status_waker.register(waker);
        me
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

    /// Polls for a state change on the given PID.
    pub fn poll_status(&self, pid: Pid, cx: &mut Context) -> Poll<Result<Wait, Error>> {
        // Check if there is a worker thread associated with this PID and create
        // one if there isn't.
        let mut pids = self.pids.lock();
        match pids.entry(pid) {
            Entry::Occupied(mut occupied) => {
                let status = futures::ready!(occupied.get_mut().poll_status(cx.waker()));

                // This should be the last event. We need to remove the PID from
                // the map so the thread can be spawned again if the PID is ever
                // reused.
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    occupied.remove();
                }

                Poll::Ready(Wait::from_raw(pid, status))
            }
            Entry::Vacant(vacant) => {
                // No thread exists for this yet. Create it.
                // TODO: A potential optimization here is that we could call
                // `try_wait` instead of spawning a new thread.
                let event = Arc::new(Event::from_status_waker(cx.waker()));
                vacant.insert(event.clone());
                spawn_worker(pid, event);
                Poll::Pending
            }
        }
    }

    /// Polls for an exit event on the given PID.
    pub fn poll_exit(&self, pid: Pid, cx: &mut Context) -> Poll<Stopped> {
        let mut pids = self.pids.lock();
        match pids.entry(pid) {
            Entry::Occupied(mut occupied) => {
                futures::ready!(occupied.get_mut().poll_exit(cx.waker()));
                Poll::Ready(Stopped::new_unchecked(pid))
            }
            Entry::Vacant(vacant) => {
                // No thread exists for this yet. Create it.
                let event = Arc::new(Event::from_exit_waker(cx.waker()));
                vacant.insert(event.clone());
                spawn_worker(pid, event);
                Poll::Pending
            }
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
pub struct WaitFuture(pub(super) Running);

impl Future for WaitFuture {
    type Output = Result<Wait, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        NOTIFIER.poll_status(self.0.pid(), cx)
    }
}

/// A future representing PTRACE_EVENT_EXIT. The future resolves when the process
/// receives a PTRACE_EVENT_EXIT. A process can receive this event at any time,
/// even when in another ptrace stop state.
///
/// The next state after this should be the final exit status.
pub struct ExitFuture(pub(super) Pid);

impl Future for ExitFuture {
    type Output = Stopped;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        NOTIFIER.poll_exit(self.0, cx)
    }
}

#[cfg(test)]
mod test {
    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::Pid;

    use super::*;

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
