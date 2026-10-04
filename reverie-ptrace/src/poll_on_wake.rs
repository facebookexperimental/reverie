/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Poll a rarely ready future again only after its own waker has fired.
//!
//! `futures::select_biased!`, `tokio::select!` and hand-written `poll_fn`
//! loops poll every pending branch each time the enclosing task resumes. The
//! tracer task resumes at least once per ptrace stop, while a watcher such as
//! session cancellation or a Tool failure signal completes at most once per
//! task. A [`WakeGate`] skips the polls in between. It polls its inner future
//! only on the first poll, after a waker that the inner future registered has
//! fired, or after its owner re-arms it.
//!
//! This relies only on the `Future` contract: an inner future that returns
//! `Pending` has arranged for the waker it was given to be woken once it can
//! make progress. tokio `Notify` (including `notify_waiters`), tokio I/O
//! readiness and its cooperative budget, `futures::future::Shared` and
//! oneshot channels all honor it. A future that returns `Pending` without
//! arranging a wake is never polled again by this gate.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Wake;
use std::task::Waker;

use futures::task::AtomicWaker;

struct WakeFlag {
    /// Set by every wake of the gate's waker and by [`WakeGate::rearm`];
    /// cleared just before the inner future is polled.
    woken: AtomicBool,
    /// The waker of the task that last polled through the gate.
    parent: AtomicWaker,
}

impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // Publish the flag before waking the parent, so the parent's next poll
        // observes it.
        self.woken.store(true, Ordering::Release);
        self.parent.wake();
    }
}

/// Polls one inner poll function only when it can have made progress: on the
/// first poll, after the waker it was polled with fired, or after
/// [`WakeGate::rearm`]. Every other poll returns `Pending` without calling it.
pub(crate) struct WakeGate {
    flag: Arc<WakeFlag>,
    /// The waker handed to the inner poll function, built once from `flag`.
    waker: Waker,
}

impl WakeGate {
    /// A gate whose first poll always reaches the inner poll function.
    pub(crate) fn new() -> Self {
        let flag = Arc::new(WakeFlag {
            woken: AtomicBool::new(true),
            parent: AtomicWaker::new(),
        });
        let waker = Waker::from(flag.clone());
        Self { flag, waker }
    }

    /// Calls `poll` with the gate's own waker if the gate was woken or re-armed
    /// since the last call; otherwise returns `Pending`. Either way, a later
    /// wake of the gate's waker wakes `cx`.
    pub(crate) fn poll_with<T>(
        &self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(&mut Context<'_>) -> Poll<T>,
    ) -> Poll<T> {
        // Register before consuming the flag: a wake that sets the flag after
        // the swap below then finds this parent registered and wakes it.
        self.flag.parent.register(cx.waker());
        if !self.flag.woken.swap(false, Ordering::AcqRel) {
            return Poll::Pending;
        }
        poll(&mut Context::from_waker(&self.waker))
    }

    /// Makes the next [`WakeGate::poll_with`] call the inner poll function even
    /// though no waker fired. For an owner that already knows more work is
    /// available, such as a drain that just read a full buffer.
    pub(crate) fn rearm(&self) {
        self.flag.woken.store(true, Ordering::Release);
    }
}

/// A future polled through a [`WakeGate`]. For watcher futures in a select
/// that complete rarely: the select order is unchanged, and a watcher whose
/// waker fired is polled at its usual place in that order.
pub(crate) struct PollOnWake<F> {
    inner: F,
    gate: WakeGate,
}

impl<F: Future + Unpin> PollOnWake<F> {
    pub(crate) fn new(inner: F) -> Self {
        Self {
            inner,
            gate: WakeGate::new(),
        }
    }
}

impl<F: Future + Unpin> Future for PollOnWake<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        this.gate.poll_with(cx, |cx| Pin::new(inner).poll(cx))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    /// Counts wakes of the parent task.
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn parent() -> (Arc<CountWake>, Waker) {
        let count = Arc::new(CountWake(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        (count, waker)
    }

    /// A watcher that counts its polls, keeps the last waker it was given, and
    /// completes once `ready` is set.
    #[derive(Clone, Default)]
    struct Probe {
        polls: Rc<Cell<usize>>,
        ready: Rc<Cell<bool>>,
        waker: Rc<RefCell<Option<Waker>>>,
        /// Wake the supplied waker before returning `Pending`, as a tokio
        /// resource does when its cooperative budget is exhausted.
        self_wake: Rc<Cell<bool>>,
    }

    impl Future for Probe {
        type Output = ();

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            self.polls.set(self.polls.get() + 1);
            if self.ready.get() {
                return Poll::Ready(());
            }
            *self.waker.borrow_mut() = Some(cx.waker().clone());
            if self.self_wake.replace(false) {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    }

    impl Probe {
        fn fire(&self) {
            self.ready.set(true);
            self.waker
                .borrow_mut()
                .take()
                .expect("a pending probe registered a waker")
                .wake();
        }
    }

    #[test]
    fn first_poll_reaches_an_already_ready_future() {
        let probe = Probe::default();
        probe.ready.set(true);
        let (_count, waker) = parent();
        let mut cx = Context::from_waker(&waker);
        let mut gated = PollOnWake::new(probe.clone());
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Ready(()));
        assert_eq!(probe.polls.get(), 1);
    }

    #[test]
    fn repolls_without_a_wake_skip_the_inner_future() {
        let probe = Probe::default();
        let (count, waker) = parent();
        let mut cx = Context::from_waker(&waker);
        let mut gated = PollOnWake::new(probe.clone());
        for _ in 0..5 {
            assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Pending);
        }
        assert_eq!(probe.polls.get(), 1);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_inner_wake_wakes_the_parent_and_reaches_the_inner_future() {
        let probe = Probe::default();
        let (count, waker) = parent();
        let mut cx = Context::from_waker(&waker);
        let mut gated = PollOnWake::new(probe.clone());
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Pending);
        probe.fire();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Ready(()));
        assert_eq!(probe.polls.get(), 2);
    }

    #[test]
    fn a_wake_during_the_inner_poll_is_not_lost() {
        let probe = Probe::default();
        probe.self_wake.set(true);
        let (count, waker) = parent();
        let mut cx = Context::from_waker(&waker);
        let mut gated = PollOnWake::new(probe.clone());
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Pending);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Pending);
        assert_eq!(probe.polls.get(), 2);
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Pending);
        assert_eq!(probe.polls.get(), 2);
    }

    #[test]
    fn the_latest_parent_is_the_one_woken() {
        let probe = Probe::default();
        let (first, first_waker) = parent();
        let (second, second_waker) = parent();
        let mut gated = PollOnWake::new(probe.clone());
        let mut cx = Context::from_waker(&first_waker);
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Pending);
        let mut cx = Context::from_waker(&second_waker);
        assert_eq!(Pin::new(&mut gated).poll(&mut cx), Poll::Pending);
        probe.fire();
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(second.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rearm_reaches_the_inner_poll_without_a_wake() {
        let gate = WakeGate::new();
        let (count, waker) = parent();
        let mut cx = Context::from_waker(&waker);
        let calls = Cell::new(0);
        let mut poll = || {
            gate.poll_with(&mut cx, |_| {
                calls.set(calls.get() + 1);
                Poll::<()>::Pending
            })
        };
        assert_eq!(poll(), Poll::Pending);
        assert_eq!(poll(), Poll::Pending);
        assert_eq!(calls.get(), 1);
        gate.rearm();
        assert_eq!(poll(), Poll::Pending);
        assert_eq!(calls.get(), 2);
        assert_eq!(poll(), Poll::Pending);
        assert_eq!(calls.get(), 2);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    }
}
