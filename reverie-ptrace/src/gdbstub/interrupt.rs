/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! gdb's interrupt: the byte 0x03 that gdb sends while the guest runs, for
//! Ctrl-C or its `interrupt` command, asking the stub to stop the guest and
//! report a stop ("Interrupts" in the gdb remote protocol).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::Pid;
use tokio::sync::Notify;

/// gdb's request to stop the running guest, shared by the session, which arms
/// it while gdb waits for a stop, the packet relay, which raises it when the
/// interrupt byte arrives, and every traced thread, the first of which to
/// reach a point where it can stop takes it.
///
/// A thread takes it at a stop it makes anyway: at its next ptrace stop, as
/// it enters or leaves a Tool callback, or, when no thread is running, where
/// it waits inside a callback (`allow_in_place`). Only a thread whose stop the
/// session waits for may take it (`wait_for`). The thread that took it
/// reports a SIGINT stop and waits for gdb; in a guest the Tool runs one
/// thread at a time, the others hold at their next such point
/// ([`is_taken`](Self::is_taken)) until gdb resumes the guest.
#[derive(Clone, Debug, Default)]
pub struct Interrupt(Arc<Inner>);

#[derive(Debug, Default)]
struct Inner {
    state: AtomicU8,
    /// The command, numbered from 1 in the order gdb sent the commands, whose
    /// stop the session waits for.
    armed_command: AtomicU64,
    /// The number of the last command gdb sent before its latest interrupt
    /// byte. The relay sees the byte as soon as it arrives, and may see it
    /// before the session has taken the resume that the byte follows; the
    /// byte then applies when the session arms for that resume.
    interrupted_after: AtomicU64,
    /// Whether a thread waiting inside a Tool callback may take the interrupt
    /// where it waits: no thread was running to take it at its next stop.
    in_place: AtomicBool,
    /// The threads whose stops the session waits for, the only ones that
    /// may take the interrupt: the stop of any other would reach no one.
    waiting: Mutex<HashSet<Pid>>,
    /// The threads the session sent SIGSTOP to, to make them stop for the
    /// interrupt (`kick`).
    kicked: Mutex<HashSet<Pid>>,
    /// The Tool runs one thread at a time (`GdbServer::sequentialized_guest`).
    sequentialized: AtomicBool,
    changed: Notify,
}

/// gdb holds the guest stopped: no resume is outstanding.
const IDLE: u8 = 0;
/// gdb waits for a stop: a resume is outstanding.
const ARMED: u8 = 1;
/// gdb asked for a stop that no thread has taken yet.
const REQUESTED: u8 = 2;
/// A thread took the request; it is stopped for gdb until gdb resumes it.
const TAKEN: u8 = 3;

impl Interrupt {
    fn state(&self) -> u8 {
        self.0.state.load(Ordering::SeqCst)
    }

    fn transition(&self, from: u8, to: u8) -> bool {
        self.0
            .state
            .compare_exchange(from, to, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn changed(&self) {
        self.0.changed.notify_waiters();
    }

    /// The session resumes the guest for command number `command` and waits
    /// for its stop: an interrupt may now come, and one gdb sent after that
    /// command has. A request still taken, by a thread whose stop gdb has yet
    /// to see or resume, stays taken until that thread is resumed.
    pub fn arm(&self, command: u64) {
        self.0.in_place.store(false, Ordering::SeqCst);
        self.0.armed_command.store(command, Ordering::SeqCst);
        self.arm_from(IDLE);
    }

    /// Arms from state `from`, raising the request at once if gdb sent its
    /// interrupt after the command armed for.
    fn arm_from(&self, from: u8) -> bool {
        if !self.transition(from, ARMED) {
            return false;
        }
        if self.0.interrupted_after.load(Ordering::SeqCst)
            >= self.0.armed_command.load(Ordering::SeqCst)
            && self.transition(ARMED, REQUESTED)
        {
            self.changed();
        }
        true
    }

    /// The session has a stop for gdb: a request no thread took is dropped,
    /// as the stop answers it. A request taken stays taken until its thread
    /// is resumed (`release`).
    pub fn disarm(&self) {
        if self.transition(REQUESTED, IDLE) {
            self.changed();
        } else {
            self.transition(ARMED, IDLE);
        }
        // The next resume's threads are published when the session waits
        // for them; until then no thread may take a request.
        self.lock(&self.0.waiting).clear();
    }

    fn lock<'a>(&self, set: &'a Mutex<HashSet<Pid>>) -> std::sync::MutexGuard<'a, HashSet<Pid>> {
        set.lock()
            .expect("should not be poisoned: no code panics while holding it")
    }

    /// The session waits for the stops of threads `tids`.
    pub fn wait_for(&self, tids: impl IntoIterator<Item = Pid>) {
        *self.lock(&self.0.waiting) = tids.into_iter().collect();
        self.changed();
    }

    /// The Tool runs one thread at a time: a thread that waits inside a
    /// callback may stop there, and the others hold while one is stopped.
    pub fn set_sequentialized(&self) {
        self.0.sequentialized.store(true, Ordering::SeqCst);
    }

    pub fn sequentialized(&self) -> bool {
        self.0.sequentialized.load(Ordering::SeqCst)
    }

    /// Records that the session sent thread `tid` SIGSTOP, to make it stop
    /// for the pending request.
    pub fn kick(&self, tid: Pid) {
        self.lock(&self.0.kicked).insert(tid);
    }

    /// Whether thread `tid`'s SIGSTOP stop is the session's `kick`, which
    /// the thread then consumes.
    pub fn take_kick(&self, tid: Pid) -> bool {
        self.lock(&self.0.kicked).remove(&tid)
    }

    /// gdb sent the interrupt byte after command number `after`. It applies
    /// to that command's resume, now or once the session arms for it, and is
    /// ignored if it came while gdb held the guest stopped, or while an
    /// earlier request is pending. Returns whether it raised a request now.
    pub fn request(&self, after: u64) -> bool {
        self.0.interrupted_after.fetch_max(after, Ordering::SeqCst);
        let requested = self.0.armed_command.load(Ordering::SeqCst) <= after
            && self.transition(ARMED, REQUESTED);
        if requested {
            self.changed();
        }
        requested
    }

    /// Whether a request waits for a thread to take it.
    pub fn is_requested(&self) -> bool {
        self.state() == REQUESTED
    }

    /// Lets a thread that waits inside a Tool callback take the pending
    /// request where it waits. The session allows it when no thread runs.
    pub fn allow_in_place(&self) {
        if self.is_requested() && !self.0.in_place.swap(true, Ordering::SeqCst) {
            self.changed();
        }
    }

    /// Takes the pending request for thread `tid`, returning whether it is
    /// the one thread that stops for it.
    pub fn take(&self, tid: Pid) -> bool {
        if !self.is_requested() || !self.lock(&self.0.waiting).contains(&tid) {
            return false;
        }
        let taken = self.transition(REQUESTED, TAKEN);
        if taken {
            // The bytes gdb has sent so far are answered by this stop.
            let answered = self.0.interrupted_after.load(Ordering::SeqCst) + 1;
            self.0.armed_command.fetch_max(answered, Ordering::SeqCst);
            self.changed();
        }
        taken
    }

    /// Whether a thread took a request and has not been resumed from its stop.
    pub fn is_taken(&self) -> bool {
        self.state() == TAKEN
    }

    /// The thread that took the request was resumed by gdb: the guest runs
    /// again, and the threads holding for it go on.
    pub fn release(&self) {
        if self.arm_from(TAKEN) {
            self.changed();
        }
    }

    /// Waits until `ready` holds. A change made between the check and the wait
    /// is not missed: the waiter is registered before the check.
    async fn until(&self, ready: impl Fn(&Self) -> bool) {
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if ready(self) {
                return;
            }
            changed.await;
        }
    }

    /// Waits for a request that a thread waiting inside a Tool callback may
    /// take where it waits.
    pub async fn requested_in_place(&self) {
        self.until(|interrupt| {
            interrupt.is_requested() && interrupt.0.in_place.load(Ordering::SeqCst)
        })
        .await
    }

    /// Waits for a request that thread `tid` may take where it waits: the
    /// request is pending, in-place taking is allowed, and the session
    /// waits for `tid`'s stop. A thread the session does not wait for never
    /// resolves this, so polling it cannot spin on a ready future.
    pub async fn requested_in_place_for(&self, tid: Pid) {
        self.until(|interrupt| {
            interrupt.is_requested()
                && interrupt.0.in_place.load(Ordering::SeqCst)
                && interrupt.lock(&interrupt.0.waiting).contains(&tid)
        })
        .await
    }

    /// Waits for a request that no thread has taken.
    pub async fn requested(&self) {
        self.until(Self::is_requested).await
    }

    /// Waits until the pending request is taken or answered.
    pub async fn settled(&self) {
        self.until(|interrupt| !interrupt.is_requested()).await
    }

    /// Waits until no thread is stopped for a request.
    pub async fn released(&self) {
        self.until(|interrupt| !interrupt.is_taken()).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::FutureExt;

    use super::*;

    /// The thread the tests' session waits for.
    fn t() -> Pid {
        Pid::from_raw(7)
    }

    /// Arms `interrupt` for command `command`, whose stop the session waits
    /// for from thread `t()`.
    fn rearm(interrupt: &Interrupt, command: u64) {
        interrupt.arm(command);
        interrupt.wait_for([t()]);
    }

    /// An interrupt whose session waits for thread `t()`.
    fn interrupt() -> Interrupt {
        let interrupt = Interrupt::default();
        interrupt.wait_for([t()]);
        interrupt
    }

    #[test]
    fn a_request_needs_a_running_guest() {
        let interrupt = interrupt();
        assert!(
            !interrupt.request(0),
            "the guest is stopped: nothing to stop"
        );
        assert!(!interrupt.take(t()));
        rearm(&interrupt, 1);
        assert!(
            !interrupt.take(t()),
            "a byte sent while stopped does not apply"
        );

        assert!(interrupt.request(1));
        assert!(!interrupt.request(1), "a second byte adds nothing");
        assert!(interrupt.take(t()));
        assert!(!interrupt.take(t()), "one thread stops for it");
    }

    #[test]
    fn a_byte_that_overtakes_its_resume_applies_to_it() {
        let interrupt = interrupt();
        // The relay sees the byte gdb sent after command 1, a resume, before
        // the session arms for that command.
        assert!(!interrupt.request(1));
        rearm(&interrupt, 1);
        assert!(interrupt.is_requested());
        assert!(interrupt.take(t()));
        // Resumed by a detach, which arms nothing.
        interrupt.disarm();
        interrupt.release();
        assert!(!interrupt.is_requested(), "the stop answered it");
        interrupt.disarm();
        rearm(&interrupt, 2);
        assert!(
            !interrupt.is_requested(),
            "nor does it apply to the next resume"
        );
    }

    #[test]
    fn another_stop_answers_an_untaken_request() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        interrupt.request(1);
        // A breakpoint stop reaches gdb first.
        interrupt.disarm();
        assert!(!interrupt.take(t()), "the request was answered");
        rearm(&interrupt, 2);
        assert!(!interrupt.take(t()), "and does not stop the next resume");
    }

    #[test]
    fn a_taken_request_lasts_until_its_thread_is_resumed() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        interrupt.request(1);
        assert!(interrupt.take(t()));
        // The session reports the stop, and later resumes the guest.
        interrupt.disarm();
        rearm(&interrupt, 2);
        assert!(interrupt.is_taken(), "its thread has not been resumed yet");
        interrupt.release();
        assert!(!interrupt.is_taken());
        assert!(!interrupt.is_requested());
        assert!(
            interrupt.request(2),
            "the guest runs: a new request is taken"
        );
    }

    #[test]
    fn a_byte_sent_before_the_taker_resumes_applies_when_it_does() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        interrupt.request(1);
        assert!(interrupt.take(t()));
        interrupt.disarm();
        rearm(&interrupt, 2);
        // gdb interrupts the resume before the thread that took the last
        // interrupt has gone on.
        assert!(!interrupt.request(2));
        interrupt.release();
        assert!(interrupt.is_requested());
    }

    #[test]
    fn waiting_in_place_needs_the_sessions_leave() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        interrupt.request(1);
        assert!(
            interrupt.requested_in_place().now_or_never().is_none(),
            "a running thread takes it at its next stop"
        );
        interrupt.allow_in_place();
        assert!(interrupt.requested_in_place().now_or_never().is_some());
        interrupt.disarm();
        rearm(&interrupt, 2);
        interrupt.request(2);
        assert!(
            interrupt.requested_in_place().now_or_never().is_none(),
            "each request is decided afresh"
        );
    }

    #[test]
    fn only_a_thread_the_session_waits_for_takes_it() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        interrupt.request(1);
        assert!(
            !interrupt.take(Pid::from_raw(8)),
            "its stop would reach no one"
        );
        assert!(interrupt.take(t()));
    }

    #[test]
    fn in_place_taking_waits_for_a_thread_the_session_waits_for() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        interrupt.request(1);
        interrupt.allow_in_place();
        let other = Pid::from_raw(8);
        assert!(
            interrupt
                .requested_in_place_for(other)
                .now_or_never()
                .is_none(),
            "a thread outside the waiting set cannot take it in place"
        );
        assert!(
            interrupt
                .requested_in_place_for(t())
                .now_or_never()
                .is_some()
        );
        interrupt.wait_for([other]);
        assert!(
            interrupt
                .requested_in_place_for(other)
                .now_or_never()
                .is_some(),
            "joining the waiting set lets the thread take it in place"
        );
    }

    #[test]
    fn a_kick_is_consumed_once() {
        let interrupt = interrupt();
        interrupt.kick(t());
        assert!(interrupt.take_kick(t()));
        assert!(
            !interrupt.take_kick(t()),
            "a later SIGSTOP is the guest's own"
        );
    }

    #[test]
    fn a_taken_request_is_not_a_new_one() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        interrupt.request(1);
        assert!(interrupt.requested().now_or_never().is_some());
        assert!(interrupt.take(t()));
        assert!(
            interrupt.requested().now_or_never().is_none(),
            "taken: nothing waits for a thread"
        );
        assert!(interrupt.settled().now_or_never().is_some());
    }

    #[tokio::test]
    async fn waiters_wake_on_the_change_they_wait_for() {
        let interrupt = interrupt();
        rearm(&interrupt, 1);
        let parked = tokio::spawn({
            let interrupt = interrupt.clone();
            async move { interrupt.requested_in_place().await }
        });
        tokio::task::yield_now().await;
        interrupt.request(1);
        interrupt.allow_in_place();
        tokio::time::timeout(Duration::from_secs(10), parked)
            .await
            .expect("the parked waiter wakes")
            .unwrap();

        assert!(interrupt.take(t()));
        let holder = tokio::spawn({
            let interrupt = interrupt.clone();
            async move { interrupt.released().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !holder.is_finished(),
            "a thread is stopped for the interrupt"
        );
        interrupt.release();
        tokio::time::timeout(Duration::from_secs(10), holder)
            .await
            .expect("the holder wakes")
            .unwrap();
    }
}
