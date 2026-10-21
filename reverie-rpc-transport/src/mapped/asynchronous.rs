use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::ReadBuf;

use super::MappedCompletion;
use super::MappedFailure;
use super::MappedStream;
use super::MappedWorkerFailure;
use super::Mapping;

/// Host-side asynchronous adapter. Its dedicated notification thread never
/// reads requests, writes responses, serializes values, or runs Tool callbacks.
/// It does not use Tokio's blocking pool. Dropping it requests worker stop and
/// closes the logical stream without waiting for user Wakers. A shared reaper
/// joins the per-connection joining helpers. Each helper joins its notification
/// worker and publishes [`Self::completion`] independently. Custom Wakers and
/// their TLS destructors must return before that worker can finish. Helper
/// cleanup is a separate observation and may remain pending longer.
pub struct AsyncMappedStream {
    stream: MappedStream,
    wake: Arc<Wake>,
    completion: MappedCompletion,
}

// Every admitted registration owns an empty node before calling arbitrary clone.
// Once clone returns, only the notification worker may consume the new Waker.
struct Node {
    waker: Option<Waker>,
    next: Option<Box<Node>>,
    notify: bool,
}

struct Registrations {
    accepting: bool,
    cloning: usize,
    slots: [Option<Box<Node>>; 2],
    retired: Option<Box<Node>>,
}

struct Wake {
    stopped: Arc<AtomicBool>,
    registrations: Mutex<Registrations>,
    changed: Condvar,
}

struct Registration<'a> {
    wake: &'a Wake,
    slot: usize,
    node: Option<Box<Node>>,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        let mut state = self
            .wake
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut node = self.node.take().unwrap();
        if node.waker.is_some() {
            if state.accepting {
                let prior = state.slots[self.slot].replace(node);
                if let Some(mut prior) = prior {
                    prior.notify = false;
                    prior.next = state.retired.take();
                    state.retired = Some(prior);
                }
            } else {
                node.next = state.retired.take();
                state.retired = Some(node);
            }
        }
        state.cloning -= 1;
        self.wake.changed.notify_all();
    }
}

impl Wake {
    fn register(&self, slot: usize, waker: &Waker) {
        let node = Box::new(Node {
            waker: None,
            next: None,
            notify: true,
        });
        {
            let mut state = self
                .registrations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.accepting {
                return;
            }
            state.cloning = state
                .cloning
                .checked_add(1)
                .expect("Waker registration count overflow");
        }
        let mut registration = Registration {
            wake: self,
            slot,
            node: Some(node),
        };
        // A clone panic propagates unchanged. The guard releases its reservation;
        // it never catches or owns that caller's panic payload.
        registration.node.as_mut().unwrap().waker = Some(waker.clone());
        drop(registration);
    }

    fn take(&self, slot: usize) -> Option<Box<Node>> {
        self.registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .slots[slot]
            .take()
    }

    fn consume(mut node: Node) {
        // The node was unlinked while locked. No arbitrary user code runs there.
        let waker = node.waker.take().unwrap();
        if node.notify {
            waker.wake();
        } else {
            drop(waker);
        }
    }

    fn wake_all(&self) {
        for slot in 0..2 {
            if let Some(node) = self.take(slot) {
                Self::consume(*node);
            }
        }
        loop {
            let node = {
                let mut state = self
                    .registrations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.retired.take().map(|mut node| {
                    state.retired = node.next.take();
                    node
                })
            };
            match node {
                Some(node) => Self::consume(*node),
                None => break,
            }
        }
    }

    fn close_and_drain(
        &self,
        mapping: &Mapping,
        outcome: &mut Result<(), MappedWorkerFailure>,
        completion: &MappedCompletion,
    ) {
        let mut state = self
            .registrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.accepting = false;
        for slot in 0..2 {
            if let Some(mut node) = state.slots[slot].take() {
                node.next = state.retired.take();
                state.retired = Some(node);
            }
        }
        loop {
            if let Some(mut node) = state.retired.take() {
                state.retired = node.next.take();
                drop(state);
                if let Err(payload) =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Self::consume(*node)))
                {
                    mapping.abort(MappedFailure::PeerFailed);
                    if outcome.is_ok() {
                        *outcome = Err(MappedWorkerFailure::Panicked);
                    }
                    if super::workers::discard_panic(Some(payload)) {
                        completion.record_payload_leak();
                    }
                }
                state = self
                    .registrations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            } else if state.cloning == 0 {
                // This worker owns no local node here. Closed admission plus no
                // admitted clone and an empty list is the final drain boundary.
                break;
            } else {
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
    }
}

impl AsyncMappedStream {
    pub(super) fn new(stream: MappedStream) -> io::Result<Self> {
        let wake = Arc::new(Wake {
            stopped: Arc::new(AtomicBool::new(false)),
            registrations: Mutex::new(Registrations {
                accepting: true,
                cloning: 0,
                slots: [None, None],
                retired: None,
            }),
            changed: Condvar::new(),
        });
        let state = wake.clone();
        let mapping = stream.mapping.clone();
        let completion = MappedCompletion::new();
        let worker_completion = completion.clone();
        let stopped = wake.stopped.clone();
        let abort = stream.abort_handle();
        let completion = super::workers::spawn(
            move |ready| {
                struct UnexpectedPanic<'a>(&'a Mapping);
                impl Drop for UnexpectedPanic<'_> {
                    fn drop(&mut self) {
                        if std::thread::panicking() {
                            self.0.abort(MappedFailure::PeerFailed);
                        }
                    }
                }
                let _unexpected_panic = UnexpectedPanic(&mapping);
                let mut outcome =
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        ready.mark();
                        monitor(&mapping, &state)
                    })) {
                        Ok(result) => result.map_err(MappedWorkerFailure::from),
                        Err(payload) => {
                            mapping.abort(MappedFailure::PeerFailed);
                            if super::workers::discard_panic(Some(payload)) {
                                worker_completion.record_payload_leak();
                            }
                            Err(MappedWorkerFailure::Panicked)
                        }
                    };
                if outcome.is_err() {
                    mapping.abort(MappedFailure::PeerFailed);
                }
                state.close_and_drain(&mapping, &mut outcome, &worker_completion);
                outcome
            },
            completion,
            stopped,
            Some(abort),
        )?;
        Ok(Self {
            stream,
            wake,
            completion,
        })
    }

    /// Observe notification worker termination separately from logical closure.
    /// Clone this handle before cancelling or dropping the stream.
    pub fn completion(&self) -> MappedCompletion {
        self.completion.clone()
    }
}

fn monitor(mapping: &Mapping, wake: &Wake) -> io::Result<()> {
    while !wake.stopped.load(Ordering::Acquire) {
        let progress = mapping.header().progress.load(Ordering::Acquire);
        if wake.stopped.load(Ordering::Acquire) {
            break;
        }
        // A wake registered after this observation is covered by the poller's
        // second queue check. Timeouts only recheck state, never imply death.
        wake.wake_all();
        mapping.wait(progress)?;
    }
    Ok(())
}

impl AsyncRead for AsyncMappedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.stream.try_read(buffer.initialize_unfilled()) {
            Ok(count) => {
                buffer.advance(count);
                Poll::Ready(Ok(()))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                this.wake.register(0, cx.waker());
                match this.stream.try_read(buffer.initialize_unfilled()) {
                    Ok(count) => {
                        buffer.advance(count);
                        Poll::Ready(Ok(()))
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for AsyncMappedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.stream.try_write(buffer) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                this.wake.register(1, cx.waker());
                match this.stream.try_write(buffer) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                    result => Poll::Ready(result),
                }
            }
            result => Poll::Ready(result),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.stream.mapping.check_failure())
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.stream.close_write();
        Poll::Ready(this.stream.mapping.check_failure())
    }
}

impl Drop for AsyncMappedStream {
    fn drop(&mut self) {
        self.wake.stopped.store(true, Ordering::Release);
        self.stream.mapping.notify();
    }
}

#[cfg(test)]
mod tests {
    use std::task::RawWaker;
    use std::task::RawWakerVTable;

    use super::*;

    #[test]
    fn closed_registration_does_not_clone_or_retain_a_new_waker() {
        unsafe fn clone(_: *const ()) -> RawWaker {
            panic!("closed registration cloned a Waker");
        }
        unsafe fn consume(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, consume, consume, consume);
        let (host, _peer) = MappedStream::pair(7).unwrap();
        let stream = host.into_async().unwrap();
        let completion = stream.completion();
        let wake = stream.wake.clone();
        drop(stream);
        assert_eq!(
            completion.wait_timeout(std::time::Duration::from_secs(3)),
            Some(Ok(()))
        );
        // The zero-sized raw handle owns nothing. Only clone is observable.
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        wake.register(0, &waker);
        wake.register(1, &waker);
        assert_eq!(
            completion.wait_helper_timeout(std::time::Duration::from_secs(3)),
            Some(Ok(()))
        );
    }
}
