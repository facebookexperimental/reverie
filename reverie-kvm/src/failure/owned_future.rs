/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Catch polling and destruction of one owned future separately.

use std::any::Any;
use std::future::Future;
use std::future::poll_fn;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::task::Poll;

pub(crate) type PanicPayload = Box<dyn Any + Send + 'static>;

pub(crate) struct CaughtFuture<R> {
    /// A returned value survives even if destroying the future panics.
    pub(crate) output: Option<R>,
    /// Original payloads, in polling-then-destruction order.
    pub(crate) panics: Vec<PanicPayload>,
}

/// Construct one future inside a catch, then catch its polling and destruction.
///
/// A Tool method may execute synchronous code before returning its future. Keep
/// that call in `build`; evaluating it before calling this helper is too late.
/// A construction panic has no returned future or output to poll or destroy.
/// As with `catch_owned_future`, a double panic during unwinding can abort.
pub(crate) async fn catch_owned_future_from<B, F>(build: B) -> CaughtFuture<F::Output>
where
    B: FnOnce() -> F,
    F: Future,
{
    match catch_unwind(AssertUnwindSafe(build)) {
        Ok(future) => catch_owned_future(future).await,
        Err(payload) => CaughtFuture {
            output: None,
            panics: vec![payload],
        },
    }
}

/// Poll one pinned allocation until completion or panic, then destroy it.
///
/// The owned future stays outside the caught poll closure. A polling panic
/// therefore ends polling without unwinding through that future's destructor;
/// destruction has its own catch after the polling phase has returned.
///
/// This function does not publish failures or resume panic payloads. Its caller
/// owns those decisions and any cleanup that must follow. Dropping this helper
/// while it is pending does not run this completion protocol. A double panic
/// during unwinding can abort the process and cannot be recovered here.
pub(crate) async fn catch_owned_future<F: Future>(future: F) -> CaughtFuture<F::Output> {
    let mut owned = Some(Box::pin(future));
    let mut panics = Vec::new();
    let output = poll_fn(|cx| {
        match catch_unwind(AssertUnwindSafe(|| {
            owned.as_mut().unwrap().as_mut().poll(cx)
        })) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => Poll::Ready(Some(output)),
            Err(payload) => {
                panics.push(payload);
                Poll::Ready(None)
            }
        }
    })
    .await;

    // Move the actual allocation into this separate catch, after no poll or
    // reference to the future remains active. Never poll it after this point.
    let future = owned.take().unwrap();
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(future))) {
        panics.push(payload);
    }

    CaughtFuture { output, panics }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::marker::PhantomPinned;
    use std::panic::resume_unwind;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Context;
    use std::task::Waker;

    use futures::channel::oneshot;

    use super::*;
    use crate::Error;

    #[derive(Default)]
    struct Observed {
        polls: AtomicUsize,
        drops: AtomicUsize,
        address: AtomicUsize,
    }

    /// Interior mutability lets this deliberately !Unpin future inspect its
    /// controls without an unsafe projection or moving its pinned allocation.
    struct ControlledFuture<R> {
        observed: Arc<Observed>,
        output: RefCell<Option<R>>,
        release: RefCell<Option<oneshot::Receiver<()>>>,
        poll_panic: RefCell<Option<PanicPayload>>,
        drop_panic: Option<PanicPayload>,
        _pin: PhantomPinned,
    }

    impl<R> ControlledFuture<R> {
        fn ready(output: R, observed: Arc<Observed>) -> Self {
            Self {
                observed,
                output: RefCell::new(Some(output)),
                release: RefCell::new(None),
                poll_panic: RefCell::new(None),
                drop_panic: None,
                _pin: PhantomPinned,
            }
        }

        fn check_address(&self) {
            let address = std::ptr::from_ref(self) as usize;
            if let Err(original) = self.observed.address.compare_exchange(
                0,
                address,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                assert_eq!(original, address, "owned future moved after its first poll");
            }
        }
    }

    impl<R> Future for ControlledFuture<R> {
        type Output = R;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<R> {
            let this = self.as_ref().get_ref();
            this.check_address();
            this.observed.polls.fetch_add(1, Ordering::SeqCst);
            if let Some(payload) = this.poll_panic.borrow_mut().take() {
                resume_unwind(payload);
            }
            {
                let mut release = this.release.borrow_mut();
                if let Some(receiver) = release.as_mut() {
                    match Pin::new(receiver).poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Ok(())) => {}
                        Poll::Ready(Err(_)) => panic!("controlled release was dropped"),
                    }
                }
                release.take();
            }
            Poll::Ready(
                this.output
                    .borrow_mut()
                    .take()
                    .expect("completed future was polled again"),
            )
        }
    }

    impl<R> Drop for ControlledFuture<R> {
        fn drop(&mut self) {
            self.check_address();
            self.observed.drops.fetch_add(1, Ordering::SeqCst);
            if let Some(payload) = self.drop_panic.take() {
                resume_unwind(payload);
            }
        }
    }

    struct PanicMarker(&'static str);

    fn payload(label: &'static str) -> (PanicPayload, usize) {
        let marker = Box::new(PanicMarker(label));
        let address = std::ptr::from_ref(marker.as_ref()) as usize;
        (marker, address)
    }

    fn assert_payload(payload: &PanicPayload, address: usize, label: &'static str) {
        let marker = payload.downcast_ref::<PanicMarker>().unwrap();
        assert_eq!(std::ptr::from_ref(marker) as usize, address);
        assert_eq!(marker.0, label);
    }

    #[test]
    fn pending_then_ready_keeps_allocation_and_drops_once() {
        let observed = Arc::new(Observed::default());
        let (release, wait) = oneshot::channel();
        let mut future = ControlledFuture::ready(73, observed.clone());
        future.release = RefCell::new(Some(wait));
        let mut caught = Box::pin(catch_owned_future(future));
        let mut cx = Context::from_waker(Waker::noop());

        assert!(caught.as_mut().poll(&mut cx).is_pending());
        assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
        assert_eq!(observed.drops.load(Ordering::SeqCst), 0);
        let first_address = observed.address.load(Ordering::SeqCst);
        assert_ne!(first_address, 0);

        release.send(()).unwrap();
        let Poll::Ready(result) = caught.as_mut().poll(&mut cx) else {
            panic!("released future stayed pending");
        };
        assert_eq!(result.output, Some(73));
        assert!(result.panics.is_empty());
        assert_eq!(observed.polls.load(Ordering::SeqCst), 2);
        assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
        assert_eq!(observed.address.load(Ordering::SeqCst), first_address);
        drop(caught);
        assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn poll_panic_is_not_repolled_and_drop_panic_is_retained_separately() {
        let observed = Arc::new(Observed::default());
        let (poll_panic, poll_address) = payload("poll");
        let (drop_panic, drop_address) = payload("drop after poll");
        let mut future = ControlledFuture::ready((), observed.clone());
        future.poll_panic = RefCell::new(Some(poll_panic));
        future.drop_panic = Some(drop_panic);
        let mut caught = Box::pin(catch_owned_future(future));
        let mut cx = Context::from_waker(Waker::noop());

        let Poll::Ready(result) = caught.as_mut().poll(&mut cx) else {
            panic!("panicking future stayed pending");
        };
        assert!(result.output.is_none());
        assert_eq!(result.panics.len(), 2);
        assert_payload(&result.panics[0], poll_address, "poll");
        assert_payload(&result.panics[1], drop_address, "drop after poll");
        assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
        assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
        drop(caught);
        assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
        assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn returned_typed_error_survives_a_destructor_panic() {
        let observed = Arc::new(Observed::default());
        let error = Arc::new(Error::GuestClock("controlled clock error".to_owned()));
        let (drop_panic, drop_address) = payload("drop after error");
        let mut future = ControlledFuture::ready(Err::<(), _>(error.clone()), observed.clone());
        future.drop_panic = Some(drop_panic);
        let mut caught = Box::pin(catch_owned_future(future));
        let mut cx = Context::from_waker(Waker::noop());

        let Poll::Ready(result) = caught.as_mut().poll(&mut cx) else {
            panic!("ready error stayed pending");
        };
        let Some(Err(returned)) = result.output else {
            panic!("returned typed error was lost");
        };
        assert!(Arc::ptr_eq(&returned, &error));
        assert!(matches!(
            returned.as_ref(),
            Error::GuestClock(message) if message == "controlled clock error"
        ));
        assert_eq!(result.panics.len(), 1);
        assert_payload(&result.panics[0], drop_address, "drop after error");
        assert_eq!(observed.polls.load(Ordering::SeqCst), 1);
        assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
        drop(caught);
        assert_eq!(observed.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn send_non_sync_state_can_cross_a_pending_await() {
        fn assert_send<T: Send>(_: &T) {}

        let (release, wait) = oneshot::channel();
        let future = async move {
            let state = Cell::new(17);
            wait.await.expect("controlled release was dropped");
            state.set(state.get() + 25);
            state.get()
        };
        let mut caught = Box::pin(catch_owned_future(future));
        assert_send(&caught);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(caught.as_mut().poll(&mut cx).is_pending());
        release.send(()).unwrap();

        let result = std::thread::spawn(move || {
            let mut cx = Context::from_waker(Waker::noop());
            let Poll::Ready(result) = caught.as_mut().poll(&mut cx) else {
                panic!("released future stayed pending on its new thread");
            };
            result
        })
        .join()
        .expect("controlled polling thread panicked");
        assert_eq!(result.output, Some(42));
        assert!(result.panics.is_empty());
    }
}
