/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Owned output drains which can park their bytes without abandoning a reader.

use std::io;
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use tokio::io::AsyncRead;
use tokio::io::ReadBuf;

pub(crate) type BoxedRead = Pin<Box<dyn AsyncRead + 'static>>;

// Each driver turn offers one bounded read to each stream. Discarding output
// uses this same fixed buffer without accumulating a Vec.
const READ_SIZE: usize = 8192;

#[derive(Debug)]
pub(crate) enum DrainEvent {
    /// Bytes were read. The driver must arrange another poll, after giving the
    /// other stream and tree owners their turn.
    Progress,
    Finished,
    /// The original I/O value, moved out exactly once. The driver must record
    /// it synchronously in the run's cause store before polling again.
    Error(io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrefixStateError {
    AlreadyParked,
    NotParked,
    ModeMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadState {
    Open,
    Eof,
    Failed,
}

pub(crate) struct CaptureDrain {
    // Keep this exact owner, including readiness registrations, even at EOF or
    // after an error. Parking moves only bytes, never the pipe or its state.
    reader: Option<BoxedRead>,
    state: ReadState,
    capture: bool,
    prefix: Option<Vec<u8>>,
    parked: bool,
    scratch: [u8; READ_SIZE],
}

impl CaptureDrain {
    pub(crate) fn capture(reader: Option<BoxedRead>) -> Self {
        Self::new(reader, true)
    }

    pub(crate) fn discard(reader: Option<BoxedRead>) -> Self {
        Self::new(reader, false)
    }

    fn new(reader: Option<BoxedRead>, capture: bool) -> Self {
        let state = if reader.is_some() {
            ReadState::Open
        } else {
            ReadState::Eof
        };
        Self {
            reader,
            state,
            capture,
            prefix: capture.then(Vec::new),
            parked: false,
            scratch: [0; READ_SIZE],
        }
    }

    /// Poll the owned reader at most once. An error is terminal, but is not EOF:
    /// its exact value is emitted once while the preceding bytes stay owned.
    /// A parked drain returns Pending without changing reader readiness.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<DrainEvent> {
        if self.parked {
            return Poll::Pending;
        }
        if self.is_finished() {
            return Poll::Ready(DrainEvent::Finished);
        }

        let mut buffer = ReadBuf::new(&mut self.scratch);
        let result = self
            .reader
            .as_mut()
            .expect("an open drain owns its reader")
            .as_mut()
            .poll_read(cx, &mut buffer);
        let bytes = buffer.filled();
        let read = bytes.len();
        if self.capture {
            self.prefix
                .as_mut()
                .expect("an unparked capture drain owns its prefix")
                .extend_from_slice(bytes);
        }

        match result {
            Poll::Ready(Err(error)) => {
                self.state = ReadState::Failed;
                Poll::Ready(DrainEvent::Error(error))
            }
            Poll::Ready(Ok(())) => {
                if read == 0 {
                    self.state = ReadState::Eof;
                    Poll::Ready(DrainEvent::Finished)
                } else {
                    Poll::Ready(DrainEvent::Progress)
                }
            }
            // Preserve every byte marked filled by the reader, even if a
            // reader reports Pending after filling part of the supplied buf.
            Poll::Pending if read != 0 => Poll::Ready(DrainEvent::Progress),
            Poll::Pending => Poll::Pending,
        }
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.state != ReadState::Open
    }

    #[cfg(test)]
    pub(crate) fn observed_prefix_for_test(&self) -> Option<&[u8]> {
        self.prefix.as_deref()
    }

    /// Suspend this drain and move its prefix out. Capture returns Some even
    /// for an absent pipe or zero bytes; discard returns None. A second take
    /// cannot invent an empty replacement for bytes already moved out.
    pub(crate) fn take_prefix(&mut self) -> Result<Option<Vec<u8>>, PrefixStateError> {
        if self.parked {
            return Err(PrefixStateError::AlreadyParked);
        }
        self.parked = true;
        Ok(self.prefix.take())
    }

    /// Move the parked prefix back before any resumed polling. An invalid
    /// restore returns all supplied bytes intact and leaves this owner alone.
    pub(crate) fn restore_prefix(
        &mut self,
        prefix: Option<Vec<u8>>,
    ) -> Result<(), (PrefixStateError, Option<Vec<u8>>)> {
        if !self.parked {
            return Err((PrefixStateError::NotParked, prefix));
        }
        if prefix.is_some() != self.capture {
            return Err((PrefixStateError::ModeMismatch, prefix));
        }
        self.prefix = prefix;
        self.parked = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fmt;
    use std::future::poll_fn;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::task::Wake;
    use std::task::Waker;

    use tokio::io::AsyncWriteExt;

    use super::*;

    #[derive(Debug)]
    struct ReaderFailure(&'static str);

    impl fmt::Display for ReaderFailure {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for ReaderFailure {}

    enum Step {
        Bytes(Vec<u8>),
        Pending,
        Error(io::Error),
        Eof,
    }

    #[derive(Default)]
    struct Probe {
        polls: Cell<usize>,
        capacities: RefCell<Vec<usize>>,
        drops: Cell<usize>,
        registered: RefCell<Option<Waker>>,
    }

    struct ScriptedReader {
        steps: VecDeque<Step>,
        probe: Rc<Probe>,
    }

    impl AsyncRead for ScriptedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.probe.polls.set(this.probe.polls.get() + 1);
            this.probe.capacities.borrow_mut().push(buffer.remaining());
            match this.steps.pop_front().expect("reader polled past terminal") {
                Step::Bytes(mut bytes) => {
                    if bytes.len() > buffer.remaining() {
                        let remaining = bytes.split_off(buffer.remaining());
                        this.steps.push_front(Step::Bytes(remaining));
                    }
                    buffer.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                Step::Pending => {
                    this.probe.registered.replace(Some(cx.waker().clone()));
                    Poll::Pending
                }
                Step::Error(error) => Poll::Ready(Err(error)),
                Step::Eof => Poll::Ready(Ok(())),
            }
        }
    }

    impl Drop for ScriptedReader {
        fn drop(&mut self) {
            self.probe.drops.set(self.probe.drops.get() + 1);
        }
    }

    fn reader(steps: impl IntoIterator<Item = Step>) -> (BoxedRead, Rc<Probe>) {
        let probe = Rc::new(Probe::default());
        let reader = ScriptedReader {
            steps: steps.into_iter().collect(),
            probe: probe.clone(),
        };
        (Box::pin(reader), probe)
    }

    fn poll(drain: &mut CaptureDrain) -> Poll<DrainEvent> {
        drain.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[derive(Default)]
    struct CountWake(AtomicUsize);

    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn capture_parking_preserves_bytes_reader_readiness_and_typed_error() {
        let first = vec![0, 255, 128, b'a', b'a', b'\n'];
        let second = vec![0, 254, b'b', b'b', 0];
        let expected = [first.as_slice(), second.as_slice()].concat();
        let error = io::Error::other(ReaderFailure("original source"));
        let source = error
            .get_ref()
            .unwrap()
            .downcast_ref::<ReaderFailure>()
            .unwrap() as *const ReaderFailure;
        let (reader, probe) = reader([
            Step::Bytes(first.clone()),
            Step::Pending,
            Step::Bytes(second),
            Step::Error(error),
        ]);
        let mut drain = CaptureDrain::capture(Some(reader));
        assert!(matches!(
            poll(&mut drain),
            Poll::Ready(DrainEvent::Progress)
        ));

        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(wake.clone());
        assert!(drain.poll(&mut Context::from_waker(&waker)).is_pending());
        let prefix = drain.take_prefix().unwrap();
        assert_eq!(prefix.as_deref(), Some(first.as_slice()));
        assert_eq!(drain.take_prefix(), Err(PrefixStateError::AlreadyParked));
        assert!(poll(&mut drain).is_pending());
        assert_eq!(probe.polls.get(), 2);
        assert_eq!(probe.drops.get(), 0);
        {
            let registered = probe.registered.borrow();
            let registered = registered.as_ref().unwrap();
            assert!(registered.will_wake(&waker));
            registered.wake_by_ref();
        }
        assert_eq!(wake.0.load(Ordering::SeqCst), 1);
        assert!(!drain.is_finished());

        drain.restore_prefix(prefix).unwrap();
        assert!(matches!(
            poll(&mut drain),
            Poll::Ready(DrainEvent::Progress)
        ));
        let Poll::Ready(DrainEvent::Error(error)) = poll(&mut drain) else {
            panic!("the real reader error must be emitted");
        };
        let retained_source = error
            .get_ref()
            .unwrap()
            .downcast_ref::<ReaderFailure>()
            .unwrap();
        assert_eq!(retained_source as *const ReaderFailure, source);
        assert_eq!(retained_source.0, "original source");
        assert!(drain.is_finished());
        assert_eq!(drain.state, ReadState::Failed);
        let prefix = drain.take_prefix().unwrap();
        assert_eq!(prefix.as_deref(), Some(expected.as_slice()));
        assert!(poll(&mut drain).is_pending());
        drain.restore_prefix(prefix).unwrap();
        for _ in 0..2 {
            assert!(matches!(
                poll(&mut drain),
                Poll::Ready(DrainEvent::Finished)
            ));
        }
        assert_eq!(probe.polls.get(), 4);
        assert_eq!(probe.drops.get(), 0);
        assert_eq!(drain.take_prefix().unwrap().unwrap(), expected);
        drop(drain);
        assert_eq!(probe.drops.get(), 1);
    }

    #[test]
    fn capture_reads_one_bounded_chunk_per_poll_and_keeps_exact_binary_output() {
        let expected: Vec<u8> = (0..READ_SIZE * 3 + 17).map(|i| (i % 256) as u8).collect();
        let (reader, probe) = reader([Step::Bytes(expected.clone()), Step::Eof]);
        let mut drain = CaptureDrain::capture(Some(reader));
        for calls in 1..=4 {
            assert!(matches!(
                poll(&mut drain),
                Poll::Ready(DrainEvent::Progress)
            ));
            assert_eq!(probe.polls.get(), calls);
            assert_eq!(
                drain.prefix.as_ref().unwrap().len(),
                (calls * READ_SIZE).min(expected.len())
            );
        }
        assert!(matches!(
            poll(&mut drain),
            Poll::Ready(DrainEvent::Finished)
        ));
        assert_eq!(probe.polls.get(), 5);
        assert_eq!(*probe.capacities.borrow(), vec![READ_SIZE; 5]);
        assert_eq!(drain.state, ReadState::Eof);
        let prefix = drain.take_prefix().unwrap();
        assert_eq!(prefix.as_deref(), Some(expected.as_slice()));
        drain.restore_prefix(prefix).unwrap();
        assert!(matches!(
            poll(&mut drain),
            Poll::Ready(DrainEvent::Finished)
        ));
        assert_eq!(probe.polls.get(), 5);
        assert_eq!(drain.take_prefix().unwrap().unwrap(), expected);
    }

    #[test]
    fn rejected_prefix_restores_return_the_supplied_bytes_unchanged() {
        let expected = vec![0, 255, 0, 128, b'\n'];
        let mut capture = CaptureDrain::capture(None);
        let (error, returned) = capture.restore_prefix(Some(expected.clone())).unwrap_err();
        assert_eq!(error, PrefixStateError::NotParked);
        assert_eq!(returned, Some(expected.clone()));
        let parked = capture.take_prefix().unwrap();
        assert_eq!(parked, Some(Vec::new()));
        assert_eq!(
            capture.restore_prefix(None),
            Err((PrefixStateError::ModeMismatch, None))
        );
        assert!(poll(&mut capture).is_pending());
        capture.restore_prefix(parked).unwrap();
        assert!(matches!(
            poll(&mut capture),
            Poll::Ready(DrainEvent::Finished)
        ));

        let mut discard = CaptureDrain::discard(None);
        assert_eq!(discard.take_prefix(), Ok(None));
        let (error, returned) = discard.restore_prefix(returned).unwrap_err();
        assert_eq!(error, PrefixStateError::ModeMismatch);
        assert_eq!(returned, Some(expected));
        assert!(poll(&mut discard).is_pending());
        discard.restore_prefix(None).unwrap();
        assert_eq!(discard.take_prefix(), Ok(None));
    }

    #[test]
    fn discard_retains_no_prefix_and_emits_its_error_once() {
        let error = io::Error::other(ReaderFailure("discard reader"));
        let (reader, probe) = reader([
            Step::Bytes(vec![0x80; READ_SIZE * 2 + 1]),
            Step::Error(error),
        ]);
        let mut drain = CaptureDrain::discard(Some(reader));
        for calls in 1..=3 {
            assert!(matches!(
                poll(&mut drain),
                Poll::Ready(DrainEvent::Progress)
            ));
            assert_eq!(probe.polls.get(), calls);
            assert!(drain.prefix.is_none());
            assert_eq!(drain.take_prefix(), Ok(None));
            assert!(poll(&mut drain).is_pending());
            assert_eq!(probe.polls.get(), calls);
            drain.restore_prefix(None).unwrap();
        }
        let Poll::Ready(DrainEvent::Error(error)) = poll(&mut drain) else {
            panic!("discard must retain reader failures");
        };
        assert_eq!(
            error
                .get_ref()
                .unwrap()
                .downcast_ref::<ReaderFailure>()
                .unwrap()
                .0,
            "discard reader"
        );
        assert!(drain.is_finished());
        assert_eq!(drain.take_prefix(), Ok(None));
        drain.restore_prefix(None).unwrap();
        assert!(matches!(
            poll(&mut drain),
            Poll::Ready(DrainEvent::Finished)
        ));
        assert_eq!(probe.polls.get(), 4);
        assert_eq!(*probe.capacities.borrow(), vec![READ_SIZE; 4]);
        assert!(drain.prefix.is_none());
    }

    #[test]
    fn empty_capture_and_absent_capture_both_own_an_empty_prefix() {
        let (reader, probe) = reader([Step::Eof]);
        for reader in [Some(reader), None] {
            let mut drain = CaptureDrain::capture(reader);
            assert!(matches!(
                poll(&mut drain),
                Poll::Ready(DrainEvent::Finished)
            ));
            assert!(drain.is_finished());
            assert_eq!(drain.take_prefix(), Ok(Some(Vec::new())));
        }
        assert_eq!(probe.polls.get(), 1);
        assert_eq!(probe.drops.get(), 1);
        let mut discard = CaptureDrain::discard(None);
        assert!(discard.is_finished());
        assert_eq!(discard.take_prefix(), Ok(None));
    }

    #[test]
    fn one_failed_reader_does_not_consume_the_other_drain() {
        let (left, left_probe) = reader([Step::Error(io::Error::other(ReaderFailure("left")))]);
        let expected = vec![0, 255, b'r', b'r'];
        let (right, right_probe) = reader([Step::Bytes(expected.clone()), Step::Eof]);
        let mut left = CaptureDrain::capture(Some(left));
        let mut right = CaptureDrain::capture(Some(right));
        assert!(matches!(poll(&mut left), Poll::Ready(DrainEvent::Error(_))));
        assert_eq!(right_probe.polls.get(), 0);
        assert_eq!(right_probe.drops.get(), 0);
        assert!(matches!(
            poll(&mut right),
            Poll::Ready(DrainEvent::Progress)
        ));
        assert!(matches!(
            poll(&mut right),
            Poll::Ready(DrainEvent::Finished)
        ));
        assert_eq!(right.take_prefix().unwrap().unwrap(), expected);
        assert_eq!(left.take_prefix().unwrap().unwrap(), Vec::<u8>::new());
        assert_eq!(left_probe.polls.get(), 1);
        assert_eq!(left_probe.drops.get(), 0);
    }

    struct CountReads<R> {
        reader: Pin<Box<R>>,
        polls: Rc<Cell<usize>>,
    }

    impl<R: AsyncRead> AsyncRead for CountReads<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.polls.set(this.polls.get() + 1);
            this.reader.as_mut().poll_read(cx, buffer)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_stream_readiness_and_unread_suffix_survive_parking() {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            real_stream_readiness_and_unread_suffix(),
        )
        .await
        .expect("the complete stream parking test exceeded three seconds");
    }

    async fn real_stream_readiness_and_unread_suffix() {
        let (reader, mut writer) = tokio::net::UnixStream::pair().unwrap();
        let polls = Rc::new(Cell::new(0));
        let mut drain = CaptureDrain::capture(Some(Box::pin(CountReads {
            reader: Box::pin(reader),
            polls: polls.clone(),
        })));
        let first = [0, 255, 128, b'a', b'a'];
        let second = [0, 254, b'b', b'b', b'\n'];
        writer.write_all(&first).await.unwrap();
        while drain.prefix.as_ref().unwrap().len() < first.len() {
            assert!(matches!(
                poll_fn(|cx| drain.poll(cx)).await,
                DrainEvent::Progress
            ));
        }
        // Register the real pipe's readiness before suspending its owner.
        poll_fn(|cx| {
            assert!(drain.poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let prefix = drain.take_prefix().unwrap();
        assert_eq!(prefix.as_deref(), Some(first.as_slice()));
        let before = polls.get();
        writer.write_all(&second).await.unwrap();
        drop(writer);
        assert!(poll(&mut drain).is_pending());
        assert_eq!(polls.get(), before);
        drain.restore_prefix(prefix).unwrap();
        loop {
            match poll_fn(|cx| drain.poll(cx)).await {
                DrainEvent::Progress => {}
                DrainEvent::Finished => break,
                DrainEvent::Error(error) => panic!("real stream failed: {error}"),
            }
        }
        let expected = [first.as_slice(), second.as_slice()].concat();
        assert_eq!(drain.take_prefix().unwrap().unwrap(), expected);
        assert!(drain.is_finished());
    }
}
