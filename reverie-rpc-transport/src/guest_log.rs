//! Retained V3 and ordered V4 capture for trusted, cooperating processes.
//!
//! # Shared memory and process ownership
//!
//! These protocols are not a memory sandbox. Size seals prevent resizing, not
//! mutation through another descriptor or mapping. For the entire lifetime of
//! every imported mapping, writer, collector and capture worker, all participants
//! must preserve initialized layout fields and access frame/credit storage only
//! through the matching protocol. Non-atomic payloads require the protocol's
//! exclusive producer/consumer ownership and release/acquire publication.
//!
//! Only trusted peers may receive backing descriptors or lifetime endpoints;
//! this includes descriptor duplicates, inherited descriptors and mapped aliases.
//! A fork child must never reuse an inherited producer's private progress. Reserve
//! its distinct incarnation before fork, resolve the actual result in the parent,
//! and activate that incarnation in the child before writing. Retain the guest
//! lifetime endpoint until all admitted writers are quiescent. Endpoint closure,
//! FINISH, actual process reap and successful publication remain separate facts.
//!
//! Creation, import and activation are unsafe where the library cannot enforce
//! these requirements. Invalid version/layout checks do not remove the caller's
//! obligation to control every writable alias. This module does not install a
//! runtime writer or provide a mapped process launcher.

//! Buffered guest records, independent of synchronous GlobalTool RPC.
//! A lifetime endpoint must outlive every admitted shared-memory writer.

mod buffer;
mod capture;
pub use capture::*;
#[cfg(feature = "test-guest-log")]
pub mod fixture;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

pub use buffer::FAILURE;
pub use buffer::PAYLOAD;
pub use buffer::Producer;
pub use buffer::PublishError;
pub use buffer::SharedBuffer;
pub use buffer::channel_pair;
pub use buffer::ordered;
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    pub byte_limit: usize,
    pub producers: usize,
    pub slots: usize,
}
impl Options {
    pub fn bounded(byte_limit: usize) -> Self {
        Self {
            byte_limit,
            producers: 16,
            slots: 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueKind {
    Startup,
    Protocol,
    Producer,
    Truncated,
    Cancelled,
    Interrupted,
    Cutoff,
    Rpc,
    Child,
    Cleanup,
    Publication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Issue {
    pub kind: IssueKind,
    pub message: String,
}

#[derive(Clone, Copy)]
enum IssueOrigin {
    Integrity,
    GuestOutcomePolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    NotStarted,
    Collecting,
    Draining,
    Complete,
    Incomplete,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderState {
    Unassigned,
    Queued,
    Ready,
}

/// Separate from the canonical byte budget: at most one rejected frame per producer.
pub const REJECTED_PAYLOAD_LIMIT: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedFrame {
    pub ordinal: u64,
    pub kind: u32,
    pub length: u32,
    pub sequence: u64,
    pub offset: u64,
    pub total: u64,
    pub payload: Vec<u8>,
    /// Declared payload bytes not retained, including bytes beyond a valid slot.
    pub omitted_payload_bytes: u64,
}

impl RejectedFrame {
    fn capture(frame: buffer::Frame) -> Self {
        let retained = (frame.length as usize).min(REJECTED_PAYLOAD_LIMIT);
        Self {
            ordinal: frame.ordinal,
            kind: frame.kind,
            length: frame.length,
            sequence: frame.sequence,
            offset: frame.offset,
            total: frame.total,
            payload: frame.payload[..retained].to_vec(),
            omitted_payload_bytes: u64::from(frame.length) - retained as u64,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Stream {
    pub incarnation: u64,
    pub pid: u64,
    pub parent: u64,
    pub bytes: Vec<u8>,
    pub fragment: Vec<u8>,
    pub fragment_sequence: Option<u64>,
    pub complete_records: u64,
    pub finished: bool,
    pub unread_frames: u64,
    pub rejected_frame: Option<RejectedFrame>,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub phase: Phase,
    pub reader: ReaderState,
    pub run: RunState,
    pub peer_closed: bool,
    pub root_reaped: bool,
    pub issues: Vec<Issue>,
    pub streams: Vec<Stream>,
    pub rpc_issues: Vec<crate::ConnectionIssue>,
}

impl Report {
    pub fn qualifies(&self) -> bool {
        self.phase == Phase::Complete
            && self.run == RunState::Succeeded
            && self.issues.is_empty()
            && self.rpc_issues.is_empty()
    }
    pub fn terminal(&self) -> bool {
        matches!(self.phase, Phase::Complete | Phase::Incomplete)
    }
}

struct State {
    report: Report,
    stop_at: Option<Instant>,
    mapping: Option<Arc<SharedBuffer>>,
}

struct Retention {
    state: Mutex<State>,
    changed: Notify,
    lease: AtomicU8,
    options: Options,
    drain: Duration,
    rpc: Mutex<Option<crate::RpcIssueMonitor>>,
    capture: std::sync::OnceLock<Arc<capture::Shared>>,
}

const STARTUP: u8 = 0;
const QUEUED: u8 = 1;
const RUNNING: u8 = 2;
const FINAL: u8 = 3;

/// Caller-owned evidence. Clones neither cancel the run nor keep a worker running.
#[derive(Clone)]
pub struct LogHandle(Arc<Retention>);

/// A publication position bound to one retained capture and producer, not scan order.
pub struct LogCursor {
    handle: LogHandle,
    incarnation: u64,
    offset: usize,
}

impl LogCursor {
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn write_to(&mut self, writer: &mut impl io::Write) -> io::Result<usize> {
        let bytes = self.handle.delta(self.incarnation, self.offset)?;
        let mut written = 0;
        while written < bytes.len() {
            let result = writer.write(&bytes[written..]);
            match result {
                Ok(length) if length > 0 && length <= bytes.len() - written => {
                    self.offset += length;
                    written += length;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    let error = result.err().unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::WriteZero,
                            "guest-log destination made no valid progress",
                        )
                    });
                    self.handle.stop(IssueKind::Publication, &error);
                    return Err(error);
                }
            }
        }
        Ok(written)
    }
}

/// Single-use startup/finalization ownership, constructed outside cancellation.
pub struct LogSink {
    handle: LogHandle,
    transferred: bool,
    prepared: Option<UnixStream>,
    #[cfg(feature = "test-guest-log")]
    fixture: Option<Arc<fixture::Control>>,
}

pub fn retained_log(options: Options) -> (LogSink, LogHandle) {
    retained_log_with_drain(options, Duration::from_secs(30))
}

fn retained_log_with_drain(options: Options, drain: Duration) -> (LogSink, LogHandle) {
    let handle = LogHandle(Arc::new(Retention {
        state: Mutex::new(State {
            report: Report {
                phase: Phase::NotStarted,
                reader: ReaderState::Unassigned,
                run: RunState::Pending,
                peer_closed: false,
                root_reaped: false,
                issues: Vec::new(),
                streams: Vec::new(),
                rpc_issues: Vec::new(),
            },
            stop_at: None,
            mapping: None,
        }),
        changed: Notify::new(),
        lease: AtomicU8::new(STARTUP),
        options,
        drain,
        rpc: Mutex::new(None),
        capture: std::sync::OnceLock::new(),
    }));
    (
        LogSink {
            handle: handle.clone(),
            transferred: false,
            prepared: None,
            #[cfg(feature = "test-guest-log")]
            fixture: None,
        },
        handle,
    )
}

impl LogHandle {
    pub fn cursor(&self, incarnation: u64) -> LogCursor {
        LogCursor {
            handle: self.clone(),
            incarnation,
            offset: 0,
        }
    }
    pub fn snapshot(&self) -> Report {
        let mut report = self.0.state.lock().unwrap().report.clone();
        if let Some(capture) = self.0.capture.get() {
            report.phase = if capture.publication_finalized() {
                Phase::Incomplete
            } else {
                Phase::Collecting
            };
        }
        if let Some(rpc) = &*self.0.rpc.lock().unwrap() {
            report.rpc_issues = rpc.snapshot();
        }
        report
    }
    pub fn retain_rpc(&self, monitor: crate::RpcIssueMonitor) -> io::Result<()> {
        let mut rpc = self.0.rpc.lock().unwrap();
        if rpc.is_some() {
            return Err(io::Error::other("log RPC monitor already installed"));
        }
        *rpc = Some(monitor);
        Ok(())
    }
    pub fn options(&self) -> Options {
        self.0.options
    }
    pub fn stopped(&self) -> bool {
        self.0.state.lock().unwrap().stop_at.is_some()
    }
    pub fn issue(&self, kind: IssueKind, message: impl ToString) {
        self.issue_with_origin(kind, message, IssueOrigin::Integrity);
    }
    fn issue_with_origin(&self, kind: IssueKind, message: impl ToString, origin: IssueOrigin) {
        // Latch before conversion, deduplication or bounded diagnostic omission.
        if let Some(capture) = self.0.capture.get() {
            if matches!(origin, IssueOrigin::Integrity) {
                capture.latch_integrity_fault(match kind {
                    IssueKind::Startup | IssueKind::Child => IntegrityFault::OwnedChild,
                    IssueKind::Cancelled | IssueKind::Interrupted | IssueKind::Cutoff => {
                        IntegrityFault::CancellationOrDeadline
                    }
                    IssueKind::Protocol => IntegrityFault::Collector,
                    IssueKind::Producer => IntegrityFault::Lifecycle,
                    IssueKind::Rpc => IntegrityFault::Rpc,
                    IssueKind::Publication | IssueKind::Truncated => IntegrityFault::Publication,
                    IssueKind::Cleanup => IntegrityFault::Teardown,
                });
            }
        }
        let mut state = self.0.state.lock().unwrap();
        {
            let mut message = message.to_string();
            if let Some(capture) = self.0.capture.get() {
                if state.report.issues.len() >= 32 {
                    capture.latch_integrity_fault(IntegrityFault::MissingEvidence);
                    let _ = capture.omitted_issues.try_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |count| count.checked_add(1),
                    );
                    return;
                }
                if message.len() > 1024 {
                    capture.latch_integrity_fault(IntegrityFault::MissingEvidence);
                    let mut boundary = 1024;
                    while !message.is_char_boundary(boundary) {
                        boundary -= 1;
                    }
                    message.truncate(boundary);
                    let _ = capture.omitted_issues.try_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |count| count.checked_add(1),
                    );
                }
            }
            if !state
                .report
                .issues
                .iter()
                .any(|issue| issue.kind == kind && issue.message == message)
            {
                state.report.issues.push(Issue { kind, message });
            }
        }
        drop(state);
        self.0.changed.notify_waiters();
    }
    pub fn run_state(&self, run: RunState) {
        let mut state = self.0.state.lock().unwrap();
        if !matches!(
            state.report.run,
            RunState::Failed | RunState::Cancelled | RunState::Interrupted
        ) {
            state.report.run = run;
        }
        drop(state);
        self.0.changed.notify_waiters();
    }
    pub fn root_reaped(&self) {
        self.0.state.lock().unwrap().report.root_reaped = true;
    }

    /// Synchronous and level-triggered, including before queued workers run.
    pub fn stop(&self, kind: IssueKind, message: impl ToString) {
        self.stop_with_origin(kind, message, IssueOrigin::Integrity);
    }
    fn stop_with_origin(&self, kind: IssueKind, message: impl ToString, origin: IssueOrigin) {
        self.issue_with_origin(kind, message, origin);
        if let Some(capture) = self.0.capture.get() {
            self.0
                .state
                .lock()
                .unwrap()
                .stop_at
                .get_or_insert_with(Instant::now);
            capture.stop_guest();
            self.0.changed.notify_waiters();
            return;
        }
        let mut state = self.0.state.lock().unwrap();
        state.stop_at.get_or_insert_with(Instant::now);
        if let Some(mapping) = &state.mapping {
            mapping.stop();
        }
        let lease = self.0.lease.load(Ordering::Acquire);
        if lease < RUNNING
            && self
                .0
                .lease
                .compare_exchange(lease, FINAL, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            state.report.phase = Phase::Incomplete;
        } else if !state.report.terminal() {
            state.report.phase = Phase::Draining;
        }
        drop(state);
        self.0.changed.notify_waiters();
    }

    /// Wait before launching an independently scheduled producer. Queued collectors
    /// are revocable without draining; only readiness transfers draining ownership.
    pub async fn ready(&self) -> io::Result<()> {
        loop {
            if self
                .0
                .capture
                .get()
                .is_some_and(|capture| capture.guest_stopped())
            {
                return Err(io::Error::other("prepared capture startup closed"));
            }
            let notified = self.0.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.0.state.lock().unwrap();
                if state.stop_at.is_some() || state.report.terminal() {
                    return Err(io::Error::other("guest-log startup stopped"));
                }
                if state.report.reader == ReaderState::Ready {
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    pub async fn finished(&self) -> Report {
        loop {
            let notified = self.0.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let report = self.snapshot();
            if report.terminal() {
                return report;
            }
            notified.await;
        }
    }

    pub async fn stopping(&self) {
        loop {
            let notified = self.0.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.stopped() {
                return;
            }
            notified.await;
        }
    }

    /// Per-producer cursor; no scan-order merge or host timestamp is implied.
    pub fn delta(&self, incarnation: u64, offset: usize) -> io::Result<Vec<u8>> {
        let state = self.0.state.lock().unwrap();
        let stream = state
            .report
            .streams
            .iter()
            .find(|stream| stream.incarnation == incarnation)
            .ok_or_else(|| io::Error::other("unknown guest-log stream"))?;
        stream
            .bytes
            .get(offset..)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| io::Error::other("invalid guest-log cursor"))
    }
}

impl LogSink {
    pub fn take_prepared_endpoint(&mut self) -> io::Result<Option<UnixStream>> {
        if self.handle.0.capture.get().is_none() {
            return Ok(None);
        }
        if self.handle.stopped()
            || self
                .handle
                .0
                .capture
                .get()
                .is_some_and(|capture| capture.guest_stopped())
        {
            return Err(io::Error::other("prepared guest startup stopped"));
        }
        let endpoint = self
            .prepared
            .take()
            .ok_or_else(|| io::Error::other("prepared endpoint already transferred"))?;
        self.transferred = true;
        Ok(Some(endpoint))
    }
    #[cfg(feature = "test-guest-log")]
    pub fn fixture_control(&self) -> Option<Arc<fixture::Control>> {
        self.fixture.clone()
    }
    #[cfg(feature = "test-guest-log")]
    pub fn with_fixture_control(mut self, control: Arc<fixture::Control>) -> Self {
        self.fixture = Some(control);
        self
    }
    pub fn handle(&self) -> LogHandle {
        self.handle.clone()
    }
    /// Attach the sole V3 collector to a trusted lifetime endpoint.
    ///
    /// # Safety
    /// The endpoint must belong to a channel governed by this module's shared
    /// memory and process-ownership contract. All backing aliases must preserve
    /// immutable layout and protocol ownership for the collector's full lifetime.
    /// No other collector may consume this channel. The caller must retain guest
    /// lifetime endpoints and coordinate startup/cancellation with all writers.
    ///
    /// ```compile_fail,E0133
    /// use reverie_rpc_transport::guest_log as g;
    /// fn requires_ownership_contract(sink: g::LogSink, socket: std::os::unix::net::UnixStream) {
    ///     let _ = sink.reader(socket);
    /// }
    /// ```
    pub unsafe fn reader(mut self, socket: UnixStream) -> io::Result<Collector> {
        if self.handle.0.capture.get().is_some() {
            return Err(io::Error::other(
                "prepared capture already owns its collector",
            ));
        }
        let mapping = Arc::new(unsafe { SharedBuffer::receive(socket.as_raw_fd()) }?);
        if mapping.options() != self.handle.options() {
            return Err(io::Error::other("guest-log budget mismatch"));
        }
        {
            let mut state = self.handle.0.state.lock().unwrap();
            self.handle
                .0
                .lease
                .compare_exchange(STARTUP, QUEUED, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| io::Error::other("guest-log startup cancelled"))?;
            state.mapping = Some(mapping.clone());
            state.report.reader = ReaderState::Queued;
        }
        self.handle.0.changed.notify_waiters();
        self.transferred = true;
        Ok(Collector {
            socket,
            mapping,
            handle: self.handle.clone(),
            finalized: false,
            #[cfg(feature = "test-guest-log")]
            fixture: self.fixture.take(),
        })
    }
}

impl Drop for LogSink {
    fn drop(&mut self) {
        if !self.transferred {
            self.handle
                .stop(IssueKind::Interrupted, "log startup owner dropped");
        }
    }
}

/// Created before scheduling its worker. The queued permit can be revoked without
/// relying on a saturated blocking pool to execute or destroy the closure.
pub struct Collector {
    socket: UnixStream,
    mapping: Arc<SharedBuffer>,
    handle: LogHandle,
    finalized: bool,
    #[cfg(feature = "test-guest-log")]
    fixture: Option<Arc<fixture::Control>>,
}

#[derive(Default)]
struct Decoded {
    next: u64,
    length: Option<usize>,
    stream: Stream,
    failed: bool,
}

impl Decoded {
    fn accept(&mut self, frame: buffer::Frame, budget: &mut usize) -> io::Result<()> {
        let invalid = || io::Error::other("invalid shared guest-log record sequence/length");
        if self.next == 0 {
            self.next = 1;
        }
        if self.stream.finished || frame.sequence != self.next || frame.length as usize > PAYLOAD {
            return Err(invalid());
        }
        match frame.kind {
            buffer::BEGIN if self.length.is_none() && frame.length == 0 && frame.offset == 0 => {
                let length = usize::try_from(frame.total).map_err(|_| invalid())?;
                *budget = budget.checked_sub(length).ok_or_else(invalid)?;
                self.length = Some(length);
                self.stream.fragment_sequence = Some(frame.sequence);
            }
            buffer::DATA => {
                let length = self.length.ok_or_else(invalid)?;
                if frame.total != length as u64
                    || frame.offset != self.stream.fragment.len() as u64
                    || frame.length == 0
                    || frame.length as usize > length.saturating_sub(self.stream.fragment.len())
                {
                    return Err(invalid());
                }
                self.stream
                    .fragment
                    .extend_from_slice(&frame.payload[..frame.length as usize]);
            }
            buffer::END => {
                let length = self.length.ok_or_else(invalid)?;
                if frame.length != 0
                    || frame.total != length as u64
                    || frame.offset != length as u64
                    || self.stream.fragment.len() != length
                {
                    return Err(invalid());
                }
                self.stream.bytes.append(&mut self.stream.fragment);
                self.stream.fragment_sequence = None;
                self.stream.complete_records += 1;
                self.length = None;
                self.next = self.next.checked_add(1).ok_or_else(invalid)?;
            }
            buffer::FINISH
                if self.length.is_none()
                    && frame.length == 0
                    && frame.total == 0
                    && frame.offset == 0 =>
            {
                self.stream.finished = true
            }
            _ => return Err(invalid()),
        }
        Ok(())
    }
}

fn peer_closed(socket: &UnixStream) -> io::Result<bool> {
    let mut byte = 0u8;
    let mut vector = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    let result = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
    if result < 0 {
        let error = io::Error::last_os_error();
        return if matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            Ok(false)
        } else {
            Err(error)
        };
    }
    if result != 0 || message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other("unexpected lifetime-channel packet"));
    }
    Ok(true)
}

impl Collector {
    pub fn run(mut self) -> Report {
        if self
            .handle
            .0
            .lease
            .compare_exchange(QUEUED, RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.finalized = true;
            return self.handle.snapshot();
        }
        let mut decoded: Vec<Decoded> = (0..self.handle.options().producers)
            .map(|_| Decoded::default())
            .collect();
        {
            let mut state = self.handle.0.state.lock().unwrap();
            if state.stop_at.is_none() {
                state.report.phase = Phase::Collecting;
            }
            state.report.reader = ReaderState::Ready;
        }
        self.handle.0.changed.notify_waiters();
        let mut closed = false;
        let mut invalid = false;
        let mut budget = self.handle.options().byte_limit;
        loop {
            let failure = self.mapping.failure();
            if failure != 0 {
                self.handle.stop(
                    if failure & buffer::TRUNCATED != 0 {
                        IssueKind::Truncated
                    } else {
                        IssueKind::Producer
                    },
                    "guest-log sticky producer failure",
                );
            }
            match peer_closed(&self.socket) {
                Ok(value) => closed |= value,
                Err(error) => {
                    self.handle.stop(IssueKind::Protocol, error);
                    invalid = true;
                }
            }
            let mut any = false;
            let mut consumed = [false; 64];
            #[cfg(feature = "test-guest-log")]
            let gated = !self.handle.stopped()
                && !closed
                && decoded
                    .iter()
                    .any(|entry| entry.stream.complete_records != 0)
                && self.fixture.as_ref().is_some_and(|control| control.gated());
            #[cfg(feature = "test-guest-log")]
            if gated {
                self.fixture.as_ref().unwrap().mark_gated();
            }
            for (index, decoder) in decoded
                .iter_mut()
                .enumerate()
                .take(self.mapping.allocated())
            {
                #[cfg(feature = "test-guest-log")]
                if gated {
                    continue;
                }
                let channel = self.mapping.channel(index);
                if decoder.failed {
                    decoder.stream.unread_frames = channel
                        .head
                        .load(Ordering::Acquire)
                        .saturating_sub(channel.tail.load(Ordering::Acquire));
                    continue;
                }
                let status = channel.state.load(Ordering::Acquire);
                if !matches!(status, buffer::ACTIVE | buffer::FINISHED) {
                    continue;
                }
                decoder.stream.incarnation = index as u64 + 1;
                decoder.stream.pid = channel.pid.load(Ordering::Acquire);
                decoder.stream.parent = u64::from(channel.parent.load(Ordering::Acquire));
                match self.mapping.read(index) {
                    Ok(Some(frame)) => {
                        any = true;
                        if let Err(error) = decoder.accept(frame, &mut budget) {
                            decoder.stream.rejected_frame = Some(RejectedFrame::capture(frame));
                            self.handle.stop(
                                IssueKind::Protocol,
                                format!("producer {}: {error}", index + 1),
                            );
                            invalid = true;
                            decoder.failed = true;
                        }
                        consumed[index] = true;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        self.handle.stop(IssueKind::Protocol, format!("{error:?}"));
                        invalid = true;
                        decoder.failed = true;
                    }
                }
            }
            {
                let mut state = self.handle.0.state.lock().unwrap();
                state.report.peer_closed = closed;
                state.report.streams = decoded
                    .iter()
                    .filter(|entry| entry.stream.incarnation != 0)
                    .map(|entry| entry.stream.clone())
                    .collect();
            }
            self.handle.0.changed.notify_waiters();
            for (index, consumed) in consumed.iter().enumerate() {
                if *consumed {
                    self.mapping.consume(index);
                }
            }
            let cutoff = self
                .handle
                .0
                .state
                .lock()
                .unwrap()
                .stop_at
                .is_some_and(|time| time.elapsed() >= self.handle.0.drain);
            if cutoff || (closed && !any) {
                if cutoff && !closed {
                    self.handle.issue(
                        IssueKind::Cutoff,
                        "log lifetime did not close within stop deadline",
                    );
                }
                let complete = closed
                    && !invalid
                    && !cutoff
                    && self.mapping.failure() == 0
                    && self.complete(&decoded);
                if !complete {
                    self.handle.issue(
                        IssueKind::Protocol,
                        "missing producer registration/terminal record or forced cutoff",
                    );
                }
                let mut state = self.handle.0.state.lock().unwrap();
                state.report.phase = if complete && state.stop_at.is_none() {
                    Phase::Complete
                } else {
                    Phase::Incomplete
                };
                state.mapping = None;
                self.handle.0.lease.store(FINAL, Ordering::Release);
                self.finalized = true;
                drop(state);
                self.handle.0.changed.notify_waiters();
                return self.handle.snapshot();
            }
            if !any {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn complete(&self, decoded: &[Decoded]) -> bool {
        (0..self.mapping.allocated()).all(|index| {
            let channel = self.mapping.channel(index);
            let state = channel.state.load(Ordering::Acquire);
            if index != 0 && state == buffer::CANCELLED_FORK {
                return channel.fork_result.load(Ordering::Acquire) == u64::MAX;
            }
            state == buffer::FINISHED
                && channel.pid.load(Ordering::Acquire) != 0
                && channel.fork_result.load(Ordering::Acquire)
                    == channel.pid.load(Ordering::Acquire)
                && channel.head.load(Ordering::Acquire) == channel.tail.load(Ordering::Acquire)
                && channel.head.load(Ordering::Acquire)
                    == channel.terminal_head.load(Ordering::Acquire)
                && decoded[index].stream.finished
                && decoded[index].length.is_none()
                && channel.terminal_sequence.load(Ordering::Acquire) == decoded[index].next
        })
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        if !self.finalized {
            self.handle
                .stop(IssueKind::Interrupted, "collector owner interrupted");
            let mut state = self.handle.0.state.lock().unwrap();
            state.report.phase = Phase::Incomplete;
            state.mapping = None;
            self.handle.0.lease.store(FINAL, Ordering::Release);
            drop(state);
            self.handle.0.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests;
