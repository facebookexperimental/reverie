use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::Weak;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;
use std::time::Instant;

pub use ordered::RecordCommit;
pub use plan::InertCapturePlan;
pub use publication::Attempt as PublicationAttempt;
pub use publication::Report as PublicationReport;

use super::IssueKind;
use super::LogHandle;
use super::LogSink;
use super::Phase;
use super::PublishError;
use super::ReaderState;
use super::Retention;
use super::RunState;
use super::Stream;
use super::ordered;

mod plan;
mod split;
pub use split::*;
pub(crate) mod publication;

#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub producers: usize,
    pub slots_per_producer: usize,
    pub max_record_bytes: usize,
    pub host_pending_bytes: usize,
    pub guest_pending_bytes: usize,
    pub pending_records: usize,
    pub diagnostic_bytes: usize,
}

impl CaptureLimits {
    fn ordered(self) -> ordered::Limits {
        ordered::Limits {
            producers: self.producers,
            slots: self.slots_per_producer,
            max_record_bytes: self.max_record_bytes,
            host_pending_bytes: self.host_pending_bytes,
            guest_pending_bytes: self.guest_pending_bytes,
            pending_records: self.pending_records,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureTimeouts {
    pub startup: Duration,
    pub blocked_publication: Duration,
    pub final_drain: Duration,
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureOptions {
    pub limits: CaptureLimits,
    pub timeouts: CaptureTimeouts,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DestinationProgress {
    pub acknowledged_data_bytes: u64,
    pub discarded_bytes: u64,
    pub marker_bytes: u64,
    pub marker_complete: bool,
    pub marker_failed: bool,
    pub output_ceiling: bool,
}

pub trait CaptureDestination: io::Write + Send + 'static {
    fn progress(&self) -> DestinationProgress;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactStability {
    Stable,
    MayAppend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestStopReason {
    Cancelled,
    Failed,
    Interrupted,
}

#[derive(Clone, Debug)]
pub struct GuestReport {
    pub phase: Phase,
    pub run: RunState,
    pub root_reaped: bool,
    pub peer_closed: bool,
    pub issues: Vec<super::Issue>,
    pub rpc_issues: Vec<crate::ConnectionIssue>,
}

impl GuestReport {
    pub fn terminal(&self) -> bool {
        matches!(self.phase, Phase::Complete | Phase::Incomplete)
    }
}

#[derive(Clone, Debug)]
pub struct CaptureReport {
    pub guest: GuestReport,
    pub host: ordered::Admission,
    pub guest_admission: ordered::Admission,
    pub active_host_calls: usize,
    pub late_host_writes: u64,
    pub commits_observed: bool,
    pub collector_finished: bool,
    pub publication: PublicationReport,
    pub error: Option<String>,
    pub streams: Vec<Stream>,
    pub omitted_diagnostic_bytes: u64,
    pub omitted_issues: u64,
}

impl CaptureReport {
    pub fn qualifies(&self) -> bool {
        self.guest.phase == Phase::Complete
            && self.guest.run == RunState::Succeeded
            && self.guest.root_reaped
            && self.guest.peer_closed
            && self.guest.issues.is_empty()
            && self.guest.rpc_issues.is_empty()
            && self.host.closed
            && self.host.entrants == 0
            && self.guest_admission.closed
            && self.guest_admission.entrants == 0
            && self.active_host_calls == 0
            && self.late_host_writes == 0
            && self.commits_observed
            && self.collector_finished
            && self.error.is_none()
            && self.publication.error.is_none()
            && self.publication.drained
            && self.publication.stability == ArtifactStability::Stable
            && self.omitted_issues == 0
            && !self.publication.progress.output_ceiling
            && !self.publication.progress.marker_failed
    }
}

pub struct CaptureStartError {
    pub cause: io::Error,
    pub handle: Option<LogHandle>,
}

impl std::fmt::Debug for CaptureStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CaptureStartError")
            .field("cause", &self.cause)
            .field("has_evidence", &self.handle.is_some())
            .finish()
    }
}
impl std::fmt::Display for CaptureStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.cause.fmt(formatter)
    }
}
impl std::error::Error for CaptureStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
impl From<io::Error> for CaptureStartError {
    fn from(cause: io::Error) -> Self {
        Self {
            cause,
            handle: None,
        }
    }
}

struct State {
    ready: bool,
    guest_phase: Phase,
    peer_closed: bool,
    guest_stop: Option<Instant>,
    deadline: Option<Instant>,
    commits_observed: bool,
    collector_finished: bool,
    collector_witness: Option<CollectorWitness>,
    error: Option<String>,
    streams: Vec<Stream>,
    omitted_diagnostic_bytes: u64,
}

// Raw facts retained by the actual finalizing collector, independent of the
// legacy phase (which also incorporates guest exit policy).
#[derive(Clone, Copy)]
struct CollectorWitness {
    peer_closed: bool,
    guest_complete: bool,
    host_complete: bool,
    commits_observed: bool,
    host: ordered::Admission,
    guest: ordered::Admission,
    active_host_calls: usize,
    late_host_writes: u64,
    normal_return: bool,
}

impl CollectorWitness {
    fn complete(self) -> bool {
        self.peer_closed
            && self.guest_complete
            && self.host_complete
            && self.commits_observed
            && self.host.closed
            && self.host.entrants == 0
            && self.guest.closed
            && self.guest.entrants == 0
            && self.active_host_calls == 0
            && self.late_host_writes == 0
            && self.normal_return
    }
}

pub(super) struct Shared {
    retention: Weak<Retention>,
    options: CaptureOptions,
    buffer: Arc<ordered::Buffer>,
    publication: publication::Publication,
    state: Mutex<State>,
    host: Option<Mutex<ordered::Writer>>,
    split: Option<Arc<split::lifecycle::Lifecycle>>,
    collector_join: Mutex<Option<bool>>,
    host_complete: std::sync::atomic::AtomicBool,
    active_host_calls: AtomicUsize,
    late_host_writes: AtomicU64,
    pub(super) omitted_issues: AtomicU64,
    integrity_faults: AtomicU64,
    collector: Mutex<Option<JoinHandle<()>>>,
}

impl Shared {
    pub(super) fn guest_stopped(&self) -> bool {
        self.buffer.guest_stopped()
    }
    pub(super) fn publication_finalized(&self) -> bool {
        self.publication.snapshot().finalized
    }
    fn notify(&self) {
        if let Some(retention) = self.retention.upgrade() {
            retention.changed.notify_waiters();
        }
    }

    pub(super) fn stop_guest(&self) {
        self.buffer.close(ordered::Role::Guest);
        let mut state = self.state.lock().unwrap();
        state.guest_stop.get_or_insert_with(Instant::now);
        if !matches!(state.guest_phase, Phase::Complete | Phase::Incomplete) {
            state.guest_phase = Phase::Draining;
        }
        drop(state);
        self.notify();
    }

    fn fail(&self, message: &str) {
        self.latch_integrity_fault(IntegrityFault::SharedFailure);
        self.record_failure(message, super::IssueOrigin::Integrity);
    }

    pub(super) fn latch_integrity_fault(&self, fault: IntegrityFault) {
        self.integrity_faults
            .fetch_or(fault as u64, Ordering::AcqRel);
    }

    // Only the settled split lifecycle may select this origin. It preserves
    // every old issue/stop/first-message effect without calling exit 7 success.
    fn record_guest_outcome_policy_failure(&self) {
        self.record_failure(
            "split coordinator facts/teardown do not qualify",
            super::IssueOrigin::GuestOutcomePolicy,
        );
    }

    fn record_failure(&self, message: &str, origin: super::IssueOrigin) {
        self.state
            .lock()
            .unwrap()
            .error
            .get_or_insert_with(|| message.to_owned());
        if let Some(retention) = self.retention.upgrade() {
            LogHandle(retention).stop_with_origin(IssueKind::Publication, message, origin);
        } else {
            self.stop_guest();
        }
    }

    fn close(&self, deadline: Instant) {
        self.buffer.close(ordered::Role::Host);
        self.buffer.close(ordered::Role::Guest);
        let mut state = self.state.lock().unwrap();
        state.deadline = Some(state.deadline.map_or(deadline, |old| old.min(deadline)));
        drop(state);
        self.notify();
    }

    fn join_finished(&self) -> bool {
        let mut thread = self.collector.lock().unwrap();
        if thread.as_ref().is_some_and(|thread| thread.is_finished()) {
            *self.collector_join.lock().unwrap() = Some(thread.take().unwrap().join().is_ok());
        }
        thread.is_none()
    }
}

pub struct CaptureOwner {
    handle: LogHandle,
    shared: Arc<Shared>,
    finalized: bool,
}

#[derive(Clone)]
pub struct HostProducer {
    handle: LogHandle,
    shared: Arc<Shared>,
}

impl HostProducer {
    pub fn record_failed(&self) {
        self.shared
            .fail("host formatter failed before complete-record commit");
    }
    pub fn write_record(&self, bytes: &[u8]) -> Result<RecordCommit, PublishError> {
        let closed = || self.shared.buffer.admission(ordered::Role::Host).closed;
        if closed() {
            let _ = self.shared.late_host_writes.try_update(
                Ordering::AcqRel,
                Ordering::Acquire,
                |count| count.checked_add(1),
            );
            self.handle.issue(
                IssueKind::Publication,
                "host record attempted after capture close",
            );
            return Err(PublishError::Stopped);
        }
        self.shared.active_host_calls.fetch_add(1, Ordering::AcqRel);
        let result = self.write_inner(bytes);
        self.shared
            .active_host_calls
            .fetch_sub(1, Ordering::Release);
        if result.is_err() {
            self.shared.fail("host record did not commit");
        }
        result
    }

    fn write_inner(&self, bytes: &[u8]) -> Result<RecordCommit, PublishError> {
        let deadline = Instant::now() + self.shared.options.timeouts.blocked_publication;
        let mut writer = loop {
            if self.shared.buffer.admission(ordered::Role::Host).closed {
                return Err(PublishError::Stopped);
            }
            match self
                .shared
                .host
                .as_ref()
                .expect("local host writer")
                .try_lock()
            {
                Ok(writer) => break writer,
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(PublishError::Invalid),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Err(PublishError::Full);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        writer.write_record(bytes, |_, _| {
            if Instant::now() >= deadline {
                return Err(PublishError::Full);
            }
            std::thread::sleep(Duration::from_millis(1));
            Ok(())
        })
    }
}

impl CaptureOwner {
    pub fn handle(&self) -> LogHandle {
        self.handle.clone()
    }

    pub fn finish_until(&mut self, deadline: Instant) -> CaptureReport {
        self.shared.close(deadline);
        let deadline = self
            .shared
            .state
            .lock()
            .unwrap()
            .deadline
            .expect("installed deadline");
        while !self.shared.join_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        if !self.shared.join_finished() {
            self.shared.fail("collector unsettled at final deadline");
        }
        self.shared.publication.finish_until(deadline);
        self.shared.notify();
        self.finalized = true;
        self.handle.capture_snapshot().expect("prepared capture")
    }
}

impl Drop for CaptureOwner {
    fn drop(&mut self) {
        if !self.finalized {
            self.handle.issue(
                IssueKind::Interrupted,
                "capture owner dropped without explicit finalization",
            );
            self.shared.stop_guest();
            self.shared
                .close(Instant::now() + self.shared.options.timeouts.final_drain);
        }
    }
}

impl LogHandle {
    pub fn is_prepared_capture(&self) -> bool {
        self.0.capture.get().is_some()
    }

    pub fn capture_snapshot(&self) -> Option<CaptureReport> {
        let shared = self.0.capture.get()?;
        let legacy = self.snapshot();
        let state = shared.state.lock().unwrap();
        Some(CaptureReport {
            guest: GuestReport {
                phase: state.guest_phase,
                run: legacy.run,
                root_reaped: legacy.root_reaped,
                peer_closed: state.peer_closed,
                issues: legacy.issues,
                rpc_issues: legacy.rpc_issues,
            },
            host: shared.buffer.admission(ordered::Role::Host),
            guest_admission: shared.buffer.admission(ordered::Role::Guest),
            active_host_calls: shared.active_host_calls.load(Ordering::Acquire),
            late_host_writes: shared.late_host_writes.load(Ordering::Acquire),
            commits_observed: state.commits_observed,
            collector_finished: state.collector_finished,
            publication: shared.publication.snapshot(),
            error: state.error.clone(),
            streams: state.streams.clone(),
            omitted_diagnostic_bytes: state.omitted_diagnostic_bytes,
            omitted_issues: shared.omitted_issues.load(Ordering::Acquire),
        })
    }

    pub fn request_guest_stop(&self, reason: GuestStopReason) {
        let (kind, run) = match reason {
            GuestStopReason::Cancelled => (IssueKind::Cancelled, RunState::Cancelled),
            GuestStopReason::Failed => (IssueKind::Child, RunState::Failed),
            GuestStopReason::Interrupted => (IssueKind::Interrupted, RunState::Interrupted),
        };
        self.run_state(run);
        self.stop(kind, "guest domain stop requested");
    }

    pub async fn guest_finished(&self) -> GuestReport {
        loop {
            let notified = self.0.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(report) = self.capture_snapshot() {
                if report.guest.terminal() {
                    return report.guest;
                }
            } else {
                let report = self.finished().await;
                return GuestReport {
                    phase: report.phase,
                    run: report.run,
                    root_reaped: report.root_reaped,
                    peer_closed: report.peer_closed,
                    issues: report.issues,
                    rpc_issues: report.rpc_issues,
                };
            }
            notified.await;
        }
    }
}

/// Start the collector and destination worker before guest startup.
///
/// # Safety
/// The returned guest endpoint may be transferred only to trusted cooperating
/// writers under the [module contract](super). Every descriptor/mapping alias
/// must preserve initialized layout and the protocol for all capture workers'
/// lifetimes. Retain guest endpoints through admitted writer quiescence, and use
/// distinct fork incarnations. Do not fork and then use inherited host worker,
/// lock or producer state in the child. The owner must coordinate emitters,
/// actual process reap and finalization; setup closure alone is not completion.
///
/// ```compile_fail,E0133
/// use reverie_rpc_transport::guest_log as g;
/// fn requires_ownership_contract<D: g::CaptureDestination>(options: g::CaptureOptions, destination: D) {
///     let _ = g::prepared_capture(options, destination);
/// }
/// ```
pub unsafe fn prepared_capture<D: CaptureDestination>(
    options: CaptureOptions,
    destination: D,
) -> Result<(CaptureOwner, LogSink, HostProducer), CaptureStartError> {
    unsafe {
        prepared_capture_with(options, destination, |worker| {
            std::thread::Builder::new()
                .name("capture-collector".into())
                .spawn(worker)
        })
    }
}

unsafe fn prepared_capture_with<D: CaptureDestination>(
    options: CaptureOptions,
    destination: D,
    spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> io::Result<JoinHandle<()>>,
) -> Result<(CaptureOwner, LogSink, HostProducer), CaptureStartError> {
    let (plan, deadline) = unsafe { InertCapturePlan::for_startup(options) }?;
    let (options, buffer, host, guest) = plan.into_local_parts();
    let buffer = Arc::new(buffer);
    let writer = unsafe { buffer.activate(0, i64::from(std::process::id())) }
        .map_err(|_| io::Error::other("host registration failed"))?;
    let collector = buffer
        .collector()
        .map_err(|_| io::Error::other("collector registration failed"))?;
    let (mut sink, handle) = super::retained_log_with_drain(
        super::Options {
            byte_limit: options.limits.host_pending_bytes + options.limits.guest_pending_bytes,
            producers: options.limits.producers,
            slots: options.limits.slots_per_producer,
        },
        options.timeouts.final_drain,
    );
    let publication = publication::Publication::start(
        destination,
        options.limits.pending_records,
        options.limits.diagnostic_bytes,
        options.timeouts.blocked_publication,
    )
    .map_err(|cause| CaptureStartError {
        cause,
        handle: Some(handle.clone()),
    })?;
    let shared = Arc::new(Shared {
        retention: Arc::downgrade(&handle.0),
        options,
        buffer,
        publication,
        state: Mutex::new(State {
            ready: false,
            guest_phase: Phase::NotStarted,
            peer_closed: false,
            guest_stop: None,
            deadline: None,
            commits_observed: false,
            collector_finished: false,
            collector_witness: None,
            error: None,
            streams: Vec::new(),
            omitted_diagnostic_bytes: 0,
        }),
        host: Some(Mutex::new(writer)),
        split: None,
        collector_join: Mutex::new(None),
        host_complete: std::sync::atomic::AtomicBool::new(false),
        active_host_calls: AtomicUsize::new(0),
        late_host_writes: AtomicU64::new(0),
        omitted_issues: AtomicU64::new(0),
        integrity_faults: AtomicU64::new(0),
        collector: Mutex::new(None),
    });
    assert!(handle.0.capture.set(shared.clone()).is_ok());
    sink.prepared = Some(guest);
    let owner = CaptureOwner {
        handle: handle.clone(),
        shared: shared.clone(),
        finalized: false,
    };
    let worker = shared.clone();
    let thread = spawn(Box::new(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collect(&worker, host, collector)
        }));
        if result.is_err() {
            worker.fail("capture collector panicked");
        }
        let mut state = worker.state.lock().unwrap();
        if let Some(witness) = &mut state.collector_witness {
            witness.normal_return = result.is_ok();
        }
        state.collector_finished = true;
        if !matches!(state.guest_phase, Phase::Complete | Phase::Incomplete) {
            state.guest_phase = Phase::Incomplete;
        }
        drop(state);
        let deadline = worker
            .state
            .lock()
            .unwrap()
            .deadline
            .unwrap_or_else(|| Instant::now() + worker.options.timeouts.final_drain);
        worker.publication.finish_until(deadline);
        worker.notify();
    }));
    let thread = match thread {
        Ok(thread) => thread,
        Err(cause) => {
            handle.stop(IssueKind::Startup, &cause);
            shared.close(deadline);
            shared.publication.finish_until(deadline);
            shared.state.lock().unwrap().guest_phase = Phase::Incomplete;
            return Err(CaptureStartError {
                cause,
                handle: Some(handle),
            });
        }
    };
    *shared.collector.lock().unwrap() = Some(thread);
    if !shared.publication.wait_ready(deadline) {
        return Err(CaptureStartError {
            cause: io::Error::other("capture destination startup failed/deadline"),
            handle: Some(handle),
        });
    }
    while !shared.state.lock().unwrap().ready {
        if Instant::now() >= deadline || shared.join_finished() {
            return Err(CaptureStartError {
                cause: io::Error::other("capture collector startup failed/deadline"),
                handle: Some(handle),
            });
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    {
        let mut state = handle.0.state.lock().unwrap();
        state.report.reader = ReaderState::Ready;
        state.report.phase = Phase::Collecting;
    }
    let producer = HostProducer { handle, shared };
    Ok((owner, sink, producer))
}

fn collect(shared: &Shared, socket: UnixStream, mut collector: ordered::Collector) {
    shared.state.lock().unwrap().ready = true;
    shared.notify();
    let mut pending = None;
    loop {
        let now = Instant::now();
        if shared.buffer.guest_failed() {
            if let Some(retention) = shared.retention.upgrade() {
                LogHandle(retention)
                    .stop(IssueKind::Producer, "guest complete-record emission failed");
            } else {
                shared.stop_guest();
            }
        }
        let publication_failed = shared
            .publication
            .check_blocked(now, shared.options.timeouts.blocked_publication);
        if publication_failed {
            shared.fail("canonical destination publication failed");
        }
        if pending.is_none() {
            match collector.poll() {
                Ok(record) => pending = record,
                Err(_) => shared.fail("source ordered collection failed"),
            }
        }
        if let Some(record) = pending.take() {
            if publication_failed {
                shared.publication.discard(record);
            } else {
                pending = shared.publication.enqueue(record).err();
            }
        }
        let closed = match super::peer_closed(&socket) {
            Ok(closed) => closed,
            Err(_) => {
                shared.fail("guest lifetime endpoint protocol failure");
                false
            }
        };
        let (guest_cutoff, deadline) = {
            let state = shared.state.lock().unwrap();
            (
                state.guest_stop.is_some_and(|stop| {
                    now.saturating_duration_since(stop) >= shared.options.timeouts.final_drain
                }),
                state.deadline,
            )
        };
        if let Some(lifecycle) = &shared.split {
            let observed = lifecycle.snapshot();
            shared.active_host_calls.store(
                observed.entrants.try_into().unwrap_or(usize::MAX),
                Ordering::Release,
            );
            shared
                .late_host_writes
                .store(observed.late_writes, Ordering::Release);
            if observed.faulted {
                shared.fail("split coordinator lifecycle fault");
            }
        }
        let complete = closed && collector.guest_complete();
        let drained = closed && collector.guest_drained();
        if guest_cutoff && shared.buffer.unresolved_guest_commit() {
            shared.fail(
                "guest commit entrant unresolved at cutoff; ordered continuation unavailable",
            );
        }
        if closed {
            shared.buffer.close(ordered::Role::Guest);
        }
        {
            let mut state = shared.state.lock().unwrap();
            state.peer_closed = closed;
            if complete && state.guest_stop.is_none() {
                state.guest_phase = Phase::Complete;
            } else if guest_cutoff || drained || (closed && shared.buffer.order_failed()) {
                state.guest_phase = Phase::Incomplete;
                (state.streams, state.omitted_diagnostic_bytes) =
                    collector.diagnostics(shared.options.limits.diagnostic_bytes);
            }
        }
        shared.notify();
        let finalizing = shared.buffer.admission(ordered::Role::Host).closed;
        let observed = match collector.commits_observed() {
            Ok(observed) => observed,
            Err(_) => {
                shared.fail("source commit order has an unresolved hole");
                false
            }
        };
        let expired = deadline.is_some_and(|deadline| now >= deadline);
        if finalizing && ((observed && pending.is_none() && (drained || guest_cutoff)) || expired) {
            if expired && !(observed && pending.is_none() && complete) {
                shared.fail("capture final drain deadline exceeded");
            }
            let host_complete = collector.host_complete();
            shared.host_complete.store(host_complete, Ordering::Release);
            if shared.split.is_some() && !host_complete {
                shared.fail("split host has no complete FINISH");
            }
            if collector.host_partial() || shared.active_host_calls.load(Ordering::Acquire) != 0 {
                shared.fail("host emission incomplete at close");
            }
            let mut state = shared.state.lock().unwrap();
            state.commits_observed = observed && pending.is_none();
            state.collector_witness = Some(CollectorWitness {
                peer_closed: closed,
                guest_complete: complete,
                host_complete,
                commits_observed: observed && pending.is_none(),
                host: shared.buffer.admission(ordered::Role::Host),
                guest: shared.buffer.admission(ordered::Role::Guest),
                active_host_calls: shared.active_host_calls.load(Ordering::Acquire),
                late_host_writes: shared.late_host_writes.load(Ordering::Acquire),
                normal_return: false,
            });
            (state.streams, state.omitted_diagnostic_bytes) =
                collector.diagnostics(shared.options.limits.diagnostic_bytes);
            if !complete {
                state.guest_phase = Phase::Incomplete;
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests;
