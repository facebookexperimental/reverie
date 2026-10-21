use std::io;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::JoinHandle;
use std::time::Duration;

use super::MappedAbort;
use super::MappedFailure;

const RECHECK: Duration = Duration::from_millis(100);

/// The notification worker's failure, recorded after its thread was joined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappedWorkerFailure {
    /// A custom Waker or the notification worker panicked.
    Panicked,
    /// The shared futex wait failed. The original OS error is retained.
    Io {
        kind: io::ErrorKind,
        raw_os_error: Option<i32>,
    },
}
impl From<io::Error> for MappedWorkerFailure {
    fn from(error: io::Error) -> Self {
        Self::Io {
            kind: error.kind(),
            raw_os_error: error.raw_os_error(),
        }
    }
}
type Outcome = Result<(), MappedWorkerFailure>;

/// Cleanup of the joining helper, separately from notification-worker join.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappedHelperFailure {
    /// The helper panicked, including before its private entry.
    Panicked,
    /// A panic payload's destructor panicked; its secondary payload was retained
    /// without destruction to contain a second arbitrary destructor panic.
    PanicPayloadLeaked,
}
type Cleanup = Result<(), MappedHelperFailure>;

/// Actual cleanup of either reaper handle assigned to startup recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappedReaperCleanup {
    NotRequired,
    Pending,
    Joined,
    Panicked,
    PanicPayloadLeaked,
}

struct Observation<T> {
    result: Mutex<Option<T>>,
    changed: Condvar,
}
impl<T: Copy> Observation<T> {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            changed: Condvar::new(),
        }
    }
    fn get(&self) -> Option<T> {
        *self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn wait(&self, timeout: Duration) -> Option<T> {
        let result = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (result, _) = self
            .changed
            .wait_timeout_while(result, timeout, |r| r.is_none())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *result
    }
    fn publish(&self, value: T) {
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(result.is_none(), "completion published twice");
        *result = Some(value);
        self.changed.notify_all();
    }
}

/// Observes actual notification-thread join, independently of stream Drop.
///
/// Each connection has a notification thread and a dedicated Rust joining
/// helper. `result` is published by that helper only after actual worker join,
/// including native TLS destruction. It does not mean the helper has finished.
/// Use `helper_result` for its separate reclamation boundary. Release task
/// locks and allow custom callbacks to return before waiting. These observations
/// certify neither peer-process exit nor the shared reaper's own reclamation.
#[derive(Clone)]
pub struct MappedCompletion {
    state: Arc<CompletionState>,
}
struct CompletionState {
    worker: Observation<Outcome>,
    helper: Observation<Cleanup>,
    leaked: AtomicBool,
    reapers: Mutex<[MappedReaperCleanup; 2]>,
}
impl MappedCompletion {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(CompletionState {
                worker: Observation::new(),
                helper: Observation::new(),
                leaked: AtomicBool::new(false),
                reapers: Mutex::new([MappedReaperCleanup::NotRequired; 2]),
            }),
        }
    }
    /// None until the notification thread has actually been joined.
    pub fn result(&self) -> Option<Outcome> {
        self.state.worker.get()
    }
    /// Wait for notification-thread join. Never hold a lock needed by a Waker.
    pub fn wait_timeout(&self, timeout: Duration) -> Option<Outcome> {
        self.state.worker.wait(timeout)
    }
    /// None while helper execution, native TLS, joining or payload disposal is
    /// pending. A failed startup can retain a handle at rest until a later
    /// successful constructor starts the resource reaper; no automatic cleanup
    /// is promised in that case.
    pub fn helper_result(&self) -> Option<Cleanup> {
        self.state.helper.get()
    }
    /// Wait separately for actual helper join and retained payload disposal.
    pub fn wait_helper_timeout(&self, timeout: Duration) -> Option<Cleanup> {
        self.state.helper.wait(timeout)
    }
    /// Startup recovery's current and retiring reapers, in that order. Pending
    /// remains pending through native TLS and payload disposal. This reports
    /// recovery ownership only, not the active resource reaper's eventual exit.
    pub fn reaper_recovery(&self) -> [MappedReaperCleanup; 2] {
        *self
            .state
            .reapers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn complete(&self, outcome: Outcome) {
        self.state.worker.publish(outcome);
    }
    pub(super) fn record_payload_leak(&self) {
        self.state.leaked.store(true, Ordering::Release);
    }
}

/// The stage where asynchronous adapter construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappedStartStage {
    HelperSpawn,
    HelperReadiness,
    ReaperSpawn,
    ReaperReadiness,
    WorkerSpawn,
    WorkerReadiness,
}

/// An inspectable startup error, available through `io::Error::get_ref` and
/// `downcast_ref`. No adapter was published. Its completion handle preserves
/// cleanup observations even if a started helper is still running or retained.
#[derive(Debug)]
pub struct MappedStartError {
    stage: MappedStartStage,
    cause: io::Error,
    completion: MappedCompletion,
}
impl std::fmt::Debug for MappedCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappedCompletion")
            .field("worker", &self.result())
            .field("helper", &self.helper_result())
            .finish()
    }
}
impl MappedStartError {
    pub fn stage(&self) -> MappedStartStage {
        self.stage
    }
    pub fn completion(&self) -> MappedCompletion {
        self.completion.clone()
    }
}
impl std::fmt::Display for MappedStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mapped RPC {:?}: {}", self.stage, self.cause)
    }
}
impl std::error::Error for MappedStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

pub(super) struct Ready {
    record: Arc<Record>,
}
impl Ready {
    /// Called only after the notification closure installed its containment and
    /// Waker drain path. Until then the constructor cannot publish the adapter.
    pub(super) fn mark(self) {
        let mut state = self
            .record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!state.worker_ready);
        state.worker_ready = true;
        self.record.changed.notify_all();
    }
}

struct Record {
    state: Mutex<RecordState>,
    changed: Condvar,
    completion: MappedCompletion,
    stopped: Arc<AtomicBool>,
    abort: Option<MappedAbort>,
}
struct RecordState {
    helper: Option<JoinHandle<Cleanup>>,
    helper_joining: bool,
    helper_started: bool,
    helper_ready: bool,
    helper_failed_start: bool,
    worker_ready: bool,
    worker_failed_start: bool,
    assignment: Assignment,
}
enum Assignment {
    Waiting,
    Worker(JoinHandle<Outcome>),
    Abandoned,
    Recovery(ReaperHandles),
    Taken,
}
struct ReaperHandles {
    current: Option<JoinHandle<()>>,
    retiring: Option<JoinHandle<()>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    Starting,
    Running,
    Recovering,
}
struct ReaperStart {
    entered: AtomicBool,
    cancelled: AtomicBool,
}
struct State {
    records: Vec<Arc<Record>>,
    reservations: usize,
    current: Option<JoinHandle<()>>,
    retiring: Option<JoinHandle<()>>,
    phase: Phase,
    start: Option<Arc<ReaperStart>>,
    // Handles local to the recovery helper remain counted until actual join.
    recovering_current: bool,
    recovering_retiring: bool,
    reaper_panics: usize,
    reaper_payload_leaks: usize,
}
impl Default for State {
    fn default() -> Self {
        Self {
            records: Vec::new(),
            reservations: 0,
            current: None,
            retiring: None,
            phase: Phase::Idle,
            start: None,
            recovering_current: false,
            recovering_retiring: false,
            reaper_panics: 0,
            reaper_payload_leaks: 0,
        }
    }
}
#[derive(Default)]
struct Registry {
    state: Mutex<State>,
    changed: Condvar,
    #[cfg(test)]
    hooks: tests::Hooks,
}

/// Local returned handles are handed to preallocated shared cells on unwind.
/// Drop never joins and never calls user code.
struct Constructor {
    registry: Arc<Registry>,
    record: Arc<Record>,
    helper: Option<JoinHandle<Cleanup>>,
    worker: Option<JoinHandle<Outcome>>,
    reaper: Option<JoinHandle<()>>,
    owns_start: bool,
    published: bool,
}
impl Constructor {
    fn handoff_helper(&mut self) {
        if let Some(handle) = self.helper.take() {
            let mut state = self
                .record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(state.helper.is_none() && !state.helper_joining);
            state.helper_started = true;
            state.helper = Some(handle);
            self.registry.changed.notify_all();
        }
    }
    fn handoff_reaper(&mut self) {
        if let Some(handle) = self.reaper.take() {
            let mut state = self
                .registry
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(state.phase, Phase::Starting);
            assert!(state.current.is_none());
            state.current = Some(handle);
            self.registry.changed.notify_all();
        }
    }
    fn handoff_worker(&mut self) {
        if let Some(handle) = self.worker.take() {
            let mut state = self
                .record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(matches!(state.assignment, Assignment::Waiting));
            state.assignment = Assignment::Worker(handle);
            self.record.changed.notify_all();
        }
    }
    fn error(&self, stage: MappedStartStage, cause: io::Error) -> io::Error {
        io::Error::new(
            cause.kind(),
            MappedStartError {
                stage,
                cause,
                completion: self.record.completion.clone(),
            },
        )
    }
}
impl Drop for Constructor {
    fn drop(&mut self) {
        self.handoff_helper();
        self.handoff_reaper();
        self.handoff_worker();
        let mut registry = self
            .registry
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.published {
            self.record.stopped.store(true, Ordering::Release);
            if let Some(abort) = &self.record.abort {
                abort.abort(MappedFailure::PeerFailed);
            }
            if self.owns_start {
                assert_eq!(registry.phase, Phase::Starting);
                registry
                    .start
                    .as_ref()
                    .unwrap()
                    .cancelled
                    .store(true, Ordering::Release);
                if registry.current.is_some() {
                    assert!(state.helper_ready);
                    assert!(matches!(state.assignment, Assignment::Waiting));
                    registry.phase = Phase::Recovering;
                    registry.recovering_current = registry.current.is_some();
                    registry.recovering_retiring = registry.retiring.is_some();
                    *self
                        .record
                        .completion
                        .state
                        .reapers
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = [
                        MappedReaperCleanup::Pending,
                        if registry.retiring.is_some() {
                            MappedReaperCleanup::Pending
                        } else {
                            MappedReaperCleanup::NotRequired
                        },
                    ];
                    state.assignment = Assignment::Recovery(ReaperHandles {
                        current: registry.current.take(),
                        retiring: registry.retiring.take(),
                    });
                } else {
                    // The reaper spawn itself failed: there is no new handle.
                    registry.current = registry.retiring.take();
                    registry.phase = Phase::Idle;
                    registry.start = None;
                }
            }
            if matches!(state.assignment, Assignment::Waiting) {
                state.assignment = Assignment::Abandoned;
            }
            self.record.changed.notify_all();
        }
        registry.reservations -= 1;
        if !state.helper_started {
            // Spawn Err produced no handle. No worker exists at this stage.
            assert!(!state.helper_ready);
            registry
                .records
                .retain(|record| !Arc::ptr_eq(record, &self.record));
        }
        self.registry.changed.notify_all();
    }
}

pub(super) fn spawn(
    work: impl FnOnce(Ready) -> Outcome + Send + 'static,
    completion: MappedCompletion,
    stopped: Arc<AtomicBool>,
    abort: Option<MappedAbort>,
) -> io::Result<MappedCompletion> {
    static REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();
    REGISTRY
        .get_or_init(Default::default)
        .spawn(work, completion, stopped, abort)
}

impl Registry {
    fn spawn(
        self: &Arc<Self>,
        work: impl FnOnce(Ready) -> Outcome + Send + 'static,
        completion: MappedCompletion,
        stopped: Arc<AtomicBool>,
        abort: Option<MappedAbort>,
    ) -> io::Result<MappedCompletion> {
        let record = Arc::new(Record {
            state: Mutex::new(RecordState {
                helper: None,
                helper_joining: false,
                helper_started: false,
                helper_ready: false,
                helper_failed_start: false,
                worker_ready: false,
                worker_failed_start: false,
                assignment: Assignment::Waiting,
            }),
            changed: Condvar::new(),
            completion,
            stopped,
            abort,
        });
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.records.try_reserve(1).map_err(io::Error::other)?;
            state.reservations = state
                .reservations
                .checked_add(1)
                .expect("constructor reservation overflow");
            state.records.push(record.clone());
        }
        let mut owner = Constructor {
            registry: self.clone(),
            record: record.clone(),
            helper: None,
            worker: None,
            reaper: None,
            owns_start: false,
            published: false,
        };
        #[cfg(test)]
        self.hooks.at(tests::Point::Reserved);
        let registry = self.clone();
        let helper_record = record.clone();
        #[cfg(test)]
        self.hooks
            .spawn_error(tests::Point::HelperSpawn)
            .map_err(|e| owner.error(MappedStartStage::HelperSpawn, e))?;
        owner.helper = Some(
            std::thread::Builder::new()
                .name("reverie-rpc-join".into())
                .spawn(move || registry.helper(helper_record))
                .map_err(|e| owner.error(MappedStartStage::HelperSpawn, e))?,
        );
        #[cfg(test)]
        self.hooks.at(tests::Point::HelperReturned);
        owner.handoff_helper();
        #[cfg(test)]
        self.hooks.at(tests::Point::HelperHandedOff);
        {
            let mut state = record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !state.helper_ready {
                if state.helper_failed_start
                    || state.helper.as_ref().is_some_and(JoinHandle::is_finished)
                {
                    state.helper_failed_start = true;
                    return Err(owner.error(
                        MappedStartStage::HelperReadiness,
                        io::Error::other("helper ended before readiness"),
                    ));
                }
                state = record
                    .changed
                    .wait_timeout(state, RECHECK)
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .0;
            }
        }
        self.ensure_reaper(&mut owner)?;
        #[cfg(test)]
        self.hooks.at(tests::Point::BeforeWorker);
        #[cfg(test)]
        self.hooks
            .spawn_error(tests::Point::WorkerSpawn)
            .map_err(|e| owner.error(MappedStartStage::WorkerSpawn, e))?;
        let worker_registry = self.clone();
        let worker_record = record.clone();
        owner.worker = Some(
            std::thread::Builder::new()
                .name("reverie-rpc-wake".into())
                .spawn(move || {
                    #[cfg(test)]
                    worker_registry.hooks.at(tests::Point::WorkerEntry);
                    let _ = worker_registry;
                    work(Ready {
                        record: worker_record,
                    })
                })
                .map_err(|e| owner.error(MappedStartStage::WorkerSpawn, e))?,
        );
        #[cfg(test)]
        self.hooks.at(tests::Point::WorkerReturned);
        owner.handoff_worker();
        #[cfg(test)]
        self.hooks.at(tests::Point::WorkerHandedOff);
        {
            let mut state = record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !state.worker_ready {
                if state.worker_failed_start {
                    return Err(owner.error(
                        MappedStartStage::WorkerReadiness,
                        io::Error::other("notification worker ended before readiness"),
                    ));
                }
                state = record
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        let completion = record.completion.clone();
        #[cfg(test)]
        self.hooks.at(tests::Point::BeforePublication);
        owner.published = true;
        Ok(completion)
    }

    fn ensure_reaper(self: &Arc<Self>, owner: &mut Constructor) -> io::Result<()> {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                match state.phase {
                    Phase::Running => return Ok(()),
                    Phase::Idle => {
                        assert!(state.retiring.is_none());
                        assert!(!state.recovering_current && !state.recovering_retiring);
                        state.retiring = state.current.take();
                        state.phase = Phase::Starting;
                        state.start = Some(Arc::new(ReaperStart {
                            entered: AtomicBool::new(false),
                            cancelled: AtomicBool::new(false),
                        }));
                        owner.owns_start = true;
                        break;
                    }
                    Phase::Starting | Phase::Recovering => {
                        state = self
                            .changed
                            .wait(state)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                }
            }
        }
        let start = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .start
            .as_ref()
            .unwrap()
            .clone();
        #[cfg(test)]
        self.hooks.at(tests::Point::ReaperReserved);
        #[cfg(test)]
        self.hooks
            .spawn_error(tests::Point::ReaperSpawn)
            .map_err(|e| owner.error(MappedStartStage::ReaperSpawn, e))?;
        let registry = self.clone();
        let entry_start = start.clone();
        owner.reaper = Some(
            std::thread::Builder::new()
                .name("reverie-rpc-reap".into())
                .spawn(move || registry.reap(entry_start))
                .map_err(|e| owner.error(MappedStartStage::ReaperSpawn, e))?,
        );
        #[cfg(test)]
        self.hooks.at(tests::Point::ReaperReturned);
        owner.handoff_reaper();
        #[cfg(test)]
        self.hooks.at(tests::Point::ReaperHandedOff);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !start.entered.load(Ordering::Acquire) {
            if state.current.as_ref().unwrap().is_finished() {
                return Err(owner.error(
                    MappedStartStage::ReaperReadiness,
                    io::Error::other("reaper ended before readiness"),
                ));
            }
            state = self
                .changed
                .wait_timeout(state, RECHECK)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
        state.phase = Phase::Running;
        owner.owns_start = false;
        self.changed.notify_all();
        Ok(())
    }

    fn helper(self: &Arc<Self>, record: Arc<Record>) -> Cleanup {
        #[cfg(test)]
        self.hooks.at(tests::Point::HelperEntry);
        // The assignment guard in helper_assignment is installed before it
        // publishes readiness, including on a resumed cleanup after unwind.
        let mut panicked = false;
        loop {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.helper_assignment(&record)
            })) {
                Ok(()) => break,
                Err(payload) => {
                    panicked = true;
                    if discard_panic(Some(payload)) {
                        record.completion.record_payload_leak();
                    }
                    let state = record
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if matches!(state.assignment, Assignment::Taken) {
                        break;
                    }
                }
            }
        }
        if record.completion.state.leaked.load(Ordering::Acquire) {
            Err(MappedHelperFailure::PanicPayloadLeaked)
        } else if panicked {
            Err(MappedHelperFailure::Panicked)
        } else {
            Ok(())
        }
    }

    fn helper_assignment(self: &Arc<Self>, record: &Arc<Record>) {
        let mut assigned = AssignedWorker {
            record: record.clone(),
            handle: None,
        };
        let mut state = record
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.helper_ready = true;
        record.changed.notify_all();
        while matches!(state.assignment, Assignment::Waiting) {
            state = record
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        let assignment = std::mem::replace(&mut state.assignment, Assignment::Taken);
        drop(state);
        match assignment {
            Assignment::Worker(handle) => {
                assigned.handle = Some(handle);
                {
                    let mut state = record
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    while !state.worker_ready {
                        if assigned.handle.as_ref().unwrap().is_finished() {
                            // This says entry cannot become ready later, not that
                            // native TLS or actual join has completed.
                            state.worker_failed_start = true;
                            record.changed.notify_all();
                            break;
                        }
                        state = record
                            .changed
                            .wait_timeout(state, RECHECK)
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .0;
                    }
                }
                // An internal unwind restores this permission to the record;
                // the outer private entry catches it and resumes cleanup.
                #[cfg(test)]
                self.hooks.at(tests::Point::BeforeJoin);
                let (outcome, payload) = match assigned.handle.take().unwrap().join() {
                    Ok(outcome) => (outcome, None),
                    Err(payload) => {
                        if let Some(abort) = &record.abort {
                            abort.abort(MappedFailure::PeerFailed);
                        }
                        (Err(MappedWorkerFailure::Panicked), Some(payload))
                    }
                };
                record.completion.complete(outcome);
                if discard_panic(payload) {
                    record.completion.record_payload_leak();
                }
            }
            Assignment::Abandoned => {}
            Assignment::Recovery(handles) => self.recover(handles, record),
            Assignment::Waiting | Assignment::Taken => {
                unreachable!("helper assignment consumed twice")
            }
        }
        #[cfg(test)]
        self.hooks.at(tests::Point::HelperAfterWorker);
    }

    fn recover(&self, handles: ReaperHandles, record: &Arc<Record>) {
        let mut owned = AssignedReapers {
            handles,
            record: record.clone(),
        };
        // These are reaper handles, never notification-worker handles. Recovery
        // cannot delay another dedicated helper's worker-result publication.
        if let Some(handle) = owned.handles.current.take() {
            let result = self.join_reaper(handle);
            if result == MappedReaperCleanup::PanicPayloadLeaked {
                record.completion.record_payload_leak();
            }
            record
                .completion
                .state
                .reapers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[0] = result;
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recovering_current = false;
        }
        if let Some(handle) = owned.handles.retiring.take() {
            let result = self.join_reaper(handle);
            if result == MappedReaperCleanup::PanicPayloadLeaked {
                record.completion.record_payload_leak();
            }
            record
                .completion
                .state
                .reapers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)[1] = result;
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recovering_retiring = false;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(state.phase, Phase::Recovering);
        assert!(state.current.is_none() && state.retiring.is_none());
        assert!(!state.recovering_current && !state.recovering_retiring);
        state.start = None;
        state.phase = Phase::Idle;
        self.changed.notify_all();
        // No automatic retry. Our own helper handle remains a visible pending
        // record until a later successful constructor supplies a resource reaper.
    }

    fn join_reaper(&self, handle: JoinHandle<()>) -> MappedReaperCleanup {
        let payload = handle.join().err();
        let panicked = payload.is_some();
        let leaked = discard_panic(payload);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.reaper_panics = state.reaper_panics.saturating_add(usize::from(panicked));
        state.reaper_payload_leaks = state
            .reaper_payload_leaks
            .saturating_add(usize::from(leaked));
        if leaked {
            MappedReaperCleanup::PanicPayloadLeaked
        } else if panicked {
            MappedReaperCleanup::Panicked
        } else {
            MappedReaperCleanup::Joined
        }
    }

    fn reap(&self, start: Arc<ReaperStart>) {
        #[cfg(test)]
        self.hooks.at(tests::Point::ReaperEntry);
        start.entered.store(true, Ordering::Release);
        self.changed.notify_all();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while state.phase == Phase::Starting && !start.cancelled.load(Ordering::Acquire) {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        if start.cancelled.load(Ordering::Acquire) {
            return;
        }
        drop(state);
        loop {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(state.phase, Phase::Running);
            let finished = state.records.iter().find_map(|record| {
                let mut rs = record
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if rs.helper.as_ref().is_some_and(JoinHandle::is_finished) {
                    // Publish startup failure before a possibly blocking join.
                    if !rs.helper_ready {
                        rs.helper_failed_start = true;
                        record.changed.notify_all();
                    }
                    rs.helper_joining = true;
                    Some((record.clone(), rs.helper.take().unwrap()))
                } else {
                    None
                }
            });
            if let Some((record, handle)) = finished {
                drop(state);
                let (mut result, payload) = match handle.join() {
                    Ok(result) => (result, None),
                    Err(payload) => (Err(MappedHelperFailure::Panicked), Some(payload)),
                };
                if discard_panic(payload) {
                    result = Err(MappedHelperFailure::PanicPayloadLeaked);
                }
                record.completion.state.helper.publish(result);
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                record
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .helper_joining = false;
                state.records.retain(|r| !Arc::ptr_eq(r, &record));
                self.changed.notify_all();
                continue;
            }
            if state.retiring.as_ref().is_some_and(JoinHandle::is_finished) {
                let handle = state.retiring.take().unwrap();
                // Keep the retiring ownership counted during native TLS and
                // panic-payload disposal, so this generation cannot retire.
                state.recovering_retiring = true;
                drop(state);
                self.join_reaper(handle);
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.recovering_retiring = false;
                continue;
            }
            if state.records.is_empty() && state.reservations == 0 && state.retiring.is_none() {
                assert!(!state.recovering_current && !state.recovering_retiring);
                state.phase = Phase::Idle;
                state.start = None;
                drop(state);
                #[cfg(test)]
                self.hooks.at(tests::Point::ReaperExit);
                return;
            }
            let _ = self
                .changed
                .wait_timeout(state, RECHECK)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

struct AssignedReapers {
    handles: ReaperHandles,
    record: Arc<Record>,
}
impl Drop for AssignedReapers {
    fn drop(&mut self) {
        if self.handles.current.is_some() || self.handles.retiring.is_some() {
            let mut state = self
                .record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(matches!(state.assignment, Assignment::Taken));
            state.assignment = Assignment::Recovery(ReaperHandles {
                current: self.handles.current.take(),
                retiring: self.handles.retiring.take(),
            });
        }
    }
}

struct AssignedWorker {
    record: Arc<Record>,
    handle: Option<JoinHandle<Outcome>>,
}
impl Drop for AssignedWorker {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let mut state = self
                .record
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(matches!(state.assignment, Assignment::Taken));
            state.assignment = Assignment::Worker(handle);
            self.record.changed.notify_all();
        }
    }
}

/// Returns true when a secondary panic payload had to be retained undestroyed.
pub(super) fn discard_panic(payload: Option<Box<dyn std::any::Any + Send>>) -> bool {
    if let Err(second) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(second);
        true
    } else {
        false
    }
}

#[cfg(test)]
#[path = "workers/tests.rs"]
mod tests;
