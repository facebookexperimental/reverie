/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use super::InputUnavailable;
use super::ReservedInputImage;
use super::ReservedInputLayout;

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

/// Opaque run identity for local extension state; not a guest identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InputRunId(u64);

/// Authenticated descriptor-table creation edge. This is not a census or an
/// acquisition receipt; consumers snapshot their own history at this edge.
#[derive(Debug, Clone, Copy)]
pub struct InputFilesEvent {
    /// Exact source table owner at the native birth/exec cut.
    pub source: InputTaskRegistration,
    /// New child or replacement-image owner.
    pub destination: InputTaskRegistration,
    /// Native sharing proof. None conservatively unifies the lifetimes.
    pub shared: Option<bool>,
    /// True for an authenticated exec replacement (close-on-exec may remove FDs).
    pub exec: bool,
}

/// Synchronous local history observer. It runs outside registry locks, before
/// child/image publication. It cannot acquire a new native execution grant.
pub trait InputFilesObserver: std::fmt::Debug + Send + Sync {
    /// Snapshot/link Tool-owned history for this actual native edge.
    fn observe(
        &self,
        control: &ReservedInputControl,
        event: InputFilesEvent,
    ) -> Result<(), InputUnavailable>;
}

/// Native task incarnation. Numeric TID reuse cannot reproduce this identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputTaskId {
    run: u64,
    generation: u64,
    tid: i32,
}

impl InputTaskId {
    /// Physical task number, meaningful only with the retained generation.
    pub fn native_tid(self) -> i32 {
        self.tid
    }
    /// Run-local, non-reused native task generation.
    pub fn generation(self) -> u64 {
        self.generation
    }
}

/// Lifetime of one actual or conservatively unified native address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionLifetime {
    run: u64,
    generation: u64,
}

/// Lifetime of a native descriptor table, distinct from address-space sharing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileTableLifetime {
    run: u64,
    generation: u64,
}

/// Native thread-group incarnation, independent of a reusable TGID number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadGroupLifetime {
    run: u64,
    generation: u64,
}

/// Native registration supplied before the Tool publishes logical ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputTaskRegistration {
    /// Exact task incarnation.
    pub task: InputTaskId,
    /// Actual native thread number.
    pub native_tid: i32,
    /// Actual native thread-group number.
    pub native_pid: i32,
    /// Actual `Guest::tid()` bound by the constructed backend Tool view.
    /// Decoder-only native retention has no such binding yet.
    pub tool_tid: Option<i32>,
    /// Actual `Guest::pid()` from that same Tool view, not an inferred alias.
    pub tool_pid: Option<i32>,
    /// Retained native group incarnation.
    pub group: ThreadGroupLifetime,
    /// Retained creator, if this is a child.
    pub parent: Option<InputTaskId>,
    /// Actual or conservatively shared memory lifetime.
    pub region: RegionLifetime,
    /// Actual or conservatively shared descriptor-table lifetime.
    pub files: FileTableLifetime,
}

/// Existing Tool grant that authorizes a local operation scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputGrantKind {
    /// An ordinary live execution grant.
    Ordinary,
    /// The matching grant for an already-published pending operation barrier.
    PendingVfork {
        /// Tool operation identity retained across its existing barrier.
        logical_operation: u64,
    },
}

/// A consumed generation of actual Tool execution authority.
///
/// This is deliberately not Clone and cannot be constructed from task identity.
#[derive(Debug)]
pub struct InputOperationScope {
    control: ReservedInputControl,
    task: InputTaskId,
    grant: u64,
    logical_operation: u64,
}

impl InputOperationScope {
    /// Exact native task whose real grant authorized this operation.
    pub fn task(&self) -> InputTaskId {
        self.task
    }
    /// Tool's logical operation identity, independent of physical retries.
    pub fn logical_operation(&self) -> u64 {
        self.logical_operation
    }
}

/// Target of a Tool-declared memory access or persistent exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputTarget {
    /// A known native address-space lifetime.
    Region(RegionLifetime),
    /// The target cannot be bounded to an authenticated lifetime.
    Unknown,
}

/// Checked memory range, or a range that could not be determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSpan {
    /// Half-open byte range; constructors reject overflow.
    Range {
        /// First byte.
        address: u64,
        /// Number of bytes.
        length: u64,
    },
    /// This access's range is not proved.
    Unknown,
}

impl InputSpan {
    /// Construct a range without wrapping its end.
    pub fn range(address: u64, length: u64) -> Result<Self, InputUnavailable> {
        address
            .checked_add(length)
            .ok_or_else(|| InputUnavailable::new("input-access-range"))?;
        Ok(Self::Range { address, length })
    }
    fn overlaps(self, layout: ReservedInputLayout) -> bool {
        match self {
            Self::Unknown => true,
            Self::Range { address, length } => {
                length != 0
                    && address.checked_add(length).is_none_or(|end| {
                        address < layout.base + layout.page_bytes as u64 && end > layout.base
                    })
            }
        }
    }
}

/// Mechanism of the Tool-declared access. Classification belongs to the Tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAccessDirection {
    /// A native reader may observe input bytes.
    Read,
    /// Native copyout obeying normal mapping permissions.
    Write,
    /// Both native input and ordinary copyout.
    ReadWrite,
    /// A native writer may bypass ordinary mapping permissions.
    ForcedWrite,
}

/// Duration of the Tool-declared exposure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputAccessLifetime {
    /// Retained through physical completion, copyout and logical readmission.
    Transient,
    /// Monotone until the actual region/run ends.
    Persistent,
}

/// Complete policy declaration before a native operation can leave its grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputAccess {
    /// Actual target, or explicit uncertainty.
    pub target: InputTarget,
    /// Exact checked range, or explicit uncertainty.
    pub span: InputSpan,
    /// Read or privileged write.
    pub direction: InputAccessDirection,
    /// Required retention lifetime.
    pub lifetime: InputAccessLifetime,
    /// Opaque diagnostic owned by the Tool.
    pub cause: Arc<str>,
}

/// Registry-owned access obligation. Drop never retires it.
#[derive(Debug)]
pub struct InputAccessLease {
    run: u64,
    id: u64,
}

/// Opaque monotone cause supplied by the Tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputExposure {
    /// Affected lifetime, or whole-run uncertainty.
    pub target: InputTarget,
    /// Stable Tool-owned diagnostic.
    pub cause: Arc<str>,
}

/// Expected relationship, checked against actual native birth observations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputExpectedSharing {
    /// Expected address-space equality; None is unknown, not false.
    pub memory: Option<bool>,
    /// Expected descriptor-table equality; None is unknown, not false.
    pub files: Option<bool>,
    /// Whether this operation can create a native task at all.
    pub may_create: bool,
    /// Expected thread-group sharing; None is unproved.
    pub thread_group: Option<bool>,
}

/// Immutable input proof associated with a physical call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputCallInput {
    /// All relevant inputs are the immutable six register operands.
    Registers,
    /// Exact future bytes used by the prepared native attempt.
    Immutable {
        /// Guest address to which these bytes belong.
        address: u64,
        /// Retained immutable content, never a late guest-memory reread.
        bytes: Arc<[u8]>,
    },
    /// The original pointer input has no immutable lifetime proof.
    Unknown,
}

/// Description of one actual call, not a thread-global next-call annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalInjectionDescription {
    /// Native syscall number.
    pub number: u64,
    /// Exact native register operands.
    pub args: [u64; 6],
    /// Input ownership evidence.
    pub input: InputCallInput,
    /// Tool expectation; backend native checks establish actual sharing.
    pub expected_sharing: InputExpectedSharing,
    /// Pre-issue transient accesses retained until native completion/readmission.
    pub transient: Vec<InputAccess>,
    /// Prospective causes activated only by a retained birth/consumption.
    pub prospective: Vec<InputExposure>,
    /// Cause retained when a successful/uncertain call has no owned lifecycle.
    pub unknown_lifecycle: Option<InputExposure>,
}

/// Non-reused identity of one physical injection within its run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalInjectionId {
    run: u64,
    id: u64,
}

/// Consuming call-specific handle; the underlying obligation is backend-owned.
#[derive(Debug)]
pub struct PhysicalInjectionReceipt {
    control: ReservedInputControl,
    id: PhysicalInjectionId,
}

impl PhysicalInjectionReceipt {
    /// Retain an equality/query handle without cloning injection authority.
    pub fn id(&self) -> PhysicalInjectionId {
        self.id
    }
    /// Owning run facade, for backend transport only.
    pub fn control(&self) -> &ReservedInputControl {
        &self.control
    }
}

/// Native stage of a retained physical call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalInjectionState {
    /// Registered before provider/future preparation.
    Prepared,
    /// Actual native entry was issued.
    Issued,
    /// Backend retained the actual child before any callback or continuation.
    RetainedBirth(InputTaskId),
    /// An authenticated native completion established no child.
    ProvedNoChild,
    /// The actual lifecycle could not be authenticated.
    OutcomeUnknown,
}

/// Queryable immutable evidence after the consuming call handle moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhysicalInjectionObservation {
    /// Exact physical attempt.
    pub id: PhysicalInjectionId,
    /// Native state, not the Tool's returned logical result.
    pub state: PhysicalInjectionState,
    /// Complete image certified by final-stop write/readback, if any.
    pub verified_image: Option<ReservedInputImage>,
}

/// Native phase of a page transaction, retained independently of its future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputTransactionPhase {
    /// No page bytes have been written; normal preparation may yield.
    Preparing,
    /// All asynchronous preparation finished at an owned stop.
    PreparedStopped,
    /// At least one page write may have taken effect.
    Initializing,
    /// One bounded complete-image normalization is in progress.
    Normalizing,
    /// The complete future image was read back at the final stop.
    Ready,
    /// The prepared native entry is running or stopped inside the kernel.
    Launched,
}

/// A sticky cohort freeze. Dropping it does not thaw its members.
#[derive(Debug)]
pub struct InputFreezeCohort {
    run: u64,
    id: u64,
}

#[derive(Debug)]
struct Task {
    registration: InputTaskRegistration,
    grant: Option<(u64, InputGrantKind, bool)>,
    frozen: BTreeSet<u64>,
    native_terminal: bool,
    native_effects_complete: bool,
}

#[derive(Debug, Clone, Default)]
struct Region {
    layout: Option<ReservedInputLayout>,
    exposures: Vec<InputExposure>,
    transaction: Option<PhysicalInjectionId>,
}

#[derive(Debug)]
struct Access {
    task: InputTaskId,
    declaration: InputAccess,
    physical: Option<PhysicalInjectionId>,
    operation: Option<crate::native_syscall::NativeOperationCompletion>,
    native_complete: bool,
}

#[derive(Debug)]
struct Injection {
    task: InputTaskId,
    operation: u64,
    grant: u64,
    description: PhysicalInjectionDescription,
    state: PhysicalInjectionState,
    phase: Option<InputTransactionPhase>,
    image: Option<ReservedInputImage>,
    verified_image: Option<ReservedInputImage>,
}

#[derive(Debug, Default)]
struct State {
    next: u64,
    tasks: BTreeMap<InputTaskId, Task>,
    by_tid: BTreeMap<i32, InputTaskId>,
    regions: BTreeMap<RegionLifetime, Region>,
    accesses: BTreeMap<u64, Access>,
    injections: BTreeMap<PhysicalInjectionId, Injection>,
    freezes: BTreeMap<u64, BTreeSet<InputTaskId>>,
    global_exposures: Vec<InputExposure>,
    files_possibly_shared: BTreeMap<FileTableLifetime, bool>,
    groups_may_have_other_threads: BTreeMap<ThreadGroupLifetime, bool>,
    regions_may_have_other_processes: BTreeSet<RegionLifetime>,
    frozen_groups: BTreeMap<ThreadGroupLifetime, BTreeSet<u64>>,
    fatal: Option<String>,
}

impl State {
    fn next(&mut self) -> Result<u64, InputUnavailable> {
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| InputUnavailable::new("input-generation-exhausted"))?;
        Ok(self.next)
    }
    fn live(&self, task: InputTaskId) -> Result<&Task, InputUnavailable> {
        if self.fatal.is_some() {
            return Err(InputUnavailable::new("input-run-terminal"));
        }
        self.tasks
            .get(&task)
            .filter(|task| !task.native_terminal && !task.native_effects_complete)
            .ok_or_else(|| InputUnavailable::new("input-task-not-live"))
    }

    fn validate_access(&self, declaration: &InputAccess) -> Result<(), InputUnavailable> {
        if let InputSpan::Range { address, length } = declaration.span {
            InputSpan::range(address, length)?;
        }
        if let InputTarget::Region(region) = declaration.target
            && !self.regions.contains_key(&region)
        {
            return Err(InputUnavailable::new("input-target-identity"));
        }
        for (region_id, region) in &self.regions {
            let initialized = region.transaction.is_some_and(|id| {
                self.injections[&id].phase != Some(InputTransactionPhase::Preparing)
            });
            if initialized
                && match declaration.target {
                    InputTarget::Unknown => true,
                    InputTarget::Region(id) => id == *region_id,
                }
                && region
                    .layout
                    .is_some_and(|layout| declaration.span.overlaps(layout))
            {
                return Err(InputUnavailable::new("input-transaction-busy"));
            }
        }
        Ok(())
    }
}

/// A backend's read-only observer of retained native task generations.
/// It must not recapture a numeric task, resume, wait or enter Tool code.
/// The registry calls it only outside its leaf lock.
pub trait InputNativeExitObserver: std::fmt::Debug + Send + Sync {
    /// True proves this exact task's kernel exit effects ended, independently
    /// of final group wait/notifier retirement. False/error proves no exit.
    fn effects_complete(&self, task: InputTaskId) -> Result<bool, InputUnavailable>;
}

/// Run-owned leaf registry. State mutation never calls out or awaits. The
/// explicit native observation method releases the leaf lock before querying.
#[derive(Debug, Clone)]
pub struct ReservedInputControl {
    run: u64,
    state: Arc<Mutex<State>>,
    native_exit_observer: Arc<OnceLock<Arc<dyn InputNativeExitObserver>>>,
    files_observer: Arc<OnceLock<Arc<dyn InputFilesObserver>>>,
}

impl ReservedInputControl {
    /// Construct the backend's run registry before installing it in GlobalTool.
    /// This does not grant setup, stopped-task ownership or Tool execution.
    pub fn new_backend() -> Result<Self, InputUnavailable> {
        let run = NEXT_RUN
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| InputUnavailable::new("input-run-generation-exhausted"))?;
        Ok(Self {
            run,
            state: Arc::new(Mutex::new(State::default())),
            native_exit_observer: Arc::new(OnceLock::new()),
            files_observer: Arc::new(OnceLock::new()),
        })
    }

    /// Stable identity for local nonserialized extension state.
    pub fn run_identity(&self) -> InputRunId {
        InputRunId(self.run)
    }

    /// Install one local table-history observer before target registration.
    pub fn install_files_observer(
        &self,
        observer: Arc<dyn InputFilesObserver>,
    ) -> Result<(), InputUnavailable> {
        self.files_observer
            .set(observer)
            .map_err(|_| InputUnavailable::new("input-files-observer-already-installed"))
    }

    /// Backend-only: install the run's exact-generation native observer once.
    pub fn backend_install_exit_observer(
        &self,
        observer: Arc<dyn InputNativeExitObserver>,
    ) -> Result<(), InputUnavailable> {
        self.native_exit_observer
            .set(observer)
            .map_err(|_| InputUnavailable::new("input-exit-observer-already-installed"))
    }

    /// Observe native completion after an existing Tool fence, without waiting
    /// for group reap. True does not settle the logical fence or remove a native
    /// identity. The observer runs outside the leaf lock and can only report
    /// facts for a generation already retained by the backend.
    pub fn observe_exit_effects(&self, task: InputTaskId) -> Result<bool, InputUnavailable> {
        {
            let mut state = self.state.lock().unwrap();
            let owner = state
                .tasks
                .get(&task)
                .ok_or_else(|| InputUnavailable::new("input-task-not-owned"))?;
            if owner.native_effects_complete {
                return Ok(true);
            }
            if owner.native_terminal {
                // Physical death does not authenticate an unsettled image.
                // Retain the same failure that blocked terminal settlement.
                Self::effects_complete_locked(&mut state, task)?;
                return Ok(true);
            }
        }
        let observer = self
            .native_exit_observer
            .get()
            .ok_or_else(|| InputUnavailable::new("input-exit-observer-unavailable"))?;
        if !observer.effects_complete(task)? {
            return Ok(false);
        }
        let mut state = self.state.lock().unwrap();
        Self::effects_complete_locked(&mut state, task)?;
        Ok(true)
    }

    /// Resolve a currently retained native TID to its exact incarnation.
    pub fn task_identity(&self, native_tid: i32) -> Option<InputTaskId> {
        self.state.lock().unwrap().by_tid.get(&native_tid).copied()
    }

    /// Whether this actual table has a backend-proved private lifetime.
    /// The answer stays false after a possible sharing attempt, even if it fails.
    pub fn files_proven_unshared(&self, task: InputTaskId) -> bool {
        let state = self.state.lock().unwrap();
        state
            .tasks
            .get(&task)
            .and_then(|task| state.files_possibly_shared.get(&task.registration.files))
            == Some(&false)
    }

    /// Observe registration, grant and file-table proof in one leaf-lock read.
    pub fn native_syscall_authority(
        &self,
        task: InputTaskId,
    ) -> Result<crate::native_syscall::NativeSyscallAuthority, InputUnavailable> {
        let state = self.state.lock().unwrap();
        let task = state.live(task)?;
        Ok(crate::native_syscall::NativeSyscallAuthority {
            registration: task.registration,
            grant: task.grant.map(|(generation, kind, _)| (generation, kind)),
            files_proven_unshared: state.files_possibly_shared.get(&task.registration.files)
                == Some(&false),
        })
    }

    /// Return the current identity binding, without granting execution.
    pub fn registration(&self, task: InputTaskId) -> Option<InputTaskRegistration> {
        self.state
            .lock()
            .unwrap()
            .tasks
            .get(&task)
            .map(|task| task.registration)
    }

    /// Backend-only: bind the actual Tool view before any consuming callback.
    /// Rebinding the same image to a different Tool identity is refused.
    pub fn backend_bind_tool_identity(
        &self,
        task: InputTaskId,
        tid: i32,
        pid: i32,
    ) -> Result<InputTaskRegistration, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        state.live(task)?;
        let registration = &mut state.tasks.get_mut(&task).unwrap().registration;
        if registration.tool_tid.is_some_and(|old| old != tid)
            || registration.tool_pid.is_some_and(|old| old != pid)
        {
            return Err(InputUnavailable::new("input-tool-identity-conflict"));
        }
        registration.tool_tid = Some(tid);
        registration.tool_pid = Some(pid);
        Ok(*registration)
    }

    /// Publish an actual Tool grant at its existing authoritative boundary.
    pub fn grant(&self, task: InputTaskId, kind: InputGrantKind) -> Result<u64, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if !state.live(task)?.frozen.is_empty() {
            return Err(InputUnavailable::new("input-task-frozen"));
        }
        let generation = state.next()?;
        state.tasks.get_mut(&task).unwrap().grant = Some((generation, kind, false));
        Ok(generation)
    }

    /// Invalidate authority synchronously before its Tool grant is released.
    pub fn invalidate_operation(&self, task: InputTaskId) {
        if let Some(task) = self.state.lock().unwrap().tasks.get_mut(&task) {
            task.grant = None;
        }
    }

    /// Observe the actual current grant, without minting or renewing one.
    pub fn current_grant(&self, task: InputTaskId) -> Option<u64> {
        self.state
            .lock()
            .unwrap()
            .tasks
            .get(&task)
            .and_then(|task| task.grant.map(|grant| grant.0))
    }

    /// Authenticate the current grant for a backend's pre-release immutable
    /// request ticket. A missing, retired or frozen owner cannot bind a request;
    /// this neither consumes nor renews authority and is never used at issue to
    /// invent a new background grant.
    pub fn native_request_grant(&self, task: InputTaskId) -> Result<u64, InputUnavailable> {
        let state = self.state.lock().unwrap();
        let owner = state.live(task)?;
        if !owner.frozen.is_empty() {
            return Err(InputUnavailable::new("input-task-frozen"));
        }
        owner
            .grant
            .map(|grant| grant.0)
            .ok_or_else(|| InputUnavailable::new("input-no-execution-grant"))
    }

    /// Consume the current actual grant into one operation; never mints a grant.
    pub fn begin_operation(
        &self,
        task: InputTaskId,
        logical_operation: u64,
    ) -> Result<InputOperationScope, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let task_state = state.live(task)?;
        let (generation, kind, consumed) = task_state
            .grant
            .ok_or_else(|| InputUnavailable::new("input-no-execution-grant"))?;
        if consumed || !task_state.frozen.is_empty() {
            return Err(InputUnavailable::new("input-grant-unavailable"));
        }
        if matches!(kind, InputGrantKind::PendingVfork { logical_operation: pending } if pending != logical_operation)
        {
            return Err(InputUnavailable::new("input-barrier-operation-mismatch"));
        }
        state.tasks.get_mut(&task).unwrap().grant = Some((generation, kind, true));
        Ok(InputOperationScope {
            control: self.clone(),
            task,
            grant: generation,
            logical_operation,
        })
    }

    /// Acquire before native issue or a Tool release that can permit issue.
    pub fn acquire_access(
        &self,
        task: InputTaskId,
        declaration: InputAccess,
    ) -> Result<InputAccessLease, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        state.live(task)?;
        // Preparation still exposes the old complete page. A nested ordinary
        // access may register then; the final stopped scan must see it. Once
        // that scan has published write authority, new conflicting access
        // cannot race it.
        state.validate_access(&declaration)?;
        let id = state.next()?;
        state.accesses.insert(
            id,
            Access {
                task,
                declaration,
                physical: None,
                operation: None,
                native_complete: false,
            },
        );
        Ok(InputAccessLease { run: self.run, id })
    }

    /// Attach an access to exactly one already-registered physical call.
    pub fn attach_access(
        &self,
        lease: &InputAccessLease,
        receipt: &PhysicalInjectionReceipt,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if lease.run != self.run || receipt.id.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let task = state
            .injections
            .get(&receipt.id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?
            .task;
        let access = state
            .accesses
            .get_mut(&lease.id)
            .ok_or_else(|| InputUnavailable::new("input-access-missing"))?;
        if access.task != task || access.physical.is_some() || access.operation.is_some() {
            return Err(InputUnavailable::new("input-access-binding"));
        }
        access.physical = Some(receipt.id);
        Ok(())
    }

    /// Trusted Tool completion of an ordinary background operation after its
    /// native return and all copyout, before logical readmission. Never call on
    /// cancellation or Tool error. Physical-call and operation-bound leases
    /// instead require their exact native completion proof, so this cannot
    /// override an unsettled call or a closed-operation obligation.
    pub fn complete_access_after_return(
        &self,
        lease: &InputAccessLease,
        task: InputTaskId,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if lease.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let access = state
            .accesses
            .get_mut(&lease.id)
            .ok_or_else(|| InputUnavailable::new("input-access-missing"))?;
        if access.task != task || access.physical.is_some() || access.operation.is_some() {
            return Err(InputUnavailable::new("input-access-binding"));
        }
        access.native_complete = true;
        Ok(())
    }

    /// Bind this lease to one explicit operation before its native calls can
    /// escape the caller. The retained proof has no observer/control cycle.
    pub fn bind_access_operation(
        &self,
        lease: &InputAccessLease,
        task: InputTaskId,
        operation: &crate::native_syscall::NativeOperation,
    ) -> Result<(), InputUnavailable> {
        self.bind_access_completion(lease, task, &operation.completion())
    }

    /// Bind an observer-free completion handle for the same exact operation.
    /// This is useful for retained table-copy obligations without a strong cycle.
    pub fn bind_access_completion(
        &self,
        lease: &InputAccessLease,
        task: InputTaskId,
        completion: &crate::native_syscall::NativeOperationCompletion,
    ) -> Result<(), InputUnavailable> {
        if lease.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let proof = completion.clone();
        let mut state = self.state.lock().unwrap();
        let access = state
            .accesses
            .get_mut(&lease.id)
            .ok_or_else(|| InputUnavailable::new("input-access-missing"))?;
        if access.task != task || access.physical.is_some() {
            return Err(InputUnavailable::new("input-access-binding"));
        }
        if access
            .operation
            .as_ref()
            .is_some_and(|bound| !bound.same_operation(&proof))
        {
            return Err(InputUnavailable::new("input-operation-binding"));
        }
        access.operation = Some(proof);
        Ok(())
    }

    /// Mark native effects complete from this exact closed operation. This also
    /// supports cancelled callbacks when all attempts have affirmative native
    /// completion/no-issue proof. It does not retire the lease: matching logical
    /// readmission or the existing authenticated terminal fence still owns that.
    pub fn complete_access_after_operation(
        &self,
        lease: &InputAccessLease,
        task: InputTaskId,
        operation: &crate::native_syscall::NativeOperation,
    ) -> Result<(), InputUnavailable> {
        self.complete_access_after_completion(lease, task, &operation.completion())
    }

    /// Observer-free form of [`Self::complete_access_after_operation`], requiring
    /// the exact prebound completion handle and the same native-completion proof.
    pub fn complete_access_after_completion(
        &self,
        lease: &InputAccessLease,
        task: InputTaskId,
        completion: &crate::native_syscall::NativeOperationCompletion,
    ) -> Result<(), InputUnavailable> {
        if lease.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let proof = completion.clone();
        // Closed-and-complete is monotone. Do not nest the operation mutex under
        // the registry's leaf lock or invoke a Tool callback from it.
        if !proof.effects_complete() {
            return Err(InputUnavailable::new("input-native-operation-unsettled"));
        }
        let mut state = self.state.lock().unwrap();
        let access = state
            .accesses
            .get_mut(&lease.id)
            .ok_or_else(|| InputUnavailable::new("input-access-missing"))?;
        if access.task != task
            || access.physical.is_some()
            || !access
                .operation
                .as_ref()
                .is_some_and(|bound| bound.same_operation(&proof))
        {
            return Err(InputUnavailable::new("input-operation-binding"));
        }
        access.native_complete = true;
        Ok(())
    }

    /// Retire a completed transient access at its exact current readmission grant.
    pub fn readmit_access(
        &self,
        lease: InputAccessLease,
        task: InputTaskId,
        grant: u64,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if lease.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let owner = state.live(task)?;
        if !owner.frozen.is_empty() || owner.grant.map(|g| g.0) != Some(grant) {
            return Err(InputUnavailable::new("input-readmission-mismatch"));
        }
        let access = state
            .accesses
            .get(&lease.id)
            .ok_or_else(|| InputUnavailable::new("input-access-missing"))?;
        if access.task != task || !access.native_complete {
            return Err(InputUnavailable::new("input-native-access-unsettled"));
        }
        if access.declaration.lifetime == InputAccessLifetime::Transient {
            state.accesses.remove(&lease.id);
        }
        Ok(())
    }

    /// Add an irreversible exposure while preserving its actual target scope.
    pub fn add_exposure(&self, exposure: InputExposure) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        Self::add_exposure_locked(&mut state, exposure)
    }

    /// Backend-only: retain an unclassified effect before its continuation.
    /// Unlike a retrospective exposure, this must not cross a page transaction
    /// that already passed its final access scan. Check and publication share
    /// the same leaf lock: Preparing still has the old complete page and its
    /// final scan will see this cause; later phases are an ownership conflict.
    /// The caller must fail before the effect on error. This does not classify
    /// Linux behavior, acquire a grant, retire an owner, or wait for a writer.
    pub fn backend_expose_before_continuation(
        &self,
        task: InputTaskId,
        exposure: InputExposure,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        state.live(task)?;
        state.validate_access(&InputAccess {
            target: exposure.target,
            span: InputSpan::Unknown,
            direction: InputAccessDirection::ReadWrite,
            lifetime: InputAccessLifetime::Persistent,
            cause: exposure.cause.clone(),
        })?;
        Self::add_exposure_locked(&mut state, exposure)
    }

    fn add_exposure_locked(
        state: &mut State,
        exposure: InputExposure,
    ) -> Result<(), InputUnavailable> {
        match exposure.target {
            InputTarget::Unknown => state.global_exposures.push(exposure),
            InputTarget::Region(region) => state
                .regions
                .get_mut(&region)
                .ok_or_else(|| InputUnavailable::new("input-target-identity"))?
                .exposures
                .push(exposure),
        }
        Ok(())
    }

    /// Register a physical call before constructing its provider future.
    pub fn prepare_injection(
        &self,
        scope: &InputOperationScope,
        description: PhysicalInjectionDescription,
    ) -> Result<PhysicalInjectionReceipt, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        Self::validate_scope(self.run, &state, scope)?;
        let id = PhysicalInjectionId {
            run: self.run,
            id: state.next()?,
        };
        Self::attach_declared_accesses(&mut state, id, scope.task, &description)?;
        state.injections.insert(
            id,
            Injection {
                task: scope.task,
                operation: scope.logical_operation,
                grant: scope.grant,
                description,
                state: PhysicalInjectionState::Prepared,
                phase: None,
                image: None,
                verified_image: None,
            },
        );
        Ok(PhysicalInjectionReceipt {
            control: self.clone(),
            id,
        })
    }

    /// Register an unstaged physical call under the current actual grant.
    /// This does not require page admission and cannot mint execution authority.
    pub fn prepare_observed_injection(
        &self,
        task: InputTaskId,
        logical_operation: u64,
        description: PhysicalInjectionDescription,
    ) -> Result<PhysicalInjectionReceipt, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let owner = state.live(task)?;
        let grant = owner
            .grant
            .ok_or_else(|| InputUnavailable::new("input-no-execution-grant"))?
            .0;
        if !owner.frozen.is_empty() {
            return Err(InputUnavailable::new("input-task-frozen"));
        }
        let id = PhysicalInjectionId {
            run: self.run,
            id: state.next()?,
        };
        Self::attach_declared_accesses(&mut state, id, task, &description)?;
        state.injections.insert(
            id,
            Injection {
                task,
                operation: logical_operation,
                grant,
                description,
                state: PhysicalInjectionState::Prepared,
                phase: None,
                image: None,
                verified_image: None,
            },
        );
        Ok(PhysicalInjectionReceipt {
            control: self.clone(),
            id,
        })
    }

    fn attach_declared_accesses(
        state: &mut State,
        physical: PhysicalInjectionId,
        task: InputTaskId,
        description: &PhysicalInjectionDescription,
    ) -> Result<(), InputUnavailable> {
        if description.expected_sharing.may_create
            && description.expected_sharing.files != Some(false)
        {
            let files = state.tasks[&task].registration.files;
            state.files_possibly_shared.insert(files, true);
        }
        for declaration in &description.transient {
            if declaration.lifetime != InputAccessLifetime::Transient {
                return Err(InputUnavailable::new("input-call-access-not-transient"));
            }
            state.validate_access(declaration)?;
        }
        for declaration in &description.transient {
            let id = state.next()?;
            state.accesses.insert(
                id,
                Access {
                    task,
                    declaration: declaration.clone(),
                    physical: Some(physical),
                    operation: None,
                    native_complete: false,
                },
            );
        }
        Ok(())
    }

    /// Complete readmission of this call's declared transient accesses after
    /// native completion and Tool copyout. It never changes the current grant.
    pub fn readmit_injection(
        &self,
        id: PhysicalInjectionId,
        task: InputTaskId,
        grant: u64,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let owner = state.live(task)?;
        if !owner.frozen.is_empty() || owner.grant.map(|g| g.0) != Some(grant) {
            return Err(InputUnavailable::new("input-readmission-mismatch"));
        }
        let call = state
            .injections
            .get(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if call.task != task
            || matches!(
                call.state,
                PhysicalInjectionState::Prepared | PhysicalInjectionState::Issued
            )
            || state
                .accesses
                .values()
                .any(|a| a.physical == Some(id) && !a.native_complete)
        {
            return Err(InputUnavailable::new("input-native-access-unsettled"));
        }
        state.accesses.retain(|_, access| {
            access.physical != Some(id)
                || access.declaration.lifetime == InputAccessLifetime::Persistent
        });
        Ok(())
    }

    /// Finish one settled logical operation without renewing its existing grant.
    /// Cancellation must not use this to erase outstanding native work.
    pub fn finish_operation(&self, scope: InputOperationScope) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        Self::validate_scope(self.run, &state, &scope)?;
        if state.injections.values().any(|call| {
            call.task == scope.task
                && call.operation == scope.logical_operation
                && matches!(
                    call.state,
                    PhysicalInjectionState::Prepared | PhysicalInjectionState::Issued
                )
        }) {
            return Err(InputUnavailable::new("input-operation-unsettled"));
        }
        let grant = state
            .tasks
            .get_mut(&scope.task)
            .unwrap()
            .grant
            .as_mut()
            .unwrap();
        grant.2 = false;
        Ok(())
    }

    fn validate_scope(
        run: u64,
        state: &State,
        scope: &InputOperationScope,
    ) -> Result<(), InputUnavailable> {
        if scope.control.run != run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let task = state.live(scope.task)?;
        if task.grant.map(|grant| grant.0) != Some(scope.grant) || !task.frozen.is_empty() {
            return Err(InputUnavailable::new("input-operation-stale"));
        }
        Ok(())
    }

    /// Query retained evidence without recreating authority to issue the call.
    pub fn injection_observation(
        &self,
        id: PhysicalInjectionId,
    ) -> Option<PhysicalInjectionObservation> {
        self.state
            .lock()
            .unwrap()
            .injections
            .get(&id)
            .map(|call| PhysicalInjectionObservation {
                id,
                state: call.state,
                verified_image: call.verified_image.clone(),
            })
    }

    /// Freeze an exact native cohort before logical ownership is removed.
    pub fn freeze_tasks(
        &self,
        tasks: &[InputTaskId],
    ) -> Result<InputFreezeCohort, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        Self::freeze_locked(self.run, &mut state, tasks.iter().copied().collect())
    }

    fn freeze_locked(
        run: u64,
        state: &mut State,
        members: BTreeSet<InputTaskId>,
    ) -> Result<InputFreezeCohort, InputUnavailable> {
        if members
            .iter()
            .any(|task| task.run != run || !state.tasks.contains_key(task))
        {
            return Err(InputUnavailable::new("input-task-not-owned"));
        }
        let id = state.next()?;
        for task in &members {
            let task = state.tasks.get_mut(task).unwrap();
            task.frozen.insert(id);
            task.grant = None;
        }
        state.freezes.insert(id, members);
        Ok(InputFreezeCohort { run, id })
    }

    /// Freeze retained group victims before a yielding retirement operation.
    /// A survivor caller is excluded explicitly; later native group members
    /// join the same fence even if their registration follows logical removal.
    pub fn freeze_group(
        &self,
        task: InputTaskId,
        include_caller: bool,
    ) -> Result<InputFreezeCohort, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let group = state
            .tasks
            .get(&task)
            .ok_or_else(|| InputUnavailable::new("input-task-not-owned"))?
            .registration
            .group;
        let members = state
            .tasks
            .iter()
            .filter_map(|(id, owner)| {
                (owner.registration.group == group && (include_caller || *id != task))
                    .then_some(*id)
            })
            .collect();
        let cohort = Self::freeze_locked(self.run, &mut state, members)?;
        state
            .frozen_groups
            .entry(group)
            .or_default()
            .insert(cohort.id);
        Ok(cohort)
    }

    /// Retained backend terminal fact. Missing identity is not proof of death.
    pub fn native_terminal(&self, task: InputTaskId) -> Option<bool> {
        self.state
            .lock()
            .unwrap()
            .tasks
            .get(&task)
            .map(|owner| owner.native_terminal)
    }

    /// Retained exact membership for a synchronous no-effect decision.
    pub fn cohort_members(
        &self,
        cohort: &InputFreezeCohort,
    ) -> Result<Vec<InputTaskId>, InputUnavailable> {
        let state = self.state.lock().unwrap();
        if cohort.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        state
            .freezes
            .get(&cohort.id)
            .map(|tasks| tasks.iter().copied().collect())
            .ok_or_else(|| InputUnavailable::new("input-freeze-missing"))
    }

    /// Apply an existing all-accounted fence to complete matching cohorts only.
    /// No partial cohort or empty intent is thawed by this operation.
    pub fn settle_fenced_tasks(&self, fenced: &[InputTaskId]) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let fenced: BTreeSet<_> = fenced.iter().copied().collect();
        if fenced
            .iter()
            .any(|id| id.run != self.run || !state.tasks.contains_key(id))
        {
            return Err(InputUnavailable::new("input-task-not-owned"));
        }
        // A supplied fence is an assertion that these exact native task
        // generations are accounted for. Do not return success while silently
        // retaining one of their unsettled native accesses: the caller may
        // discard its fence handles after this method succeeds.
        if fenced
            .iter()
            .any(|task| !state.tasks[task].native_effects_complete)
            || state
                .accesses
                .values()
                .any(|access| fenced.contains(&access.task) && !access.native_complete)
        {
            return Err(InputUnavailable::new("input-cohort-native-unsettled"));
        }
        let completed: Vec<_> = state
            .freezes
            .iter()
            .filter_map(|(id, members)| {
                (!members.is_empty()
                    && members.is_subset(&fenced)
                    && members
                        .iter()
                        .all(|task| state.tasks[task].native_effects_complete)
                    && !state
                        .accesses
                        .values()
                        .any(|a| members.contains(&a.task) && !a.native_complete))
                .then_some(*id)
            })
            .collect();
        for id in completed {
            let members = state.freezes.remove(&id).unwrap();
            for group in state.frozen_groups.values_mut() {
                group.remove(&id);
            }
            for task in &members {
                state.tasks.get_mut(task).unwrap().frozen.remove(&id);
            }
            state.accesses.retain(|_, access| {
                !members.contains(&access.task)
                    || access.declaration.lifetime == InputAccessLifetime::Persistent
            });
        }
        Ok(())
    }

    /// Cancel only a positively established no-effect retirement intent.
    /// A native terminal observation makes this operation unavailable.
    pub fn cancel_freeze_before_effect(
        &self,
        cohort: InputFreezeCohort,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if cohort.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let tasks = state
            .freezes
            .get(&cohort.id)
            .ok_or_else(|| InputUnavailable::new("input-freeze-missing"))?;
        if tasks.iter().any(|task| {
            let owner = &state.tasks[task];
            owner.native_effects_complete || owner.native_terminal
        }) {
            return Err(InputUnavailable::new("input-retirement-has-native-effect"));
        }
        let tasks = state.freezes.remove(&cohort.id).unwrap();
        for freezes in state.frozen_groups.values_mut() {
            freezes.remove(&cohort.id);
        }
        for task in tasks {
            state
                .tasks
                .get_mut(&task)
                .unwrap()
                .frozen
                .remove(&cohort.id);
        }
        Ok(())
    }

    /// Consume the Tool's all-accounted cohort fence only after native settlement.
    /// An individual physical exit cannot call this as a substitute for that fence.
    pub fn settle_frozen_cohort(&self, cohort: InputFreezeCohort) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if cohort.run != self.run {
            return Err(InputUnavailable::new("input-run-mismatch"));
        }
        let tasks = state
            .freezes
            .get(&cohort.id)
            .ok_or_else(|| InputUnavailable::new("input-freeze-missing"))?;
        if tasks
            .iter()
            .any(|task| !state.tasks[task].native_effects_complete)
            || state
                .accesses
                .values()
                .any(|access| tasks.contains(&access.task) && !access.native_complete)
        {
            return Err(InputUnavailable::new("input-cohort-native-unsettled"));
        }
        let tasks = state.freezes.remove(&cohort.id).unwrap();
        for freezes in state.frozen_groups.values_mut() {
            freezes.remove(&cohort.id);
        }
        state.accesses.retain(|_, access| {
            !tasks.contains(&access.task)
                || access.declaration.lifetime == InputAccessLifetime::Persistent
        });
        for task in tasks {
            state
                .tasks
                .get_mut(&task)
                .unwrap()
                .frozen
                .remove(&cohort.id);
        }
        Ok(())
    }
}

impl ReservedInputControl {
    /// Backend-only: retain a freshly owned root before any Tool callback.
    pub fn backend_register_root(
        &self,
        tid: i32,
        pid: i32,
    ) -> Result<InputTaskRegistration, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if state.by_tid.contains_key(&tid) {
            return Err(InputUnavailable::new("input-task-already-owned"));
        }
        let task = InputTaskId {
            run: self.run,
            generation: state.next()?,
            tid,
        };
        let region = RegionLifetime {
            run: self.run,
            generation: state.next()?,
        };
        let files = FileTableLifetime {
            run: self.run,
            generation: state.next()?,
        };
        let group = ThreadGroupLifetime {
            run: self.run,
            generation: state.next()?,
        };
        let registration = InputTaskRegistration {
            task,
            native_tid: tid,
            native_pid: pid,
            tool_tid: None,
            tool_pid: None,
            group,
            parent: None,
            region,
            files,
        };
        state.regions.insert(region, Region::default());
        state.files_possibly_shared.insert(files, false);
        state
            .groups_may_have_other_threads
            .entry(group)
            .or_insert(false);
        state.by_tid.insert(tid, task);
        state.tasks.insert(
            task,
            Task {
                registration,
                grant: None,
                frozen: BTreeSet::new(),
                native_terminal: false,
                native_effects_complete: false,
            },
        );
        Ok(registration)
    }

    /// Backend-only: retain a newborn using actual native sharing observations.
    /// Unknown sharing conservatively retains the parent's lifetime.
    pub fn backend_register_child(
        &self,
        parent: InputTaskId,
        tid: i32,
        pid: i32,
        memory_shared: Option<bool>,
        files_shared: Option<bool>,
    ) -> Result<InputTaskRegistration, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let parent_state = state.live(parent)?;
        let parent_registration = parent_state.registration;
        let mut freezes = parent_state.frozen.clone();
        if let Some(existing) = state.by_tid.get(&tid) {
            let registration = state.tasks[existing].registration;
            return if registration.parent == Some(parent) && registration.native_pid == pid {
                Ok(registration)
            } else {
                Err(InputUnavailable::new("input-child-owner-conflict"))
            };
        }
        let region = if memory_shared == Some(false) {
            let region = RegionLifetime {
                run: self.run,
                generation: state.next()?,
            };
            let mut copied = state.regions[&parent_registration.region].clone();
            // Kernel consumption precedes this capture; no writer authority is copied.
            copied.transaction = None;
            for exposure in &mut copied.exposures {
                exposure.target = InputTarget::Region(region);
            }
            state.regions.insert(region, copied);
            region
        } else {
            parent_registration.region
        };
        let files = if files_shared == Some(false) {
            FileTableLifetime {
                run: self.run,
                generation: state.next()?,
            }
        } else {
            parent_registration.files
        };
        state
            .files_possibly_shared
            .insert(files, files_shared != Some(false));
        let task = InputTaskId {
            run: self.run,
            generation: state.next()?,
            tid,
        };
        let group = if pid == parent_registration.native_pid {
            parent_registration.group
        } else {
            ThreadGroupLifetime {
                run: self.run,
                generation: state.next()?,
            }
        };
        if let Some(group_freezes) = state.frozen_groups.get(&group) {
            freezes.extend(group_freezes.iter().copied());
        }
        let registration = InputTaskRegistration {
            task,
            native_tid: tid,
            native_pid: pid,
            tool_tid: None,
            tool_pid: None,
            group,
            parent: Some(parent),
            region,
            files,
        };
        state
            .groups_may_have_other_threads
            .entry(group)
            .or_insert(false);
        if pid == parent_registration.native_pid {
            state.groups_may_have_other_threads.insert(group, true);
        } else if memory_shared != Some(false) {
            state.regions_may_have_other_processes.insert(region);
        }
        if memory_shared.is_none() {
            state
                .regions
                .get_mut(&region)
                .unwrap()
                .exposures
                .push(InputExposure {
                    target: InputTarget::Region(region),
                    cause: "input-native-memory-identity-unavailable".into(),
                });
        }
        state.by_tid.insert(tid, task);
        for freeze in &freezes {
            state.freezes.get_mut(freeze).unwrap().insert(task);
        }
        state.tasks.insert(
            task,
            Task {
                registration,
                grant: None,
                frozen: freezes,
                native_terminal: false,
                native_effects_complete: false,
            },
        );
        drop(state);
        if let Some(observer) = self.files_observer.get() {
            observer.observe(
                self,
                InputFilesEvent {
                    source: parent_registration,
                    destination: registration,
                    shared: files_shared,
                    exec: false,
                },
            )?;
        }
        Ok(registration)
    }

    /// Native group creation history, never a live-task census. A possible
    /// sibling creation permanently removes this proof for that group.
    pub fn group_proven_singleton(&self, task: InputTaskId) -> bool {
        let state = self.state.lock().unwrap();
        state.tasks.get(&task).is_some_and(|owner| {
            state
                .groups_may_have_other_threads
                .get(&owner.registration.group)
                == Some(&false)
        })
    }

    /// Whether retained native history proves that this memory lifetime has
    /// never had a separate process owner. Unknown pairwise sharing is not proof.
    pub fn region_proven_single_process(&self, task: InputTaskId) -> bool {
        let state = self.state.lock().unwrap();
        state.tasks.get(&task).is_some_and(|owner| {
            !state
                .regions_may_have_other_processes
                .contains(&owner.registration.region)
        })
    }

    /// Backend-only: an authenticated Exec edge replaces this image.
    pub fn backend_exec(
        &self,
        task: InputTaskId,
    ) -> Result<InputTaskRegistration, InputUnavailable> {
        self.backend_exec_replacement(task, task)
    }

    /// Backend-only: an actual nonleader Exec edge binds the surviving native
    /// leader to a fresh image/task generation. The displaced and former
    /// generations keep their old regions, accesses and fence membership.
    /// This must precede retiring the former native owner. Neither ECHILD nor
    /// disappearance of a numeric TID is authority to call this operation.
    pub fn backend_exec_replacement(
        &self,
        displaced: InputTaskId,
        former: InputTaskId,
    ) -> Result<InputTaskRegistration, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if state.fatal.is_some() {
            return Err(InputUnavailable::new("input-run-terminal"));
        }
        let old_leader = state
            .tasks
            .get(&displaced)
            .ok_or_else(|| InputUnavailable::new("input-exec-owner-not-retained"))?
            .registration;
        let old_former = state
            .tasks
            .get(&former)
            .ok_or_else(|| InputUnavailable::new("input-exec-former-not-retained"))?
            .registration;
        if old_leader.group != old_former.group || old_leader.native_tid != old_leader.native_pid {
            return Err(InputUnavailable::new("input-exec-owner-mismatch"));
        }
        // Singleton exec/retirement fences name the old image, not its live
        // replacement. A separately retained whole-group intent is sticky
        // and must still include every replacement published in that group.
        let freezes = state
            .frozen_groups
            .get(&old_former.group)
            .cloned()
            .unwrap_or_default();
        Self::effects_complete_locked(&mut state, displaced)?;
        if former != displaced {
            Self::effects_complete_locked(&mut state, former)?;
        }
        let task = InputTaskId {
            run: self.run,
            generation: state.next()?,
            tid: old_leader.native_tid,
        };
        let region = RegionLifetime {
            run: self.run,
            generation: state.next()?,
        };
        let files = FileTableLifetime {
            run: self.run,
            generation: state.next()?,
        };
        state.regions.insert(region, Region::default());
        state.files_possibly_shared.insert(files, false);
        let registration = InputTaskRegistration {
            task,
            native_tid: old_leader.native_tid,
            native_pid: old_leader.native_pid,
            tool_tid: None,
            tool_pid: None,
            region,
            files,
            ..old_former
        };
        for old in [displaced, former] {
            if state.by_tid.get(&old.tid) == Some(&old) {
                state.by_tid.remove(&old.tid);
            }
        }
        state.by_tid.insert(task.tid, task);
        // Old exact-image cohort handles remain valid until the Tool's fence;
        // only the independent sticky group intent follows this new image.
        for freeze in &freezes {
            state.freezes.get_mut(freeze).unwrap().insert(task);
        }
        state.tasks.insert(
            task,
            Task {
                registration,
                grant: None,
                frozen: freezes,
                native_terminal: false,
                native_effects_complete: false,
            },
        );
        drop(state);
        if let Some(observer) = self.files_observer.get() {
            observer.observe(
                self,
                InputFilesEvent {
                    source: old_former,
                    destination: registration,
                    shared: Some(false),
                    exec: true,
                },
            )?;
        }
        Ok(registration)
    }

    /// Backend-only: publish an authenticated setup; no configuration mints it.
    pub fn backend_set_layout(
        &self,
        task: InputTaskId,
        layout: ReservedInputLayout,
    ) -> Result<(), InputUnavailable> {
        let layout = layout.validate()?;
        let mut state = self.state.lock().unwrap();
        let region = state.live(task)?.registration.region;
        state.regions.get_mut(&region).unwrap().layout = Some(layout);
        Ok(())
    }

    /// The authenticated layout in this actual address-space lifetime, if set up.
    pub fn layout(&self, task: InputTaskId) -> Option<ReservedInputLayout> {
        let state = self.state.lock().unwrap();
        let task = state.tasks.get(&task)?;
        state.regions.get(&task.registration.region)?.layout
    }

    /// Backend-only: validate that an opaque receipt reached its exact call.
    pub fn backend_bind_injection(
        &self,
        receipt: &PhysicalInjectionReceipt,
        task: InputTaskId,
        number: u64,
        args: [u64; 6],
    ) -> Result<(), InputUnavailable> {
        let state = self.state.lock().unwrap();
        let call = state
            .injections
            .get(&receipt.id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        let owner = state.live(task)?;
        if receipt.id.run != self.run
            || call.task != task
            || call.description.number != number
            || call.description.args != args
            || call.state != PhysicalInjectionState::Prepared
            || owner.grant.map(|grant| grant.0) != Some(call.grant)
            || !owner.frozen.is_empty()
        {
            return Err(InputUnavailable::new("input-physical-call-mismatch"));
        }
        Ok(())
    }

    /// Backend-only: immutable original/future input for preparation classifiers.
    pub fn backend_description(
        &self,
        id: PhysicalInjectionId,
    ) -> Option<PhysicalInjectionDescription> {
        self.state
            .lock()
            .unwrap()
            .injections
            .get(&id)
            .map(|call| call.description.clone())
    }

    /// Backend-only: install cancellation ownership before changing entry state.
    pub fn backend_begin_preparation(
        &self,
        receipt: &PhysicalInjectionReceipt,
        scope: &InputOperationScope,
        image: ReservedInputImage,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        Self::validate_scope(self.run, &state, scope)?;
        let region_id = state.live(scope.task)?.registration.region;
        let region = &state.regions[&region_id];
        if region.transaction.is_some() {
            return Err(InputUnavailable::new("input-transaction-busy"));
        }
        if region.layout != Some(image.layout()) {
            return Err(InputUnavailable::new("input-layout-not-authenticated"));
        }
        let call = state
            .injections
            .get(&receipt.id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if call.task != scope.task
            || call.operation != scope.logical_operation
            || call.grant != scope.grant
            || call.state != PhysicalInjectionState::Prepared
            || call.phase.is_some()
        {
            return Err(InputUnavailable::new("input-transaction-binding"));
        }
        // This publication also serializes nested preparation; no page write yet.
        state.regions.get_mut(&region_id).unwrap().transaction = Some(receipt.id);
        let call = state.injections.get_mut(&receipt.id).unwrap();
        call.phase = Some(InputTransactionPhase::Preparing);
        call.image = Some(image);
        Ok(())
    }

    /// Backend-only: final owned stop, after all asynchronous preparation.
    /// This atomically checks access conflicts before authorizing a page write.
    pub fn backend_prepared_stopped(
        &self,
        id: PhysicalInjectionId,
    ) -> Result<ReservedInputImage, InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let call = state
            .injections
            .get(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        let task = state.live(call.task)?;
        if call.phase != Some(InputTransactionPhase::Preparing)
            || task.grant.map(|grant| grant.0) != Some(call.grant)
            || !task.frozen.is_empty()
        {
            return Err(InputUnavailable::new("input-operation-stale"));
        }
        let region = task.registration.region;
        // A retained terminal cohort can still perform native cleanup reads
        // without a prior explicit access lease. Quarantine the entire region
        // until the cohort's all-accounted fence, including late members.
        if state
            .tasks
            .values()
            .any(|owner| owner.registration.region == region && !owner.frozen.is_empty())
        {
            return Err(InputUnavailable::new("input-region-frozen"));
        }
        let image = call
            .image
            .clone()
            .ok_or_else(|| InputUnavailable::new("input-image-missing"))?;
        if let Some(cause) = state
            .global_exposures
            .first()
            .or_else(|| state.regions[&region].exposures.first())
        {
            return Err(InputUnavailable::new(cause.cause.clone()));
        }
        for access in state.accesses.values() {
            let targets = match access.declaration.target {
                InputTarget::Unknown => true,
                InputTarget::Region(id) => id == region,
            };
            if targets && access.declaration.span.overlaps(image.layout()) {
                return Err(InputUnavailable::new(access.declaration.cause.clone()));
            }
        }
        state.injections.get_mut(&id).unwrap().phase = Some(InputTransactionPhase::PreparedStopped);
        Ok(image)
    }

    /// Backend-only: publish before the first force-write, including a failed write.
    pub fn backend_initializing(&self, id: PhysicalInjectionId) -> Result<(), InputUnavailable> {
        self.transition(
            id,
            InputTransactionPhase::PreparedStopped,
            InputTransactionPhase::Initializing,
        )
    }

    /// Backend-only: allow exactly one normalization attempt after a possible write.
    pub fn backend_normalizing(&self, id: PhysicalInjectionId) -> Result<(), InputUnavailable> {
        self.transition(
            id,
            InputTransactionPhase::Initializing,
            InputTransactionPhase::Normalizing,
        )
    }

    fn transition(
        &self,
        id: PhysicalInjectionId,
        from: InputTransactionPhase,
        to: InputTransactionPhase,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let call = state
            .injections
            .get_mut(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if call.phase != Some(from) {
            return Err(InputUnavailable::new("input-transaction-phase"));
        }
        call.phase = Some(to);
        Ok(())
    }

    /// Backend-only: exact full-image readback, not a successful transport count.
    pub fn backend_verified_image(
        &self,
        id: PhysicalInjectionId,
        readback: &[u8],
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let call = state
            .injections
            .get_mut(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if !matches!(
            call.phase,
            Some(InputTransactionPhase::Initializing | InputTransactionPhase::Normalizing)
        ) {
            return Err(InputUnavailable::new("input-transaction-phase"));
        }
        let image = call
            .image
            .as_ref()
            .ok_or_else(|| InputUnavailable::new("input-image-missing"))?;
        if image.bytes() != readback {
            return Err(InputUnavailable::new("input-image-readback-mismatch"));
        }
        call.verified_image = Some(image.clone());
        call.phase = Some(InputTransactionPhase::Ready);
        Ok(())
    }

    /// Backend-only: bind actual native entry immediately before native execution.
    pub fn backend_issued(&self, id: PhysicalInjectionId) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let task = state
            .injections
            .get(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?
            .task;
        let description = &state.injections[&id].description;
        let may_thread = description.expected_sharing.may_create
            && description.expected_sharing.thread_group != Some(false);
        let may_process_share = description.expected_sharing.may_create
            && description.expected_sharing.memory != Some(false)
            && description.expected_sharing.thread_group != Some(true);
        let registration = state.tasks[&task].registration;
        if may_thread {
            state
                .groups_may_have_other_threads
                .insert(registration.group, true);
        }
        if may_process_share {
            state
                .regions_may_have_other_processes
                .insert(registration.region);
        }

        if state.injections.iter().any(|(other, call)| {
            *other != id && call.task == task && call.state == PhysicalInjectionState::Issued
        }) {
            return Err(InputUnavailable::new("input-native-call-already-issued"));
        }
        let call = state
            .injections
            .get_mut(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if call.state != PhysicalInjectionState::Prepared
            || !matches!(call.phase, None | Some(InputTransactionPhase::Ready))
        {
            return Err(InputUnavailable::new("input-issue-phase"));
        }
        call.state = PhysicalInjectionState::Issued;
        if call.phase.is_some() {
            call.phase = Some(InputTransactionPhase::Launched);
        }
        Ok(())
    }

    /// Backend-only decoder lookup of an already issued physical call. This is
    /// not a pending/next-injection slot: preparation never publishes an entry.
    pub fn backend_issued_call(&self, task: InputTaskId) -> Option<PhysicalInjectionId> {
        self.state
            .lock()
            .unwrap()
            .injections
            .iter()
            .find_map(|(id, call)| {
                (call.task == task && call.state == PhysicalInjectionState::Issued).then_some(*id)
            })
    }

    /// Backend-only: settle a proved not-run attempt after entry/register recovery.
    /// This cannot erase uncertain issued state or an unnormalized partial image.
    pub fn backend_settled_not_run(&self, id: PhysicalInjectionId) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let call = state
            .injections
            .get(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if call.state != PhysicalInjectionState::Prepared
            || !matches!(
                call.phase,
                None | Some(
                    InputTransactionPhase::Preparing
                        | InputTransactionPhase::PreparedStopped
                        | InputTransactionPhase::Ready
                )
            )
        {
            return Err(InputUnavailable::new("input-not-run-unproved"));
        }
        Self::finish_locked(&mut state, id, PhysicalInjectionState::ProvedNoChild)
    }

    /// Backend-only: authenticate an actual no-child completion at an owned stop.
    pub fn backend_no_child(&self, id: PhysicalInjectionId) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        if state
            .injections
            .get(&id)
            .is_none_or(|call| call.state != PhysicalInjectionState::Issued)
        {
            return Err(InputUnavailable::new("input-no-child-unproved"));
        }
        Self::finish_locked(&mut state, id, PhysicalInjectionState::ProvedNoChild)
    }

    /// Backend-only: earliest retained decoder capture, before Tool or child resume.
    pub fn backend_retained_birth(
        &self,
        id: PhysicalInjectionId,
        child: InputTaskId,
        memory_shared: Option<bool>,
        files_shared: Option<bool>,
    ) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let call = state
            .injections
            .get(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if call.state == PhysicalInjectionState::RetainedBirth(child) {
            return Ok(());
        }
        if call.state != PhysicalInjectionState::Issued || !state.tasks.contains_key(&child) {
            return Err(InputUnavailable::new("input-birth-binding"));
        }
        let expected = call.description.expected_sharing;
        if expected
            .memory
            .zip(memory_shared)
            .is_some_and(|(a, b)| a != b)
            || expected
                .files
                .zip(files_shared)
                .is_some_and(|(a, b)| a != b)
        {
            return Err(InputUnavailable::new("input-native-sharing-mismatch"));
        }
        let exposures = call.description.prospective.clone();
        for exposure in exposures {
            Self::add_exposure_locked(&mut state, exposure)?;
        }
        Self::finish_locked(&mut state, id, PhysicalInjectionState::RetainedBirth(child))
    }

    /// Backend-only: success or cancellation with no authenticated child ownership.
    pub fn backend_unknown_outcome(&self, id: PhysicalInjectionId) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let call = state
            .injections
            .get(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?;
        if let Some(exposure) = call.description.unknown_lifecycle.clone() {
            Self::add_exposure_locked(&mut state, exposure)?;
        }
        Self::finish_locked(&mut state, id, PhysicalInjectionState::OutcomeUnknown)
    }

    fn finish_locked(
        state: &mut State,
        id: PhysicalInjectionId,
        result: PhysicalInjectionState,
    ) -> Result<(), InputUnavailable> {
        let task_id = state
            .injections
            .get(&id)
            .ok_or_else(|| InputUnavailable::new("input-call-missing"))?
            .task;
        let region = state.tasks[&task_id].registration.region;
        let call = state.injections.get_mut(&id).unwrap();
        call.state = result;
        call.phase = None;
        if state.regions[&region].transaction == Some(id) {
            state.regions.get_mut(&region).unwrap().transaction = None;
        }
        for access in state
            .accesses
            .values_mut()
            .filter(|access| access.physical == Some(id))
        {
            access.native_complete = true;
        }
        Ok(())
    }

    /// Backend-only: verify a continuation is not exposing an unresolved image.
    /// `physical` is the explicit call-local owner, never a next-call slot.
    pub fn backend_continuation(
        &self,
        task: InputTaskId,
        physical: Option<PhysicalInjectionId>,
    ) -> Result<(), InputUnavailable> {
        let state = self.state.lock().unwrap();
        let task = state.live(task)?;
        if let Some(id) = state.regions[&task.registration.region].transaction {
            let phase = state.injections[&id].phase;
            if matches!(
                phase,
                Some(InputTransactionPhase::Preparing | InputTransactionPhase::PreparedStopped)
            ) {
                return Ok(());
            }
            if physical != Some(id)
                || !matches!(
                    phase,
                    Some(InputTransactionPhase::Ready | InputTransactionPhase::Launched)
                )
            {
                return Err(InputUnavailable::new("input-unsettled-continuation"));
            }
        }
        Ok(())
    }

    fn terminal_gate_locked(state: &mut State, task: InputTaskId) -> Result<(), InputUnavailable> {
        let unfinished: Vec<_> = state
            .injections
            .iter()
            .filter(|(_, call)| {
                call.task == task
                    && matches!(
                        call.state,
                        PhysicalInjectionState::Prepared | PhysicalInjectionState::Issued
                    )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in unfinished {
            let call = &state.injections[&id];
            if matches!(
                call.phase,
                Some(
                    InputTransactionPhase::Initializing
                        | InputTransactionPhase::Normalizing
                        | InputTransactionPhase::Ready
                        | InputTransactionPhase::Launched
                )
            ) {
                state
                    .fatal
                    .get_or_insert_with(|| "input-terminal-before-settlement".to_owned());
                return Err(InputUnavailable::new("input-terminal-before-settlement"));
            }
            if call.state == PhysicalInjectionState::Issued {
                if let Some(exposure) = call.description.unknown_lifecycle.clone() {
                    Self::add_exposure_locked(state, exposure)?;
                }
                Self::finish_locked(state, id, PhysicalInjectionState::OutcomeUnknown)?;
            } else {
                Self::finish_locked(state, id, PhysicalInjectionState::ProvedNoChild)?;
            }
        }
        Ok(())
    }

    /// Backend-only: a callback future has ended or been cancelled. Resolve its
    /// retained preparation before any terminal/exec owner can publish or await.
    /// This does not assert that the native task itself is dead.
    pub fn backend_cancel_injections(&self, task: InputTaskId) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let owner = state
            .tasks
            .get_mut(&task)
            .ok_or_else(|| InputUnavailable::new("input-task-not-owned"))?;
        owner.grant = None;
        let unfinished: Vec<_> = state
            .injections
            .iter()
            .filter(|(_, call)| {
                call.task == task
                    && matches!(
                        call.state,
                        PhysicalInjectionState::Prepared | PhysicalInjectionState::Issued
                    )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in unfinished {
            let call = &state.injections[&id];
            if matches!(
                call.phase,
                Some(
                    InputTransactionPhase::Initializing
                        | InputTransactionPhase::Normalizing
                        | InputTransactionPhase::Ready
                        | InputTransactionPhase::Launched
                )
            ) {
                state
                    .fatal
                    .get_or_insert_with(|| "input-terminal-before-settlement".to_owned());
                return Err(InputUnavailable::new("input-terminal-before-settlement"));
            }
            if call.state == PhysicalInjectionState::Issued {
                if let Some(exposure) = call.description.unknown_lifecycle.clone() {
                    Self::add_exposure_locked(&mut state, exposure)?;
                }
                Self::finish_locked(&mut state, id, PhysicalInjectionState::OutcomeUnknown)?;
            }
            // Prepared/Preparing has not issued or changed the page. Keep it
            // owned until actual exit effects or an authenticated Exec settle
            // the old context. Callback Drop alone is not ProvedNoChild.
        }
        Ok(())
    }

    fn effects_complete_locked(
        state: &mut State,
        task: InputTaskId,
    ) -> Result<(), InputUnavailable> {
        Self::terminal_gate_locked(state, task)?;
        let owner = state
            .tasks
            .get_mut(&task)
            .ok_or_else(|| InputUnavailable::new("input-task-not-owned"))?;
        owner.native_effects_complete = true;
        owner.grant = None;
        for access in state
            .accesses
            .values_mut()
            .filter(|access| access.task == task)
        {
            access.native_complete = true;
        }
        Ok(())
    }

    /// Backend-only: record an authenticated physical death before publication.
    /// A failed image gate still retains its transaction, accesses and cohorts;
    /// physical death cannot turn that failure into successful settlement.
    pub fn backend_terminal(&self, task: InputTaskId) -> Result<(), InputUnavailable> {
        let mut state = self.state.lock().unwrap();
        let owner = state
            .tasks
            .get_mut(&task)
            .ok_or_else(|| InputUnavailable::new("input-task-not-owned"))?;
        owner.native_terminal = true;
        owner.grant = None;
        if state.by_tid.get(&task.tid) == Some(&task) {
            state.by_tid.remove(&task.tid);
        }
        Self::effects_complete_locked(&mut state, task)?;
        // Physical task death settles its native accesses but does not retire
        // frozen/logically outstanding accesses or their external scopes.
        for access in state
            .accesses
            .values_mut()
            .filter(|access| access.task == task)
        {
            access.native_complete = true;
        }
        Ok(())
    }

    /// Backend-only: retain the first terminal failure before cancelling owners.
    pub fn backend_fail(&self, reason: impl Into<String>) {
        let mut state = self.state.lock().unwrap();
        if state.fatal.is_none() {
            state.fatal = Some(reason.into());
        }
    }

    /// First retained failure; observing it does not clear the gate.
    pub fn failure(&self) -> Option<String> {
        self.state.lock().unwrap().fatal.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reserved_input::InputAbi;
    use crate::reserved_input::InputWrite;
    use crate::reserved_input::RESERVED_INPUT_BASE;

    fn root() -> (ReservedInputControl, InputTaskRegistration) {
        let control = ReservedInputControl::new_backend().unwrap();
        let task = control.backend_register_root(10, 10).unwrap();
        control
            .backend_set_layout(
                task.task,
                ReservedInputLayout {
                    base: RESERVED_INPUT_BASE,
                    page_bytes: 4096,
                    abi: InputAbi::X86_64,
                },
            )
            .unwrap();
        (control, task)
    }

    #[derive(Debug)]
    struct EmptyNativeOperation;
    impl crate::native_syscall::NativeOperationObserver for EmptyNativeOperation {
        fn observe(
            &self,
            _: &dyn crate::native_syscall::NativeSyscallFacts,
            _: &crate::native_syscall::NativeSyscallCall,
        ) -> Result<Option<Arc<dyn crate::native_syscall::NativeSyscallObserver>>, crate::Error>
        {
            Ok(None)
        }
    }

    #[test]
    fn access_completion_requires_its_exact_closed_and_native_settled_operation() {
        use crate::native_syscall::NativeOperation;
        let (control, task) = root();
        let grant = control.grant(task.task, InputGrantKind::Ordinary).unwrap();
        let operation = NativeOperation::new(Arc::new(EmptyNativeOperation));
        let helper = NativeOperation::new(Arc::new(EmptyNativeOperation));
        helper.close();
        let lease = control
            .acquire_access(
                task.task,
                InputAccess {
                    target: InputTarget::Region(task.region),
                    span: InputSpan::Unknown,
                    direction: InputAccessDirection::Read,
                    lifetime: InputAccessLifetime::Transient,
                    cause: Arc::from("test-operation"),
                },
            )
            .unwrap();
        control
            .bind_access_completion(&lease, task.task, &operation.completion())
            .unwrap();
        assert_eq!(
            control
                .complete_access_after_return(&lease, task.task)
                .unwrap_err()
                .reason(),
            "input-access-binding",
            "legacy completion cannot override an operation proof"
        );
        assert_eq!(
            control
                .complete_access_after_operation(&lease, task.task, &helper)
                .unwrap_err()
                .reason(),
            "input-operation-binding"
        );
        assert!(
            control
                .complete_access_after_operation(&lease, task.task, &operation)
                .is_err()
        );
        let never_issued = operation.begin_native_attempt().unwrap();
        let issued = operation.begin_native_attempt().unwrap();
        issued.transition_started();
        operation.close();
        never_issued.cancelled_before_transition();
        issued.cancelled_before_transition();
        assert!(
            control
                .complete_access_after_operation(&lease, task.task, &operation)
                .is_err()
        );
        assert!(!control.state.lock().unwrap().accesses[&lease.id].native_complete);
        issued.effects_ended();
        control
            .complete_access_after_operation(&lease, task.task, &operation)
            .unwrap();
        assert!(
            control
                .state
                .lock()
                .unwrap()
                .accesses
                .contains_key(&lease.id),
            "native completion must not retire logical readmission"
        );
        control.readmit_access(lease, task.task, grant).unwrap();
        assert!(control.state.lock().unwrap().accesses.is_empty());

        let never = NativeOperation::new(Arc::new(EmptyNativeOperation));
        let activity = never.begin_native_attempt().unwrap();
        activity.cancelled_before_transition();
        never.close();
        assert!(never.effects_complete());
    }

    fn call(
        control: &ReservedInputControl,
        task: InputTaskId,
    ) -> (
        InputOperationScope,
        PhysicalInjectionReceipt,
        ReservedInputImage,
    ) {
        control.grant(task, InputGrantKind::Ordinary).unwrap();
        let scope = control.begin_operation(task, 7).unwrap();
        let receipt = control
            .prepare_injection(
                &scope,
                PhysicalInjectionDescription {
                    number: 0,
                    args: [0; 6],
                    input: InputCallInput::Registers,
                    expected_sharing: InputExpectedSharing::default(),
                    transient: vec![],
                    prospective: vec![],
                    unknown_lifecycle: None,
                },
            )
            .unwrap();
        let image = ReservedInputImage::new(
            control.layout(task).unwrap(),
            &[InputWrite {
                offset: 8,
                bytes: &[4, 9],
            }],
        )
        .unwrap();
        (scope, receipt, image)
    }

    #[test]
    fn a_scope_requires_and_consumes_the_actual_matching_grant() {
        let (control, task) = root();
        assert_eq!(
            control.begin_operation(task.task, 7).unwrap_err().reason(),
            "input-no-execution-grant"
        );
        control
            .grant(
                task.task,
                InputGrantKind::PendingVfork {
                    logical_operation: 8,
                },
            )
            .unwrap();
        assert_eq!(
            control.begin_operation(task.task, 7).unwrap_err().reason(),
            "input-barrier-operation-mismatch"
        );
        let scope = control.begin_operation(task.task, 8).unwrap();
        assert!(control.begin_operation(task.task, 8).is_err());
        control.invalidate_operation(task.task);
        assert!(
            control
                .prepare_injection(
                    &scope,
                    PhysicalInjectionDescription {
                        number: 0,
                        args: [0; 6],
                        input: InputCallInput::Registers,
                        expected_sharing: InputExpectedSharing::default(),
                        transient: vec![],
                        prospective: vec![],
                        unknown_lifecycle: None,
                    }
                )
                .is_err()
        );
    }

    #[test]
    fn dropped_handles_do_not_retire_access_before_native_completion_and_readmission() {
        let (control, task) = root();
        let lease = control
            .acquire_access(
                task.task,
                InputAccess {
                    target: InputTarget::Region(task.region),
                    span: InputSpan::Unknown,
                    direction: InputAccessDirection::Read,
                    lifetime: InputAccessLifetime::Transient,
                    cause: "reader-not-readmitted".into(),
                },
            )
            .unwrap();
        let (scope, receipt, image) = call(&control, task.task);
        control.attach_access(&lease, &receipt).unwrap();
        control
            .backend_begin_preparation(&receipt, &scope, image.clone())
            .unwrap();
        assert_eq!(
            control
                .backend_prepared_stopped(receipt.id())
                .unwrap_err()
                .reason(),
            "reader-not-readmitted"
        );
        control.backend_settled_not_run(receipt.id()).unwrap();
        // Native completion alone leaves the lease: it still blocks a new writer.
        let (scope2, receipt2, _) = call(&control, task.task);
        control
            .backend_begin_preparation(&receipt2, &scope2, image)
            .unwrap();
        assert_eq!(
            control
                .backend_prepared_stopped(receipt2.id())
                .unwrap_err()
                .reason(),
            "reader-not-readmitted"
        );
        let grant = control.current_grant(task.task).unwrap();
        control.readmit_access(lease, task.task, grant).unwrap();
        assert!(control.backend_prepared_stopped(receipt2.id()).is_ok());
    }

    #[test]
    fn cancellation_after_a_possible_write_cannot_open_a_continuation() {
        let (control, task) = root();
        let (scope, receipt, image) = call(&control, task.task);
        control
            .backend_begin_preparation(&receipt, &scope, image)
            .unwrap();
        control.backend_prepared_stopped(receipt.id()).unwrap();
        control.backend_initializing(receipt.id()).unwrap();
        let id = receipt.id();
        drop(receipt);
        drop(scope);
        assert_eq!(
            control
                .backend_continuation(task.task, Some(id))
                .unwrap_err()
                .reason(),
            "input-unsettled-continuation"
        );
        assert!(control.backend_settled_not_run(id).is_err());
        assert!(control.backend_terminal(task.task).is_err());
        assert_eq!(
            control.failure().as_deref(),
            Some("input-terminal-before-settlement")
        );
    }

    #[test]
    fn physical_death_retains_a_failed_image_and_its_logical_quarantine() {
        let (control, parent) = root();
        let shared = control
            .backend_register_child(parent.task, 11, 11, Some(true), Some(false))
            .unwrap();
        let copied = control
            .backend_register_child(parent.task, 12, 12, Some(false), Some(false))
            .unwrap();
        // This outstanding access is outside the image being initialized.
        // Its logical owner must survive even when that owner's task dies.
        let access = control
            .acquire_access(
                parent.task,
                InputAccess {
                    target: InputTarget::Region(copied.region),
                    span: InputSpan::Unknown,
                    direction: InputAccessDirection::Read,
                    lifetime: InputAccessLifetime::Transient,
                    cause: "retained-reader".into(),
                },
            )
            .unwrap();
        let (scope, receipt, image) = call(&control, parent.task);
        control
            .backend_begin_preparation(&receipt, &scope, image)
            .unwrap();
        control.backend_prepared_stopped(receipt.id()).unwrap();
        control.backend_initializing(receipt.id()).unwrap();
        control.backend_normalizing(receipt.id()).unwrap();
        let cohort = control.freeze_tasks(&[parent.task, shared.task]).unwrap();
        control.backend_fail("input-normalization:transport-failure");
        assert_eq!(
            control.backend_terminal(parent.task).unwrap_err().reason(),
            "input-terminal-before-settlement"
        );
        assert_eq!(control.native_terminal(parent.task), Some(true));
        assert_eq!(control.native_terminal(shared.task), Some(false));
        assert_eq!(control.task_identity(parent.native_tid), None);
        assert_eq!(control.task_identity(shared.native_tid), Some(shared.task));
        assert_eq!(control.current_grant(parent.task), None);
        assert_eq!(
            control
                .observe_exit_effects(parent.task)
                .unwrap_err()
                .reason(),
            "input-terminal-before-settlement"
        );
        assert_eq!(
            control
                .backend_cancel_injections(parent.task)
                .unwrap_err()
                .reason(),
            "input-terminal-before-settlement"
        );
        assert_eq!(
            control.failure().as_deref(),
            Some("input-normalization:transport-failure")
        );
        for task in [parent.task, shared.task, copied.task] {
            assert!(
                control
                    .backend_continuation(task, Some(receipt.id()))
                    .is_err()
            );
            assert!(control.grant(task, InputGrantKind::Ordinary).is_err());
        }
        assert_eq!(
            control
                .settle_fenced_tasks(&[parent.task])
                .unwrap_err()
                .reason(),
            "input-cohort-native-unsettled"
        );
        assert_eq!(
            control
                .cancel_freeze_before_effect(cohort)
                .unwrap_err()
                .reason(),
            "input-retirement-has-native-effect"
        );
        let state = control.state.lock().unwrap();
        assert!(!state.tasks[&parent.task].native_effects_complete);
        assert_eq!(
            state.regions[&parent.region].transaction,
            Some(receipt.id())
        );
        assert_eq!(
            state.injections[&receipt.id()].phase,
            Some(InputTransactionPhase::Normalizing)
        );
        assert_eq!(
            state.injections[&receipt.id()].state,
            PhysicalInjectionState::Prepared
        );
        assert!(!state.accesses[&access.id].native_complete);
        assert_eq!(state.freezes.len(), 1);
        assert_eq!(state.tasks[&parent.task].frozen.len(), 1);
        assert_eq!(state.tasks[&shared.task].frozen.len(), 1);
    }

    #[test]
    fn normalization_requires_the_entire_same_image_before_settlement() {
        let (control, task) = root();
        let (scope, receipt, image) = call(&control, task.task);
        control
            .backend_begin_preparation(&receipt, &scope, image.clone())
            .unwrap();
        control.backend_prepared_stopped(receipt.id()).unwrap();
        control.backend_initializing(receipt.id()).unwrap();
        control.backend_normalizing(receipt.id()).unwrap();
        assert!(control.backend_normalizing(receipt.id()).is_err());
        let mut partial = image.bytes().to_vec();
        partial[4095] = 1;
        assert_eq!(
            control
                .backend_verified_image(receipt.id(), &partial)
                .unwrap_err()
                .reason(),
            "input-image-readback-mismatch"
        );
        control
            .backend_verified_image(receipt.id(), image.bytes())
            .unwrap();
        control.backend_settled_not_run(receipt.id()).unwrap();
        assert!(control.backend_continuation(task.task, None).is_ok());
        assert_eq!(
            control
                .injection_observation(receipt.id())
                .unwrap()
                .verified_image,
            Some(image)
        );
    }

    #[test]
    fn local_unknown_span_blocks_shared_memory_but_not_an_independent_copy() {
        let (control, parent) = root();
        let shared = control
            .backend_register_child(parent.task, 11, 11, Some(true), Some(false))
            .unwrap();
        let copied = control
            .backend_register_child(parent.task, 12, 12, Some(false), Some(false))
            .unwrap();
        control
            .acquire_access(
                parent.task,
                InputAccess {
                    target: InputTarget::Region(parent.region),
                    span: InputSpan::Unknown,
                    direction: InputAccessDirection::Read,
                    lifetime: InputAccessLifetime::Transient,
                    cause: "parent-reader".into(),
                },
            )
            .unwrap();
        let (scope, receipt, image) = call(&control, shared.task);
        control
            .backend_begin_preparation(&receipt, &scope, image)
            .unwrap();
        assert_eq!(
            control
                .backend_prepared_stopped(receipt.id())
                .unwrap_err()
                .reason(),
            "parent-reader"
        );
        control.backend_settled_not_run(receipt.id()).unwrap();
        let (scope, receipt, image) = call(&control, copied.task);
        control
            .backend_begin_preparation(&receipt, &scope, image)
            .unwrap();
        assert!(control.backend_prepared_stopped(receipt.id()).is_ok());
    }

    #[test]
    fn a_frozen_cohort_captures_late_children_and_never_thaws_on_one_exit() {
        let (control, parent) = root();
        let cohort = control.freeze_tasks(&[parent.task]).unwrap();
        let child = control
            .backend_register_child(parent.task, 11, 11, Some(true), Some(true))
            .unwrap();
        assert_eq!(
            control
                .grant(child.task, InputGrantKind::Ordinary)
                .unwrap_err()
                .reason(),
            "input-task-frozen"
        );
        control.backend_terminal(parent.task).unwrap();
        assert_eq!(
            control
                .grant(child.task, InputGrantKind::Ordinary)
                .unwrap_err()
                .reason(),
            "input-task-frozen"
        );
        assert!(control.settle_frozen_cohort(cohort).is_err());
    }

    #[test]
    fn a_frozen_region_blocks_other_members_until_the_cohort_fence() {
        let (control, parent) = root();
        let writer = control
            .backend_register_child(parent.task, 11, 11, Some(true), Some(false))
            .unwrap();
        let copied = control
            .backend_register_child(parent.task, 12, 12, Some(false), Some(false))
            .unwrap();
        let cohort = control.freeze_tasks(&[parent.task]).unwrap();
        let (scope, receipt, image) = call(&control, writer.task);
        control
            .backend_begin_preparation(&receipt, &scope, image)
            .unwrap();
        assert_eq!(
            control
                .backend_prepared_stopped(receipt.id())
                .unwrap_err()
                .reason(),
            "input-region-frozen"
        );
        control.backend_terminal(parent.task).unwrap();
        assert_eq!(
            control
                .backend_prepared_stopped(receipt.id())
                .unwrap_err()
                .reason(),
            "input-region-frozen"
        );
        let (copy_scope, copy_receipt, copy_image) = call(&control, copied.task);
        control
            .backend_begin_preparation(&copy_receipt, &copy_scope, copy_image)
            .unwrap();
        assert!(control.backend_prepared_stopped(copy_receipt.id()).is_ok());
        control.settle_frozen_cohort(cohort).unwrap();
        assert!(control.backend_prepared_stopped(receipt.id()).is_ok());
    }

    #[test]
    fn a_supplied_fence_cannot_silently_accept_a_live_member() {
        let (control, parent) = root();
        let child = control
            .backend_register_child(parent.task, 11, 10, Some(true), Some(true))
            .unwrap();
        let cohort = control.freeze_group(parent.task, true).unwrap();
        control.backend_terminal(parent.task).unwrap();
        assert_eq!(
            control
                .settle_fenced_tasks(&[parent.task, child.task])
                .unwrap_err()
                .reason(),
            "input-cohort-native-unsettled"
        );
        assert_eq!(control.cohort_members(&cohort).unwrap().len(), 2);
        control.settle_fenced_tasks(&[parent.task]).unwrap();
        assert_eq!(control.cohort_members(&cohort).unwrap().len(), 2);
        control.backend_terminal(child.task).unwrap();
        control
            .settle_fenced_tasks(&[parent.task, child.task])
            .unwrap();
        assert!(control.cohort_members(&cohort).is_err());
    }

    #[test]
    fn preparation_keeps_old_page_access_but_final_scan_owns_the_write_cut() {
        let (control, task) = root();
        let (scope, receipt, image) = call(&control, task.task);
        control
            .backend_begin_preparation(&receipt, &scope, image)
            .unwrap();
        let access = InputAccess {
            target: InputTarget::Region(task.region),
            span: InputSpan::Unknown,
            direction: InputAccessDirection::Read,
            lifetime: InputAccessLifetime::Transient,
            cause: "nested-old-page-reader".into(),
        };
        let reader = control.acquire_access(task.task, access.clone()).unwrap();
        assert_eq!(
            control
                .backend_prepared_stopped(receipt.id())
                .unwrap_err()
                .reason(),
            "nested-old-page-reader"
        );
        control
            .complete_access_after_return(&reader, task.task)
            .unwrap();
        control
            .readmit_access(reader, task.task, scope.grant)
            .unwrap();
        control.backend_prepared_stopped(receipt.id()).unwrap();
        assert_eq!(
            control
                .acquire_access(task.task, access)
                .unwrap_err()
                .reason(),
            "input-transaction-busy"
        );
    }

    #[test]
    fn unclassified_continuation_cannot_cross_another_regions_staged_transaction() {
        for phase in [
            InputTransactionPhase::Preparing,
            InputTransactionPhase::PreparedStopped,
            InputTransactionPhase::Initializing,
            InputTransactionPhase::Normalizing,
            InputTransactionPhase::Ready,
            InputTransactionPhase::Launched,
        ] {
            let (control, writer) = root();
            let signal_target = control
                .backend_register_child(writer.task, 11, 11, Some(false), Some(false))
                .unwrap();
            assert_ne!(writer.region, signal_target.region);
            let target_grant = control
                .grant(signal_target.task, InputGrantKind::Ordinary)
                .unwrap();
            let (scope, receipt, image) = call(&control, writer.task);
            let id = receipt.id();
            control
                .backend_begin_preparation(&receipt, &scope, image.clone())
                .unwrap();
            if phase != InputTransactionPhase::Preparing {
                control.backend_prepared_stopped(id).unwrap();
            }
            if matches!(
                phase,
                InputTransactionPhase::Initializing
                    | InputTransactionPhase::Normalizing
                    | InputTransactionPhase::Ready
                    | InputTransactionPhase::Launched
            ) {
                control.backend_initializing(id).unwrap();
            }
            if phase == InputTransactionPhase::Normalizing {
                control.backend_normalizing(id).unwrap();
            }
            if matches!(
                phase,
                InputTransactionPhase::Ready | InputTransactionPhase::Launched
            ) {
                control.backend_verified_image(id, image.bytes()).unwrap();
            }
            if phase == InputTransactionPhase::Launched {
                control.backend_issued(id).unwrap();
            }
            assert_eq!(
                control.state.lock().unwrap().injections[&id].phase,
                Some(phase)
            );
            // A guard for the resuming task's own region alone cannot see this
            // writer. Exercise the actual cross-region publication boundary.
            control
                .backend_continuation(signal_target.task, None)
                .unwrap();
            let before = format!("{:?}", *control.state.lock().unwrap());
            let exposure = InputExposure {
                target: InputTarget::Unknown,
                cause: "unclassified-signal-forward".into(),
            };
            let result =
                control.backend_expose_before_continuation(signal_target.task, exposure.clone());
            if phase == InputTransactionPhase::Preparing {
                result.unwrap();
                assert_eq!(
                    control.backend_prepared_stopped(id).unwrap_err().reason(),
                    "unclassified-signal-forward"
                );
                assert_eq!(
                    control.state.lock().unwrap().injections[&id].phase,
                    Some(phase)
                );
                assert_eq!(
                    control.injection_observation(id).unwrap().verified_image,
                    None
                );
                drop(receipt);
                drop(scope);
                let state = control.state.lock().unwrap();
                assert_eq!(state.global_exposures, [exposure]);
                assert_eq!(state.regions[&writer.region].transaction, Some(id));
                assert!(state.accesses.is_empty());
            } else {
                assert_eq!(result.unwrap_err().reason(), "input-transaction-busy");
                assert_eq!(
                    format!("{:?}", *control.state.lock().unwrap()),
                    before,
                    "a conflicting attempt must neither publish a cause nor alter ownership"
                );
            }
            assert_eq!(
                control.current_grant(signal_target.task),
                Some(target_grant)
            );
            assert_eq!(
                control.failure(),
                None,
                "the caller owns infrastructure failure"
            );
        }
    }

    #[test]
    fn preparing_a_call_does_not_annotate_a_prologue_native_birth() {
        let (control, task) = root();
        let (scope, receipt, image) = call(&control, task.task);
        control
            .backend_begin_preparation(&receipt, &scope, image.clone())
            .unwrap();
        assert_eq!(control.backend_issued_call(task.task), None);
        control.backend_prepared_stopped(receipt.id()).unwrap();
        control.backend_initializing(receipt.id()).unwrap();
        control
            .backend_verified_image(receipt.id(), image.bytes())
            .unwrap();
        assert_eq!(control.backend_issued_call(task.task), None);
        control.backend_issued(receipt.id()).unwrap();
        assert_eq!(control.backend_issued_call(task.task), Some(receipt.id()));
        control.backend_no_child(receipt.id()).unwrap();
        assert_eq!(control.backend_issued_call(task.task), None);
    }

    #[test]
    fn task_number_reuse_does_not_reuse_its_authority() {
        let (control, first) = root();
        control.backend_terminal(first.task).unwrap();
        let second = control.backend_register_root(10, 10).unwrap();
        assert_ne!(first.task, second.task);
        assert_ne!(first.region, second.region);
        assert!(control.grant(first.task, InputGrantKind::Ordinary).is_err());
        assert!(control.grant(second.task, InputGrantKind::Ordinary).is_ok());
    }

    #[test]
    fn nonleader_exec_keeps_old_fence_and_rebinds_only_the_surviving_view() {
        let (control, leader) = root();
        let leader = control
            .backend_bind_tool_identity(leader.task, 5000, 5000)
            .unwrap();
        let former = control
            .backend_register_child(leader.task, 11, 10, Some(true), Some(true))
            .unwrap();
        let former = control
            .backend_bind_tool_identity(former.task, 5001, 5000)
            .unwrap();
        let fence = control.freeze_tasks(&[leader.task]).unwrap();
        let former_fence = control.freeze_tasks(&[former.task]).unwrap();
        let replacement = control
            .backend_exec_replacement(leader.task, former.task)
            .unwrap();
        assert_eq!(control.cohort_members(&fence).unwrap(), [leader.task]);
        assert_eq!(
            control.cohort_members(&former_fence).unwrap(),
            [former.task]
        );
        assert_eq!(
            replacement.tool_tid, None,
            "new image cannot inherit the former logical binding by accident"
        );
        let replacement = control
            .backend_bind_tool_identity(replacement.task, 5000, 5000)
            .unwrap();
        assert_ne!(replacement.task, leader.task);
        assert_ne!(replacement.region, leader.region);
        assert_eq!(
            control.registration(former.task).unwrap().tool_tid,
            Some(5001)
        );
        assert_eq!(control.registration(leader.task).unwrap(), leader);
        assert_eq!(control.task_identity(10), Some(replacement.task));
        assert_eq!(control.task_identity(11), None);
        assert!(control.observe_exit_effects(leader.task).unwrap());
        assert!(control.observe_exit_effects(former.task).unwrap());
        control.settle_fenced_tasks(&[leader.task]).unwrap();
        control.settle_fenced_tasks(&[former.task]).unwrap();
        assert!(
            control
                .grant(leader.task, InputGrantKind::Ordinary)
                .is_err()
        );
        assert!(
            control
                .grant(replacement.task, InputGrantKind::Ordinary)
                .is_ok()
        );
        control.backend_terminal(former.task).unwrap();
        assert_eq!(control.task_identity(10), Some(replacement.task));
    }
}
