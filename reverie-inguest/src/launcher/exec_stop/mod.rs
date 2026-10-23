// Copyright (c) Meta Platforms, Inc. and affiliates.
// Licensed under the BSD-style license in the LICENSE file.

//! Owned first-image exec-stop mechanics, without runtime readiness policy.
//!
//! The caller owns namespace/resource setup and an external physical deadline.
//! All methods run on the original ptracer OS thread. Synchronous waits are not
//! wall bounded; cancellation can signal the retained generation from another
//! thread, but only its original ptracer performs terminal-wait cleanup.
#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod child;
#[cfg(feature = "stage1a-probe")]
pub mod images;
/// Owned original child-input observations; no mapping or resume capability.
pub mod initial_inputs;
mod initial_stack_inputs;
#[cfg(feature = "loader-private-runtime")]
mod input_data;
#[cfg(feature = "loader-private-runtime")]
pub use input_data::CopiedInitialData;
#[cfg(feature = "loader-private-runtime")]
pub use input_data::CopiedInputLocations;
#[cfg(feature = "loader-private-runtime")]
pub use input_data::CopiedInputRequest;
#[cfg(feature = "stage1a-probe")]
pub mod inject;
#[cfg(all(feature = "loader-private-runtime", not(feature = "stage1a-probe")))]
mod inject;
#[cfg(any(feature = "stage1a-probe", feature = "loader-private-runtime"))]
mod mapping_plan;
/// Owned mapping/filter and unsafe bootstrap observation; no Guest release.
#[cfg(feature = "loader-private-runtime")]
#[allow(unsafe_code)]
pub mod physical;
mod trace;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

pub use child::PreparedExec;
#[cfg(feature = "loader-private-runtime")]
use child::live_birth_pidfd;
use safeptrace::Event;
use safeptrace::ExitStatus;
use safeptrace::Options;
use safeptrace::Regs;
use safeptrace::Running;
use safeptrace::Signal;
use safeptrace::Stopped;
use safeptrace::SyscallInfo;
use safeptrace::SyscallInfoOp;
use safeptrace::Wait;

/// Errors from mechanical operations. Runtime/protocol policy is caller-owned.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
/// Retained cleanup observations, including failures during early acquisition.
#[derive(Clone, Default)]
pub struct CleanupReceipt {
    state: Rc<RefCell<CleanupState>>,
    claimed: Rc<std::cell::Cell<bool>>,
}
impl CleanupReceipt {
    /// Copy observations without lending a borrow across cancellation or Drop.
    pub fn snapshot(&self) -> CleanupState {
        self.state.borrow().clone()
    }
    fn borrow_mut(&self) -> std::cell::RefMut<'_, CleanupState> {
        self.state.borrow_mut()
    }
    fn claim(&self) -> bool {
        !self.claimed.replace(true)
    }
}

/// The owner permitted to consume this child's kernel wait statuses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CleanupOwner {
    /// No child was created.
    #[default]
    None,
    /// Atomic clone pidfd before safeptrace generation acquisition.
    PendingPidfd,
    /// The original safeptrace ptracer-thread generation.
    Ptracer,
}
/// Actual source of terminal retirement confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupConfirmation {
    /// Pre-registration waitid on the original clone pidfd.
    PidfdWaitid,
    /// Actual terminal wait through the safeptrace cleanup owner.
    SafeptraceTerminalWait,
    /// Normal actual terminal wait after detach.
    NormalWait,
}
/// A cleanup failure never confers terminal proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupWaitFailure {
    /// The cleanup grace expired.
    TimedOut,
    /// The actual wait failed with this errno.
    Errno(i32),
    /// A nonterminal/unexpected status could not confirm retirement.
    UnexpectedStatus,
}
/// Typed lifecycle receipt. `confirmed` requires a real terminal wait.
#[derive(Clone, Debug, Default)]
pub struct CleanupState {
    /// Whether clone created a child.
    pub child_created: bool,
    /// Last actual wait owner.
    pub owner: CleanupOwner,
    /// Real terminal retirement was observed.
    pub confirmed: bool,
    /// Source of that observation.
    pub confirmation: Option<CleanupConfirmation>,
    /// Cleanup requested SIGKILL; this does not prove exit causation.
    pub kill_requested: bool,
    /// Signal request errno, if any.
    pub kill_errno: Option<i32>,
    /// Failure to confirm retirement.
    pub wait_error: Option<CleanupWaitFailure>,
    /// Actual terminal status when directly returned by the owned wait.
    pub terminal_status: Option<ExitStatus>,
}

/// Original physical child owner, retained through detach and terminal wait.
#[must_use = "retain the physical owner through terminal wait or cancellation"]
pub struct ChildOwner<'fd> {
    cleanup: safeptrace::PtracerTerminalCleanup,
    generation: safeptrace::TraceeGeneration,
    // Duplicate of the original atomic clone pidfd, never pidfd_open(pid).
    #[cfg(feature = "loader-private-runtime")]
    birth_pidfd: std::os::fd::OwnedFd,
    _thread: Option<safeptrace::PtracerThreadGuard>,
    // Retains the exact borrowed descriptor leases and pre-clone buffers.
    _request: PreparedExec<'fd>,
    receipt: CleanupReceipt,
    complete: bool,
}

impl<'fd> ChildOwner<'fd> {
    /// Same-generation shared signal/observation handle; it cannot wait here.
    pub fn cancellation_handle(&self) -> safeptrace::TerminalCleanup {
        self.generation.terminal_cleanup()
    }

    #[cfg(feature = "loader-private-runtime")]
    fn duplicate_birth_pidfd(&self, task: &Stopped) -> Result<std::os::fd::OwnedFd> {
        let guard = self
            ._thread
            .as_ref()
            .ok_or("exec_stop_missing_original_ptracer")?;
        guard.check_current()?;
        if self.complete || task.generation() != self.generation {
            return Err("exec_stop_birth_pidfd_retired_or_foreign_generation".into());
        }
        // A copied generation or a pidfd alone is not an actual held stop.
        task.getregs()?;
        let duplicate = duplicate_guarded_birth_pidfd(guard, &self.birth_pidfd)?;
        task.getregs()?;
        guard.check_current()?;
        Ok(duplicate)
    }

    #[cfg(feature = "loader-private-runtime")]
    fn duplicate_birth_pidfd_for_inherited(
        &self,
        task: &Stopped,
        fd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<std::os::fd::OwnedFd> {
        // Validate current physical owner/generation before inspecting its request.
        let birth = self.duplicate_birth_pidfd(task)?;
        if !self._request.retains_descriptor(fd) {
            return Err("exec_stop_descriptor_not_inherited".into());
        }
        Ok(birth)
    }

    /// Request kill and perform bounded retirement on the original ptracer.
    pub fn cancel(mut self) -> std::result::Result<CleanupState, Box<Self>> {
        self.retire();
        if self.complete {
            Ok(self.receipt.snapshot())
        } else {
            Err(Box::new(self))
        }
    }

    fn retire(&mut self) {
        if self.complete {
            return;
        }
        let killed = self.cleanup.shared().request_sigkill();
        {
            let mut receipt = self.receipt.borrow_mut();
            receipt.kill_requested = true;
            receipt.kill_errno = killed.err().map(safeptrace::Errno::into_raw);
        }
        let outcome = self.cleanup.wait(Duration::from_secs(2));
        {
            let mut receipt = self.receipt.borrow_mut();
            match outcome {
                Ok(true) => match self.cleanup.shared().observed_exit_status() {
                    Ok(Some(status)) => {
                        receipt.confirmed = true;
                        receipt.confirmation = Some(CleanupConfirmation::SafeptraceTerminalWait);
                        receipt.terminal_status = Some(status);
                        receipt.wait_error = None;
                    }
                    Ok(None) => receipt.wait_error = Some(CleanupWaitFailure::UnexpectedStatus),
                    Err(errno) => {
                        receipt.wait_error = Some(CleanupWaitFailure::Errno(errno.into_raw()));
                    }
                },
                Ok(false) => receipt.wait_error = Some(CleanupWaitFailure::TimedOut),
                Err(errno) => {
                    receipt.wait_error = Some(CleanupWaitFailure::Errno(errno.into_raw()))
                }
            }
        }
        // Never let diagnostic I/O precede the owned kill/reap attempts.
        if !self.receipt.snapshot().confirmed {
            eprintln!("exec-stop cleanup did not confirm child retirement: {outcome:?}");
        }
        // Explicit cancellation retains this owner on an unconfirmed attempt.
        // Drop is only bounded best effort; the outer physical run owner must
        // reject an unconfirmed receipt rather than release its backing early.
        self.complete = self.receipt.snapshot().confirmed;
    }

    // Called only after an actual terminal event from this retained driver's
    // generation. Never exposed as a caller-supplied status/retirement setter.
    #[cfg(feature = "loader-private-runtime")]
    fn record_detached_terminal(&mut self, status: ExitStatus) {
        {
            let mut receipt = self.receipt.borrow_mut();
            receipt.confirmed = true;
            receipt.confirmation = Some(CleanupConfirmation::NormalWait);
            receipt.terminal_status = Some(status);
            receipt.wait_error = None;
        }
        self.complete = true;
    }

    /// Wait for this same detached generation, retaining cleanup on every error.
    pub fn wait(mut self, running: Running) -> std::result::Result<ExitStatus, LaunchFailure<'fd>> {
        let result = (|| -> Result<ExitStatus> {
            if running.generation() != self.generation {
                return Err("exec-stop terminal wait received another generation".into());
            }
            match trace::wait(running)? {
                Wait::Exited(_, status) => Ok(status),
                other => Err(format!("exec-stop unexpected post-detach state {other:?}").into()),
            }
        })();
        match result {
            Ok(status) => {
                {
                    let mut receipt = self.receipt.borrow_mut();
                    receipt.confirmed = true;
                    receipt.confirmation = Some(CleanupConfirmation::NormalWait);
                    receipt.terminal_status = Some(status);
                }
                self.complete = true;
                Ok(status)
            }
            Err(error) => {
                let receipt = self.receipt.clone();
                let deferred = self.cancel().err();
                Err(LaunchFailure {
                    error,
                    receipt,
                    owner: deferred,
                    pending: None,
                })
            }
        }
    }
}
impl std::fmt::Debug for ChildOwner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildOwner")
            .field("generation", &self.generation)
            .field("cleanup", &self.receipt.snapshot())
            .finish()
    }
}
impl Drop for ChildOwner<'_> {
    fn drop(&mut self) {
        self.retire();
    }
}

/// Authentic kernel observations on both sides of the exec return drain.
#[derive(Debug)]
pub struct ExecBoundary {
    /// Event-stop register image before draining the kernel return.
    pub event_regs: Regs,
    /// Event-stop syscall information.
    pub event_info: SyscallInfo,
    /// Actual initial exec former tid.
    pub former_tid: safeptrace::Pid,
    /// Syscall-exit register image with no guest instruction progress.
    pub exit_regs: Regs,
    /// Typed successful x86-64 exec syscall-exit observation.
    pub exit_info: SyscallInfo,
}

#[cfg(feature = "loader-private-runtime")]
fn duplicate_guarded_birth_pidfd(
    guard: &safeptrace::PtracerThreadGuard,
    fd: &std::os::fd::OwnedFd,
) -> Result<std::os::fd::OwnedFd> {
    guard.check_current()?;
    let duplicate = duplicate_live_birth_pidfd(fd)?;
    guard.check_current()?;
    Ok(duplicate)
}

// Private kernel operation, called only after the retained host guard succeeds.
#[cfg(feature = "loader-private-runtime")]
fn duplicate_live_birth_pidfd(fd: &std::os::fd::OwnedFd) -> Result<std::os::fd::OwnedFd> {
    live_birth_pidfd(fd)?;
    // OwnedFd::try_clone uses a new CLOEXEC descriptor to the SAME kernel object.
    let duplicate = fd.try_clone()?;
    live_birth_pidfd(fd)?;
    live_birth_pidfd(&duplicate)?;
    Ok(duplicate)
}

/// The complete original entry context; restoration proves no runtime readiness.
pub struct EntryContext {
    /// Kernel entry registers, including FS/GS.
    regs: Regs,
    generation: safeptrace::TraceeGeneration,
    /// Opaque complete xstate image.
    xstate: safeptrace::XState,
    /// Original guest signal mask.
    signal_mask: u64,
    /// Start of the selected initial stack VMA.
    stack_start: u64,
    /// Original bytes of the entire selected initial stack VMA.
    stack_bytes: Vec<u8>,
}
impl EntryContext {
    /// Original kernel register image.
    pub fn regs(&self) -> &Regs {
        &self.regs
    }
    /// Original opaque xstate bytes.
    pub fn xstate(&self) -> &safeptrace::XState {
        &self.xstate
    }
    /// Original signal mask.
    pub fn signal_mask(&self) -> u64 {
        self.signal_mask
    }
    /// Original selected initial stack start.
    pub fn stack_start(&self) -> u64 {
        self.stack_start
    }
    /// Original selected initial stack contents.
    pub fn stack_bytes(&self) -> &[u8] {
        &self.stack_bytes
    }

    /// Snapshot the actual stopped image without modifying it.
    fn capture(task: &Stopped) -> Result<Self> {
        let regs = task.getregs()?;
        let signal_mask = task.getsigmask()?;
        let xstate = task.getxstate()?;
        let (stack_start, stack_bytes) = snapshot_stack(task, regs.rsp)?;
        Ok(Self {
            regs,
            generation: task.generation(),
            xstate,
            signal_mask,
            stack_start,
            stack_bytes,
        })
    }

    // Only the retained post-initializer path calls this. The preparation
    // restore below intentionally continues to require the ORIGINAL stack.
    // Snapshot CURRENT stack bytes: genuine Detcore may have changed AT_RANDOM.
    // No write targets this stack, including its AT_RANDOM pointed-to bytes.
    #[cfg(feature = "loader-private-runtime")]
    fn restore_after_initializer(&self, task: &Stopped, mask: u64) -> Result<()> {
        if task.generation() != self.generation {
            return Err("mapped_handover_foreign_context".into());
        }
        let current_stack = trace::read(task, self.stack_start, self.stack_bytes.len())?;
        task.setxstate(&self.xstate)?;
        task.setregs(&self.regs)?;
        task.setsigmask(mask)?;
        if register_words(&task.getregs()?) != register_words(&self.regs)
            || task.getxstate()? != self.xstate
            || task.getsigmask()? != mask
            || trace::read(task, self.stack_start, current_stack.len())? != current_stack
        {
            return Err("mapped_handover_context_readback".into());
        }
        Ok(())
    }

    /// Check the untouched guest stack, restore and read back the exact context.
    /// This says nothing about whether the caller's runtime is ready to release.
    pub fn restore(&self, task: &Stopped) -> Result<()> {
        if task.generation() != self.generation {
            return Err("exec-stop context restore received another generation".into());
        }
        if trace::read(task, self.stack_start, self.stack_bytes.len())? != self.stack_bytes {
            return Err("loader refused: bootstrap changed the kernel guest stack".into());
        }
        task.setxstate(&self.xstate)?;
        task.setregs(&self.regs)?;
        task.setsigmask(self.signal_mask)?;
        if register_words(&task.getregs()?) != register_words(&self.regs)
            || task.getxstate()? != self.xstate
            || task.getsigmask()? != self.signal_mask
        {
            return Err("loader refused: original kernel entry context did not restore".into());
        }
        Ok(())
    }
}

/// A genuine stopped initial image together with its physical lifetime owner.
#[must_use = "retain this actual stop and physical owner until terminal cleanup"]
pub struct InitialExecStop<'fd> {
    task: Stopped,
    context: EntryContext,
    boundary: ExecBoundary,
    owner: ChildOwner<'fd>,
}
impl<'fd> InitialExecStop<'fd> {
    /// The actual child identity, without a raw ptrace generation capability.
    pub fn pid(&self) -> safeptrace::Pid {
        self.task.pid()
    }

    /// Fixture-only raw access; never a production runtime-ready capability.
    #[cfg(feature = "stage1a-probe")]
    pub fn stopped(&self) -> &Stopped {
        &self.task
    }
    /// Duplicate this held birth's original kernel pidfd for coordinator admission.
    /// Runs only on the original ptracer OS thread and checks the actual stopped
    /// generation. This conveys descriptor identity only, never wait ownership,
    /// image qualification, readiness or permission to resume. Use it with the
    /// existing passive admission/watch; ChildOwner remains the sole ptrace waiter.
    /// Liveness is checked around duplication, not guaranteed after return.
    #[cfg(feature = "loader-private-runtime")]
    pub fn duplicate_birth_pidfd(&self) -> Result<std::os::fd::OwnedFd> {
        self.owner.duplicate_birth_pidfd(&self.task)
    }

    /// Duplicate this held birth only for a descriptor borrowed by its retained launch.
    ///
    /// This checks the exact borrowed descriptor in the immutable PreparedExec,
    /// not an equal inode, path, or caller-supplied identity. The original lease
    /// must remain valid without unsafe close/replacement or concurrent offset
    /// mutation. The child has not run guest instructions; its exec inheritance
    /// is still governed by that retained request. No resume capability is added.
    #[cfg(feature = "loader-private-runtime")]
    pub fn duplicate_birth_pidfd_for_inherited(
        &self,
        fd: std::os::fd::BorrowedFd<'_>,
    ) -> Result<std::os::fd::OwnedFd> {
        self.owner
            .duplicate_birth_pidfd_for_inherited(&self.task, fd)
    }

    /// Inspect the original entry and initial stack without reading environ.
    pub fn entry(&self) -> &EntryContext {
        &self.context
    }
    /// Inspect the exact exec boundary observations.
    pub fn boundary(&self) -> &ExecBoundary {
        &self.boundary
    }
    /// Cancel while no guest instruction has been released.
    pub fn cancel(self) -> std::result::Result<CleanupState, Box<ChildOwner<'fd>>> {
        self.owner.cancel()
    }
    /// Fixture-only transfer for the separate test-runtime protocol.
    /// Production release must instead require genuine Detcore readiness.
    #[cfg(feature = "stage1a-probe")]
    pub fn into_parts(self) -> (Stopped, EntryContext, ExecBoundary, ChildOwner<'fd>) {
        (self.task, self.context, self.boundary, self.owner)
    }
}

/// Failed launch retaining any child whose terminal retirement is unconfirmed.
#[must_use = "unconfirmed failure retains the original child cleanup authority"]
pub struct LaunchFailure<'fd> {
    /// Source error; no runtime-ready state was established.
    pub error: Box<dyn std::error::Error>,
    receipt: CleanupReceipt,
    owner: Option<Box<ChildOwner<'fd>>>,
    pending: Option<Box<(child::PendingChild, PreparedExec<'fd>)>>,
}
impl LaunchFailure<'_> {
    /// Snapshot actual cleanup observations, including unconfirmed retirement.
    pub fn cleanup(&self) -> CleanupState {
        self.receipt.snapshot()
    }
    /// Retry bounded retirement without discarding an unresolved owner.
    pub fn retry_cleanup(&mut self) -> bool {
        if let Some(owner) = &mut self.owner {
            owner.retire();
        }
        if self.owner.as_ref().is_some_and(|owner| owner.complete) {
            self.owner.take();
        }
        if let Some(pending) = &mut self.pending {
            pending.0.retire();
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| !pending.0.is_owned())
        {
            self.pending.take();
        }
        self.owner.is_none() && self.pending.is_none()
    }
}
impl std::fmt::Debug for LaunchFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchFailure")
            .field("error", &self.error)
            .field("cleanup", &self.cleanup())
            .finish()
    }
}
impl std::fmt::Display for LaunchFailure<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for LaunchFailure<'_> {}

/// First-image direct-exec launcher, independent of runtime readiness policy.
pub struct ExecStop;
impl ExecStop {
    /// Clone one owned child and drain only its initial exec's kernel return.
    /// Caller must retain an external physical deadline for synchronous waits.
    pub fn spawn<'fd>(
        request: PreparedExec<'fd>,
        receipt: CleanupReceipt,
    ) -> std::result::Result<InitialExecStop<'fd>, LaunchFailure<'fd>> {
        if !receipt.claim() {
            return Err(LaunchFailure {
                error: "exec-stop cleanup receipt already used".into(),
                receipt,
                owner: None,
                pending: None,
            });
        }
        let mut pending = match request.fork(receipt.clone()) {
            Ok(pending) => pending,
            Err(error) => {
                return Err(LaunchFailure {
                    error: format!("loader_clone_pidfd_refused: {error}").into(),
                    receipt,
                    owner: None,
                    pending: None,
                });
            }
        };
        #[cfg(feature = "loader-private-runtime")]
        let birth_pidfd = match pending.duplicate_birth_pidfd() {
            Ok(fd) => fd,
            Err(error) => {
                pending.retire();
                let deferred = pending.is_owned().then(|| Box::new((pending, request)));
                return Err(LaunchFailure {
                    error: format!("exec_stop_birth_pidfd_retention_failed: {error}").into(),
                    receipt,
                    owner: None,
                    pending: deferred,
                });
            }
        };
        let pid = pending.pid();
        let running = match Running::new_on_ptracer_thread(pid) {
            Ok(running) => running,
            Err(error) => {
                pending.retire();
                let deferred = pending.is_owned().then(|| Box::new((pending, request)));
                return Err(LaunchFailure {
                    error: error.into(),
                    receipt,
                    owner: None,
                    pending: deferred,
                });
            }
        };
        let cleanup = running.terminal_cleanup_on_ptracer_thread();
        let generation = running.generation();
        // No fallible operation between installing the original generation's
        // cleanup owner and disarming the atomic pre-registration pidfd owner.
        let mut owner = ChildOwner {
            cleanup,
            generation,
            #[cfg(feature = "loader-private-runtime")]
            birth_pidfd,
            _thread: None,
            _request: request,
            receipt: receipt.clone(),
            complete: false,
        };
        pending.transfer_to_ptracer();
        let result = (|| -> Result<(Stopped, EntryContext, ExecBoundary)> {
            owner._thread = Some(owner.generation.ptracer_thread_guard()?);
            let (initial, event) = trace::stopped(running, "initial TRACEME stop")?;
            if !matches!(event, Event::Signal(Signal::SIGSTOP)) {
                return Err(format!("loader refused: wrong initial stop {event:?}").into());
            }
            initial.setoptions(
                Options::PTRACE_O_EXITKILL
                    | Options::PTRACE_O_TRACEEXEC
                    | Options::PTRACE_O_TRACESYSGOOD,
            )?;
            let (exec, event) = trace::stopped(initial.resume(None)?, "kernel exec event")?;
            let at_event = exec.getregs()?;
            let at_event_info = exec.getsyscallinfo()?;
            if !matches!(event, Event::Exec(former) if former == pid) {
                return Err(
                    format!("loader refused: expected initial exec event, got {event:?}").into(),
                );
            }
            if at_event.orig_rax != libc::SYS_execve as u64 {
                return Err(
                    "loader refused: exec event did not originate in the launcher's execve".into(),
                );
            }
            let (task, event) = trace::stopped(exec.syscall(None)?, "exec syscall-exit drain")?;
            let info = task.getsyscallinfo()?;
            let entry = task.getregs()?;
            if !matches!(event, Event::Syscall)
                || info.architecture != 0xc000_003e
                || info.operation
                    != (SyscallInfoOp::Exit {
                        return_value: 0,
                        is_error: false,
                    })
                || entry.rip != at_event.rip
                || entry.rsp != at_event.rsp
                || info.instruction_pointer != entry.rip
                || info.stack_pointer != entry.rsp
            {
                return Err(format!(
                    "loader refused: exec return did not drain without entry progress: {info:?}"
                )
                .into());
            }
            let context = EntryContext::capture(&task)?;
            let boundary = ExecBoundary {
                event_regs: at_event,
                event_info: at_event_info,
                former_tid: pid,
                exit_regs: entry,
                exit_info: info,
            };
            Ok((task, context, boundary))
        })();
        match result {
            Ok((task, context, boundary)) => Ok(InitialExecStop {
                task,
                context,
                boundary,
                owner,
            }),
            Err(error) => {
                let deferred = owner.cancel().err();
                Err(LaunchFailure {
                    error,
                    receipt,
                    owner: deferred,
                    pending: None,
                })
            }
        }
    }
}

fn snapshot_stack(task: &Stopped, rsp: u64) -> Result<(u64, Vec<u8>)> {
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", task.pid()))?;
    let mut selected = None;
    for line in maps.lines().filter(|line| line.ends_with("[stack]")) {
        let span = line
            .split_whitespace()
            .next()
            .ok_or("missing stack range")?;
        let (lo, hi) = span.split_once('-').ok_or("invalid stack range")?;
        let lo = u64::from_str_radix(lo, 16)?;
        let hi = u64::from_str_radix(hi, 16)?;
        if (lo..hi).contains(&rsp) {
            if selected.is_some() || hi - lo > 16 * 1024 * 1024 {
                return Err("loader refused: ambiguous or oversized initial stack".into());
            }
            selected = Some((lo, trace::read(task, lo, (hi - lo) as usize)?));
        }
    }
    selected.ok_or_else(|| "loader refused: initial stack VMA not found".into())
}

/// Exact native x86-64 register words, including segment and base state.
pub fn register_words(r: &Regs) -> [u64; 27] {
    [
        r.r15, r.r14, r.r13, r.r12, r.rbp, r.rbx, r.r11, r.r10, r.r9, r.r8, r.rax, r.rcx, r.rdx,
        r.rsi, r.rdi, r.orig_rax, r.rip, r.cs, r.eflags, r.rsp, r.ss, r.fs_base, r.gs_base, r.ds,
        r.es, r.fs, r.gs,
    ]
}

#[cfg(all(test, feature = "loader-private-runtime"))]
// Test-only raw FD queries and the explicit isolated rlimit control. Each raw
// operation documents SAFETY; production unsafe remains in the child boundary.
#[allow(unsafe_code)]
mod birth_pidfd_tests;
