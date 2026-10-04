/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs::File;
use std::future::Future;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use futures::FutureExt;
use futures::channel::oneshot;
use futures::future::Shared;
use kvm_bindings::CpuId;
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_bindings::kvm_enable_cap;
use kvm_bindings::kvm_regs;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_bindings::kvm_xsave;
use kvm_ioctls::Cap;
use kvm_ioctls::Kvm;
use kvm_ioctls::VcpuExit;
use kvm_ioctls::VcpuFd;
use kvm_ioctls::VmFd;
use reverie::BackendStatsRequest;
use reverie::BackendStatsSource;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Pid;
use reverie::SignalProcessId;
use reverie::ThreadOwnership;
use reverie::Tool;

use crate::CpuidPolicy;
use crate::Error;
use crate::GuestMemory;
use crate::Result;
use crate::Syscall;
use crate::SyscallRequest;
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::MAX_GUEST_THREADS;
use crate::bootstrap::SYSCALL_FRAME_ADDRESS;
use crate::bootstrap::SYSCALL_TRAMPOLINE_ADDRESS;
use crate::bootstrap::SegmentBase;
use crate::bootstrap::THREAD_SYSCALL_AREA_START;
use crate::bootstrap::THREAD_SYSCALL_AREA_STRIDE;
use crate::bootstrap::THREAD_TOOL_STACK_AREA_START;
use crate::bootstrap::TOOL_STACK_SIZE;
use crate::bootstrap::TOOL_STACK_TOP;
use crate::bootstrap::configure_long_mode;
use crate::bootstrap::configure_long_mode_with_syscall_area;
use crate::bootstrap::configure_process_syscall_return;
use crate::bootstrap::configure_user_segments;
use crate::bootstrap::exception_from_halt;
use crate::bootstrap::exception_pushes_error_code;
use crate::bootstrap::process_syscall_return_registers;
use crate::bootstrap::set_user_segment_base;
use crate::bootstrap::stage_process_syscall_return;
use crate::bootstrap::syscall_hypercall_address;
use crate::bootstrap::thread_tool_stack_top;
use crate::bootstrap::try_set_syscall_return_park;
use crate::elf::LoadedStaticElf;
use crate::elf::TaskLifecycleTable;
use crate::elf::initial_thread_name;
use crate::elf::load_static_elf;
use crate::elf::load_static_elf_file;
use crate::executor::AbandonedRuns;
use crate::executor::CapturedOutput;
#[cfg(test)]
use crate::executor::ChildCompletion;
use crate::executor::ChildCompletionSlot;
use crate::executor::ChildStartCommand;
use crate::executor::ChildStartGate;
use crate::executor::ChildThread;
use crate::executor::ElfExecutor;
use crate::executor::ProcessAction;
use crate::executor::ProcessExit;
use crate::executor::ProcessSignalBindingGuard;
use crate::executor::RunAdmission;
use crate::executor::SignalDisposition;
use crate::executor::conventional_exit_code;
use crate::runtime::PendingChildCancellation;
use crate::runtime::PendingChildKind;
use crate::runtime::PendingChildStart;
use crate::runtime::SharedChildStarts;
use crate::runtime::ToolContext;
use crate::signal::LEGACY_FPSTATE_SIZE;
use crate::signal::RT_SIGFRAME_SIZE;
use crate::signal::RT_SIGRETURN_SIZE;
use crate::signal::RtSigframe;
use crate::signal::SA_RESTORER;
use crate::signal::SIGNAL_UCONTEXT_FLAGS;
use crate::signal::Sigcontext;
use crate::signal::SignalFrameLayout;
use crate::signal::Ucontext;
use crate::signal::XsaveImage;
use crate::stats::KvmBackendStats;
use crate::stats::KvmExitCollector;
use crate::syscall::FRAME_SIZE;

/// KVM currently permits userspace exits for this standardized hypercall.
/// The prototype uses it as a transport opcode and places the syscall frame
/// address in the first hypercall argument.
pub const VMCALL_SYSCALL_TRANSPORT: u64 = 12;

const SYSCALL_FRAME_STRIDE: u64 = 4096;
const PAGE_SIZE: u64 = 4096;
const VMCALL: [u8; 3] = [0x0f, 0x01, 0xc1];
const VMMCALL: [u8; 3] = [0x0f, 0x01, 0xd9];
const HLT: u8 = 0xf4;
const VMWARE_BACKDOOR_MAGIC: u64 = 0x564d_5868;
const VMWARE_BACKDOOR_PORT: u64 = 0x5658;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StaticElfException {
    vector: u8,
    instruction_pointer: u64,
    stack_pointer: u64,
    rflags: u64,
}

pub(crate) struct InstructionBoundary<I> {
    pub(crate) registers: kvm_regs,
    pub(crate) instruction: I,
    special_registers: kvm_bindings::kvm_sregs,
    code_segment: u16,
    stack_segment: u16,
}

pub(crate) type TimestampBoundary = InstructionBoundary<crate::timestamp::TimestampInstruction>;
pub(crate) type CpuidBoundary = InstructionBoundary<crate::cpuid_instruction::Instruction>;

pub(crate) enum ToolInstructionBoundary {
    Timestamp(TimestampBoundary),
    Cpuid(CpuidBoundary),
}

pub(crate) enum ToolInstructionResult {
    Timestamp(reverie::RdtscResult),
    Cpuid(reverie::CpuIdResult),
}

impl ToolInstructionBoundary {
    pub(crate) fn user_registers(&self) -> libc::user_regs_struct {
        match self {
            Self::Timestamp(boundary) => boundary.user_registers(),
            Self::Cpuid(boundary) => boundary.user_registers(),
        }
    }
}

impl<I> InstructionBoundary<I> {
    pub(crate) fn user_registers(&self) -> libc::user_regs_struct {
        let mut registers = crate::runtime::kvm_registers(self.registers, u64::MAX);
        registers.cs = self.code_segment.into();
        registers.ss = self.stack_segment.into();
        registers.ds = self.special_registers.ds.selector.into();
        registers.es = self.special_registers.es.selector.into();
        registers.fs = self.special_registers.fs.selector.into();
        registers.gs = self.special_registers.gs.selector.into();
        registers.fs_base = self.special_registers.fs.base;
        registers.gs_base = self.special_registers.gs.base;
        registers
    }
}

#[derive(Clone)]
pub(crate) struct PageZeroFault {
    pub(crate) registers: kvm_regs,
    pub(crate) event: reverie::SignalEvent,
    code_segment: u16,
    stack_segment: u16,
    error_code: u64,
    address: u64,
    halted_registers: kvm_regs,
    special_registers: kvm_bindings::kvm_sregs,
    xsave: Arc<kvm_xsave>,
    transport: [u8; FRAME_SIZE],
    transport_address: u64,
}

impl PageZeroFault {
    #[cfg(test)]
    pub(crate) fn for_test(event: reverie::SignalEvent) -> Self {
        Self {
            event,
            // SAFETY: these plain KVM ABI structures admit all-zero values.
            // Policy and pending-domain tests never submit this fixture to KVM.
            registers: unsafe { std::mem::zeroed() },
            halted_registers: unsafe { std::mem::zeroed() },
            special_registers: unsafe { std::mem::zeroed() },
            xsave: Arc::new(unsafe { std::mem::zeroed() }),
            code_segment: crate::signal::USER_CODE_SELECTOR,
            stack_segment: crate::signal::USER_DATA_SELECTOR,
            error_code: 4,
            address: 0,
            transport: [0; FRAME_SIZE],
            transport_address: 0x1000,
        }
    }

    pub(crate) fn pending(&self) -> crate::executor::PendingSignal {
        crate::executor::PendingSignal {
            event: self.event,
            domain: crate::executor::PendingSignalDomain::Thread,
        }
    }

    pub(crate) fn resume_user(&self, backend: &mut KvmBackend, registers: kvm_regs) -> Result<()> {
        configure_user_segments(&backend.vcpu)?;
        let mut special = backend.vcpu.get_sregs()?;
        special.cs.selector = self.code_segment;
        special.ss.selector = self.stack_segment;
        backend.vcpu.set_sregs(&special)?;
        backend.vcpu.set_regs(&registers)?;
        Ok(())
    }

    pub(crate) fn user_registers(&self) -> libc::user_regs_struct {
        let mut registers = crate::runtime::kvm_registers(self.registers, u64::MAX);
        registers.cs = self.code_segment.into();
        registers.ss = self.stack_segment.into();
        registers.fs_base = self.special_registers.fs.base;
        registers.gs_base = self.special_registers.gs.base;
        registers.ds = self.special_registers.ds.selector.into();
        registers.es = self.special_registers.es.selector.into();
        registers.fs = self.special_registers.fs.selector.into();
        registers.gs = self.special_registers.gs.selector.into();
        registers
    }

    fn restore_boundary(&self, backend: &mut KvmBackend) -> Result<()> {
        backend
            .memory
            .write_raw(self.transport_address, &self.transport)?;
        backend.vcpu.set_sregs(&self.special_registers)?;
        backend.vcpu.set_regs(&self.halted_registers)?;
        unsafe {
            backend.vcpu.set_xsave(self.xsave.as_ref())?;
        }
        Ok(())
    }

    fn configure_child(&self, backend: &mut KvmBackend, stack: Option<u64>) -> Result<()> {
        let mut registers = self.registers;
        registers.rax = 0;
        if let Some(stack) = stack {
            registers.rsp = stack;
        }
        self.resume_user(backend, registers)?;
        unsafe {
            backend.vcpu.set_xsave(self.xsave.as_ref())?;
        }
        Ok(())
    }
}

extern "C" fn interrupt_guest_worker(_signal: libc::c_int) {
    #[cfg(test)]
    tests::inline_interrupt_tests::observe_delivery();
}

fn worker_interrupt_signal() -> libc::c_int {
    libc::SIGURG
}

fn install_worker_interrupt_handler() -> Result<()> {
    static INSTALL_ERRNO: OnceLock<libc::c_int> = OnceLock::new();
    let errno = *INSTALL_ERRNO.get_or_init(|| {
        // SAFETY: action is initialized before sigaction reads it. The handler
        // performs no operations and exists only to make blocking syscalls
        // return EINTR during KVM thread-group teardown.
        unsafe {
            let mut action = std::mem::zeroed::<libc::sigaction>();
            action.sa_sigaction = interrupt_guest_worker as *const () as usize;
            action.sa_flags = 0;
            libc::sigemptyset(&mut action.sa_mask);
            if libc::sigaction(worker_interrupt_signal(), &action, std::ptr::null_mut()) == 0 {
                0
            } else {
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EIO)
            }
        }
    });
    if errno == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(errno).into())
    }
}

fn set_guest_interrupt_signal_mask(how: libc::c_int) -> Result<bool> {
    // SAFETY: set and previous are initialized before libc reads or writes them.
    unsafe {
        let mut set = std::mem::zeroed::<libc::sigset_t>();
        let mut previous = std::mem::zeroed::<libc::sigset_t>();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, worker_interrupt_signal());
        let error = libc::pthread_sigmask(how, &set, &mut previous);
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error).into());
        }
        Ok(libc::sigismember(&previous, worker_interrupt_signal()) == 1)
    }
}
type GuestWorkerResult = Result<(ExitStatus, Vec<u8>, Vec<u8>)>;

#[path = "vm/worker_join.rs"]
mod worker_join;
use worker_join::WorkerJoins;

struct GuestWorkerHandle {
    tid: i32,
    start: Option<ChildStartGate>,
    returning: Option<Arc<AtomicBool>>,
    handle: std::thread::JoinHandle<GuestWorkerResult>,
}

/// The outermost worker wrapper drops this after the actual worker closure
/// and its owned state have returned or unwound. This only makes the worker
/// eligible for an owned physical join: arbitrary TLS destructors may follow.
struct WorkerCompletionNotice {
    group: Arc<GuestThreadGroup>,
    returning: Arc<AtomicBool>,
}

impl WorkerCompletionNotice {
    fn new(group: Arc<GuestThreadGroup>) -> Self {
        Self {
            group,
            returning: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Drop for WorkerCompletionNotice {
    fn drop(&mut self) {
        self.returning.store(true, Ordering::Release);
        self.group.notify_worker_completion();
    }
}

/// How an inline (Direct) fork child's completion resolved for its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForkedProcessCompletion {
    /// The caller's fork returns the child PID with the status recorded.
    Returned,
    /// The caller's process exited while the child ran; an outside namespace
    /// init reaped the child and the caller's fork never returns.
    Detached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProcessActionOutcome {
    pub(crate) image_replaced: bool,
    pub(crate) syscall_result: i64,
    pub(crate) cancelled: bool,
}

impl ProcessActionOutcome {
    fn returned(syscall_result: i64) -> Self {
        Self {
            image_replaced: false,
            syscall_result,
            cancelled: false,
        }
    }

    pub(crate) fn replaced() -> Self {
        Self {
            image_replaced: true,
            syscall_result: 0,
            cancelled: false,
        }
    }

    fn cancelled() -> Self {
        Self {
            image_replaced: false,
            // No guest result is installed for this terminal disposition.
            syscall_result: 0,
            cancelled: true,
        }
    }
}

pub(crate) type GuestCancellationSubscription = Shared<oneshot::Receiver<()>>;

struct CancellationWake {
    sender: oneshot::Sender<()>,
    receiver: GuestCancellationSubscription,
}

impl Default for CancellationWake {
    fn default() -> Self {
        let (sender, receiver) = oneshot::channel();
        Self {
            sender,
            receiver: receiver.shared(),
        }
    }
}

#[derive(Default)]
// TODO-HUMAN-REVIEW(PR-172): Review process-wide KVM worker cancellation state.
pub(crate) struct GuestThreadGroup {
    cancelled: AtomicBool,
    cancelled_after_failure: AtomicBool,
    cancellation_wake: Mutex<CancellationWake>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Propagate worker exit_group to the root vCPU.
    // TODO-HUMAN-REVIEW(PR-177): Review KVM thread-group exit ordering.
    exit_status: Mutex<Option<ExitStatus>>,
    root: Mutex<Option<libc::pthread_t>>,
    workers: Mutex<Vec<libc::pthread_t>>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Join cancelled KVM workers before root teardown returns.
    // TODO-HUMAN-REVIEW(PR-178): Review KVM worker join ordering.
    worker_handles: Mutex<Vec<GuestWorkerHandle>>,
    worker_joins: Arc<WorkerJoins>,
    // Helpers are canceled before a terminal Rust-worker join. Each blocked
    // worker retains and physically joins its own C read helper locally.
    terminal_reads: Arc<crate::terminal_read::ReadRegistry>,
    // Joining moves handles out of the registry. Cancellation must still own
    // every pending gate while a moved handle is blocking in JoinHandle::join.
    worker_start_gates: Mutex<std::collections::BTreeMap<i32, ChildStartGate>>,
    // Intermediate joins must not consume a failed exit hook. Keep every
    // failure until the process owner reports teardown, ordered by guest TID.
    worker_errors: Mutex<std::collections::BTreeMap<i32, Vec<Arc<Error>>>>,
    // A caught worker panic is published before retirement, then matched to
    // that worker's actual panicked join without creating another cause.
    reported_worker_panics: Mutex<std::collections::BTreeMap<i32, WorkerPanicRecord>>,
    // Keep payload destruction out of worker unwind and physical join. Typed
    // diagnostics remain in worker_errors for repeated teardown observations.
    completed_worker_panics: Mutex<Vec<WorkerPanicRecord>>,
    failure_state: Mutex<WorkerFailureState>,
    transport_slots: Mutex<Vec<bool>>,
}

struct WorkerPanicRecord {
    error: Arc<Error>,
    _cleanup_panics: Vec<crate::failure::owned_future::PanicPayload>,
    _join_payload: Option<crate::failure::owned_future::PanicPayload>,
}

#[derive(Default)]
struct WorkerFailureState {
    natural_join_started: bool,
    worker_failed: bool,
    reportable_errors: std::collections::BTreeSet<i32>,
}

/// Publish a host-owned worker's returned error before retirement can wake a
/// Tool-owned peer. Ordinary non-Tool workers retain their existing result.
pub(crate) fn finish_host_worker_outcome<R>(
    failure: Option<&crate::failure::FailureContext>,
    tid: Pid,
    result: Result<R>,
    retire: impl FnOnce(bool),
) -> Result<R> {
    let result = result.map_err(|error| match failure {
        Some(failure) => failure.for_thread(tid).publish("host-owned worker", error),
        None => error,
    });
    retire(result.is_err());
    result
}

/// Finish the already caught worker panic. This is not a general unwind guard:
/// callback state may already have unwound, so no consuming hook is invented.
#[cfg(test)]
pub(crate) fn finish_caught_worker_panic(
    failure: Option<&crate::failure::FailureContext>,
    group: &GuestThreadGroup,
    tid: i32,
    error: Error,
    payload: Box<dyn std::any::Any + Send>,
    retire: impl FnOnce(),
) -> ! {
    let error = publish_caught_worker_panic(failure, tid, error);
    resume_caught_worker_panic(
        group,
        tid,
        error,
        crate::failure::owned_future::CaughtFuture {
            output: Some(Ok(())),
            panics: Vec::new(),
        },
        payload,
        retire,
    )
}

fn publish_caught_worker_panic(
    failure: Option<&crate::failure::FailureContext>,
    tid: i32,
    error: Error,
) -> Error {
    match failure {
        Some(failure) => failure
            .for_thread(Pid::from_raw(tid))
            .publish("worker panic", error),
        None => error,
    }
}

#[cfg(test)]
fn resume_caught_worker_panic(
    group: &GuestThreadGroup,
    tid: i32,
    error: Error,
    cleanup: crate::failure::owned_future::CaughtFuture<Result<()>>,
    payload: crate::failure::owned_future::PanicPayload,
    retire: impl FnOnce(),
) -> ! {
    let mut errors: Vec<_> = cleanup
        .output
        .expect("unstarted child cleanup drain did not return")
        .err()
        .into_iter()
        .collect();
    errors.extend(
        cleanup
            .panics
            .iter()
            .map(|_| Error::GuestWorkerPanic.cleanup("unstarted-child cleanup")),
    );
    let record = WorkerPanicRecord {
        error: Arc::new(error.with_cleanup(errors)),
        _cleanup_panics: cleanup.panics,
        _join_payload: None,
    };
    resume_worker_panic_record(group, tid, record, payload, retire)
}

fn resume_worker_panic_record(
    group: &GuestThreadGroup,
    tid: i32,
    record: WorkerPanicRecord,
    payload: crate::failure::owned_future::PanicPayload,
    retire: impl FnOnce(),
) -> ! {
    let previous = group
        .reported_worker_panics
        .lock()
        .expect("KVM reported worker panic lock poisoned")
        .insert(tid, record);
    assert!(
        previous.is_none(),
        "KVM worker panic recorded twice for tid {tid}"
    );
    retire();
    group.record_worker_failure(tid);
    std::panic::resume_unwind(payload)
}

impl GuestThreadGroup {
    /// Subscribe before rechecking the caller's existing cancellation and exit
    /// predicates. Readiness only requests another recheck; it grants no entry
    /// and does not decide whether worker cancellation applies to the root.
    /// Take a fresh subscription after every wake, including an irrelevant one.
    pub(crate) fn subscribe_cancellation(&self) -> GuestCancellationSubscription {
        self.cancellation_wake
            .lock()
            .expect("KVM cancellation wake lock poisoned")
            .receiver
            .clone()
    }

    /// Called after publishing state and releasing every group registry lock.
    fn notify_cancellation(&self) {
        let previous = {
            let mut wake = self
                .cancellation_wake
                .lock()
                .expect("KVM cancellation wake lock poisoned");
            std::mem::take(&mut *wake)
        };
        // Install a pending generation before invoking any wake callback. In
        // particular, exec rearm and a root ignoring worker-only cancellation
        // must not inherit a permanently-ready notification. Send outside the
        // notification lock too: a callback may immediately subscribe again.
        let _ = previous.sender.send(());
    }

    #[cfg(test)]
    pub(crate) fn has_worker_handles(&self) -> bool {
        self.has_owned_worker_joins()
    }

    pub(crate) fn record_worker_failure(&self, tid: i32) {
        self.cancelled_after_failure.store(true, Ordering::Release);
        let joining = {
            let mut state = self
                .failure_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !self.cancelled.load(Ordering::Acquire) {
                state.reportable_errors.insert(tid);
            }
            state.worker_failed = true;
            state.natural_join_started
        };
        if joining {
            self.cancel_workers();
        }
    }

    fn take_worker_error_report(&self, tid: i32) -> bool {
        self.failure_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .reportable_errors
            .remove(&tid)
    }

    fn begin_natural_join(&self) {
        let failed = {
            let mut state = self
                .failure_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.natural_join_started = true;
            state.worker_failed
        };
        // The shared lock covers both arrival orders: a completed failure must
        // not hide behind an earlier live handle, and a later failure must wake
        // a natural join that is already waiting for that handle.
        if failed {
            self.cancel_workers();
        }
    }

    fn exit_status(&self) -> Option<ExitStatus> {
        *self
            .exit_status
            .lock()
            .expect("KVM exit-group lock poisoned")
    }

    fn request_exit_group(&self, status: ExitStatus) {
        let status = *self
            .exit_status
            .lock()
            .expect("KVM exit-group lock poisoned")
            .get_or_insert(status);
        self.cancelled.store(true, Ordering::Release);
        self.terminal_reads.request_exit_group(status);

        if let Some(root) = *self.root.lock().expect("KVM guest root lock poisoned") {
            // SAFETY: root is registered for the lifetime of its run loop.
            unsafe {
                libc::pthread_kill(root, worker_interrupt_signal());
            }
        }
        let workers = self.workers.lock().expect("KVM guest worker lock poisoned");
        for &worker in workers.iter() {
            // SAFETY: the registry lock keeps each pthread ID live for this call.
            unsafe {
                libc::pthread_kill(worker, worker_interrupt_signal());
            }
        }
        drop(workers);
        self.notify_cancellation();
    }

    #[cfg(any(test, feature = "native-test-support"))]
    pub(crate) fn add_worker_handle(
        &self,
        tid: i32,
        handle: std::thread::JoinHandle<GuestWorkerResult>,
    ) {
        self.add_worker_handle_with_gate(tid, None, handle);
    }

    #[cfg(test)]
    fn add_unstarted_worker(
        &self,
        tid: i32,
        start: ChildStartGate,
        handle: std::thread::JoinHandle<GuestWorkerResult>,
    ) {
        self.add_worker_handle_with_gate(tid, Some(start), handle);
    }

    #[cfg(any(test, feature = "native-test-support"))]
    fn add_worker_handle_with_gate(
        &self,
        tid: i32,
        start: Option<ChildStartGate>,
        handle: std::thread::JoinHandle<GuestWorkerResult>,
    ) {
        self.add_worker_handle_with_completion(tid, start, None, handle);
    }

    fn add_worker_handle_with_completion(
        &self,
        tid: i32,
        start: Option<ChildStartGate>,
        returning: Option<Arc<AtomicBool>>,
        handle: std::thread::JoinHandle<GuestWorkerResult>,
    ) {
        let joins = self.worker_joins.lock();
        let mut handles = self
            .worker_handles
            .lock()
            .expect("KVM guest worker-handle lock poisoned");
        assert!(
            !handles.iter().any(|worker| worker.tid == tid) && !joins.active.contains_key(&tid),
            "duplicate KVM guest worker tid {tid}"
        );
        if let Some(gate) = &start {
            self.worker_start_gates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(tid, gate.clone());
        }
        let gate = start.clone();
        handles.push(GuestWorkerHandle {
            tid,
            start,
            returning,
            handle,
        });
        drop(handles);
        drop(joins);
        if self.cancelled.load(Ordering::Acquire)
            && let Some(gate) = gate
        {
            self.cancel_worker_gate(&gate);
        }
        self.notify_worker_completion();
    }

    fn subscribe_worker_completion(&self) -> GuestCancellationSubscription {
        self.worker_joins.subscribe()
    }

    fn notify_worker_completion(&self) {
        self.worker_joins.notify();
    }

    fn retain_joined_worker_panic(
        &self,
        tid: i32,
        payload: crate::failure::owned_future::PanicPayload,
    ) -> Arc<Error> {
        // Move the entire record out before touching payload ownership. A
        // temporary guard chained to field extraction could drop other fields
        // while still holding the registry lock.
        let record = {
            self.reported_worker_panics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&tid)
        };
        let mut record = record.unwrap_or_else(|| WorkerPanicRecord {
            error: Arc::new(Error::GuestWorkerPanic),
            _cleanup_panics: Vec::new(),
            _join_payload: None,
        });
        record._join_payload = Some(payload);
        let error = record.error.clone();
        self.completed_worker_panics
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(record);
        error
    }

    fn cancel_worker_gate(&self, gate: &ChildStartGate) {
        let cancelled = if self.cancelled_after_failure.load(Ordering::Acquire) {
            gate.cancel_after_failure()
        } else {
            gate.cancel()
        };
        if matches!(
            cancelled,
            crate::executor::ChildStartCancellation::NewlyCancelled {
                delivery_failed: true
            }
        ) {
            eprintln!("reverie-kvm unstarted guest thread lost its cancellation gate");
        }
    }

    fn cancel_pending_worker_gates(&self, handles: &[GuestWorkerHandle]) {
        for gate in handles.iter().filter_map(|worker| worker.start.as_ref()) {
            self.cancel_worker_gate(gate);
        }
    }

    pub(crate) fn teardown_result(&self) -> Result<()> {
        let errors = self
            .worker_errors
            .lock()
            .expect("KVM worker error lock poisoned");
        let mut collected: Vec<_> = errors
            .iter()
            .flat_map(|(&tid, errors)| {
                errors
                    .iter()
                    .cloned()
                    .map(move |error| Error::WorkerFailure { tid, error })
            })
            .collect();
        drop(errors);
        collected.extend(
            self.worker_joins
                .errors()
                .into_iter()
                .map(Error::SharedFailure),
        );
        if let Err(error) = self.terminal_reads.teardown_result() {
            collected.push(error);
        }
        Error::combine(collected)
    }

    fn cancel_workers(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.terminal_reads.cancel_workers();
        let gates = self
            .worker_start_gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for gate in gates {
            self.cancel_worker_gate(&gate);
        }
        let workers = self
            .workers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for &worker in workers.iter() {
            // SAFETY: the registry lock keeps each pthread ID live for this call.
            unsafe {
                libc::pthread_kill(worker, worker_interrupt_signal());
            }
        }
        drop(workers);
        self.notify_cancellation();
    }

    // TODO-HUMAN-REVIEW(PR-211): Review KVM exec sibling cancellation ordering.
    fn rearm_after_exec(&self) {
        debug_assert!(
            self.worker_start_gates
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
        );
        // Exec reaches this boundary only after every old worker has joined.
        // The read registry must reject rearm with any old helper still owned.
        self.terminal_reads.rearm_after_exec();
        *self
            .exit_status
            .lock()
            .expect("KVM exit-group lock poisoned") = None;
        *self
            .failure_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = WorkerFailureState::default();
        self.cancelled.store(false, Ordering::Release);
        self.cancelled_after_failure.store(false, Ordering::Release);
    }

    // AUTONOMOUS-BOT-IMPLEMENTED: Reuse syscall transports after guest threads exit.
    // TODO-HUMAN-REVIEW(PR-176): Review KVM transport slot lifecycle.
    fn reserve_transport_slot(&self, child_tid: i32) -> Result<usize> {
        let mut slots = self
            .transport_slots
            .lock()
            .expect("KVM transport-slot lock poisoned");
        if slots.is_empty() {
            slots.resize(MAX_GUEST_THREADS as usize, false);
        }
        let slot = slots
            .iter()
            .position(|in_use| !*in_use)
            .ok_or(Error::GuestThreadLimitExceeded(child_tid))?;
        slots[slot] = true;
        Ok(slot)
    }

    fn release_transport_slot(&self, slot: usize) {
        let mut slots = self
            .transport_slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(in_use) = slots.get_mut(slot) {
            *in_use = false;
        }
    }
}

pub(crate) struct GuestThreadRegistration {
    group: Arc<GuestThreadGroup>,
    pthread: libc::pthread_t,
    root: bool,
    restore_blocked_signal: bool,
}

impl GuestThreadRegistration {
    fn register(group: Arc<GuestThreadGroup>, root: bool) -> Result<Self> {
        let restore_blocked_signal = set_guest_interrupt_signal_mask(libc::SIG_UNBLOCK)?;
        // SAFETY: pthread_self identifies this live calling thread.
        let pthread = unsafe { libc::pthread_self() };
        if root {
            let previous = group
                .root
                .lock()
                .expect("KVM guest root lock poisoned")
                .replace(pthread);
            assert!(previous.is_none(), "KVM guest root already registered");
        } else {
            group
                .workers
                .lock()
                .expect("KVM guest worker lock poisoned")
                .push(pthread);
        }
        Ok(Self {
            group,
            pthread,
            root,
            restore_blocked_signal,
        })
    }

    fn suspend_for_inline_fork(
        &self,
        gate: Arc<crate::entry::EntryGate>,
        origin: crate::entry::EntryOrigin,
        panics: Arc<crate::failure::tool_panics::ToolPanics>,
    ) -> Result<GuestInterruptSuspension<'_>> {
        // Only the private synchronous Direct driver supplies this owner.
        if unsafe { libc::pthread_equal(libc::pthread_self(), self.pthread) } == 0 {
            return Err(interrupt_ownership_error(
                "Direct fork moved off its registered pthread",
            ));
        }
        let restore_blocked_signal = set_guest_interrupt_signal_mask(libc::SIG_BLOCK)?;
        let mut suspended = GuestInterruptSuspension {
            registration: self,
            restore_blocked_signal,
            detached: false,
            active: true,
            gate,
            origin,
            panics,
        };
        let withdrawn = if self.root {
            match self.group.root.lock() {
                Ok(mut root) if *root == Some(self.pthread) => {
                    *root = None;
                    suspended.detached = true;
                    Ok(())
                }
                Ok(_) => Err(interrupt_ownership_error(
                    "Direct root registration changed",
                )),
                Err(_) => Err(interrupt_ownership_error("Direct root registry poisoned")),
            }
        } else {
            match self.group.workers.lock() {
                Ok(mut workers)
                    if workers.iter().filter(|&&id| id == self.pthread).count() == 1 =>
                {
                    workers.retain(|id| *id != self.pthread);
                    suspended.detached = true;
                    Ok(())
                }
                Ok(_) => Err(interrupt_ownership_error(
                    "Direct worker registration changed",
                )),
                Err(_) => Err(interrupt_ownership_error("Direct worker registry poisoned")),
            }
        };
        // Senders hold these same locks through pthread_kill. No old-parent
        // send remains in flight, and no registry lock crosses the child await.
        if let Err(error) = withdrawn.and_then(|()| deliver_guest_interrupt_at_neutral_boundary()) {
            return suspended.finish(Err(error));
        }
        Ok(suspended)
    }
}

fn interrupt_ownership_error(message: &'static str) -> Error {
    Error::EntryControl {
        operation: "Direct inline-fork interrupt ownership",
        source: std::io::Error::other(message),
    }
}

/// Called only with SIGURG blocked and its old group's target withdrawn.
/// Linux x86-64 signal delivery and normal rt_sigreturn recheck pending work
/// before returning to this caller. A competing handler's temporary mask is
/// restored on sigreturn; a handler that changes the saved mask to keep SIGURG
/// blocked is refused below. We do not synchronously consume any signal.
fn deliver_guest_interrupt_at_neutral_boundary() -> Result<()> {
    set_guest_interrupt_signal_mask(libc::SIG_UNBLOCK)?;
    if set_guest_interrupt_signal_mask(libc::SIG_BLOCK)? {
        return Err(interrupt_ownership_error(
            "SIGURG remained blocked after neutral delivery",
        ));
    }
    // Observation only, never query-then-wait: an unexpected new/foreign pending
    // SIGURG refuses transfer rather than being consumed as an ancestor kick.
    let mut pending = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigpending(&mut pending) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::sigismember(&pending, worker_interrupt_signal()) } == 1 {
        return Err(interrupt_ownership_error(
            "SIGURG remains pending after neutral delivery",
        ));
    }
    Ok(())
}

/// Physical target suspension only: group state, handles, start gates and
/// logical cancellation stay owned. Actual Direct callers poll on one pthread;
/// this private guard does not make arbitrary migrating futures safe.
struct GuestInterruptSuspension<'a> {
    registration: &'a GuestThreadRegistration,
    restore_blocked_signal: bool,
    detached: bool,
    active: bool,
    gate: Arc<crate::entry::EntryGate>,
    origin: crate::entry::EntryOrigin,
    panics: Arc<crate::failure::tool_panics::ToolPanics>,
}

impl GuestInterruptSuspension<'_> {
    fn restore(&mut self) -> Result<()> {
        let registration = self.registration;
        if unsafe { libc::pthread_equal(libc::pthread_self(), registration.pthread) } == 0 {
            return Err(interrupt_ownership_error(
                "Direct restoration moved off its registered pthread",
            ));
        }
        let mut errors = Vec::new();
        if self.detached {
            // The awaited child's registration has already withdrawn, even
            // when its backend object remains in existing deferred cleanup.
            match set_guest_interrupt_signal_mask(libc::SIG_BLOCK) {
                Ok(_) => {
                    if let Err(error) = deliver_guest_interrupt_at_neutral_boundary() {
                        errors.push(error);
                    }
                }
                Err(error) => errors.push(error),
            }
            if registration.root {
                let mut root = match registration.group.root.lock() {
                    Ok(root) => root,
                    Err(poisoned) => {
                        errors.push(interrupt_ownership_error(
                            "restoring poisoned Direct root registry",
                        ));
                        poisoned.into_inner()
                    }
                };
                if root.is_none() {
                    *root = Some(registration.pthread);
                } else {
                    errors.push(interrupt_ownership_error(
                        "Direct root was replaced while suspended",
                    ));
                }
            } else {
                let mut workers = match registration.group.workers.lock() {
                    Ok(workers) => workers,
                    Err(poisoned) => {
                        errors.push(interrupt_ownership_error(
                            "restoring poisoned Direct worker registry",
                        ));
                        poisoned.into_inner()
                    }
                };
                if !workers.contains(&registration.pthread) {
                    workers.push(registration.pthread);
                } else {
                    errors.push(interrupt_ownership_error(
                        "Direct worker was replaced while suspended",
                    ));
                }
            }
            self.detached = false;
        }
        if let Err(error) = set_guest_interrupt_signal_mask(if self.restore_blocked_signal {
            libc::SIG_BLOCK
        } else {
            libc::SIG_UNBLOCK
        }) {
            errors.push(error);
        }
        Error::combine(errors)
    }

    fn finish<T>(mut self, result: Result<T>) -> Result<T> {
        self.active = false;
        crate::entry::driver::combine_pending(result, self.restore())
    }
}

impl Drop for GuestInterruptSuspension<'_> {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            if let Err(error) = self.restore() {
                // Retain a typed control failure on this exact entry owner.
                // EntryGate captures before waking; a wake panic must not
                // replace an already-unwinding child or destroy its payload.
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.gate.poison(self.origin.clone(), error);
                }));
                if let Err(payload) = caught {
                    self.panics.append(vec![payload]);
                }
            }
        }
    }
}

impl Drop for GuestThreadRegistration {
    fn drop(&mut self) {
        if self.root {
            let mut root = self
                .group
                .root
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if *root == Some(self.pthread) {
                *root = None;
            }
        } else {
            self.group
                .workers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .retain(|worker| *worker != self.pthread);
        }
        if self.restore_blocked_signal {
            let _ = set_guest_interrupt_signal_mask(libc::SIG_BLOCK);
        }
    }
}

fn duplicate_stdin() -> Result<Option<File>> {
    // Duplicate before opening /dev/kvm so internal descriptors can never alias
    // a logically open guest stdin.
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    if fd >= 0 {
        // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
        return Ok(Some(unsafe { File::from_raw_fd(fd) }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBADF) {
        Ok(None)
    } else {
        Err(error.into())
    }
}

fn validate_root_pid(pid: i32) -> Result<i32> {
    if pid > 0 {
        Ok(pid)
    } else {
        Err(Error::InvalidGuestPid(pid))
    }
}

/// The PID-namespace init process seen by the deterministic container. The
/// ptrace backend runs the guest inside a real PID namespace whose `init` is
/// PID 1, so the conventional root guest (PID 3, see detcore `ROOT_DETPID`) has
/// `getppid() == 1`. KVM synthesizes the guest identity rather than using a real
/// namespace, so it must reproduce the same parent value for parity.
const CONTAINER_INIT_PID: i32 = 1;

/// Deterministic parent PID for the container's root guest, matching the ptrace
/// backend. A guest that is itself the namespace init (PID 1) has no parent and
/// reports `getppid() == 0`, exactly as Linux `init` does; any other root guest
/// is parented to the namespace init (PID 1).
fn root_parent_pid(root_pid: i32) -> i32 {
    if root_pid == CONTAINER_INIT_PID {
        0
    } else {
        CONTAINER_INIT_PID
    }
}

/// Normalizes either KVM-observable RIP form to the post-hypercall boundary
/// that can be restored after a returning injected process action.
fn normalize_completed_syscall_boundary_registers(
    memory: &GuestMemory,
    registers: kvm_regs,
    hypercall_instruction: [u8; 3],
    hypercall_address: u64,
) -> Result<kvm_regs> {
    normalize_completed_syscall_boundary_registers_with_read(
        |address, bytes| memory.read_raw(address, bytes),
        registers,
        hypercall_instruction,
        hypercall_address,
    )
}

fn normalize_completed_syscall_boundary_registers_with_read(
    mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    mut registers: kvm_regs,
    hypercall_instruction: [u8; 3],
    hypercall_address: u64,
) -> Result<kvm_regs> {
    let return_address = hypercall_address
        .checked_add(hypercall_instruction.len() as u64)
        .ok_or_else(|| Error::UnexpectedVcpuExit("hypercall RIP overflow".to_owned()))?;
    if registers.rip != hypercall_address && registers.rip != return_address {
        return Err(Error::UnexpectedVcpuExit(format!(
            "syscall boundary RIP {:#x} is neither hypercall {hypercall_address:#x} nor return {return_address:#x}",
            registers.rip,
        )));
    }
    let mut observed = [0; 3];
    read(hypercall_address, &mut observed)?;
    if observed != hypercall_instruction {
        return Err(Error::UnexpectedVcpuExit(format!(
            "syscall boundary at {hypercall_address:#x} does not contain the configured hypercall"
        )));
    }
    if registers.rip == hypercall_address {
        registers.rip = return_address;
    }
    // The static Tool loop publishes zero to KVM_EXIT_HYPERCALL.ret before
    // any process action can consume the exit. Both admitted RIP forms model
    // that same completed-hypercall state.
    registers.rax = 0;
    Ok(registers)
}

/// Exact reusable state for a syscall transport whose KVM hypercall has
/// already been acknowledged but whose ring-zero return path has not run.
///
/// A returning process action temporarily consumes that transport to park and
/// snapshot the parent. Restoring only the logical user registers is not
/// sufficient: a later signal delivery still stages its frame through the
/// stopped ring-zero trampoline. Keep the complete transport frame plus both
/// KVM register sets together so every caller restores the same boundary.
#[derive(Clone)]
pub(crate) struct CompletedSyscallBoundary {
    frame_address: u64,
    frame: [u8; FRAME_SIZE],
    registers: kvm_regs,
    special_registers: kvm_bindings::kvm_sregs,
    action_return_registers: Option<kvm_regs>,
    stage_action_outcome: bool,
}

impl CompletedSyscallBoundary {
    pub(crate) fn capture(
        backend: &KvmBackend,
        frame_address: u64,
        action_return_registers: Option<kvm_regs>,
    ) -> Result<Self> {
        let mut frame = [0; FRAME_SIZE];
        backend.memory.read_raw(frame_address, &mut frame)?;
        let (registers, special_registers) = backend.completed_syscall_boundary_registers()?;
        Ok(Self {
            frame_address,
            frame,
            registers,
            special_registers,
            action_return_registers,
            stage_action_outcome: false,
        })
    }

    fn capture_with_read(
        backend: &KvmBackend,
        frame_address: u64,
        action_return_registers: Option<kvm_regs>,
        mut read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    ) -> Result<Self> {
        let mut frame = [0; FRAME_SIZE];
        read(frame_address, &mut frame)?;
        let (registers, special_registers) =
            backend.completed_syscall_boundary_registers_with_read(&mut read)?;
        Ok(Self {
            frame_address,
            frame,
            registers,
            special_registers,
            action_return_registers,
            stage_action_outcome: false,
        })
    }

    pub(crate) async fn capture_admitted(
        backend: &mut KvmBackend,
        frame_address: u64,
        action_return_registers: Option<kvm_regs>,
        stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
    ) -> Result<Option<Self>> {
        backend
            .prepare_action_read(stop, |backend, access| {
                Self::capture_with_read(
                    backend,
                    frame_address,
                    action_return_registers,
                    |address, bytes| access.read_raw(address, bytes),
                )
            })
            .await
    }

    pub(crate) async fn capture_for_action_admitted(
        backend: &mut KvmBackend,
        frame_address: u64,
        action_return_registers: Option<kvm_regs>,
        action: &ProcessAction,
        stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
    ) -> Result<Option<ProcessActionContinuation>> {
        Ok(
            Self::capture_admitted(backend, frame_address, action_return_registers, stop)
                .await?
                .map(|mut boundary| {
                    boundary.stage_action_outcome = true;
                    ProcessActionContinuation::from_captured(action, boundary)
                }),
        )
    }

    pub(crate) fn capture_for_action(
        backend: &KvmBackend,
        frame_address: u64,
        action_return_registers: Option<kvm_regs>,
        action: &ProcessAction,
    ) -> Result<ProcessActionContinuation> {
        match action {
            ProcessAction::Fork { .. } | ProcessAction::Thread { .. } => {
                let mut boundary = Self::capture(backend, frame_address, action_return_registers)?;
                boundary.stage_action_outcome = true;
                Ok(ProcessActionContinuation::Restore(Box::new(boundary)))
            }
            ProcessAction::Exec { .. } => {
                let mut boundary = Self::capture(backend, frame_address, action_return_registers)?;
                boundary.stage_action_outcome = true;
                Ok(ProcessActionContinuation::Exec(Box::new(boundary)))
            }
        }
    }

    pub(crate) fn stage_action_result(&self, backend: &KvmBackend, result: i64) -> Result<()> {
        let mut memory = backend.memory.clone();
        if let Some(mut registers) = self.action_return_registers {
            registers.rax = result as u64;
            stage_process_syscall_return(&mut memory, &backend.vcpu, self.frame_address, registers)
        } else {
            SyscallRequest::write_result(&mut memory, self.frame_address, result)
        }
    }

    fn restore(&self, backend: &mut KvmBackend) -> Result<()> {
        let memory = backend.memory.clone();
        memory.write_raw(self.frame_address, &self.frame)?;
        backend.vcpu.set_sregs(&self.special_registers)?;
        backend.vcpu.set_regs(&self.registers)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            frame_address: 0x1000,
            frame: [0; FRAME_SIZE],
            // SAFETY: these plain KVM ABI register structures admit all-zero
            // values, and policy-only tests never submit them to KVM.
            registers: unsafe { std::mem::zeroed() },
            special_registers: unsafe { std::mem::zeroed() },
            action_return_registers: None,
            stage_action_outcome: false,
        }
    }
}

pub(crate) enum ProcessActionContinuation {
    Restore(Box<CompletedSyscallBoundary>),
    Exec(Box<CompletedSyscallBoundary>),
}

impl ProcessActionContinuation {
    pub(crate) fn from_captured(
        action: &ProcessAction,
        boundary: CompletedSyscallBoundary,
    ) -> Self {
        match action {
            ProcessAction::Fork { .. } | ProcessAction::Thread { .. } => {
                Self::Restore(Box::new(boundary))
            }
            ProcessAction::Exec { .. } => Self::Exec(Box::new(boundary)),
        }
    }

    fn finish(
        self,
        backend: &mut KvmBackend,
        action_result: Result<ProcessActionOutcome>,
    ) -> Result<ProcessActionOutcome> {
        // Never restore after a failed action: its partial process state must
        // remain observable to the caller's fatal cleanup path.
        let outcome = action_result?;
        if outcome.cancelled {
            return Ok(outcome);
        }
        match (self, outcome.image_replaced) {
            (Self::Restore(boundary), _) | (Self::Exec(boundary), false) => {
                boundary.restore(backend)?;
                if boundary.stage_action_outcome {
                    boundary.stage_action_result(backend, outcome.syscall_result)?;
                }
            }
            (Self::Exec(_), true) => {}
        }
        Ok(outcome)
    }
}

/// A single-vCPU KVM backend used to exercise the syscall transport.
///
/// A run that does not return, because its future was dropped or it unwound,
/// abandons the backend. The run's guest threads and child processes are
/// cancelled only when the backend drops, and until then share its memory,
/// so it refuses every later run, image, and memory access. Dropping it never
/// waits for them: each runs to its own exit, as it would had its run
/// returned, which may need turns from the embedder's scheduler, and a
/// reaper thread the run started joins it.
pub struct KvmBackend {
    // Field order ensures the vCPU and VM are dropped before registered memory.
    pub(crate) vcpu: crate::clock::CountedVcpu,
    vm: VmFd,
    pub(crate) memory: GuestMemory,
    _kvm: Kvm,
    cpuid_policy: CpuidPolicy,
    hypercall_instruction: [u8; 3],
    syscall_trampoline_address: u64,
    pub(crate) syscall_frame_address: u64,
    thread_group: Arc<GuestThreadGroup>,
    pub(crate) tool_failure: Option<crate::failure::FailureContext>,
    pub(crate) entry_driver: Option<crate::entry::owner::DriverOwner>,
    tool_panics: Arc<crate::failure::tool_panics::ToolPanics>,
    // Public root/direct runs can resume a panic after returning their Tool
    // ownership. Keep the accompanying diagnostics on this backend.
    completed_tool_panics: Mutex<Vec<CompletedToolPanic>>,
    thread_slot: Option<usize>,
    is_guest_thread: bool,
    // Who owns this backend's guest threads. The single value drives BOTH the
    // CLONE_THREAD worker dispatch path (`run_process_action_with_tool`) and
    // `futex`/CLEARTID ownership (`is_backend_owned_syscall`), so the two can
    // never disagree. Propagated to every child backend. This is the *effective*
    // ownership; when running a tool it is resolved from `thread_ownership_override`
    // (if set) else the tool's `Tool::thread_ownership` at run entry.
    pub(crate) thread_ownership: ThreadOwnership,
    // Explicit caller override for `thread_ownership`. `None` means "follow the
    // tool" — resolve from `Tool::thread_ownership` at run entry (the safe,
    // Tool-owned "follow children" default). `Some(_)` forces that ownership
    // regardless of the tool (set via `set_thread_ownership` /
    // `unmonitored_threads`), and survives run-entry resolution.
    thread_ownership_override: Option<ThreadOwnership>,
    // Set by the active execution consumer, never copied to a new vCPU. A
    // Host-owned worker has no Tool dispatcher and must retain native TSC.
    intercept_rdtsc: bool,
    cpuid_interception: crate::cpuid_instruction::Interception,
    pub(crate) static_elf: Option<LoadedStaticElf>,
    stdin: Option<File>,
    pub(crate) root_pid: i32,
    // One optional collector is shared by every fork and thread backend in the
    // guest tree. `None` is the allocation-free, update-free default.
    pub(crate) exit_collector: Option<Arc<KvmExitCollector>>,
    // Public runs that never returned, with every child host thread their
    // roots still own. Once one exists, no run or image is admitted.
    pub(crate) abandoned_runs: Arc<Mutex<AbandonedRuns>>,
}

struct CompletedToolPanic {
    _error: Arc<Error>,
    _secondary_payloads: Vec<crate::failure::owned_future::PanicPayload>,
    _run_failure: Option<Arc<crate::failure::RunFailure>>,
}

// A failed spawn has no physical child owner. Keep this transfer alive even
// if an unexpected unwind destroys its retained consuming future.
struct ChildToolPanicTransfer {
    parent: Arc<crate::failure::tool_panics::ToolPanics>,
    child: Arc<crate::failure::tool_panics::ToolPanics>,
}

impl Drop for ChildToolPanicTransfer {
    fn drop(&mut self) {
        self.parent.append(self.child.take());
    }
}

struct KvmProcessSnapshot {
    memory: GuestMemory,
    registers: kvm_regs,
    xsave: kvm_xsave,
    stdin: Option<File>,
    cpuid_policy: CpuidPolicy,
}

struct ForkedProcess {
    pid: i32,
    backend: KvmBackend,
    executor: ElfExecutor,
}

/// One fork child's logical wait-publication ownership. This is deliberately
/// non-generic: the runtime already owns `&T::GlobalState` at the exact point
/// where the final process status becomes authoritative.
pub(crate) struct OwnChildExitContext {
    pub(crate) child: SignalProcessId,
    pub(crate) _parent_binding: ProcessSignalBindingGuard,
    pub(crate) completion: Arc<ChildCompletionSlot>,
    pub(crate) raw_child_pid: i32,
}

// A process snapshot can be taken while another Tool-owned thread has its own
// scratch page exposed in the shared user-access map. The fork child must not
// inherit any of those temporary mappings; normalize only the copied map and
// leave the parent's live handlers unchanged.
fn hide_tool_scratch_pages(memory: &GuestMemory) -> Result<()> {
    memory.unmap_user_range(TOOL_STACK_TOP - TOOL_STACK_SIZE, TOOL_STACK_SIZE)?;
    memory.unmap_user_range(
        THREAD_TOOL_STACK_AREA_START,
        BOOT_RESERVED_END - THREAD_TOOL_STACK_AREA_START,
    )?;
    Ok(())
}

struct InitializedKvmResources {
    vcpu: VcpuFd,
    vm: VmFd,
    kvm: Kvm,
    hypercall_instruction: [u8; 3],
}

impl KvmBackend {
    /// The lexical scope remains with the invocation that will retire it.
    /// Child construction can carry parent memory views until this binding.
    pub(crate) fn start_entry_driver(&mut self) -> crate::entry::owner::DriverScope {
        assert!(
            self.entry_driver.is_none(),
            "KVM entry driver already active"
        );
        let scope = crate::entry::owner::DriverScope::new();
        self.entry_driver = Some(scope.owner());
        self.restore_entry_origin();
        scope
    }

    pub(crate) fn entry_driver_owner(&self) -> Option<crate::entry::owner::DriverOwner> {
        self.entry_driver.clone()
    }

    pub(crate) fn set_operation_origin(
        &mut self,
        origin: Option<crate::entry::owner::OperationOrigin>,
    ) {
        self.memory.set_operation_origin(origin.clone());
        self.vcpu.set_operation_origin(origin);
    }

    pub(crate) fn restore_entry_origin(&mut self) {
        let origin = self.entry_driver.as_ref().map(|owner| owner.origin());
        self.set_operation_origin(origin);
    }

    /// The caller holds this guard outside the owned callback future and its
    /// complete borrow scope, then restores ordinary views after destruction.
    pub(crate) fn begin_entry_callback(
        &mut self,
    ) -> Result<Option<crate::entry::owner::CallbackScope>> {
        self.check_entry_owner()?;
        let Some(owner) = self.entry_driver_owner() else {
            return Ok(None);
        };
        let callback = owner.begin_callback(None)?;
        self.set_operation_origin(Some(callback.origin()));
        Ok(Some(callback))
    }

    pub(crate) fn set_tool_failure(&mut self, origin: Option<crate::failure::FailureContext>) {
        self.vcpu.set_failure_context(origin.clone());
        self.memory.set_failure_context(origin.clone());
        self.tool_failure = origin;
    }

    pub(crate) fn entry_cancellation(&self) -> GuestCancellationSubscription {
        self.thread_group.subscribe_cancellation()
    }

    pub(crate) fn failure_subscription(
        &self,
        is_traced_tree_root: bool,
    ) -> Option<crate::failure::FailureSubscription> {
        self.tool_failure
            .as_ref()
            .map(|failure| failure.driver_subscription(is_traced_tree_root))
    }

    pub(crate) fn terminal_read_context(
        &self,
        executor: &ElfExecutor,
        memory: &GuestMemory,
    ) -> crate::terminal_read::ReadContext {
        crate::terminal_read::ReadContext::new(
            self.thread_group.terminal_reads.clone(),
            self.is_guest_thread,
            crate::entry::driver::EntryDriverWatch::for_memory(memory),
            self.tool_failure
                .as_ref()
                .map(|failure| failure.terminal_wait(executor.is_traced_tree_root())),
            self.tool_panic_owner(),
            self.is_tool_guest_worker(),
        )
    }

    pub(crate) fn execute_static_elf_syscall(
        &self,
        executor: &mut ElfExecutor,
        request: &SyscallRequest,
        memory: &GuestMemory,
    ) -> Result<i64> {
        // A zero-count host read can block even through dup or a rebound fd 0.
        // Executor routing selects the owned endpoint after installing the
        // shared table snapshot and excluding synthetic descriptions.
        if request.number() == libc::SYS_read as u64 && request.args()[2] == 0 {
            let mut context = self.terminal_read_context(executor, memory);
            executor.execute_checked_with_read_context(request, memory, &mut context)
        } else {
            executor.execute_checked(request, memory)
        }
    }

    pub(crate) fn report_tool_failure(&self, phase: &'static str, error: Error) -> Error {
        match &self.tool_failure {
            Some(failure) => failure.publish(phase, error),
            None => error,
        }
    }

    pub(crate) fn guest_thread_is_cancelled(&self) -> bool {
        self.is_guest_thread && self.thread_group.cancelled.load(Ordering::Acquire)
    }

    /// Creates a VM with one vCPU and a memory slot starting at GPA zero.
    pub fn new(memory_size: usize) -> Result<Self> {
        Self::new_with_cpuid_policy(memory_size, CpuidPolicy::default())
    }

    /// Creates a VM with an explicitly reserved supervisor standard input.
    ///
    /// Callers that initialize async runtimes before KVM should reserve stdin
    /// first so an originally closed descriptor cannot be reused internally.
    pub fn new_with_stdin(memory_size: usize, stdin: Option<File>) -> Result<Self> {
        Self::new_with_cpuid_policy_and_stdin(memory_size, CpuidPolicy::default(), stdin)
    }

    /// Creates a VM with a caller-selected CPUID feature policy.
    pub fn new_with_cpuid_policy(memory_size: usize, cpuid_policy: CpuidPolicy) -> Result<Self> {
        let stdin = duplicate_stdin()?;
        Self::new_with_cpuid_policy_and_stdin(memory_size, cpuid_policy, stdin)
    }

    fn new_with_cpuid_policy_and_stdin(
        memory_size: usize,
        cpuid_policy: CpuidPolicy,
        stdin: Option<File>,
    ) -> Result<Self> {
        let memory = GuestMemory::new(0, memory_size)?;
        Self::new_with_memory_and_cpuid_policy(memory, cpuid_policy, stdin)
    }

    fn initialize_resources(
        memory: &GuestMemory,
        cpuid_policy: CpuidPolicy,
    ) -> Result<InitializedKvmResources> {
        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;
        if !vm.check_extension(Cap::ExitHypercall) {
            return Err(Error::HypercallExitUnsupported);
        }

        let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        // TODO-HUMAN-REVIEW(PR-129): Review host-selected private hypercall transport.
        let hypercall_instruction = supported_hypercall_instruction(&cpuid)?;
        cpuid_policy.apply(&mut cpuid)?;
        let cap = kvm_enable_cap {
            cap: Cap::ExitHypercall as u32,
            args: [1_u64 << VMCALL_SYSCALL_TRANSPORT, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap)?;

        let region = kvm_userspace_memory_region {
            slot: 0,
            guest_phys_addr: memory.guest_base(),
            memory_size: memory.len() as u64,
            userspace_addr: memory.host_address(),
            flags: 0,
        };
        // SAFETY: memory owns a page-aligned mapping that remains live until
        // after vcpu and vm are dropped, and slot 0 is registered only once.
        unsafe {
            vm.set_user_memory_region(region)?;
        }

        let vcpu = vm.create_vcpu(0)?;
        vcpu.set_cpuid2(&cpuid)?;
        Ok(InitializedKvmResources {
            vcpu,
            vm,
            kvm,
            hypercall_instruction,
        })
    }

    fn new_with_memory_and_cpuid_policy(
        memory: GuestMemory,
        cpuid_policy: CpuidPolicy,
        stdin: Option<File>,
    ) -> Result<Self> {
        install_worker_interrupt_handler()?;
        const INITIALIZATION_ATTEMPTS: usize = 3;
        let mut attempts = 0;
        let InitializedKvmResources {
            vcpu,
            vm,
            kvm,
            hypercall_instruction,
        } = loop {
            attempts += 1;
            match Self::initialize_resources(&memory, cpuid_policy) {
                Ok(resources) => break resources,
                Err(Error::Kvm(error))
                    if error.errno() == libc::EINTR && attempts < INITIALIZATION_ATTEMPTS => {}
                Err(error) => return Err(error),
            }
        };
        Ok(Self {
            vcpu: crate::clock::CountedVcpu::new(vcpu, memory.clone())?,
            vm,
            memory,
            _kvm: kvm,
            cpuid_policy,
            hypercall_instruction,
            syscall_trampoline_address: SYSCALL_TRAMPOLINE_ADDRESS,
            syscall_frame_address: SYSCALL_FRAME_ADDRESS,
            thread_group: Arc::new(GuestThreadGroup::default()),
            tool_failure: None,
            entry_driver: None,
            tool_panics: Arc::default(),
            completed_tool_panics: Mutex::new(Vec::new()),
            thread_slot: None,
            is_guest_thread: false,
            // Effective ownership before any tool run resolves it. The direct
            // (non-tool) personality never dispatches threads through a Tool loop,
            // so Host is the correct effective value there; when a tool runs,
            // `run_static_elf_with_tool` resolves this from the override or the
            // tool's `Tool::thread_ownership` (the Tool-owned "follow children"
            // default).
            thread_ownership: ThreadOwnership::Host,
            // No explicit caller override: follow the tool at run entry.
            thread_ownership_override: None,
            intercept_rdtsc: false,
            cpuid_interception: crate::cpuid_instruction::Interception::default(),
            static_elf: None,
            stdin,
            root_pid: 1,
            exit_collector: None,
            abandoned_runs: Arc::default(),
        })
    }

    /// Enables or disables completed-process-tree KVM exit statistics.
    ///
    /// Call this once before entering the guest. Enabling creates the collector
    /// that every later fork and `CLONE_THREAD` child inherits; disabling drops
    /// it, so unmeasured runs allocate and update no statistics state. After
    /// an abandoned run, this configures only later runs, which are refused.
    pub fn set_backend_stats_request(&mut self, request: BackendStatsRequest) {
        self.exit_collector = request
            .is_enabled()
            .then(|| Arc::new(KvmExitCollector::default()));
    }

    /// Returns whether this process tree is collecting KVM exit statistics.
    pub fn backend_stats_request(&self) -> BackendStatsRequest {
        BackendStatsRequest::new(self.exit_collector.is_some())
    }

    /// Records one vCPU exit in the shared process-tree collector, when enabled.
    ///
    /// This is an associated function over a disjoint field so callers can use
    /// it while the live [`VcpuExit`] still borrows the vCPU's `KVM_RUN` mapping.
    pub(crate) fn record_exit(collector: Option<&KvmExitCollector>, exit: &VcpuExit<'_>) {
        if let Some(collector) = collector {
            collector.record(exit);
        }
    }

    /// Forces who owns this backend's guest threads (see [`ThreadOwnership`]),
    /// overriding the tool's own [`reverie::Tool::thread_ownership`].
    ///
    /// The single value drives both the CLONE_THREAD worker dispatch path and
    /// `futex`/CLEARTID ownership, so execution and synchronization can never
    /// disagree. Normally you do **not** call this: when running a tool the
    /// ownership is resolved from the tool's `Tool::thread_ownership`, whose
    /// default is the safe Tool-owned "follow children" model. Call this only to
    /// force a specific ownership regardless of the tool; the override is sticky
    /// and survives run-entry resolution. Call it before running. After an
    /// abandoned run, this configures only later runs, which are refused.
    pub fn set_thread_ownership(&mut self, thread_ownership: ThreadOwnership) {
        self.thread_ownership_override = Some(thread_ownership);
        self.thread_ownership = thread_ownership;
    }

    /// Opt this backend's guest threads *out* of tool monitoring: run every
    /// child thread uninstrumented on the direct host personality with
    /// host-backed `futex`/CLEARTID synchronization ([`ThreadOwnership::Host`]).
    ///
    /// This is the deliberately-named "scary" opt-out. It is **not** `unsafe`
    /// (it cannot cause undefined behavior), but it is a determinism/coverage
    /// hazard, so weigh it carefully:
    ///
    /// * The tool never sees the opted-out threads' syscalls, so it cannot
    ///   sanitize, record, or schedule them — determinism is **not** guaranteed
    ///   for those threads or anything ordered against them.
    /// * A tool that expects to schedule the whole thread group (e.g. Detcore)
    ///   has its model broken by unmonitored siblings, and mixing unmonitored
    ///   threads with tool-owned joins can deadlock a `pthread_join`.
    ///
    /// Prefer leaving threads tool-owned (the default). Use this only when a
    /// backend genuinely cannot or must not drive a thread through the tool.
    pub fn unmonitored_threads(&mut self) -> &mut Self {
        self.set_thread_ownership(ThreadOwnership::Host);
        self
    }

    /// Resolves the effective [`ThreadOwnership`] for a tool run: an explicit
    /// caller override ([`Self::set_thread_ownership`] /
    /// [`Self::unmonitored_threads`]) wins, otherwise follow the tool's
    /// [`reverie::Tool::thread_ownership`] (default: Tool-owned "follow
    /// children"). Called once at run entry, before any thread is created.
    pub(crate) fn resolve_thread_ownership(&mut self, ownership: ThreadOwnership) {
        self.thread_ownership = self.thread_ownership_override.unwrap_or(ownership);
    }

    /// Panic-not-hang tripwire enforced at thread creation: the thread's
    /// *execution* owner (which dispatch arm `run_process_action_with_tool`
    /// takes) and its *futex/CLEARTID* owner (how `is_backend_owned_syscall`
    /// classifies `futex`) must agree. They are both derived from the single
    /// [`ThreadOwnership`] value, so this can only fail if a future change
    /// reintroduces a second, independent source of truth — exactly the
    /// split-brain that historically deadlocked `pthread_join` (a Tool-executed
    /// worker whose `futex` was host-owned: the joiner's host `FUTEX_WAIT` was
    /// never woken by the exiting worker's logical `CLEARTID`, observed as a
    /// silent hang / exit=124). Asserting here converts that regression into an
    /// immediate, clearly-labelled panic instead of a hang.
    fn debug_assert_thread_ownership_consistent(&self) {
        debug_assert_eq!(
            self.thread_ownership.executes_on_tool(),
            !crate::runtime::is_backend_owned_syscall(
                libc::SYS_futex as u64,
                self.thread_ownership,
            ),
            "thread execution owner and futex owner disagree for {:?}: a \
             Tool-executed worker with a host-owned futex (or a host-executed \
             worker with a Tool-owned futex) deadlocks pthread_join and must be \
             unrepresentable now that one ThreadOwnership drives both decisions",
            self.thread_ownership,
        );
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-238): Review configurable KVM root process identity.
    pub fn set_root_pid(&mut self, pid: i32) -> Result<()> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        let pid = validate_root_pid(pid)?;
        self.root_pid = pid;
        if let Some(loaded) = self.static_elf.as_mut() {
            loaded.pid = pid;
            loaded.pgid = pid;
            loaded.tid = pid;
            loaded.ppid = root_parent_pid(pid);
            loaded.task_lifecycle = Arc::new(Mutex::new(TaskLifecycleTable::with_root(
                pid,
                pid,
                pid,
                loaded.dumpable,
            )));
        }
        Ok(())
    }

    /// Installs an arbitrary real-mode program and selects it as the vCPU entry point.
    pub fn install_real_mode_program(&mut self, entry_point: u64, code: &[u8]) -> Result<()> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        self.memory.write(entry_point, code)?;
        self.static_elf = None;

        let mut sregs = self.vcpu.get_sregs()?;
        sregs.cs.base = 0;
        sregs.cs.selector = 0;
        sregs.ds.base = 0;
        sregs.ds.selector = 0;
        self.vcpu.set_sregs(&sregs)?;

        let mut regs = self.vcpu.get_regs()?;
        regs.rip = entry_point;
        regs.rflags = 2;
        self.vcpu.set_regs(&regs)?;
        self.vcpu.new_guest();
        Ok(())
    }

    /// Returns the Tool scratch-page top for this backend. Process leaders use
    /// the fixed root page; guest threads use the page paired with their
    /// transport slot.
    pub(crate) fn tool_stack_top(&self) -> u64 {
        self.thread_slot
            .map_or(TOOL_STACK_TOP, thread_tool_stack_top)
    }

    /// Ends a public run that returned; see `RunAdmission::finish`.
    pub(crate) fn finish_run(&self, admission: RunAdmission) {
        admission.finish(&self.thread_group);
    }

    /// Releases a guest thread's transport and Tool scratch-page slot.
    ///
    /// Normal exit paths call this before notifying the scheduler or clearing
    /// the child TID, so the next guest thread's slot does not depend on when
    /// the host worker object is destroyed. `Drop` remains the error-path
    /// fallback.
    pub(crate) fn release_thread_slot(&mut self) {
        if let Some(slot) = self.thread_slot.take() {
            self.thread_group.release_transport_slot(slot);
        }
    }

    /// Returns the VM's guest memory. A dropped run's guest threads may still
    /// be using it, so after one this fails until the backend drops.
    pub fn memory(&self) -> Result<&GuestMemory> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        Ok(&self.memory)
    }

    /// Returns mutable access to the VM's guest memory. As for
    /// [`Self::memory`], this fails after a dropped run.
    pub fn memory_mut(&mut self) -> Result<&mut GuestMemory> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        Ok(&mut self.memory)
    }

    /// Loads a static ELF executable and prepares the vCPU to enter it in long mode.
    ///
    /// The initial process personality supports x86-64 `ET_EXEC` images without a
    /// `PT_INTERP` segment. Dynamic executables require a userspace dynamic linker
    /// and are deliberately rejected.
    /// After executing an initial ELF, create a fresh backend for another initial
    /// image. Guest exec is a separate supported continuation of its clock.
    pub fn install_static_elf(&mut self, image: &[u8], argv0: &str) -> Result<()> {
        self.install_static_elf_with_args(image, &[argv0], &[])
    }

    /// Loads a static ELF with an explicit `argv` and `envp` and prepares the
    /// vCPU to enter it in long mode.
    ///
    /// `argv` must be non-empty; `argv[0]` becomes the program name reported to
    /// the guest (initial stack and `AT_EXECFN`/`readlink("/proc/self/exe")`).
    /// The guest observes a standard System V initial stack: `argc`, the `argv`
    /// pointer array, a NULL terminator, the `envp` pointer array, a NULL
    /// terminator, and the auxiliary vector.
    pub fn install_static_elf_with_args(
        &mut self,
        image: &[u8],
        argv: &[&str],
        envp: &[&str],
    ) -> Result<()> {
        let cwd = std::env::current_dir()?;
        self.install_static_elf_with_context(image, argv, envp, &cwd)
    }

    /// Loads independently supplied ELF bytes, arguments, environment, and working directory.
    ///
    /// This entry does not establish a backing file from `argv[0]`. Executable
    /// following-stat and retained self-exec require a known backing file and
    /// return ENOENT without one. The legacy nominal executable readlink remains.
    pub fn install_static_elf_with_context(
        &mut self,
        image: &[u8],
        argv: &[&str],
        envp: &[&str],
        cwd: &Path,
    ) -> Result<()> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        self.vcpu.check_initial_elf_install()?;
        let loaded = load_static_elf(&mut self.memory, image, argv, envp, cwd)?;
        self.install_loaded_static_elf(loaded)
    }

    fn install_loaded_static_elf(&mut self, mut loaded: LoadedStaticElf) -> Result<()> {
        loaded.pid = self.root_pid;
        loaded.pgid = self.root_pid;
        loaded.tid = self.root_pid;
        loaded.ppid = root_parent_pid(self.root_pid);
        loaded.task_lifecycle = Arc::new(Mutex::new(TaskLifecycleTable::with_root(
            self.root_pid,
            self.root_pid,
            self.root_pid,
            loaded.dumpable,
        )));
        loaded.stdin = self.stdin.as_ref().map(File::try_clone).transpose()?;
        configure_long_mode(
            &mut self.memory,
            &self.vcpu,
            loaded.entry_point,
            loaded.stack_pointer,
            self.hypercall_instruction,
        )?;
        self.memory.enable_user_access();
        self.static_elf = Some(loaded);
        self.vcpu.new_elf_guest();
        Ok(())
    }

    /// Loads image bytes from the supplied open file, retaining the final executable.
    ///
    /// Positional reads start at zero without changing the file's shared offset.
    /// `argv[0]` remains independent of the file identity. The retained object's
    /// path supplies the initial executable name; later exec uses its invoked name.
    /// For scripts, each interpreter is read from its retained open file, and the
    /// final interpreter's file and bytes become the executable identity. The
    /// original script still supplies the invoked name and script argument.
    /// This does not add initial execution authorization or snapshot concurrent
    /// host file writes. The caller must provide a stable, readable executable.
    pub fn install_static_elf_file_with_context(
        &mut self,
        file: File,
        argv: &[&str],
        envp: &[&str],
        cwd: &Path,
    ) -> Result<()> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        self.vcpu.check_initial_elf_install()?;
        let loaded = load_static_elf_file(&mut self.memory, file, argv, envp, cwd)?;
        self.install_loaded_static_elf(loaded)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-228): Review the KVM random-seed configuration API.
    /// Configure the deterministic seed used by getrandom and virtual random devices.
    /// Configuring an installed image starts its getrandom stream at byte zero.
    pub fn set_random_seed(&mut self, seed: u64) -> Result<()> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        let loaded = self
            .static_elf
            .as_mut()
            .ok_or(Error::StaticElfNotInstalled)?;
        loaded.random_seed = seed;
        loaded.getrandom_offset = 0;
        Ok(())
    }

    /// Returns the stable ring-zero continuation for a consumed syscall
    /// hypercall. KVM reports RIP at the VMCALL/VMMCALL instruction; after
    /// userspace publishes `exit.ret`, the next KVM_RUN advances past it.
    /// Process-action parking consumes that exit, so a reusable boundary must
    /// model the post-hypercall instruction rather than replaying the syscall.
    pub(crate) fn completed_syscall_boundary_registers(
        &self,
    ) -> Result<(kvm_regs, kvm_bindings::kvm_sregs)> {
        let hypercall_address = syscall_hypercall_address(
            self.hypercall_instruction,
            self.syscall_trampoline_address,
            self.syscall_frame_address,
        );
        let registers = normalize_completed_syscall_boundary_registers(
            &self.memory,
            self.vcpu.get_regs()?,
            self.hypercall_instruction,
            hypercall_address,
        )?;
        Ok((registers, self.vcpu.get_sregs()?))
    }

    fn completed_syscall_boundary_registers_with_read(
        &self,
        read: impl FnMut(u64, &mut [u8]) -> Result<()>,
    ) -> Result<(kvm_regs, kvm_bindings::kvm_sregs)> {
        let hypercall_address = syscall_hypercall_address(
            self.hypercall_instruction,
            self.syscall_trampoline_address,
            self.syscall_frame_address,
        );
        let registers = normalize_completed_syscall_boundary_registers_with_read(
            read,
            self.vcpu.get_regs()?,
            self.hypercall_instruction,
            hypercall_address,
        )?;
        Ok((registers, self.vcpu.get_sregs()?))
    }

    fn snapshot_process(&self) -> Result<KvmProcessSnapshot> {
        #[cfg(test)]
        tests::entry_action_tests::observe("snapshot");
        let mut memory = self.memory.snapshot()?;
        #[cfg(test)]
        tests::entry_action_tests::observe_fork_memory(&memory.entry_gate());
        // Snapshot preparation is still part of the issuing operation. The
        // actual child receives its independent origin only when it runs.
        memory.set_failure_context(self.tool_failure.clone());
        memory.set_operation_origin(self.memory.entry_origin().operation);
        hide_tool_scratch_pages(&memory)?;
        Ok(KvmProcessSnapshot {
            memory,
            registers: self.vcpu.get_regs()?,
            xsave: self.vcpu.get_xsave()?,
            stdin: self.stdin.as_ref().map(File::try_clone).transpose()?,
            cpuid_policy: self.cpuid_policy,
        })
    }

    fn from_process_snapshot(snapshot: KvmProcessSnapshot) -> Result<Self> {
        #[cfg(test)]
        tests::entry_action_tests::observe("fork_backend");
        let mut child = Self::new_with_memory_and_cpuid_policy(
            snapshot.memory,
            snapshot.cpuid_policy,
            snapshot.stdin,
        )?;
        configure_long_mode(
            &mut child.memory,
            &child.vcpu,
            0,
            snapshot.registers.rsp,
            child.hypercall_instruction,
        )?;
        child.vcpu.set_regs(&snapshot.registers)?;
        // SAFETY: this guest setup does not enable dynamically sized XSTATE features.
        unsafe { child.vcpu.set_xsave(&snapshot.xsave)? };
        Ok(child)
    }

    // TODO-HUMAN-REVIEW(PR-172): Review independent vCPU creation from clone3 state.
    fn from_thread_state(
        memory: GuestMemory,
        registers: kvm_regs,
        xsave: kvm_xsave,
        stdin: Option<File>,
        cpuid_policy: CpuidPolicy,
        child_tid: i32,
        thread_group: Arc<GuestThreadGroup>,
    ) -> Result<Self> {
        #[cfg(test)]
        tests::entry_action_tests::observe("thread_backend");
        let mut child = Self::new_with_memory_and_cpuid_policy(memory, cpuid_policy, stdin)?;
        child.thread_group = thread_group;
        child.is_guest_thread = true;
        let slot = child.thread_group.reserve_transport_slot(child_tid)?;
        child.thread_slot = Some(slot);
        let syscall_trampoline_address =
            THREAD_SYSCALL_AREA_START + slot as u64 * THREAD_SYSCALL_AREA_STRIDE;
        let syscall_frame_address = syscall_trampoline_address + PAGE_SIZE;
        child.syscall_trampoline_address = syscall_trampoline_address;
        child.syscall_frame_address = syscall_frame_address;
        configure_long_mode_with_syscall_area(
            &mut child.memory,
            &child.vcpu,
            0,
            registers.rsp,
            child.hypercall_instruction,
            syscall_trampoline_address,
            syscall_frame_address,
            false,
        )?;
        child.vcpu.set_regs(&registers)?;
        // SAFETY: this guest setup does not enable dynamically sized XSTATE features.
        unsafe { child.vcpu.set_xsave(&xsave)? };
        Ok(child)
    }

    // TODO-HUMAN-REVIEW(PR-156): Review lifecycle-hook exec image replacement API.
    pub(crate) fn exec_process(
        &mut self,
        executor: &mut ElfExecutor,
        executable: (&Path, Option<Arc<File>>),
        image: &[u8],
        argv: &[String],
        envp: &[String],
    ) -> Result<()> {
        if self.is_guest_thread {
            return Err(Error::GuestThreadExecUnsupported);
        }
        #[cfg(test)]
        tests::entry_action_tests::observe("exec_image");
        // ElfExecutor preflights the image before scheduling this action. From
        // this reset onward, any exceptional loader or KVM failure is fatal to
        // the backend and is never reported back to the old guest image. This
        // is the same point-of-no-return behavior as the prior zero_raw reset.
        let user_length = usize::try_from(self.memory.guest_end() - BOOT_RESERVED_END)
            .expect("guest memory length must fit usize");
        self.memory.discard_pages(BOOT_RESERVED_END, user_length)?;

        let argv = argv.iter().map(String::as_str).collect::<Vec<_>>();
        let envp = envp.iter().map(String::as_str).collect::<Vec<_>>();
        let mut loaded = load_static_elf(&mut self.memory, image, &argv, &envp, executor.cwd())?;
        let (executable_path, executable_file) = executable;
        loaded.executable_path = executable_file
            .as_ref()
            .and_then(|file| std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok())
            .unwrap_or_else(|| executable_path.to_owned());
        loaded.executable_file = executable_file;
        let thread_name = initial_thread_name(executable_path);
        loaded.thread_name = thread_name;
        *loaded
            .thread_group_leader_name
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = thread_name;
        loaded.stdin = self.stdin.as_ref().map(File::try_clone).transpose()?;
        configure_long_mode(
            &mut self.memory,
            &self.vcpu,
            loaded.entry_point,
            loaded.stack_pointer,
            self.hypercall_instruction,
        )?;
        self.memory.enable_user_access();
        executor.replace_after_exec(loaded);
        Ok(())
    }

    /// Capture one complete parent read state only after admission. The owned
    /// action stays with the caller across waits; no copy token or partial
    /// capture survives this synchronous closure. None is terminal cancellation.
    async fn prepare_action_read<T>(
        &mut self,
        mut stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
        capture: impl Fn(&Self, &crate::memory::RawMemoryRead<'_>) -> Result<T>,
    ) -> Result<Option<T>> {
        let gate = self.memory.entry_gate();
        loop {
            let changed = gate.subscribe();
            let cancelled = self.entry_cancellation();
            gate.admit_operation().map_err(|failure| failure.error())?;
            if stop.as_mut().now_or_never().is_some() {
                return Err(Error::RunAborted);
            }
            if self.guest_thread_group_exit_status().is_some() || self.guest_thread_is_cancelled() {
                return Ok(None);
            }
            if let Some(value) = self.memory.try_read_with(|access| capture(self, access))? {
                return Ok(Some(value));
            }
            match futures::future::select(
                futures::future::select(changed, cancelled),
                stop.as_mut(),
            )
            .await
            {
                futures::future::Either::Left(_) => {}
                futures::future::Either::Right(_) => return Err(Error::RunAborted),
            }
        }
    }

    async fn capture_thread_parent(
        &mut self,
        stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
    ) -> Result<Option<(kvm_regs, kvm_xsave, Vec<u8>)>> {
        self.prepare_action_read(stop, |backend, access| {
            #[cfg(test)]
            tests::entry_action_tests::observe("parent_capture");
            let registers = backend.vcpu.get_regs()?;
            let xsave = backend.vcpu.get_xsave()?;
            let mut frame = vec![0; FRAME_SIZE];
            access.read_raw(backend.syscall_frame_address, &mut frame)?;
            Ok((registers, xsave, frame))
        })
        .await
    }

    // The prepared action owns its frame and any earlier child state while
    // admission is closed. Only this one entry is retried; the action is not.
    // A terminal stop deliberately abandons this thread's trampoline: a stop
    // before preparation leaves its original byte, while a later stop leaves
    // the park byte installed. The terminal caller never restores/resumes
    // this guest continuation; siblings use separate per-thread trampolines,
    // and a reused slot is rewritten during thread construction. Restoring
    // here could wait on a closed gate and prevent terminal cleanup. Any
    // future caller that resumes or observes this retired thread's trampoline
    // must resolve that obligation before using this terminal path.
    async fn park_process_action(
        &mut self,
        phase: &'static str,
        mut stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
    ) -> Result<bool> {
        let gate = self.memory.entry_gate();
        let mut prepared = false;
        let mut parked: Option<Result<()>> = None;
        let with_actual_error = |parked: &mut Option<Result<()>>, error: Error| match parked.take()
        {
            Some(Err(actual)) => actual.with_cleanup(vec![error]),
            _ => error,
        };
        loop {
            #[cfg(test)]
            crate::runtime::entry_wait_observation::observe(
                crate::runtime::entry_wait_observation::Site::Parking,
                crate::runtime::entry_wait_observation::Boundary::BeforeSubscription,
            );
            let changed = gate.subscribe();
            let cancelled = self.entry_cancellation();
            #[cfg(test)]
            crate::runtime::entry_wait_observation::observe(
                crate::runtime::entry_wait_observation::Site::Parking,
                crate::runtime::entry_wait_observation::Boundary::AfterSubscription,
            );
            if let Err(failure) = gate.admit_operation() {
                return Err(with_actual_error(&mut parked, failure.error()));
            }
            if stop.as_mut().now_or_never().is_some() {
                return Err(with_actual_error(&mut parked, Error::RunAborted));
            }
            if self.guest_thread_group_exit_status().is_some() || self.guest_thread_is_cancelled() {
                // A real unexpected exit remains an error even if cancellation
                // arrived while its trampoline restoration was waiting.
                return match parked.take() {
                    Some(Err(error)) => Err(error),
                    _ => Ok(false),
                };
            }
            if parked.is_some() || !prepared {
                let restoring = parked.is_some();
                let update = try_set_syscall_return_park(
                    &mut self.memory,
                    self.hypercall_instruction,
                    self.syscall_trampoline_address,
                    self.syscall_frame_address,
                    !restoring,
                );
                match update {
                    Err(error) => return Err(with_actual_error(&mut parked, error)),
                    Ok(Some(())) if restoring => {
                        #[cfg(test)]
                        tests::entry_action_tests::observe("park_restore");
                        return parked.take().unwrap().map(|()| true);
                    }
                    Ok(Some(())) => {
                        #[cfg(test)]
                        tests::entry_action_tests::observe("park_prepare");
                        prepared = true;
                        continue;
                    }
                    Ok(None) => {}
                }
            } else if let Some(actual) = self.try_park_process_action(phase)? {
                // This is an owned result, not a borrowed VcpuExit. Retain it
                // across an unpark wait and never execute this entry twice.
                parked = Some(actual);
                continue;
            }
            match futures::future::select(
                futures::future::select(changed, cancelled),
                stop.as_mut(),
            )
            .await
            {
                futures::future::Either::Left(_) => {}
                // The future has completed. Do not poll it again on the next
                // loop iteration: async futures need not be fused.
                futures::future::Either::Right(_) => {
                    return Err(with_actual_error(&mut parked, Error::RunAborted));
                }
            }
        }
    }

    fn try_park_process_action(&mut self, phase: &'static str) -> Result<Option<Result<()>>> {
        let Some(exit) = self.vcpu.run()? else {
            return Ok(None);
        };
        Self::record_exit(self.exit_collector.as_deref(), &exit);
        Ok(Some(match exit {
            VcpuExit::Hlt => {
                #[cfg(test)]
                tests::entry_action_tests::observe("park_hlt");
                Ok(())
            }
            exit => Err(Error::UnexpectedVcpuExit(format!("{phase}: {exit:?}"))),
        }))
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn prepare_forked_process(
        &mut self,
        executor: &ElfExecutor,
        child_pid: i32,
        child_stack: Option<u64>,
        parent_tid: Option<u64>,
        child_tid: Option<u64>,
        clear_child_tid: Option<u64>,
        clear_sighand: bool,
        share_address_space: bool,
        park_syscall_return: bool,
        fault: Option<&PageZeroFault>,
    ) -> Result<ForkedProcess> {
        let mut stop = std::pin::pin!(std::future::pending());
        futures::executor::block_on(self.prepare_forked_process_admitted(
            executor,
            child_pid,
            child_stack,
            parent_tid,
            child_tid,
            clear_child_tid,
            clear_sighand,
            share_address_space,
            park_syscall_return,
            fault,
            stop.as_mut(),
        ))?
        .ok_or_else(|| Error::UnexpectedVcpuExit("test fork was cancelled".to_owned()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_forked_process_admitted(
        &mut self,
        executor: &ElfExecutor,
        child_pid: i32,
        child_stack: Option<u64>,
        parent_tid: Option<u64>,
        child_tid: Option<u64>,
        clear_child_tid: Option<u64>,
        clear_sighand: bool,
        share_address_space: bool,
        park_syscall_return: bool,
        fault: Option<&PageZeroFault>,
        stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
    ) -> Result<Option<ForkedProcess>> {
        let mut child_executor =
            executor.fork_child(child_pid, clear_sighand, share_address_space)?;
        #[cfg(test)]
        tests::entry_action_tests::observe("fork_executor");
        child_executor.set_clear_child_tid(clear_child_tid);
        if park_syscall_return
            && !self
                .park_process_action("parent did not park at fork", stop)
                .await?
        {
            return Ok(None);
        }
        let child_snapshot = self.snapshot_process()?;
        write_tid_best_effort(&mut self.memory, parent_tid, child_pid);

        let mut child = Self::from_process_snapshot(child_snapshot)?;
        // Forked children inherit the parent's thread ownership so execution and
        // `is_backend_owned_syscall`'s futex classification stay consistent.
        child.thread_ownership = self.thread_ownership;
        child.set_tool_failure(
            self.tool_failure
                .as_ref()
                .map(|failure| failure.for_process(Pid::from_raw(child_pid))),
        );
        child.set_operation_origin(self.memory.entry_origin().operation);
        child_executor.bind_address_space(&child.memory);
        child.exit_collector = self.exit_collector.clone();
        write_tid_best_effort(&mut child.memory, child_tid, child_pid);
        let (fs_base, gs_base) = child_executor.segment_bases();
        set_user_segment_base(&child.vcpu, SegmentBase::Fs, fs_base)?;
        set_user_segment_base(&child.vcpu, SegmentBase::Gs, gs_base)?;
        // The child uses root transport for future syscalls, but its initial
        // return belongs to the issuing thread's frame in the private snapshot.
        configure_process_syscall_return(
            &child.memory,
            &child.vcpu,
            self.syscall_frame_address,
            0,
            child_stack,
        )?;
        if let Some(fault) = fault {
            fault.configure_child(&mut child, child_stack)?;
        }
        Ok(Some(ForkedProcess {
            pid: child_pid,
            backend: child,
            executor: child_executor,
        }))
    }

    #[cfg(test)]
    fn finish_forked_process(
        &mut self,
        executor: &mut ElfExecutor,
        mut child: ForkedProcess,
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<ForkedProcessCompletion> {
        self.finish_forked_process_inner(executor, &mut child, status, stdout, stderr)
    }

    fn finish_forked_process_inner(
        &mut self,
        executor: &mut ElfExecutor,
        child: &mut ForkedProcess,
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<ForkedProcessCompletion> {
        // A process clone has a private snapshot, so no surviving task can
        // observe this clear; preserve the child-side ABI.
        write_tid_best_effort(
            &mut child.backend.memory,
            child.executor.take_clear_child_tid(),
            0,
        );
        child.backend.check_entry_owner()?;
        let family = child.executor.claim_process_family_exit()?;
        let snapshot = match family {
            crate::executor::ProcessFamilyExit::Child(snapshot) => snapshot,
            crate::executor::ProcessFamilyExit::Root => {
                return Err(Error::UnexpectedVcpuExit(format!(
                    "KVM fork child {} was recorded as a traced root",
                    child.pid
                )));
            }
            crate::executor::ProcessFamilyExit::RunTeardownChild { .. } => {
                // A nested Direct fork would resume this caller's synchronous
                // stack after completion. Unlike an asynchronously owned Tool
                // child, it has no detached teardown path on which a terminal
                // caller can consume that completion, so refuse rather than
                // return into the terminal caller.
                return Err(Error::UnexpectedVcpuExit(format!(
                    "KVM fork child {} completed after its parent became terminal",
                    child.pid
                )));
            }
            crate::executor::ProcessFamilyExit::ReapedByNamespaceInit {
                status: family_status,
            } => {
                // A peer's exit_group made the blocked caller's process
                // terminal and orphaned this child to an outside init, which
                // reaps it. The caller's process has no wait to record and its
                // fork never returns; the caller finishes its own exit instead.
                if family_status != status {
                    return Err(Error::UnexpectedVcpuExit(format!(
                        "KVM fork child {} family status disagrees with its process status",
                        child.pid
                    )));
                }
                executor.append_output(stdout, stderr);
                return Ok(ForkedProcessCompletion::Detached);
            }
            crate::executor::ProcessFamilyExit::Failed => {
                unreachable!("executor maps failed family state to an error")
            }
            crate::executor::ProcessFamilyExit::DescendantReparentingUnsupported { .. } => {
                unreachable!("executor maps unsupported reparenting to an error")
            }
            crate::executor::ProcessFamilyExit::ParentGenerationUnavailable { .. } => {
                unreachable!("executor maps a missing parent generation to an error")
            }
            crate::executor::ProcessFamilyExit::ParentChildRelationUnavailable { .. } => {
                unreachable!("executor maps a missing parent-child relation to an error")
            }
            crate::executor::ProcessFamilyExit::AncestryCycle { .. } => {
                unreachable!("executor maps a family ancestry cycle to an error")
            }
            crate::executor::ProcessFamilyExit::MultipleParents { .. } => {
                unreachable!("executor maps ambiguous family parents to an error")
            }
        };
        if snapshot.completion.status != status {
            return Err(Error::UnexpectedVcpuExit(format!(
                "KVM fork child {} family status disagrees with its process status",
                child.pid
            )));
        }
        let completion = crate::executor::ChildCompletion::from_waitability(
            snapshot.completion.status,
            snapshot.completion.waitable,
        );
        executor.record_child_completion(snapshot.completion.child, completion)?;
        executor.append_output(stdout, stderr);
        configure_process_syscall_return(
            &self.memory,
            &self.vcpu,
            self.syscall_frame_address,
            i64::from(child.pid),
            None,
        )?;
        Ok(ForkedProcessCompletion::Returned)
    }

    // TODO-HUMAN-REVIEW(PR-156): Review process actions completed during Tool injection.
    async fn run_process_action_inner(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        park_syscall_return: bool,
        fault: Option<&PageZeroFault>,
        mut stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
        direct_registration: Option<&GuestThreadRegistration>,
    ) -> Result<ProcessActionOutcome> {
        let outcome = match &action {
            ProcessAction::Fork { child_pid, .. } => {
                ProcessActionOutcome::returned(i64::from(*child_pid))
            }
            ProcessAction::Thread { child_tid, .. } => {
                ProcessActionOutcome::returned(i64::from(*child_tid))
            }
            ProcessAction::Exec { .. } => ProcessActionOutcome::replaced(),
        };
        match action {
            ProcessAction::Fork {
                child_pid,
                child_stack,
                parent_tid,
                child_tid,
                clear_child_tid,
                clear_sighand,
                share_address_space,
            } => {
                let Some(child) = self
                    .prepare_forked_process_admitted(
                        executor,
                        child_pid,
                        child_stack,
                        parent_tid,
                        child_tid,
                        clear_child_tid,
                        clear_sighand,
                        share_address_space,
                        park_syscall_return,
                        fault,
                        stop.as_mut(),
                    )
                    .await?
                else {
                    return Ok(ProcessActionOutcome::cancelled());
                };
                let parent_interrupt = direct_registration
                    .map(|registration| {
                        registration.suspend_for_inline_fork(
                            self.memory.entry_gate(),
                            self.memory.entry_origin(),
                            self.tool_panic_owner(),
                        )
                    })
                    .transpose()?;
                // The child's run registration/future retires before restoring
                // the parent target. Its backend object can remain in existing
                // deferred Tool cleanup; that ownership is unchanged.
                let result = async {
                    let mut child = child;
                    // This direct fork runs on the parent's call stack.
                    // It is nested work, not an independent driver
                    // that can await the parent's terminal publication.
                    child.backend.entry_driver = self.entry_driver_owner();
                    child
                        .backend
                        .set_operation_origin(self.memory.entry_origin().operation);
                    child.executor.bind_address_space(&child.backend.memory);
                    // Inline descendants share this executor with their parent.
                    // Boxing breaks the recursive future type without entering a
                    // second LocalPool or moving guest work to another host thread.
                    let result = Box::pin(
                        child
                            .backend
                            .run_static_elf_process_inner(&mut child.executor),
                    )
                    .await;
                    let result = match result {
                        Ok((status, stdout, stderr)) => self.finish_forked_process_inner(
                            executor, &mut child, status, stdout, stderr,
                        ),
                        Err(error) => Err(error),
                    };
                    if let Ok(ForkedProcessCompletion::Detached) = result {
                        return Ok(ProcessActionOutcome::cancelled());
                    }
                    if let Err(error) = result {
                        if self.entry_driver.is_some() {
                            // KvmBackend::drop cancels/joins. Keep that destruction
                            // outside the enclosing callback along with every
                            // nested owned consumer, after outer publication.
                            let transfer = ChildToolPanicTransfer {
                                parent: self.tool_panic_owner(),
                                child: child.backend.tool_panic_owner(),
                            };
                            executor.retain_unstarted_tool_cleanup(Box::pin(async move {
                                let transfer = transfer;
                                child.backend.restore_entry_origin();
                                child.executor.bind_address_space(&child.backend.memory);
                                let cleanup =
                                    crate::runtime::finish_unstarted_tool_cleanups_with_panics(
                                        &mut child.executor,
                                        &child.backend.tool_panics,
                                    )
                                    .await;
                                child.backend.cancel_guest_threads_after_failure();
                                let workers = child.backend.guest_worker_teardown_result();
                                let children = child
                                    .executor
                                    .join_child_processes_after_failure_async()
                                    .await;
                                drop(transfer);
                                Error::combine(
                                    [cleanup, workers, children]
                                        .into_iter()
                                        .filter_map(Result::err)
                                        .collect(),
                                )
                            }));
                        } else {
                            // This Direct child has no enclosing Tool callback or
                            // deferred publisher. Collect its reader/worker errors
                            // before dropping the backend and its diagnostic cache.
                            return Err(child.backend.finish_direct_process_error(error));
                        }
                        return Err(error);
                    }
                    Ok(outcome)
                }
                .await;
                return match parent_interrupt {
                    Some(suspended) => suspended.finish(result),
                    None => result,
                };
            }
            // TODO-HUMAN-REVIEW(PR-172): Review concurrent CLONE_THREAD lifecycle semantics.
            ProcessAction::Thread {
                child_tid,
                child_stack,
                parent_tid,
                child_tid_address,
                clear_child_tid,
                tls,
            } => {
                let Some((parent_registers, parent_xsave, parent_syscall_frame)) =
                    self.capture_thread_parent(stop.as_mut()).await?
                else {
                    return Ok(ProcessActionOutcome::cancelled());
                };
                let (parent_fs, parent_gs) = executor.segment_bases();

                if park_syscall_return
                    && !self
                        .park_process_action("parent did not park at thread clone", stop.as_mut())
                        .await?
                {
                    return Ok(ProcessActionOutcome::cancelled());
                }
                let child_registers = self.vcpu.get_regs()?;

                write_tid_best_effort(&mut self.memory, parent_tid, child_tid);
                write_tid_best_effort(&mut self.memory, child_tid_address, child_tid);
                let child_fs = tls.unwrap_or(parent_fs);
                let mut child_executor =
                    executor.thread_child_with_signal_observation(child_tid, false)?;
                child_executor.set_thread_context(child_tid, child_fs, parent_gs);
                child_executor.set_clear_child_tid(clear_child_tid);
                let child_stdin = self.stdin.as_ref().map(File::try_clone).transpose()?;
                let mut child = Self::from_thread_state(
                    self.memory.clone(),
                    child_registers,
                    parent_xsave,
                    child_stdin,
                    self.cpuid_policy,
                    child_tid,
                    self.thread_group.clone(),
                )?;
                // Thread children inherit the parent's thread ownership so
                // execution and futex classification stay consistent.
                self.debug_assert_thread_ownership_consistent();
                child.thread_ownership = self.thread_ownership;
                child.set_tool_failure(
                    self.tool_failure
                        .as_ref()
                        .map(|failure| failure.for_thread(Pid::from_raw(child_tid))),
                );
                child.exit_collector = self.exit_collector.clone();
                child
                    .memory
                    .write_raw(child.syscall_frame_address, &parent_syscall_frame)?;
                set_user_segment_base(&child.vcpu, SegmentBase::Fs, child_fs)?;
                set_user_segment_base(&child.vcpu, SegmentBase::Gs, parent_gs)?;
                configure_process_syscall_return(
                    &child.memory,
                    &child.vcpu,
                    child.syscall_frame_address,
                    0,
                    Some(child_stack),
                )?;

                if let Some(fault) = fault {
                    fault.configure_child(&mut child, Some(child_stack))?;
                }

                self.vcpu.set_regs(&parent_registers)?;
                configure_process_syscall_return(
                    &self.memory,
                    &self.vcpu,
                    self.syscall_frame_address,
                    i64::from(child_tid),
                    None,
                )?;

                let completion_notice = WorkerCompletionNotice::new(self.thread_group.clone());
                let returning = completion_notice.returning.clone();
                #[cfg(test)]
                tests::entry_action_tests::observe("host_spawn");
                let handle = std::thread::Builder::new()
                    .name(format!("reverie-kvm-guest-{child_tid}"))
                    .spawn(move || {
                        let _completion_notice = completion_notice;
                        let mut run_child = move || {
                            let driver = child.start_entry_driver();
                            child_executor.bind_address_space(&child.memory);
                            let execution =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    let result = child.run_static_elf_process(&mut child_executor);
                                    child.restore_entry_origin();
                                    child_executor.bind_address_space(&child.memory);
                                    let result = futures::executor::block_on(
                                        child.route_entry_outcome(result),
                                    );
                                    let result = result.map_err(|error| {
                                        child.report_tool_failure("host worker outcome", error)
                                    });
                                    let cleanup = futures::executor::block_on(
                                        crate::runtime::finish_unstarted_tool_cleanups_with_panics(
                                            &mut child_executor,
                                            &child.tool_panics,
                                        ),
                                    );
                                    let result = match (result, cleanup) {
                                        (Ok(value), Ok(())) => Ok(value),
                                        (Ok(_), Err(error)) => Err(error),
                                        (Err(error), Ok(())) => Err(error),
                                        (Err(error), Err(cleanup)) => {
                                            Err(error.with_cleanup(vec![cleanup]))
                                        }
                                    };
                                    let result = futures::executor::block_on(
                                        child.route_entry_outcome(result),
                                    );
                                    let failure = child.tool_failure.clone();
                                    let result = finish_host_worker_outcome(
                                        failure.as_ref(),
                                        Pid::from_raw(child_tid),
                                        result,
                                        |failed| {
                                            child.release_thread_slot();
                                            clear_tid_and_wake(
                                                &mut child.memory,
                                                child_executor.take_clear_child_tid(),
                                            );
                                            if failed {
                                                child_executor.retire_failed_thread();
                                                child.thread_group.record_worker_failure(child_tid);
                                            }
                                        },
                                    );
                                    // Clear-TID is best effort, but a captured
                                    // entry failure still belongs to this driver.
                                    let result = futures::executor::block_on(
                                        child.route_entry_outcome(result),
                                    )
                                    .map_err(|error| {
                                        child.report_tool_failure("host worker retirement", error)
                                    });
                                    if let Err(error) = &result
                                        && child.thread_group.take_worker_error_report(child_tid)
                                    {
                                        eprintln!(
                                            "reverie-kvm guest thread {child_tid} failed: {error}"
                                        );
                                    }
                                    result
                                }));
                            match execution {
                                Ok(result) => {
                                    let result = child.finish_entry_driver(driver, result).map_err(
                                        |error| {
                                            child.report_tool_failure(
                                                "host worker completion",
                                                error,
                                            )
                                        },
                                    );
                                    child.finish_deferred_worker_panic(child_tid, result)
                                }
                                Err(payload) => child.finish_panicked_guest_worker_with_entry(
                                    &mut child_executor,
                                    child_tid,
                                    payload,
                                    Some(driver),
                                    |_| Ok(()),
                                ),
                            }
                        };
                        run_child()
                    })?;
                self.thread_group.add_worker_handle_with_completion(
                    child_tid,
                    None,
                    Some(returning),
                    handle,
                );
            }
            ProcessAction::Exec {
                executable_path,
                executable_file,
                image,
                argv,
                envp,
            } => {
                if self.is_guest_thread {
                    return Err(Error::GuestThreadExecUnsupported);
                }
                if park_syscall_return
                    && !self
                        .park_process_action("process did not park before exec", stop.as_mut())
                        .await?
                {
                    return Ok(ProcessActionOutcome::cancelled());
                }
                // A successful exec terminates every sibling thread before the
                // new address space becomes visible. Leaving a sibling vCPU
                // alive lets it execute stale instructions in the replacement
                // image and can turn an otherwise successful exec into a fault.
                self.cancel_guest_threads_for_exec(stop.as_mut()).await?;
                self.guest_worker_teardown_result()
                    .map_err(|error| Error::ExecWorkerTeardown(Box::new(error)))?;
                let result = self.exec_process(
                    executor,
                    (&executable_path, executable_file),
                    &image,
                    &argv,
                    &envp,
                );
                self.thread_group.rearm_after_exec();
                result?;
            }
        }
        Ok(outcome)
    }

    #[cfg(test)]
    fn run_process_action(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        park_syscall_return: bool,
    ) -> Result<()> {
        let mut stop = std::pin::pin!(std::future::pending());
        futures::executor::block_on(self.run_process_action_inner(
            executor,
            action,
            park_syscall_return,
            None,
            stop.as_mut(),
            None,
        ))
        .map(|_| ())
    }

    /// Cancels and joins children created by a Tool action whose parent
    /// boundary could not be committed.
    #[cfg(test)]
    pub(crate) fn discard_unstarted_tool_children(
        &mut self,
        executor: &mut ElfExecutor,
        starts: &SharedChildStarts,
    ) -> Result<()> {
        let children = self.cancel_unstarted_tool_children(starts, false);
        self.discard_cancelled_tool_children(executor, children, false)
    }

    fn cancel_unstarted_tool_children(
        &self,
        starts: &SharedChildStarts,
        failed: bool,
    ) -> Vec<(PendingChildCancellation, bool)> {
        // A natural join can already own the handle. Capture exact gate
        // registration before Cancel lets that join finish and remove it.
        let registered = self
            .thread_group
            .worker_start_gates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        starts
            .lock()
            .expect("KVM child-start lock poisoned")
            .drain(..)
            .map(|start| {
                let registered_thread = start.tool_thread_gate().is_some_and(|(tid, gate)| {
                    registered
                        .get(&tid)
                        .is_some_and(|found| found.same_gate(gate))
                });
                let cancelled = if failed {
                    start.cancel_after_failure()
                } else {
                    start.cancel()
                };
                (cancelled, registered_thread)
            })
            .collect()
    }

    fn discard_cancelled_tool_children(
        &mut self,
        executor: &mut ElfExecutor,
        children: Vec<(PendingChildCancellation, bool)>,
        cancelled_after_failure: bool,
    ) -> Result<()> {
        let mut first_error = None;
        for (child, registered_thread) in children {
            let PendingChildCancellation::NewlyCancelled {
                child,
                delivery_failed,
            } = child
            else {
                continue;
            };
            if delivery_failed {
                first_error.get_or_insert_with(|| {
                    Error::UnexpectedVcpuExit(
                        "unstarted KVM child lost its parent cancellation gate".to_owned(),
                    )
                });
            }
            let result = match child {
                PendingChildKind::ForkProcess(pid) => executor
                    .discard_unstarted_child_process(pid)
                    .and_then(|found| {
                        found.then_some(()).ok_or_else(|| {
                            Error::UnexpectedVcpuExit(format!(
                                "unstarted KVM child process {pid} was not registered"
                            ))
                        })
                    }),
                PendingChildKind::ToolThread(tid) => self
                    .thread_group
                    .discard_unstarted_worker(tid)
                    .and_then(|found| {
                        (found || registered_thread).then_some(()).ok_or_else(|| {
                            Error::UnexpectedVcpuExit(format!(
                                "unstarted KVM guest thread {tid} was not registered"
                            ))
                        })
                    }),
            };
            if let Err(error) = result {
                // The parent already retains the fatal action error. A child
                // whose exact pending gate we just cancelled can complete its
                // consuming cleanup with only this derived marker. It is not
                // a second cleanup failure. Keep every aggregate, real hook
                // error and ordinary-cancellation error unchanged.
                if cancelled_after_failure && matches!(error, Error::RunAborted) {
                    continue;
                }
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Finish the action while its parent callback still owns borrowed state.
    /// The outer driver retains the pending gates and owns error publication,
    /// cancellation and joins after destroying that callback.
    fn finish_injected_tool_process_action_at_boundary(
        &mut self,
        continuation: ProcessActionContinuation,
        action_result: Result<ProcessActionOutcome>,
    ) -> Result<ProcessActionOutcome> {
        continuation.finish(self, action_result)
    }

    fn finish_tool_process_action_at_boundary(
        &mut self,
        executor: &mut ElfExecutor,
        starts: &SharedChildStarts,
        continuation: ProcessActionContinuation,
        action_result: Result<ProcessActionOutcome>,
    ) -> Result<ProcessActionOutcome> {
        match self.finish_injected_tool_process_action_at_boundary(continuation, action_result) {
            Ok(outcome) => Ok(outcome),
            Err(action_error) => Err(self.cleanup_unstarted_tool_children_after_error(
                executor,
                starts,
                action_error,
            )),
        }
    }

    pub(crate) fn start_pending_tool_children(
        &mut self,
        executor: &mut ElfExecutor,
        starts: &SharedChildStarts,
    ) -> Result<()> {
        self.check_entry_owner()?;
        if let Err(error) = crate::runtime::start_pending_children(starts) {
            return Err(self.cleanup_unstarted_tool_children_after_error(executor, starts, error));
        }
        Ok(())
    }

    /// Preserves the action/handler failure as the primary diagnostic while
    /// still reporting a secondary failure to cancel or join an unstarted
    /// child created during the same callback.
    pub(crate) fn cleanup_unstarted_tool_children_after_error(
        &mut self,
        executor: &mut ElfExecutor,
        starts: &SharedChildStarts,
        primary: Error,
    ) -> Error {
        // Preserve the fatal exec disposition if cancelling an unstarted child
        // adds a second diagnostic. Its owner still owes consuming Tool hooks.
        let (exec_teardown, primary) = match primary {
            Error::ExecWorkerTeardown(primary) => (true, *primary),
            primary => (false, primary),
        };
        let primary = self.report_tool_failure("Tool callback", primary);
        let result = match self.settle_unstarted_tool_children_after_failure(executor, starts) {
            Ok(()) => primary,
            Err(cleanup) => {
                primary.with_cleanup(vec![cleanup.cleanup("unstarted-child cleanup also failed")])
            }
        };
        if exec_teardown {
            Error::ExecWorkerTeardown(Box::new(result))
        } else {
            result
        }
    }

    /// Cancel and join an impossible child-start batch without publishing by
    /// itself. The caller must publish its terminal parent failure first:
    /// `CancelAfterFailure` lets child cleanup consume that transition.
    pub(crate) fn settle_unstarted_tool_children_after_failure(
        &mut self,
        executor: &mut ElfExecutor,
        starts: &SharedChildStarts,
    ) -> Result<()> {
        let children = self.cancel_unstarted_tool_children(starts, true);
        self.discard_cancelled_tool_children(executor, children, true)
    }

    /// Runs one process action and restores the completed syscall transport
    /// exactly when the action returns to the original image.
    pub(crate) async fn run_process_action_at_boundary(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        continuation: ProcessActionContinuation,
        registration: &GuestThreadRegistration,
    ) -> Result<ProcessActionOutcome> {
        let mut stop = std::pin::pin!(std::future::pending());
        let result = self
            .run_process_action_inner(
                executor,
                action,
                true,
                None,
                stop.as_mut(),
                Some(registration),
            )
            .await;
        continuation.finish(self, result)
    }

    // TODO-HUMAN-REVIEW(PR-192): Review tool lifecycle for KVM fork children.
    // TODO-HUMAN-REVIEW(PR-235): Review concurrent fork-child Tool execution.
    async fn run_process_action_with_tool_inner<T>(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        park_syscall_return: bool,
        context: ToolContext<'_, T>,
        fault: Option<&PageZeroFault>,
    ) -> Result<ProcessActionOutcome>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        let global = context.global_state.clone();
        let local = self.failure_subscription(executor.is_traced_tree_root());
        let mut stop = std::pin::pin!(async {
            match global.as_ref() {
                Some(global) => crate::failure::wait_for_failure(global.as_ref(), local).await,
                None => match local {
                    Some(local) => {
                        let _ = local.await;
                    }
                    None => std::future::pending().await,
                },
            }
        });
        match action {
            ProcessAction::Fork {
                child_pid,
                child_stack,
                parent_tid,
                child_tid,
                clear_child_tid,
                clear_sighand,
                share_address_space,
            } => {
                let Some(child) = self
                    .prepare_forked_process_admitted(
                        executor,
                        child_pid,
                        child_stack,
                        parent_tid,
                        child_tid,
                        clear_child_tid,
                        clear_sighand,
                        share_address_space,
                        park_syscall_return,
                        fault,
                        stop.as_mut(),
                    )
                    .await?
                else {
                    return Ok(ProcessActionOutcome::cancelled());
                };

                let child_pid = Pid::from_raw(child.pid);
                // Capture generation-bound process identities while both live
                // executors are still registered. The child task is retired
                // before the wait callback, so reconstructing its generation at
                // callback time would bind numeric PID reuse instead.
                executor.signal_task_identity().ok_or_else(|| {
                    Error::UnexpectedVcpuExit(
                        "KVM fork parent lost its signal generation before child admission"
                            .to_owned(),
                    )
                })?;
                let child_signal_process = child
                    .executor
                    .signal_task_identity()
                    .ok_or_else(|| {
                        Error::UnexpectedVcpuExit(
                            "KVM fork child lost its signal generation before host spawn"
                                .to_owned(),
                        )
                    })?
                    .process;
                let parent_signal_binding = executor.retain_signal_process_binding();
                let global_state = context.global_state.ok_or_else(|| {
                    Error::UnexpectedVcpuExit(
                        "forked KVM Tool process requires shared global state".to_owned(),
                    )
                })?;
                let child_tool = Arc::new(T::new(child_pid, &context.config));
                let child_thread_state = child_tool
                    .init_thread_state(child_pid, Some((context.tid, context.thread_state)));
                let config = context.config;
                let subscriptions = context.subscriptions;
                let pending_child_starts = context.pending_child_starts;
                let raw_child_pid = child.pid;
                let completion = Arc::new(ChildCompletionSlot::default());
                let child_completion = completion.clone();
                let child_exit_context = OwnChildExitContext {
                    child: child_signal_process,
                    _parent_binding: parent_signal_binding,
                    completion: completion.clone(),
                    raw_child_pid,
                };
                let panic_owner = child.backend.tool_failure.as_ref().map(|failure| {
                    crate::executor::ChildProcessPanicOwner::new(failure.run.clone())
                });
                let child_panic_owner = panic_owner.clone();
                let (start_sender, start_receiver) = std::sync::mpsc::channel();
                let start_gate = ChildStartGate::new(start_sender);
                let handle = ChildThread::spawn_owned(
                    std::thread::Builder::new()
                        .name(format!("reverie-kvm-process-{raw_child_pid}")),
                    (
                        child,
                        child_tool,
                        child_thread_state,
                        global_state,
                        config,
                        subscriptions,
                        child_exit_context,
                    ),
                    move |(
                        mut child,
                        child_tool,
                        child_thread_state,
                        global_state,
                        config,
                        subscriptions,
                        child_exit_context,
                    )| {
                        let driver = child.backend.start_entry_driver();
                        child.executor.bind_address_space(&child.backend.memory);
                        let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                            || {
                                let start = start_receiver.recv();
                                let cancel = !matches!(start, Ok(ChildStartCommand::Start));
                                let failure = match start {
                                    Ok(command) => command.failure(),
                                    Err(_) => Some(Error::UnexpectedVcpuExit(format!(
                                        "KVM child process {raw_child_pid} lost its parent start gate"
                                    ))),
                                };
                                let result = if cancel {
                                    futures::executor::block_on(
                                        child.backend.finish_unstarted_tool(
                                            &mut child.executor,
                                            child_tool,
                                            (child_pid, child_pid),
                                            global_state.as_ref(),
                                            &config,
                                            child_thread_state,
                                            failure,
                                        ),
                                    )
                                } else {
                                    futures::executor::block_on(
                                        child.backend.run_static_elf_process_with_tool(
                                            &mut child.executor,
                                            child_pid,
                                            // A forked process child is its own leader (tid == pid).
                                            child_pid,
                                            child_tool,
                                            child_thread_state,
                                            global_state,
                                            &config,
                                            &subscriptions,
                                            false,
                                            Some(child_exit_context),
                                        ),
                                    )
                                };
                                child.backend.restore_entry_origin();
                                child.executor.bind_address_space(&child.backend.memory);
                                match result {
                                    Ok((_status, _, _)) => {
                                        write_tid_best_effort(
                                            &mut child.backend.memory,
                                            child.executor.take_clear_child_tid(),
                                            0,
                                        );
                                        // A best-effort clear can have captured a real
                                        // gate failure despite its unit return value.
                                        futures::executor::block_on(
                                            child.backend.route_entry_outcome(Ok(())),
                                        )?;
                                        Ok(())
                                    }
                                    Err(error) => Err(error),
                                }
                            },
                        ));
                        let result = match execution {
                            Ok(result) => result,
                            Err(payload) => child
                                .backend
                                .finish_panicked_tool_process_owner(&mut child.executor, payload),
                        };
                        child.backend.restore_entry_origin();
                        child.executor.bind_address_space(&child.backend.memory);
                        let result =
                            futures::executor::block_on(child.backend.route_entry_outcome(result))
                                .map_err(|error| {
                                    child
                                        .backend
                                        .report_tool_failure("fork owner completion", error)
                                });
                        let result =
                            child
                                .backend
                                .finish_entry_driver(driver, result)
                                .map_err(|error| {
                                    child
                                        .backend
                                        .report_tool_failure("fork owner retirement", error)
                                });
                        if result.is_err() {
                            child_completion.fail_if_pending();
                            child
                                .executor
                                .fail_child_wait_publication(child_signal_process);
                        }
                        child
                            .backend
                            .finish_deferred_process_panic(result, child_panic_owner.as_deref())
                    },
                );
                let handle = match handle {
                    Ok(handle) => handle,
                    Err((
                        error,
                        (mut child, child_tool, child_thread_state, global_state, config, _, _),
                    )) => {
                        // Publish the original spawn failure through the parent
                        // first. Its outer owner consumes this child afterward,
                        // outside the still-borrowed parent Tool callback.
                        let transfer = ChildToolPanicTransfer {
                            parent: self.tool_panic_owner(),
                            child: child.backend.tool_panic_owner(),
                        };
                        executor.retain_unstarted_tool_cleanup(Box::pin(async move {
                            let transfer = transfer;
                            let driver = child.backend.start_entry_driver();
                            child.executor.bind_address_space(&child.backend.memory);
                            let caught =
                                crate::failure::owned_future::catch_owned_future_from(|| {
                                    child.backend.finish_unstarted_tool(
                                        &mut child.executor,
                                        child_tool,
                                        (child_pid, child_pid),
                                        global_state.as_ref(),
                                        &config,
                                        child_thread_state,
                                        Some(Error::RunAborted),
                                    )
                                })
                                .await;
                            let result = child
                                .backend
                                .tool_panic_owner()
                                .finish(caught, "unstarted fork owner");
                            child.backend.restore_entry_origin();
                            child.executor.bind_address_space(&child.backend.memory);
                            let result = child.backend.route_entry_outcome(result).await;
                            let result = child.backend.finish_entry_driver(driver, result).map_err(
                                |error| {
                                    child
                                        .backend
                                        .report_tool_failure("unstarted fork completion", error)
                                },
                            );
                            drop(transfer);
                            result.map(|_| unreachable!("failed spawn completed successfully"))
                        }));
                        return Err(Error::HostIo(error));
                    }
                };
                pending_child_starts
                    .lock()
                    .expect("KVM child-start lock poisoned")
                    .push(PendingChildStart::fork_process(
                        raw_child_pid,
                        start_gate.clone(),
                    ));
                executor.register_child_process_with_panic_owner(
                    raw_child_pid,
                    start_gate,
                    completion,
                    handle,
                    panic_owner,
                );
                configure_process_syscall_return(
                    &self.memory,
                    &self.vcpu,
                    self.syscall_frame_address,
                    i64::from(raw_child_pid),
                    None,
                )
                .map(|()| ProcessActionOutcome::returned(i64::from(raw_child_pid)))
            }
            // `ThreadOwnership::Host`: CLONE_THREAD workers run uninstrumented on
            // the direct backend personality with host-backed synchronization,
            // exactly as `run_process_action`'s Thread branch does. Execution and
            // `futex` ownership are both Host (a single `ThreadOwnership`), so the
            // joiner's real host `FUTEX_WAIT` and the exiting worker's real host
            // `CLONE_CHILD_CLEARTID` wake meet on the same futex word — no
            // deadlock. (The split-brain that deadlocks a join — a Tool-executed
            // worker whose `futex` is host-owned, so its logical CLEARTID wake
            // never reaches the host waiter — is unrepresentable now that one
            // enum drives both decisions.)
            ProcessAction::Thread { .. } if self.thread_ownership.executes_on_host() => {
                self.run_process_action_inner(
                    executor,
                    action,
                    park_syscall_return,
                    fault,
                    stop.as_mut(),
                    None,
                )
                .await
            }
            // `ThreadOwnership::Tool`: a CLONE_THREAD worker runs its own vCPU on
            // a fresh OS thread but shares the guest address space, file table,
            // and process Tool identity with its creator. It is driven through
            // the same Tool loop as the process leader so Detcore sees its
            // syscalls, shares its fd model, and schedules it; `futex` routes to
            // Detcore (runtime.rs) so a join's logical `FUTEX_WAIT` is woken by
            // the worker's logical `CLEARTID`. This mirrors the physical setup in
            // `run_process_action`'s Thread branch, but spawns the Tool loop
            // instead of the direct backend personality.
            ProcessAction::Thread {
                child_tid,
                child_stack,
                parent_tid,
                child_tid_address,
                clear_child_tid,
                tls,
            } => {
                let Some((parent_registers, parent_xsave, parent_syscall_frame)) =
                    self.capture_thread_parent(stop.as_mut()).await?
                else {
                    return Ok(ProcessActionOutcome::cancelled());
                };
                let (parent_fs, parent_gs) = executor.segment_bases();

                if park_syscall_return
                    && !self
                        .park_process_action("parent did not park at thread clone", stop.as_mut())
                        .await?
                {
                    return Ok(ProcessActionOutcome::cancelled());
                }
                let child_registers = self.vcpu.get_regs()?;

                write_tid_best_effort(&mut self.memory, parent_tid, child_tid);
                write_tid_best_effort(&mut self.memory, child_tid_address, child_tid);
                let child_fs = tls.unwrap_or(parent_fs);
                let mut child_executor = executor.thread_child(child_tid)?;
                child_executor.set_thread_context(child_tid, child_fs, parent_gs);
                child_executor.set_clear_child_tid(clear_child_tid);
                let child_stdin = self.stdin.as_ref().map(File::try_clone).transpose()?;
                let mut child = Self::from_thread_state(
                    self.memory.clone(),
                    child_registers,
                    parent_xsave,
                    child_stdin,
                    self.cpuid_policy,
                    child_tid,
                    self.thread_group.clone(),
                )?;
                // Thread children inherit the parent's thread ownership so
                // execution and futex classification stay consistent.
                self.debug_assert_thread_ownership_consistent();
                child.thread_ownership = self.thread_ownership;
                child.set_tool_failure(self.tool_failure.clone());
                child.exit_collector = self.exit_collector.clone();
                child
                    .memory
                    .write_raw(child.syscall_frame_address, &parent_syscall_frame)?;
                set_user_segment_base(&child.vcpu, SegmentBase::Fs, child_fs)?;
                set_user_segment_base(&child.vcpu, SegmentBase::Gs, parent_gs)?;
                configure_process_syscall_return(
                    &child.memory,
                    &child.vcpu,
                    child.syscall_frame_address,
                    0,
                    Some(child_stack),
                )?;

                if let Some(fault) = fault {
                    fault.configure_child(&mut child, Some(child_stack))?;
                }

                // CLONE_THREAD shares the process (thread-group) identity, so the
                // worker shares its creator's process Tool state, while the
                // thread state is keyed on the new child tid. This
                // mirrors reverie-ptrace's `cloned()`, where the child shares the
                // process Tool identity and receives fresh per-thread state
                // linked to the parent thread.
                let tgid = context.pid;
                let child_tid_pid = Pid::from_raw(child_tid);
                let global_state = context.global_state.ok_or_else(|| {
                    Error::UnexpectedVcpuExit(
                        "KVM CLONE_THREAD worker requires shared global state".to_owned(),
                    )
                })?;
                let config = context.config;
                let subscriptions = context.subscriptions;

                self.vcpu.set_regs(&parent_registers)?;
                configure_process_syscall_return(
                    &self.memory,
                    &self.vcpu,
                    self.syscall_frame_address,
                    i64::from(child_tid),
                    None,
                )?;

                let child_tool = context.process_state.clone();
                let child_thread_state = child_tool
                    .init_thread_state(child_tid_pid, Some((context.tid, context.thread_state)));
                if let Some(failure) = &child.tool_failure {
                    child.set_tool_failure(Some(failure.for_thread(child_tid_pid)));
                }
                let pending_child_starts = context.pending_child_starts;
                let (start_sender, start_receiver) = std::sync::mpsc::channel();
                let start_gate = ChildStartGate::new(start_sender);
                let completion_notice = WorkerCompletionNotice::new(self.thread_group.clone());
                let returning = completion_notice.returning.clone();
                #[cfg(test)]
                tests::entry_action_tests::observe("tool_spawn");
                let handle = crate::failure::spawn_owned(
                    std::thread::Builder::new().name(format!("reverie-kvm-guest-{child_tid}")),
                    (
                        child,
                        child_executor,
                        child_tool,
                        child_thread_state,
                        global_state,
                        config,
                        subscriptions,
                    ),
                    move |(
                        mut child,
                        mut child_executor,
                        child_tool,
                        child_thread_state,
                        global_state,
                        config,
                        subscriptions,
                    )| {
                        let _completion_notice = completion_notice;
                        let run_child = move || {
                            let driver = child.start_entry_driver();
                            child_executor.bind_address_space(&child.memory);
                            let execution = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                || {
                                    let start = start_receiver.recv();
                                    let cancel = !matches!(start, Ok(ChildStartCommand::Start));
                                    let failure = match start {
                                        Ok(command) => command.failure(),
                                        Err(_) => Some(Error::UnexpectedVcpuExit(format!(
                                            "KVM guest thread {child_tid} lost its parent start gate"
                                        ))),
                                    };
                                    let result = if cancel {
                                        futures::executor::block_on(child.finish_unstarted_tool(
                                            &mut child_executor,
                                            child_tool,
                                            (tgid, child_tid_pid),
                                            global_state.as_ref(),
                                            &config,
                                            child_thread_state,
                                            failure,
                                        ))
                                    } else {
                                        futures::executor::block_on(
                                            child.run_static_elf_process_with_tool(
                                                &mut child_executor,
                                                tgid,
                                                child_tid_pid,
                                                child_tool,
                                                child_thread_state,
                                                global_state,
                                                &config,
                                                &subscriptions,
                                                false,
                                                None,
                                            ),
                                        )
                                    };
                                    child.restore_entry_origin();
                                    child_executor.bind_address_space(&child.memory);
                                    child.release_thread_slot();
                                    clear_tid_and_wake(
                                        &mut child.memory,
                                        child_executor.take_clear_child_tid(),
                                    );
                                    let result = futures::executor::block_on(
                                        child.route_entry_outcome(result),
                                    )
                                    .map_err(|error| {
                                        child.report_tool_failure("Tool worker retirement", error)
                                    });
                                    let peer_cancelled =
                                        crate::runtime::is_peer_cancelled_tool_worker(
                                            (tgid, child_tid_pid),
                                            !cancel,
                                            &result,
                                        );
                                    if result.is_err() && !peer_cancelled {
                                        child_executor.retire_failed_thread();
                                        child.thread_group.record_worker_failure(child_tid);
                                    }
                                    if let Err(error) = &result
                                        && !peer_cancelled
                                        && child.thread_group.take_worker_error_report(child_tid)
                                        && !child.tool_panic_owner().worker_execution_panicked()
                                    {
                                        eprintln!(
                                            "reverie-kvm guest thread {child_tid} tool loop failed: {error}"
                                        );
                                    }
                                    result
                                },
                            ));
                            match execution {
                                Ok(result) => {
                                    let result = child.finish_worker_configuration(result, config);
                                    let result = child.finish_entry_driver(driver, result).map_err(
                                        |error| {
                                            child.report_tool_failure(
                                                "Tool worker completion",
                                                error,
                                            )
                                        },
                                    );
                                    child.finish_deferred_worker_panic(child_tid, result)
                                }
                                Err(payload) => child.finish_panicked_guest_worker_with_entry(
                                    &mut child_executor,
                                    child_tid,
                                    payload,
                                    Some(driver),
                                    |panics| {
                                        panics.drop_value(
                                            config,
                                            "Tool worker configuration destruction",
                                        )
                                    },
                                ),
                            }
                        };
                        run_child()
                    },
                );
                let handle = match handle {
                    Ok(handle) => handle,
                    Err((
                        error,
                        (
                            mut child,
                            mut child_executor,
                            child_tool,
                            child_thread_state,
                            global_state,
                            config,
                            _,
                        ),
                    )) => {
                        // A failed spawn never starts this child. Retain its
                        // consuming hooks until the parent has published the
                        // original error and released its borrowed callback.
                        let transfer = ChildToolPanicTransfer {
                            parent: self.tool_panic_owner(),
                            child: child.tool_panic_owner(),
                        };
                        executor.retain_unstarted_tool_cleanup(Box::pin(async move {
                            let transfer = transfer;
                            let driver = child.start_entry_driver();
                            child_executor.bind_address_space(&child.memory);
                            let caught =
                                crate::failure::owned_future::catch_owned_future_from(|| {
                                    child.finish_unstarted_tool(
                                        &mut child_executor,
                                        child_tool,
                                        (tgid, child_tid_pid),
                                        global_state.as_ref(),
                                        &config,
                                        child_thread_state,
                                        Some(Error::RunAborted),
                                    )
                                })
                                .await;
                            let result = child
                                .tool_panic_owner()
                                .finish(caught, "unstarted thread owner");
                            let result = child.finish_worker_configuration(result, config);
                            child.restore_entry_origin();
                            child_executor.bind_address_space(&child.memory);
                            let result = child.route_entry_outcome(result).await;
                            let result =
                                child.finish_entry_driver(driver, result).map_err(|error| {
                                    child.report_tool_failure("unstarted thread completion", error)
                                });
                            drop(transfer);
                            result.map(|_| unreachable!("failed spawn completed successfully"))
                        }));
                        return Err(Error::HostIo(error));
                    }
                };
                self.thread_group.add_worker_handle_with_completion(
                    child_tid,
                    Some(start_gate.clone()),
                    Some(returning),
                    handle,
                );
                pending_child_starts
                    .lock()
                    .expect("KVM child-start lock poisoned")
                    .push(PendingChildStart::tool_thread(child_tid, start_gate));
                Ok(ProcessActionOutcome::returned(i64::from(child_tid)))
            }
            other => {
                self.run_process_action_inner(
                    executor,
                    other,
                    park_syscall_return,
                    fault,
                    stop.as_mut(),
                    None,
                )
                .await
            }
        }
    }

    /// Run an injected action without consuming pending children on error.
    /// The caller must retain its SharedChildStarts outside the callback and
    /// give the complete error to the outer driver after callback destruction.
    pub(crate) async fn run_injected_process_action_with_tool_at_boundary<T>(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        context: ToolContext<'_, T>,
        continuation: ProcessActionContinuation,
    ) -> Result<ProcessActionOutcome>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        let action_result = self
            .run_process_action_with_tool_inner(executor, action, true, context, None)
            .await;
        self.finish_injected_tool_process_action_at_boundary(continuation, action_result)
    }

    /// Runs one Tool-owned process action and restores the completed syscall
    /// transport exactly when the action returns to the original image.
    pub(crate) async fn run_process_action_with_tool_at_boundary<T>(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        context: ToolContext<'_, T>,
        continuation: ProcessActionContinuation,
    ) -> Result<ProcessActionOutcome>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        let pending_child_starts = context.pending_child_starts.clone();
        let action_result = self
            .run_process_action_with_tool_inner(executor, action, true, context, None)
            .await;
        self.finish_tool_process_action_at_boundary(
            executor,
            &pending_child_starts,
            continuation,
            action_result,
        )
    }

    pub(crate) async fn run_process_action_with_tool_from_fault<T>(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        context: ToolContext<'_, T>,
        fault: &PageZeroFault,
    ) -> Result<ProcessActionOutcome>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        stage_process_syscall_return(
            &mut self.memory,
            &self.vcpu,
            fault.transport_address,
            fault.registers,
        )?;
        let result = self
            .run_process_action_with_tool_inner(executor, action, false, context, Some(fault))
            .await;
        if result.as_ref().is_ok_and(|outcome| outcome.cancelled) {
            return result;
        }
        let restored = fault.restore_boundary(self);
        match result {
            Err(error) => Err(error),
            Ok(outcome) => {
                restored?;
                Ok(outcome)
            }
        }
    }

    fn static_elf_exception(&self) -> Result<Option<StaticElfException>> {
        let registers = self.vcpu.get_regs()?;
        let Some(vector) = exception_from_halt(registers.rip) else {
            return Ok(None);
        };
        let first_frame_word = usize::from(exception_pushes_error_code(vector));
        let read_frame_word = |word: usize| -> Result<u64> {
            let mut bytes = [0; std::mem::size_of::<u64>()];
            self.memory.read_raw(
                registers.rsp + ((first_frame_word + word) * bytes.len()) as u64,
                &mut bytes,
            )?;
            Ok(u64::from_le_bytes(bytes))
        };
        Ok(Some(StaticElfException {
            vector,
            instruction_pointer: read_frame_word(0)?,
            rflags: read_frame_word(2)?,
            stack_pointer: read_frame_word(3)?,
        }))
    }

    pub(crate) fn set_rdtsc_interception(&mut self, enabled: bool) -> Result<()> {
        crate::bootstrap::set_userspace_rdtsc_interception(&self.vcpu, enabled)?;
        self.intercept_rdtsc = enabled;
        Ok(())
    }

    pub(crate) fn set_cpuid_interception(&mut self, enabled: bool) -> Result<()> {
        self.cpuid_interception.configure(&self.vcpu, enabled)
    }

    pub(crate) fn has_cpuid_interception(&self) -> bool {
        self.cpuid_interception.enabled()
    }

    pub(crate) fn tool_instruction_exception(&self) -> Result<Option<ToolInstructionBoundary>> {
        if let Some(boundary) = self.cpuid_instruction_exception()? {
            return Ok(Some(ToolInstructionBoundary::Cpuid(boundary)));
        }
        Ok(self
            .timestamp_counter_exception()?
            .map(ToolInstructionBoundary::Timestamp))
    }

    fn cpuid_instruction_exception(&self) -> Result<Option<CpuidBoundary>> {
        if !self.cpuid_interception.enabled() {
            return Ok(None);
        }
        let Some(exception) = self.static_elf_exception()? else {
            return Ok(None);
        };
        // CPUID is never an emulated #UD. LOCK and unrelated faults retain
        // their genuine exception, even when this Tool subscribes to CPUID.
        if exception.vector != 13 {
            return Ok(None);
        }
        self.cpuid_interception.verify(&self.vcpu)?;
        let halted = self.vcpu.get_regs()?;
        let special = self.vcpu.get_sregs()?;
        if special.cr0 & (1 << 31) == 0
            || special.efer & ((1 << 10) | (1 << 11)) != ((1 << 10) | (1 << 11))
            || special.cr4 & (1 << 12) != 0
        {
            return Ok(None);
        }
        let mut frame = [0; 6 * 8];
        self.memory.read_raw(halted.rsp, &mut frame)?;
        let word = |index: usize| {
            u64::from_le_bytes(
                frame[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("exception frame word"),
            )
        };
        let cs = word(2);
        let ss = word(5);
        if word(0) != 0
            || cs != u64::from(crate::signal::USER_CODE_SELECTOR)
            || ![
                u64::from(crate::signal::USER_DATA_SELECTOR),
                u64::from(crate::signal::USER_DATA_SELECTOR & !3),
            ]
            .contains(&ss)
        {
            return Ok(None);
        }
        let Some(instruction) = crate::cpuid_instruction::decode(|offset| {
            let address = exception
                .instruction_pointer
                .checked_add(u64::from(offset))?;
            crate::timestamp::fetch_user_byte(&self.memory, special.cr3, address)
        }) else {
            return Ok(None);
        };
        let mut registers = halted;
        registers.rip = exception.instruction_pointer;
        registers.rsp = exception.stack_pointer;
        registers.rflags = exception.rflags;
        Ok(Some(CpuidBoundary {
            registers,
            instruction,
            special_registers: special,
            code_segment: cs as u16,
            stack_segment: ss as u16,
        }))
    }

    pub(crate) fn timestamp_counter_exception(&self) -> Result<Option<TimestampBoundary>> {
        // This guard precedes even reading the fault frame: an unsubscribed
        // RDTSCP #UD is a genuine guest fault, not an unsolicited callback.
        if !self.intercept_rdtsc {
            return Ok(None);
        }
        let Some(exception) = self.static_elf_exception()? else {
            return Ok(None);
        };
        if !matches!(exception.vector, 6 | 13) {
            return Ok(None);
        }
        let halted = self.vcpu.get_regs()?;
        let special = self.vcpu.get_sregs()?;
        if special.cr0 & (1 << 31) == 0
            || special.efer & ((1 << 10) | (1 << 11)) != ((1 << 10) | (1 << 11))
            || special.cr4 & (1 << 12) != 0
            || special.cr4 & (1 << 2) == 0
        {
            return Ok(None);
        }
        let mut frame = [0; 6 * 8];
        let words = if exception.vector == 13 { 6 } else { 5 };
        self.memory.read_raw(halted.rsp, &mut frame[..words * 8])?;
        let word = |index: usize| {
            u64::from_le_bytes(
                frame[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("exception frame word"),
            )
        };
        let first = usize::from(exception.vector == 13);
        let cs = word(first + 1);
        let ss = word(first + 4);
        if (exception.vector == 13 && word(0) != 0)
            || cs != u64::from(crate::signal::USER_CODE_SELECTOR)
            || ![
                u64::from(crate::signal::USER_DATA_SELECTOR),
                u64::from(crate::signal::USER_DATA_SELECTOR & !3),
            ]
            .contains(&ss)
        {
            return Ok(None);
        }
        let Some(instruction) = crate::timestamp::decode(|offset| {
            let address = exception
                .instruction_pointer
                .checked_add(u64::from(offset))?;
            crate::timestamp::fetch_user_byte(&self.memory, special.cr3, address)
        }) else {
            return Ok(None);
        };
        // RDTSC is enabled by every supported CPUID policy. Only RDTSCP may
        // fault as #UD (the deterministic policy does not expose that feature).
        if exception.vector == 6 && instruction.request != reverie::Rdtsc::Tscp {
            return Ok(None);
        }
        let mut registers = halted;
        registers.rip = exception.instruction_pointer;
        registers.rsp = exception.stack_pointer;
        registers.rflags = exception.rflags;
        Ok(Some(TimestampBoundary {
            registers,
            instruction,
            special_registers: special,
            code_segment: cs as u16,
            stack_segment: ss as u16,
        }))
    }

    pub(crate) fn resume_timestamp_counter(
        &mut self,
        boundary: TimestampBoundary,
        result: reverie::RdtscResult,
    ) -> Result<()> {
        let registers =
            crate::timestamp::result_registers(boundary.registers, boundary.instruction, result)
                .ok_or_else(|| Error::UnexpectedVcpuExit("timestamp RIP overflow".to_owned()))?;
        self.resume_instruction_registers(boundary, registers)
    }

    pub(crate) fn resume_tool_instruction(
        &mut self,
        boundary: ToolInstructionBoundary,
        result: ToolInstructionResult,
    ) -> Result<()> {
        match (boundary, result) {
            (
                ToolInstructionBoundary::Timestamp(boundary),
                ToolInstructionResult::Timestamp(result),
            ) => self.resume_timestamp_counter(boundary, result),
            (ToolInstructionBoundary::Cpuid(boundary), ToolInstructionResult::Cpuid(result)) => {
                let registers = crate::cpuid_instruction::result_registers(
                    boundary.registers,
                    boundary.instruction,
                    result,
                )
                .ok_or_else(|| Error::UnexpectedVcpuExit("CPUID RIP overflow".to_owned()))?;
                self.resume_instruction_registers(boundary, registers)
            }
            _ => Err(Error::UnexpectedVcpuExit(
                "instruction callback result kind changed".to_owned(),
            )),
        }
    }

    fn resume_instruction_registers<I>(
        &mut self,
        boundary: InstructionBoundary<I>,
        registers: kvm_regs,
    ) -> Result<()> {
        // Exception stubs preserve every GPR. Returning host-side injections
        // cannot supply a replacement user register file. Preserve the saved
        // instruction state, and any intentional injected FS/GS-base effect.
        let previous = self.vcpu.get_sregs()?;
        configure_user_segments(&self.vcpu)?;
        let mut special = self.vcpu.get_sregs()?;
        special.cs.selector = boundary.code_segment;
        special.ss.selector = boundary.stack_segment;
        special.ds = previous.ds;
        special.es = previous.es;
        special.fs = previous.fs;
        special.gs = previous.gs;
        self.vcpu.set_sregs(&special)?;
        self.vcpu.set_regs(&registers)?;
        if registers.rflags & (1 << 8) != 0 {
            // The instruction has now retired. Preserve this backend's existing
            // typed #DB boundary here, before another guest instruction can
            // run; resuming with TF would report the following instruction.
            return Err(Error::GuestException {
                vector: 1,
                instruction_pointer: registers.rip,
                fault_address: special.cr2,
            });
        }
        Ok(())
    }

    pub(crate) fn capture_page_zero_fault(
        &self,
        executor: &ElfExecutor,
    ) -> Result<Option<PageZeroFault>> {
        let halted_registers = self.vcpu.get_regs()?;
        if exception_from_halt(halted_registers.rip) != Some(14) {
            return Ok(None);
        }
        let special_registers = self.vcpu.get_sregs()?;
        let address = special_registers.cr2;
        if address >= PAGE_SIZE {
            return Ok(None);
        }
        let mut frame = [0; 6 * 8];
        self.memory.read_raw(halted_registers.rsp, &mut frame)?;
        let word = |index: usize| {
            u64::from_le_bytes(
                frame[index * 8..index * 8 + 8]
                    .try_into()
                    .expect("exception frame word"),
            )
        };
        let error_code = word(0);
        let code_segment = word(2);
        let stack_segment = word(5);
        if ![4, 6, 20].contains(&error_code)
            || code_segment != u64::from(crate::signal::USER_CODE_SELECTOR)
            || ![
                u64::from(crate::signal::USER_DATA_SELECTOR),
                u64::from(crate::signal::USER_DATA_SELECTOR & !3),
            ]
            .contains(&stack_segment)
        {
            return Ok(None);
        }
        let mut registers = halted_registers;
        registers.rip = word(1);
        registers.rflags = word(3);
        registers.rsp = word(4);
        let mut transport = [0; FRAME_SIZE];
        self.memory
            .read_raw(self.syscall_frame_address, &mut transport)?;
        Ok(Some(PageZeroFault {
            registers,
            event: executor.page_zero_fault_event(address),
            code_segment: code_segment as u16,
            stack_segment: stack_segment as u16,
            error_code,
            address,
            halted_registers,
            special_registers,
            xsave: Arc::new(self.vcpu.get_xsave()?),
            transport,
            transport_address: self.syscall_frame_address,
        }))
    }

    // TODO-HUMAN-REVIEW(PR-202): Review the narrowly matched VMware backdoor probe emulation.
    pub(crate) fn try_resume_vmware_backdoor_probe(&mut self) -> Result<bool> {
        let Some(exception) = self.static_elf_exception()? else {
            return Ok(false);
        };
        if exception.vector != 13 {
            return Ok(false);
        }

        let registers = self.vcpu.get_regs()?;
        let mut instruction = [0];
        if self
            .memory
            .read_raw(exception.instruction_pointer, &mut instruction)
            .is_err()
            || instruction != [0xed]
            || registers.rbx & u64::from(u32::MAX) != VMWARE_BACKDOOR_MAGIC
            || registers.rcx & u64::from(u32::MAX) != VMWARE_BACKDOOR_PORT
        {
            return Ok(false);
        }

        let mut registers = registers;
        registers.rbx = 0;
        registers.rip = exception.instruction_pointer + 1;
        registers.rsp = exception.stack_pointer;
        registers.rflags = exception.rflags;
        configure_user_segments(&self.vcpu)?;
        self.vcpu.set_regs(&registers)?;
        Ok(true)
    }

    pub(crate) fn static_elf_halt_error(&self) -> Result<Error> {
        if let Some(exception) = self.static_elf_exception()? {
            return Ok(Error::GuestException {
                vector: exception.vector,
                instruction_pointer: exception.instruction_pointer,
                fault_address: self.vcpu.get_sregs()?.cr2,
            });
        }

        Ok(Error::UnexpectedVcpuExit(
            "static ELF halted without exiting".to_string(),
        ))
    }

    pub(crate) fn deliver_pending_signal_at_syscall_boundary(
        &mut self,
        executor: &mut ElfExecutor,
        syscall_frame_address: u64,
        result: i64,
    ) -> Result<bool> {
        let interrupted = process_syscall_return_registers(
            &self.memory,
            self.vcpu.get_regs()?,
            syscall_frame_address,
            result,
            None,
        )?;
        self.deliver_pending_signal_from_registers(executor, syscall_frame_address, interrupted)
    }

    pub(crate) fn deliver_pending_signal_from_registers(
        &mut self,
        executor: &mut ElfExecutor,
        syscall_frame_address: u64,
        interrupted: kvm_bindings::kvm_regs,
    ) -> Result<bool> {
        loop {
            let Some(pending) = executor
                .take_pending_signal_for_delivery()
                .map_err(|errno| Error::Reverie(errno.into()))?
            else {
                return Ok(false);
            };

            if executor.signal_disposition(pending.event.signal()) == SignalDisposition::Ignore {
                continue;
            }
            return self.deliver_selected_signal_from_registers(
                executor,
                syscall_frame_address,
                interrupted,
                pending,
            );
        }
    }

    pub(crate) fn deliver_selected_signal_from_registers(
        &mut self,
        executor: &mut ElfExecutor,
        syscall_frame_address: u64,
        interrupted: kvm_bindings::kvm_regs,
        pending: crate::executor::PendingSignal,
    ) -> Result<bool> {
        self.deliver_selected_signal_at_boundary(
            executor,
            syscall_frame_address,
            interrupted,
            pending,
            None,
            false,
        )
    }

    pub(crate) fn deliver_page_zero_fault(
        &mut self,
        executor: &mut ElfExecutor,
        fault: &PageZeroFault,
        pending: crate::executor::PendingSignal,
    ) -> Result<bool> {
        self.deliver_selected_signal_at_boundary(
            executor,
            self.syscall_frame_address,
            fault.registers,
            pending,
            Some(fault),
            false,
        )
    }

    /// A new clone vCPU has a complete user register file and has never entered
    /// KVM_RUN. Unlike a consumed VMCALL, its continuation can be changed
    /// directly. This is not an arbitrary running-vCPU interruption mechanism.
    pub(crate) fn deliver_selected_signal_before_thread_entry(
        &mut self,
        executor: &mut ElfExecutor,
        interrupted: kvm_regs,
        pending: crate::executor::PendingSignal,
    ) -> Result<bool> {
        if !self.is_guest_thread || self.vcpu.get_sregs()?.cs.dpl != 3 {
            return Err(Error::UnexpectedVcpuExit(
                "thread-entry signal requires an unstarted clone user continuation".to_owned(),
            ));
        }
        self.deliver_selected_signal_at_boundary(
            executor,
            self.syscall_frame_address,
            interrupted,
            pending,
            None,
            true,
        )
    }

    fn deliver_selected_signal_at_boundary(
        &mut self,
        executor: &mut ElfExecutor,
        syscall_frame_address: u64,
        interrupted: kvm_regs,
        pending: crate::executor::PendingSignal,
        fault: Option<&PageZeroFault>,
        thread_entry: bool,
    ) -> Result<bool> {
        let signal = pending.event.signal();
        match executor.signal_disposition(signal) {
            SignalDisposition::Ignore => return Ok(false),
            SignalDisposition::Terminate => {
                executor.force_signal_exit(signal);
                return Ok(false);
            }
            SignalDisposition::Stop => {
                return Err(Error::UnexpectedVcpuExit(format!(
                    "stopped-state delivery for signal {signal} is unsupported"
                )));
            }
            SignalDisposition::Handled => {}
        }

        let action = executor.signal_action(signal);
        if action.flags & SA_RESTORER == 0 || action.handler == 0 || action.handler >= (1_u64 << 47)
        {
            executor.force_signal_exit(libc::SIGSEGV);
            return Ok(false);
        }
        let altstack = executor.signal_altstack(interrupted.rsp);
        let (stack_top, lower_bound, reserve_red_zone, autodisarm) =
            match executor.signal_stack_top(action, interrupted.rsp) {
                Ok(stack) => stack,
                Err(_) => {
                    executor.force_signal_exit(libc::SIGSEGV);
                    return Ok(false);
                }
            };
        let layout = match SignalFrameLayout::below(stack_top, reserve_red_zone) {
            Ok(layout) => layout,
            Err(_) => {
                executor.force_signal_exit(libc::SIGSEGV);
                return Ok(false);
            }
        };
        if lower_bound.is_some_and(|lower_bound| !layout.fits_above(lower_bound)) {
            executor.force_signal_exit(libc::SIGSEGV);
            return Ok(false);
        }
        let xsave = if let Some(fault) = fault {
            XsaveImage::from_kvm(&fault.xsave)
        } else {
            XsaveImage::from_kvm(&self.vcpu.get_xsave()?)
        };
        let mut mcontext =
            Sigcontext::from_kvm(interrupted, layout.xsave_address, executor.signal_mask());
        if let Some(fault) = fault {
            mcontext.cs = fault.code_segment;
            mcontext.ss = fault.stack_segment;
            mcontext.err = fault.error_code;
            mcontext.trapno = 14;
            mcontext.cr2 = fault.address;
        }
        let frame = RtSigframe {
            pretcode: action.restorer,
            ucontext: Ucontext {
                flags: SIGNAL_UCONTEXT_FLAGS,
                link: 0,
                stack: altstack,
                mcontext,
                sigmask: executor.signal_mask(),
            },
            siginfo: pending.event.siginfo(),
        };
        if self
            .memory
            .user()
            .copy_to_user(layout.frame_address, &frame.encode())
            .is_err()
            || self
                .memory
                .user()
                .copy_to_user(layout.xsave_address, xsave.bytes())
                .is_err()
        {
            executor.force_signal_exit(libc::SIGSEGV);
            return Ok(false);
        }

        let mut handler = interrupted;
        handler.rax = 0;
        handler.rdi = signal as u64;
        handler.rsi = layout.frame_address + 312;
        handler.rdx = layout.frame_address + 8;
        handler.rip = action.handler;
        handler.rsp = layout.frame_address;
        handler.rflags &= !((1 << 8) | (1 << 10) | (1 << 16));
        if let Some(fault) = fault {
            fault.resume_user(self, handler)?;
        } else if thread_entry {
            self.vcpu.set_regs(&handler)?;
        } else {
            stage_process_syscall_return(
                &mut self.memory,
                &self.vcpu,
                syscall_frame_address,
                handler,
            )?;
        }
        executor.enter_signal_handler(pending, action, autodisarm);
        Ok(true)
    }

    pub(crate) fn discard_process_clear_tid_at_signal_return(&self, executor: &mut ElfExecutor) {
        if !self.is_guest_thread {
            let _ = executor.take_clear_child_tid();
        }
    }

    /// Clears a CLONE_THREAD worker's CLONE_CHILD_CLEARTID word before the
    /// worker's non-group terminal signal-boundary receipt is published.
    ///
    /// Linux clears and wakes this word in `mm_release`, called from `exit_mm`,
    /// before `exit_notify` makes the task's death observable. A receipt is
    /// how a Tool observes that death; Detcore, for example, retires the task
    /// and wakes a `pthread_join` waiter from it. If the clear waited for
    /// `finish_tool_process`, the woken joiner would read the stale TID and
    /// retry `FUTEX_WAIT` a host-timing-dependent number of times.
    ///
    /// The clear consumes the registered address, so the later call in
    /// `finish_tool_process` does nothing. A process leader keeps its existing
    /// discard-or-clear policy at the signal-return and finish sites.
    pub(crate) fn clear_worker_tid_before_terminal_receipt(&mut self, executor: &mut ElfExecutor) {
        if self.is_guest_thread {
            self.clear_registered_worker_tid_before_exit(executor);
        }
    }

    pub(crate) fn clear_registered_worker_tid_before_exit(&mut self, executor: &mut ElfExecutor) {
        #[cfg(test)]
        clear_tid_diagnostic::begin();
        self.release_thread_slot();
        let Some(address) = executor.take_clear_child_tid() else {
            #[cfg(test)]
            clear_tid_diagnostic::stopped("no registered address");
            return;
        };
        debug_assert!(self.thread_slot.is_none());
        // Errors below are dropped on purpose. A bad guest address is Linux's
        // EFAULT: mm_release ignores the failed store ("if userspace has not
        // set up a proper pointer then tough luck") and the exit proceeds with
        // no errno to report. Its FUTEX_WAKE on an unmapped word also fails
        // with EFAULT, so skipping the host wake for an inaccessible or
        // untranslatable word has the same effect. The other error source is
        // a backend failure already recorded on the entry gate. Reading it
        // here does not consume it: it stays pending on the gate, and
        // route_entry_outcome folds it into the exiting thread's outcome.
        let _ = self.memory.user().put_user_i32(address, 0);
        if self.memory.user().user_accessible_prefix(address, 4).ok() != Some(4) {
            #[cfg(test)]
            clear_tid_diagnostic::stopped("accessible prefix was not four bytes");
            return;
        }
        let Ok(operand) = self.memory.user().retain_translated_range(address, 4) else {
            #[cfg(test)]
            clear_tid_diagnostic::stopped("translation failed");
            return;
        };
        let _wake_result = unsafe {
            libc::syscall(
                libc::SYS_futex,
                operand.address(),
                libc::FUTEX_WAKE,
                1,
                0,
                0,
                0,
            )
        };
        #[cfg(test)]
        let wake_errno = if _wake_result == -1 {
            // Read this thread's errno before any other operation can replace it.
            Some(unsafe { *libc::__errno_location() })
        } else {
            None
        };
        #[cfg(test)]
        clear_tid_diagnostic::woke(operand.address(), _wake_result, wake_errno);
    }

    pub(crate) fn restore_rt_sigreturn(
        &mut self,
        executor: &mut ElfExecutor,
        syscall_frame_address: u64,
    ) -> Result<Option<kvm_bindings::kvm_regs>> {
        let current = process_syscall_return_registers(
            &self.memory,
            self.vcpu.get_regs()?,
            syscall_frame_address,
            0,
            None,
        )?;
        let Some(frame_address) = current.rsp.checked_sub(8) else {
            executor.force_signal_exit(libc::SIGSEGV);
            return Ok(None);
        };
        let mut frame_bytes = [0; RT_SIGFRAME_SIZE];
        if self
            .memory
            .user()
            .read(frame_address, &mut frame_bytes[..RT_SIGRETURN_SIZE])
            .is_err()
        {
            executor.force_signal_exit(libc::SIGSEGV);
            return Ok(None);
        }
        let frame = RtSigframe::decode(frame_bytes);
        if frame.ucontext.mcontext.validate_for_restore().is_err() {
            executor.force_signal_exit(libc::SIGSEGV);
            return Ok(None);
        }
        let fpstate = frame.ucontext.mcontext.fpstate;
        let xsave = if fpstate == 0 {
            XsaveImage::initialized_kvm()
        } else {
            let mut prefix = [0; LEGACY_FPSTATE_SIZE];
            if self.memory.user().read(fpstate, &mut prefix).is_err() {
                executor.force_signal_exit(libc::SIGSEGV);
                return Ok(None);
            }
            let size = match XsaveImage::restore_size(&prefix) {
                Ok(size) => size,
                Err(_) => {
                    executor.force_signal_exit(libc::SIGSEGV);
                    return Ok(None);
                }
            };
            let required_alignment = if size == LEGACY_FPSTATE_SIZE {
                16
            } else {
                crate::signal::XSAVE_ALIGNMENT
            };
            if !fpstate.is_multiple_of(required_alignment) {
                executor.force_signal_exit(libc::SIGSEGV);
                return Ok(None);
            }
            let mut bytes = vec![0; size];
            bytes[..LEGACY_FPSTATE_SIZE].copy_from_slice(&prefix);
            if size > LEGACY_FPSTATE_SIZE
                && self
                    .memory
                    .user()
                    .read(
                        fpstate + LEGACY_FPSTATE_SIZE as u64,
                        &mut bytes[LEGACY_FPSTATE_SIZE..],
                    )
                    .is_err()
            {
                executor.force_signal_exit(libc::SIGSEGV);
                return Ok(None);
            }
            match XsaveImage::restore_from_signal(&bytes) {
                Ok(xsave) => xsave,
                Err(_) => {
                    executor.force_signal_exit(libc::SIGSEGV);
                    return Ok(None);
                }
            }
        };
        executor.restore_signal_thread_state(
            frame.ucontext.sigmask,
            frame.ucontext.stack,
            current.rsp,
        );
        let mut restored = current;
        frame.ucontext.mcontext.restore_kvm(&mut restored);
        // SAFETY: the fixed KVM CPUID policy exposes exactly the feature subset
        // accepted by XsaveImage::restore_from_signal above.
        unsafe { self.vcpu.set_xsave(&xsave)? };
        Ok(Some(restored))
    }

    /// Runs the installed static ELF and its forked children until the root exits.
    pub fn run_static_elf(&mut self) -> Result<i32> {
        // Any return finishes the run; only an unwinding run leaves its
        // backend abandoned.
        let admission = RunAdmission::begin(&self.abandoned_runs)?;
        let status = self.run_admitted_static_elf();
        self.finish_run(admission);
        status
    }

    fn run_admitted_static_elf(&mut self) -> Result<i32> {
        let loaded = self.static_elf.take().ok_or(Error::StaticElfNotInstalled)?;
        let mut executor = ElfExecutor::with_output(loaded, None);
        let result = self.run_static_elf_process(&mut executor);
        let (status, _, _) = result.map_err(|error| self.finish_direct_process_error(error))?;
        Ok(conventional_exit_code(status))
    }

    /// Runs the installed ELF process tree and captures its standard output streams.
    pub fn run_static_elf_captured(&mut self) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let admission = RunAdmission::begin(&self.abandoned_runs)?;
        let captured = self.run_admitted_static_elf_captured();
        self.finish_run(admission);
        captured
    }

    fn run_admitted_static_elf_captured(&mut self) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        // Declared before the executor so its private pipe identities outlive
        // executor/child cleanup, including early-return and unwind paths.
        let capture_owner = self.prepare_captured_output(true)?;
        let loaded = self.static_elf.take().ok_or(Error::StaticElfNotInstalled)?;
        let mut executor = ElfExecutor::with_output(loaded, capture_owner.clone());
        let result = self.run_static_elf_process(&mut executor);
        let (status, stdout, stderr) =
            result.map_err(|error| self.finish_direct_process_error(error))?;
        Ok((conventional_exit_code(status), stdout, stderr))
    }

    /// The Direct driver has returned its error and released its callback
    /// borrows. Cancel before any physical worker join, then attach retained
    /// reader/worker diagnostics while the concrete executor still exists.
    /// Healthy runs keep their existing natural/group-exit retirement paths.
    fn finish_direct_process_error(&self, error: Error) -> Error {
        self.cancel_guest_threads_after_failure();
        error.with_cleanup(
            self.guest_worker_teardown_result()
                .err()
                .into_iter()
                .collect(),
        )
    }

    pub(crate) fn prepare_captured_output(
        &self,
        capture_output: bool,
    ) -> Result<Option<CapturedOutput>> {
        self.static_elf
            .as_ref()
            .ok_or(Error::StaticElfNotInstalled)?;
        capture_output
            .then(CapturedOutput::try_new)
            .transpose()
            .map_err(Into::into)
    }

    fn run_static_elf_process(
        &mut self,
        executor: &mut ElfExecutor,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        let mut driver = std::pin::pin!(self.run_static_elf_process_inner(executor));
        // Preserve synchronous runs that complete without parking, including
        // callers already inside a LocalPool. Poll only a borrowed pin: Pending
        // must leave the same driver alive for block_on to install its waker.
        // Inline fork descendants await this driver instead of entering a pool.
        if let Some(result) = driver.as_mut().now_or_never() {
            return result;
        }
        futures::executor::block_on(driver)
    }

    async fn run_static_elf_process_inner(
        &mut self,
        executor: &mut ElfExecutor,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        // This loop never dispatches Tool events, including Host-owned workers.
        self.set_rdtsc_interception(false)?;
        self.set_cpuid_interception(false)?;
        let registration = self.register_guest_thread()?;
        if self.is_guest_thread {
            let entry_registers = self.vcpu.get_regs()?;
            while let Some(pending) = executor
                .take_pending_signal_for_delivery()
                .map_err(|errno| Error::Reverie(errno.into()))?
            {
                if self.deliver_selected_signal_before_thread_entry(
                    executor,
                    entry_registers,
                    pending,
                )? || executor.has_pending_exit()
                {
                    break;
                }
            }
            if let Some(exit) = executor.take_exit() {
                return self.finish_static_elf_thread(executor, exit);
            }
        }
        loop {
            #[cfg(test)]
            crate::runtime::entry_wait_observation::observe(
                crate::runtime::entry_wait_observation::Site::HostMain,
                crate::runtime::entry_wait_observation::Boundary::BeforeSubscription,
            );
            let changed = self.memory.entry_gate().subscribe();
            let cancelled = self.entry_cancellation();
            #[cfg(test)]
            crate::runtime::entry_wait_observation::observe(
                crate::runtime::entry_wait_observation::Site::HostMain,
                crate::runtime::entry_wait_observation::Boundary::AfterSubscription,
            );
            self.memory
                .entry_gate()
                .admit_operation()
                .map_err(|failure| failure.error())?;
            if let Some(status) = self.guest_thread_group_exit_status() {
                return self.finish_static_elf_thread(
                    executor,
                    ProcessExit {
                        status,
                        group: true,
                    },
                );
            }
            if self.is_guest_thread && self.thread_group.cancelled.load(Ordering::Acquire) {
                return self.finish_static_elf_thread(
                    executor,
                    ProcessExit {
                        status: ExitStatus::SUCCESS,
                        group: false,
                    },
                );
            }
            let vcpu_exit = match self.vcpu.run() {
                Ok(Some(exit)) => exit,
                Ok(None) => {
                    futures::future::select(changed, cancelled).await;
                    continue;
                }
                Err(Error::Kvm(error)) if error.errno() == libc::EINTR => continue,
                Err(error) => return Err(error),
            };
            Self::record_exit(self.exit_collector.as_deref(), &vcpu_exit);
            let (segment_update, process_action, mut signal_boundary) = match vcpu_exit {
                VcpuExit::Hypercall(exit) => {
                    if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                        return Err(Error::UnexpectedHypercall(exit.nr));
                    }
                    let frame_address = exit.args[0];
                    if frame_address != self.syscall_frame_address {
                        return Err(Error::UnexpectedVcpuExit(format!(
                            "syscall frame is at unexpected address {frame_address:#x}",
                        )));
                    }
                    let return_slot = std::ptr::from_mut(exit.ret) as usize;
                    let request = SyscallRequest::read_from(&self.memory, frame_address)?;
                    // SAFETY: return_slot points into this stopped vCPU's stable KVM_RUN mapping.
                    unsafe {
                        (return_slot as *mut u64).write(0);
                    }
                    if request.number() == libc::SYS_rt_sigreturn as u64 {
                        if let Some(restored) =
                            self.restore_rt_sigreturn(executor, frame_address)?
                        {
                            let delivered = self.deliver_pending_signal_from_registers(
                                executor,
                                frame_address,
                                restored,
                            )?;
                            if !delivered {
                                stage_process_syscall_return(
                                    &mut self.memory,
                                    &self.vcpu,
                                    frame_address,
                                    restored,
                                )?;
                            }
                        }
                        if executor.has_pending_exit() {
                            self.discard_process_clear_tid_at_signal_return(executor);
                            self.clear_registered_worker_tid_before_exit(executor);
                        }
                        (None, None, None)
                    } else {
                        let userspace = process_syscall_return_registers(
                            &self.memory,
                            self.vcpu.get_regs()?,
                            frame_address,
                            0,
                            None,
                        )?;
                        executor.set_current_user_stack_pointer(userspace.rsp);
                        let result =
                            match self.execute_static_elf_syscall(executor, &request, &self.memory)
                            {
                                Ok(result) => result,
                                Err(Error::ChildWaitGroupExit { status }) => {
                                    let exit = executor.retire_child_wait_group_exit(status)?;
                                    return self.finish_static_elf_thread(executor, exit);
                                }
                                Err(Error::TerminalReadCancelled) => {
                                    let exit = match self.guest_thread_group_exit_status() {
                                        Some(status) => {
                                            executor.retire_current_thread(status, true)
                                        }
                                        None => executor.cancel_current_thread(),
                                    };
                                    return self.finish_static_elf_thread(executor, exit);
                                }
                                Err(error) => return Err(error),
                            };
                        SyscallRequest::write_result(&mut self.memory, frame_address, result)?;
                        (
                            executor.take_segment(),
                            executor.take_process_action(),
                            Some((frame_address, result)),
                        )
                    }
                }
                VcpuExit::Hlt => {
                    if self.try_resume_vmware_backdoor_probe()? {
                        continue;
                    }
                    let Some(fault) = self.capture_page_zero_fault(executor)? else {
                        return Err(self.static_elf_halt_error()?);
                    };
                    executor.prepare_captured_page_zero_fault();
                    self.deliver_page_zero_fault(executor, &fault, fault.pending())?;
                    if executor.has_pending_exit() {
                        self.discard_process_clear_tid_at_signal_return(executor);
                        self.clear_registered_worker_tid_before_exit(executor);
                    }
                    (None, None, None)
                }
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            };

            if let Some((segment, address)) = segment_update {
                set_user_segment_base(&self.vcpu, segment, address)?;
            }

            let mut returns_to_original_image = process_action
                .as_ref()
                .is_none_or(ProcessAction::returns_to_original_image);
            if !returns_to_original_image && executor.has_eligible_pending_signal() {
                return Err(Error::UnexpectedVcpuExit(
                    "KVM exec with an eligible deferred signal is unsupported; \
                     delivery requires a syscall return frame"
                        .to_owned(),
                ));
            }
            let continuation = process_action
                .as_ref()
                .map(|action| {
                    let (frame_address, _) = signal_boundary
                        .expect("a process action can only originate at a syscall boundary");
                    CompletedSyscallBoundary::capture_for_action(self, frame_address, None, action)
                })
                .transpose()?;
            if let Some(action) = process_action {
                let outcome = self
                    .run_process_action_at_boundary(
                        executor,
                        action,
                        continuation.expect("a process action has a continuation policy"),
                        &registration,
                    )
                    .await?;
                if outcome.cancelled {
                    let exit = match self.guest_thread_group_exit_status() {
                        Some(status) => ProcessExit {
                            status,
                            group: true,
                        },
                        None => ProcessExit {
                            status: ExitStatus::SUCCESS,
                            group: false,
                        },
                    };
                    return self.finish_static_elf_thread(executor, exit);
                }
                returns_to_original_image = !outcome.image_replaced;
                if let Some((_, result)) = signal_boundary.as_mut() {
                    *result = outcome.syscall_result;
                }
            }

            // exit/exit_group never return to userspace, so pending delivery
            // cannot replace an exit already selected by the syscall.
            let mut pending_exit = executor.take_exit();
            if returns_to_original_image
                && pending_exit.is_none()
                && let Some((frame_address, result)) = signal_boundary
            {
                self.deliver_pending_signal_at_syscall_boundary(executor, frame_address, result)?;
            }

            pending_exit = pending_exit.or_else(|| executor.take_exit());
            if let Some(exit) = pending_exit {
                return self.finish_static_elf_thread(executor, exit);
            }
        }
    }

    fn finish_static_elf_thread(
        &mut self,
        executor: &mut ElfExecutor,
        exit: ProcessExit,
    ) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
        executor.retire_current_thread(exit.status, exit.group);
        self.clear_registered_worker_tid_before_exit(executor);
        executor.release_files_on_exit();
        self.release_stdin_on_exit();
        if exit.group {
            self.request_guest_thread_group_exit(exit.status);
        }
        // Best-effort writes and Errno adapters can conceal a captured cause.
        // An inline child must hand that cause back to its enclosing callback
        // before cancellation or a physical join can depend on destruction.
        self.check_entry_owner()?;
        let status = if self.is_guest_thread {
            exit.status
        } else {
            if exit.group {
                self.cancel_guest_threads();
            } else {
                self.join_guest_threads();
            }
            self.guest_worker_teardown_result()?;
            executor.process_exit_status().ok_or_else(|| {
                Error::UnexpectedVcpuExit(
                    "KVM process has no final task exit status after joining workers".to_owned(),
                )
            })?
        };
        let (stdout, stderr) = executor.take_output();
        Ok((status, stdout, stderr))
    }

    pub(crate) fn register_guest_thread(&self) -> Result<GuestThreadRegistration> {
        GuestThreadRegistration::register(self.thread_group.clone(), !self.is_guest_thread)
    }

    /// Drop this backend's reserved input description at terminal ownership
    /// cleanup. Fork and thread backends retain their independent references.
    pub(crate) fn release_stdin_on_exit(&mut self) {
        self.stdin = None;
    }

    pub(crate) fn tool_panic_owner(&self) -> Arc<crate::failure::tool_panics::ToolPanics> {
        self.tool_panics.clone()
    }

    pub(crate) fn is_tool_guest_worker(&self) -> bool {
        self.is_guest_thread && self.thread_ownership.executes_on_tool()
    }

    fn finish_worker_configuration<R, C>(&self, result: Result<R>, config: C) -> Result<R> {
        let cleanup = self
            .tool_panics
            .drop_value(config, "Tool worker configuration destruction");
        match (result, cleanup) {
            (result, Ok(())) => result,
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(cleanup)) => Err(error.with_cleanup(vec![cleanup])),
        }
    }

    pub(crate) fn finish_public_tool_panic<R>(
        &self,
        result: Result<R>,
        retained_failure: Option<Arc<crate::failure::RunFailure>>,
    ) -> Result<R> {
        let mut payloads = self.tool_panics.take().into_iter();
        let Some(original) = payloads.next() else {
            return result;
        };
        let error = result.err().unwrap_or(Error::GuestWorkerPanic);
        self.completed_tool_panics
            .lock()
            .expect("KVM completed Tool panic lock poisoned")
            .push(CompletedToolPanic {
                _error: Arc::new(error),
                _secondary_payloads: payloads.collect(),
                _run_failure: retained_failure,
            });
        std::panic::resume_unwind(original)
    }

    fn finish_deferred_worker_panic<R>(&self, tid: i32, result: Result<R>) -> Result<R> {
        let mut payloads = self.tool_panics.take().into_iter();
        let Some(original) = payloads.next() else {
            return result;
        };
        let record = WorkerPanicRecord {
            error: Arc::new(result.err().unwrap_or(Error::GuestWorkerPanic)),
            _cleanup_panics: payloads.collect(),
            _join_payload: None,
        };
        let previous = self
            .thread_group
            .reported_worker_panics
            .lock()
            .expect("KVM reported worker panic lock poisoned")
            .insert(tid, record);
        assert!(
            previous.is_none(),
            "KVM worker panic recorded twice for tid {tid}"
        );
        // A configuration or entry-cleanup panic can arise after the normal
        // worker failure check. Wake a natural join before resuming it, so an
        // earlier live sibling cannot hide this completed failure.
        self.thread_group.record_worker_failure(tid);
        std::panic::resume_unwind(original)
    }

    fn finish_deferred_process_panic<R>(
        &self,
        result: Result<R>,
        panic_owner: Option<&crate::executor::ChildProcessPanicOwner>,
    ) -> Result<R> {
        let mut payloads = self.tool_panics.take().into_iter();
        let Some(original) = payloads.next() else {
            return result;
        };
        let error = Arc::new(result.err().unwrap_or(Error::GuestWorkerPanic));
        if let Some(owner) = panic_owner {
            owner.record(error.clone());
        }
        self.tool_failure
            .as_ref()
            .expect("Tool process panic lost its failure owner")
            .run
            .retain_panic_cleanup(Error::SharedFailure(error), payloads.collect());
        std::panic::resume_unwind(original)
    }

    pub(crate) fn guest_thread_group_exit_status(&self) -> Option<ExitStatus> {
        self.thread_group.exit_status()
    }

    pub(crate) fn request_guest_thread_group_exit(&self, status: ExitStatus) {
        self.thread_group.request_exit_group(status);
    }

    // TODO-HUMAN-REVIEW(PR-172): Review signal-driven KVM worker cancellation.
    pub(crate) fn cancel_guest_threads(&self) {
        self.thread_group.cancel_workers();
        if !self.is_guest_thread {
            self.thread_group.join_workers();
        }
    }

    async fn cancel_guest_threads_for_exec(
        &self,
        mut stop: Pin<&mut (dyn Future<Output = ()> + Send + '_)>,
    ) -> Result<()> {
        self.thread_group.cancel_workers();
        let watch = self.entry_driver_watch();
        watch.check()?;
        // Preserve the existing worker-Exec rejection in exec_process; a
        // guest-thread backend never becomes a physical join owner here.
        if self.is_guest_thread {
            return Ok(());
        }
        loop {
            // Subscribe before each registry/entry recheck. Private failure
            // wakes can interrupt without first publishing through the Tool.
            let mut changed = Box::pin(self.thread_group.subscribe_worker_completion());
            let mut interrupted = Box::pin(watch.wait());
            let complete = std::future::poll_fn(|cx| {
                if let Err(error) = watch.check() {
                    return std::task::Poll::Ready(Err(error));
                }
                if stop.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(Err(watch
                        .check()
                        .err()
                        .unwrap_or(Error::RunAborted)));
                }
                let (empty, returning) = match self.thread_group.advance_worker_joins_for_exec() {
                    Ok(state) => state,
                    Err(error) => return std::task::Poll::Ready(Err(error)),
                };
                if let Err(error) = watch.check() {
                    return std::task::Poll::Ready(Err(error));
                }
                if stop.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(Err(watch
                        .check()
                        .err()
                        .unwrap_or(Error::RunAborted)));
                }
                if empty {
                    return std::task::Poll::Ready(Ok(true));
                }
                if changed.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(Ok(false));
                }
                if interrupted.as_mut().poll(cx).is_ready() {
                    let Err(error) = watch.check() else {
                        panic!("private entry interruption lost its captured cause");
                    };
                    return std::task::Poll::Ready(Err(error));
                }
                if returning {
                    // A real completion notice can precede is_finished by
                    // host bookkeeping. One cooperative recheck per poll
                    // preserves entry/stop interruption through that interval.
                    cx.waker().wake_by_ref();
                }
                std::task::Poll::Pending
            })
            .await?;
            if complete {
                return Ok(());
            }
        }
    }

    pub(crate) fn cancel_guest_threads_after_failure(&self) {
        self.thread_group
            .cancelled_after_failure
            .store(true, Ordering::Release);
        self.cancel_guest_threads();
    }

    #[cfg(test)]
    fn finish_panicked_guest_worker(
        &mut self,
        executor: &mut ElfExecutor,
        tid: i32,
        payload: Box<dyn std::any::Any + Send>,
    ) -> ! {
        self.finish_panicked_guest_worker_with_entry(executor, tid, payload, None, |_| Ok(()))
    }

    fn finish_panicked_guest_worker_with_entry(
        &mut self,
        executor: &mut ElfExecutor,
        tid: i32,
        payload: Box<dyn std::any::Any + Send>,
        driver: Option<crate::entry::owner::DriverScope>,
        drop_owner: impl FnOnce(&crate::failure::tool_panics::ToolPanics) -> Result<()>,
    ) -> ! {
        // The callback and its borrowed Tool references have already unwound.
        // Keep the original JoinHandle panic while releasing this worker's
        // resources and transferring independent forks to the process owner.
        let failure = self.tool_failure.clone();
        let group = self.thread_group.clone();
        self.restore_entry_origin();
        executor.bind_address_space(&self.memory);
        // A previous callback/consumer panic may already be deferred. Keep it
        // ahead of this unexpected outer unwind and all cleanup that follows.
        self.tool_panics.append(vec![payload]);
        // The parent's consuming Tool state has unwound; separately retained
        // child consumers still exist. Transfer this exact executor's ledger,
        // retaining the panic as the primary cause.
        let error = executor.with_signal_effects(Error::GuestWorkerPanic, None);
        let error = futures::executor::block_on(self.route_entry_outcome::<()>(Err(error)))
            .expect_err("caught worker panic must remain a failure");
        let error = publish_caught_worker_panic(failure.as_ref(), tid, error);
        // Configuration belongs to the worker closure, outside the interrupted
        // callback. Its destructor runs after the original payload is retained
        // and published, under a separate catch rather than during resumption.
        let owner_cleanup = drop_owner(&self.tool_panics);
        // The previous executor has already unwound out of block_on. Each
        // retained child now gets its own polling and destruction catch, while
        // the remaining children stay owned outside that catch.
        let cleanup = futures::executor::block_on(
            crate::runtime::finish_unstarted_tool_cleanups_with_panics(executor, &self.tool_panics),
        );
        executor.retire_failed_thread();
        self.clear_registered_worker_tid_before_exit(executor);
        executor.release_files_on_exit();
        self.release_stdin_on_exit();
        executor.transfer_child_processes_to_owner();
        let result = futures::executor::block_on(
            self.route_entry_outcome::<()>(Err(error.with_cleanup(
                [owner_cleanup, cleanup]
                    .into_iter()
                    .filter_map(Result::err)
                    .collect(),
            ))),
        );
        let result = match driver {
            Some(driver) => self.finish_entry_driver(driver, result),
            None => result,
        };
        let error = result
            .map_err(|error| self.report_tool_failure("worker panic retirement", error))
            .expect_err("caught worker panic retirement must remain a failure");
        let mut payloads = self.tool_panics.take().into_iter();
        let original = payloads
            .next()
            .expect("caught worker lost its original panic");
        let record = WorkerPanicRecord {
            error: Arc::new(error),
            _cleanup_panics: payloads.collect(),
            _join_payload: None,
        };
        resume_worker_panic_record(&group, tid, record, original, || {})
    }

    /// An unexpected fork-owner unwind has already destroyed the interrupted
    /// Tool state. Consume only separately retained children, and preserve the
    /// original payload for the normal process-owner propagation below.
    fn finish_panicked_tool_process_owner(
        &mut self,
        executor: &mut ElfExecutor,
        payload: crate::failure::owned_future::PanicPayload,
    ) -> Result<()> {
        self.tool_panics.append(vec![payload]);
        self.restore_entry_origin();
        executor.bind_address_space(&self.memory);
        let error = executor.with_signal_effects(Error::GuestWorkerPanic, None);
        let error = futures::executor::block_on(self.route_entry_outcome::<()>(Err(error)))
            .expect_err("caught fork panic must remain a failure");
        let error = self.report_tool_failure("fork owner panic", error);
        let cleanup = futures::executor::block_on(
            crate::runtime::finish_unstarted_tool_cleanups_with_panics(executor, &self.tool_panics),
        );
        executor.retire_failed_thread();
        self.clear_registered_worker_tid_before_exit(executor);
        executor.release_files_on_exit();
        self.release_stdin_on_exit();
        let error = futures::executor::block_on(self.route_entry_outcome::<()>(Err(
            error.with_cleanup(cleanup.err().into_iter().collect()),
        )))
        .map_err(|error| self.report_tool_failure("fork panic retirement", error))
        .expect_err("caught fork panic retirement must remain a failure");
        // The publication above releases dependent peers before either join.
        self.cancel_guest_threads_after_failure();
        let workers = self.guest_worker_teardown_result();
        let children = executor.join_child_processes_after_failure();
        Err(error.with_cleanup(
            [workers, children]
                .into_iter()
                .filter_map(Result::err)
                .collect(),
        ))
    }

    pub(crate) fn record_guest_worker_failure(&self, tid: i32) {
        self.thread_group.record_worker_failure(tid);
    }

    pub(crate) fn join_guest_threads(&self) {
        if !self.is_guest_thread {
            self.thread_group.begin_natural_join();
            self.thread_group.join_workers();
        }
    }

    pub(crate) fn guest_worker_teardown_result(&self) -> Result<()> {
        if self.is_guest_thread {
            Ok(())
        } else {
            self.thread_group.teardown_result()
        }
    }

    /// Installs one syscall frame and a `vmcall`/`vmmcall; hlt` guest program.
    pub fn install_syscall(
        &mut self,
        entry_point: u64,
        frame_address: u64,
        request: SyscallRequest,
    ) -> Result<()> {
        self.install_syscalls(entry_point, frame_address, &[request])
    }

    /// Installs a guest program that issues each syscall through a userspace hypercall.
    ///
    /// Frames occupy consecutive guest pages because KVM validates this transport
    /// using the `KVM_HC_MAP_GPA_RANGE` argument shape before exiting to userspace.
    pub fn install_syscalls(
        &mut self,
        entry_point: u64,
        frame_address: u64,
        requests: &[SyscallRequest],
    ) -> Result<()> {
        // Precedes the first frame write into memory a dropped run's guest
        // threads may still use.
        AbandonedRuns::admit(&self.abandoned_runs)?;
        if !frame_address.is_multiple_of(SYSCALL_FRAME_STRIDE) {
            return Err(Error::InvalidSyscallFrameAddress(frame_address));
        }

        let mut code = Vec::with_capacity(requests.len().saturating_mul(15).saturating_add(1));
        for (index, request) in requests.iter().copied().enumerate() {
            let address = SYSCALL_FRAME_STRIDE
                .checked_mul(index as u64)
                .and_then(|offset| frame_address.checked_add(offset))
                .ok_or(Error::InvalidSyscallFrameAddress(frame_address))?;
            let address =
                u32::try_from(address).map_err(|_| Error::InvalidSyscallFrameAddress(address))?;

            request.write_to(&mut self.memory, u64::from(address))?;

            // Real mode defaults to 16-bit operands. The 0x66 prefix loads the
            // complete 32-bit hypercall number and guest-physical frame address.
            code.extend_from_slice(&[0x66, 0xb8]);
            code.extend_from_slice(&(VMCALL_SYSCALL_TRANSPORT as u32).to_le_bytes());
            code.extend_from_slice(&[0x66, 0xbb]);
            code.extend_from_slice(&address.to_le_bytes());
            code.extend_from_slice(&self.hypercall_instruction);
        }
        code.push(HLT);
        // Writes the program and installs the real-mode segment/rip/rflags state.
        self.install_real_mode_program(entry_point, &code)?;

        let mut regs = self.vcpu.get_regs()?;
        // The guest program loads the transport number and frame address into
        // rax/rbx itself, so only the MAP_GPA_RANGE argument shape is set here:
        // KVM validates it before forwarding the enabled hypercall to userspace.
        regs.rcx = 1;
        regs.rdx = 0;
        self.vcpu.set_regs(&regs)?;
        Ok(())
    }

    /// Runs until the guest halts, invoking `handler` for each syscall vmcall.
    ///
    /// Actual KVM_RUN interruption remains an error on this raw interface.
    /// A private close against a running vCPU can also cause EINTR; this loop
    /// does not distinguish that kick from a foreign interrupt. A production
    /// closer must not use this driver without defining that distinction.
    pub fn run<F>(&mut self, handler: F) -> Result<()>
    where
        F: FnMut(Syscall, &GuestMemory) -> i64,
    {
        let admission = RunAdmission::begin(&self.abandoned_runs)?;
        let ran = self.run_admitted(handler);
        self.finish_run(admission);
        ran
    }

    fn run_admitted<F>(&mut self, mut handler: F) -> Result<()>
    where
        F: FnMut(Syscall, &GuestMemory) -> i64,
    {
        self.set_rdtsc_interception(false)?;
        self.set_cpuid_interception(false)?;
        loop {
            let changed = self.memory.entry_gate().subscribe();
            let Some(vcpu_exit) = self.vcpu.run()? else {
                let _ = futures::executor::block_on(changed);
                continue;
            };
            Self::record_exit(self.exit_collector.as_deref(), &vcpu_exit);
            match vcpu_exit {
                VcpuExit::Hypercall(exit) => {
                    if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                        return Err(Error::UnexpectedHypercall(exit.nr));
                    }
                    let syscall =
                        SyscallRequest::read_from(&self.memory, exit.args[0])?.into_syscall()?;
                    let result = handler(syscall, &self.memory);
                    self.memory
                        .entry_gate()
                        .admit_operation()
                        .map_err(|failure| failure.error())?;
                    *exit.ret = result as u64;
                }
                VcpuExit::Hlt => return Ok(()),
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            }
        }
    }

    /// Exposes the VM fd for future backend setup without transferring
    /// ownership. A dropped run's guest threads may still be running, each on
    /// its own VM sharing this one's memory, so after one this fails until
    /// the backend drops.
    pub fn vm_fd(&self) -> Result<&VmFd> {
        AbandonedRuns::admit(&self.abandoned_runs)?;
        Ok(&self.vm)
    }
}

impl BackendStatsSource for KvmBackend {
    type Snapshot = KvmBackendStats;

    /// Snapshots exits from the root and every inherited fork/thread collector.
    /// End-of-run callers observe a complete tree because the KVM run paths join
    /// process workers and guest threads before returning to the root caller.
    fn backend_stats(&self) -> Self::Snapshot {
        self.exit_collector
            .as_deref()
            .map_or_else(KvmBackendStats::default, KvmExitCollector::snapshot)
    }
}

impl Drop for KvmBackend {
    fn drop(&mut self) {
        self.release_thread_slot();
        if !self.is_guest_thread {
            self.thread_group.cancel_workers();
            // An abandoned run's reaper joins its workers. Every public run
            // owns an admission, so with none abandoned, each run returned
            // and joined its own workers, and this finds none to wait for.
            if !AbandonedRuns::retire(&self.abandoned_runs, &self.thread_group) {
                self.thread_group.join_workers();
            }
        }
    }
}

fn write_tid_best_effort(memory: &mut GuestMemory, address: Option<u64>, tid: i32) {
    if let Some(address) = address {
        #[cfg(test)]
        tests::entry_action_tests::observe("tid_store");
        // Linux creates the child even if a clone TID store faults.
        let _ = memory.user().write(address, &tid.to_le_bytes());
    }
}

#[cfg(test)]
mod clear_tid_diagnostic {
    // This opt-in record has no allocation, callback, lock, or syscall. The
    // test initializes it before enrollment and formats it after joining the
    // waiter. It observes the existing helper; it does not repair enrollment.
    #[derive(Clone, Copy)]
    pub(super) struct Wake {
        invocations: usize,
        stage: &'static str,
        address: Option<usize>,
        result: Option<libc::c_long>,
        errno: Option<i32>,
    }

    impl std::fmt::Debug for Wake {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("Wake")
                .field("invocations", &self.invocations)
                .field("stage", &self.stage)
                .field(
                    "address",
                    &self.address.map(|address| address as *const i32),
                )
                .field("result", &self.result)
                .field("errno", &self.errno)
                .finish()
        }
    }

    std::thread_local! {
        static WAKE: std::cell::Cell<Option<Wake>> = const { std::cell::Cell::new(None) };
    }

    pub(super) fn arm() {
        WAKE.set(Some(Wake {
            invocations: 0,
            stage: "not called",
            address: None,
            result: None,
            errno: None,
        }));
    }

    pub(super) fn begin() {
        if let Some(mut wake) = WAKE.get() {
            wake.invocations = wake.invocations.saturating_add(1);
            wake.stage = "entered, not completed";
            wake.address = None;
            wake.result = None;
            wake.errno = None;
            WAKE.set(Some(wake));
        }
    }

    pub(super) fn stopped(stage: &'static str) {
        if let Some(mut wake) = WAKE.get() {
            wake.stage = stage;
            WAKE.set(Some(wake));
        }
    }

    pub(super) fn woke(address: usize, result: libc::c_long, errno: Option<i32>) {
        if let Some(mut wake) = WAKE.get() {
            wake.stage = "wake returned";
            wake.address = Some(address);
            wake.result = Some(result);
            wake.errno = errno;
            WAKE.set(Some(wake));
        }
    }

    pub(super) fn take() -> Option<Wake> {
        WAKE.take()
    }
}

// TODO-HUMAN-REVIEW(PR-172): Review CHILD_CLEARTID store and shared futex wake ordering.
pub(crate) fn clear_tid_and_wake(memory: &mut GuestMemory, address: Option<u64>) {
    #[cfg(test)]
    clear_tid_diagnostic::begin();
    let Some(address) = address else {
        #[cfg(test)]
        clear_tid_diagnostic::stopped("no registered address");
        return;
    };
    // Linux treats a failed CHILD_CLEARTID store as best-effort and skips the
    // wake when the user address is invalid.
    if memory.user().write(address, &0_i32.to_le_bytes()).is_err() {
        #[cfg(test)]
        clear_tid_diagnostic::stopped("store failed");
        return;
    }
    let Ok(operand) = memory.user().retain_translated_range(address, 4) else {
        #[cfg(test)]
        clear_tid_diagnostic::stopped("translation failed");
        return;
    };
    // SAFETY: the successful write above validates the complete futex word,
    // and GuestMemory keeps its shared host mapping alive for this call.
    let _wake_result = unsafe {
        libc::syscall(
            libc::SYS_futex,
            operand.address(),
            1, // FUTEX_WAKE; the kernel's CHILD_CLEARTID wake is not private.
            1,
            0,
            0,
            0,
        )
    };
    #[cfg(test)]
    let wake_errno = if _wake_result == -1 {
        // Read this thread's errno before any other operation can replace it.
        Some(unsafe { *libc::__errno_location() })
    } else {
        None
    };
    #[cfg(test)]
    clear_tid_diagnostic::woke(operand.address(), _wake_result, wake_errno);
}

fn supported_hypercall_instruction(cpuid: &CpuId) -> Result<[u8; 3]> {
    let supports_vmcall = cpuid
        .as_slice()
        .iter()
        .find(|entry| entry.function == 1)
        .is_some_and(|entry| entry.ecx & (1 << 5) != 0);
    if supports_vmcall {
        return Ok(VMCALL);
    }

    let supports_vmmcall = cpuid
        .as_slice()
        .iter()
        .find(|entry| entry.function == 0x8000_0001)
        .is_some_and(|entry| entry.ecx & (1 << 2) != 0);
    if supports_vmmcall {
        return Ok(VMMCALL);
    }
    Err(Error::HypercallInstructionUnsupported)
}

#[cfg(test)]
#[path = "vm/worker_panic_tests.rs"]
mod worker_panic_tests;

#[cfg(test)]
pub(crate) use tests::minimal_test_elf;

#[cfg(test)]
mod tests {
    use super::*;

    include!("cpuid_runtime_tests.rs");
    include!("vm/entry_public_tests.rs");
    include!("vm/entry_main_tests.rs");
    include!("vm/entry_spawn_tests.rs");
    include!("vm/entry_hypercall_tests.rs");
    include!("vm/entry_construction_tests.rs");
    include!("vm/entry_race_tests.rs");
    include!("vm/entry_multi_owner_tests.rs");
    include!("vm/entry_action_tests.rs");
    include!("vm/entry_wait_tests.rs");
    include!("vm/entry_eintr_tests.rs");
    include!("vm/inline_interrupt_tests.rs");
    include!("vm/memory_publication_tests.rs");
    include!("vm/read_zero_guest_tests.rs");

    #[test]
    fn action_parent_captures_yield_for_close_and_keep_stop_and_validation() {
        use std::task::Context;
        use std::task::Poll;

        type CaptureFuture<'a> =
            Pin<Box<dyn Future<Output = Result<Option<(kvm_regs, Vec<u8>)>>> + 'a>>;

        for boundary_capture in [false, true] {
            for event in ["failure", "cancellation", "poison", "reopen"] {
                let mut backend = KvmBackend::new(0x10000).expect("this control requires /dev/kvm");
                let frame_address = backend.syscall_frame_address;
                let frame = [0xa5; FRAME_SIZE];
                backend.memory.write_raw(frame_address, &frame).unwrap();
                let hypercall_address = syscall_hypercall_address(
                    backend.hypercall_instruction,
                    backend.syscall_trampoline_address,
                    frame_address,
                );
                backend
                    .memory
                    .write_raw(hypercall_address, &backend.hypercall_instruction)
                    .unwrap();
                let mut registers = backend.vcpu.get_regs().unwrap();
                registers.rip = hypercall_address;
                registers.rax = 0x1234;
                backend.vcpu.set_regs(&registers).unwrap();
                let expected = if boundary_capture {
                    CompletedSyscallBoundary::capture(&backend, frame_address, None)
                        .unwrap()
                        .registers
                } else {
                    registers
                };
                let gate = backend.memory.entry_gate();
                let group = backend.thread_group.clone();
                let mut closed = Some(
                    gate.try_close()
                        .unwrap()
                        .unwrap()
                        .finish()
                        .now_or_never()
                        .unwrap()
                        .unwrap(),
                );
                let original = Arc::new(Error::UnexpectedVcpuExit(
                    "controlled capture poison".to_owned(),
                ));
                let (sender, receiver) = oneshot::channel();
                let mut stop = Box::pin(async move {
                    receiver.await.unwrap();
                });
                // These are the actual two production capture paths. Both
                // own their buffers and drop admission before returning.
                let mut capture: CaptureFuture<'_> = if boundary_capture {
                    Box::pin(async {
                        CompletedSyscallBoundary::capture_admitted(
                            &mut backend,
                            frame_address,
                            None,
                            stop.as_mut(),
                        )
                        .await
                        .map(|result| result.map(|value| (value.registers, value.frame.to_vec())))
                    })
                } else {
                    Box::pin(async {
                        backend
                            .capture_thread_parent(stop.as_mut())
                            .await
                            .map(|result| result.map(|(registers, _, frame)| (registers, frame)))
                    })
                };
                let waker = futures::task::noop_waker();
                let mut context = Context::from_waker(&waker);
                assert!(capture.as_mut().poll(&mut context).is_pending());
                assert!(capture.as_mut().poll(&mut context).is_pending());
                match event {
                    "failure" => sender.send(()).unwrap(),
                    "cancellation" => group.request_exit_group(ExitStatus::Exited(7)),
                    "poison" => {
                        gate.poison(None, Error::SharedFailure(original.clone()));
                    }
                    "reopen" => drop(closed.take()),
                    _ => unreachable!(),
                }
                match (event, capture.as_mut().poll(&mut context)) {
                    ("failure", Poll::Ready(Err(Error::RunAborted))) => {}
                    ("cancellation", Poll::Ready(Ok(None))) => {}
                    ("poison", Poll::Ready(Err(error))) => {
                        assert!(error.retains_primary(&original))
                    }
                    ("reopen", Poll::Ready(Ok(Some((actual_registers, actual_frame))))) => {
                        assert_eq!(actual_registers, expected);
                        assert_eq!(actual_frame, frame);
                    }
                    _ => panic!("capture did not preserve {event} disposition"),
                }
                drop(capture);
                assert_eq!(
                    backend.vcpu.get_regs().unwrap(),
                    registers,
                    "capture ran or changed the vCPU"
                );
                if event == "cancellation" {
                    assert_eq!(group.exit_status(), Some(ExitStatus::Exited(7)));
                }
                drop(closed);
                if event == "reopen" && boundary_capture {
                    let mut pending = std::pin::pin!(std::future::pending());
                    let mut invalid = registers;
                    invalid.rip = hypercall_address + 1;
                    backend.vcpu.set_regs(&invalid).unwrap();
                    assert!(matches!(
                        futures::executor::block_on(CompletedSyscallBoundary::capture_admitted(
                            &mut backend,
                            frame_address,
                            None,
                            pending.as_mut()
                        )),
                        Err(Error::UnexpectedVcpuExit(_))
                    ));
                    backend.vcpu.set_regs(&registers).unwrap();
                    backend
                        .memory
                        .write_raw(hypercall_address, &[0x90; 3])
                        .unwrap();
                    assert!(matches!(
                        futures::executor::block_on(CompletedSyscallBoundary::capture_admitted(
                            &mut backend,
                            frame_address,
                            None,
                            pending.as_mut()
                        )),
                        Err(Error::UnexpectedVcpuExit(_))
                    ));
                }
            }
        }
    }

    #[test]
    fn parking_wait_preserves_failure_cancellation_and_reopen() {
        use std::task::Context;
        use std::task::Poll;

        for event in ["failure", "cancellation", "reopen"] {
            let mut backend = KvmBackend::new(0x10000).expect("this control requires /dev/kvm");
            backend.install_real_mode_program(0x1000, &[HLT]).unwrap();
            let before = backend.vcpu.get_regs().unwrap();
            let mut original_trampoline = [0; 256];
            backend
                .memory
                .read_raw(SYSCALL_TRAMPOLINE_ADDRESS, &mut original_trampoline)
                .unwrap();
            let gate = backend.memory.entry_gate();
            let group = backend.thread_group.clone();
            let mut closed = Some(
                futures::executor::block_on(gate.try_close().unwrap().unwrap().finish()).unwrap(),
            );
            let (sender, receiver) = oneshot::channel();
            // An ordinary async block panics if polled after completion; this
            // is deliberately not a fused failure future.
            let mut stop = Box::pin(async move {
                receiver.await.unwrap();
            });
            let mut parking =
                Box::pin(backend.park_process_action("parking control", stop.as_mut()));
            let waker = futures::task::noop_waker();
            let mut context = Context::from_waker(&waker);
            assert!(
                parking.as_mut().poll(&mut context).is_pending(),
                "{event}: closed parking did not yield"
            );
            match event {
                "failure" => sender.send(()).unwrap(),
                "cancellation" => group.request_exit_group(ExitStatus::Exited(7)),
                "reopen" => drop(closed.take()),
                _ => unreachable!(),
            }
            let outcome = parking.as_mut().poll(&mut context);
            match event {
                "failure" => assert!(matches!(outcome, Poll::Ready(Err(Error::RunAborted)))),
                "cancellation" => assert!(matches!(outcome, Poll::Ready(Ok(false)))),
                "reopen" => assert!(matches!(outcome, Poll::Ready(Ok(true)))),
                _ => unreachable!(),
            }
            drop(parking);
            let after = backend.vcpu.get_regs().unwrap();
            if event == "reopen" {
                assert_eq!(after.rip, 0x1001);
            } else {
                assert_eq!(after, before, "a stopped action must not enter KVM");
                // The stop returned while the close token was still held.
                assert!(closed.is_some());
                drop(closed.take());
                let mut actual = [0; 256];
                backend
                    .memory
                    .read_raw(SYSCALL_TRAMPOLINE_ADDRESS, &mut actual)
                    .unwrap();
                assert_eq!(
                    actual, original_trampoline,
                    "closed preparation changed bytes"
                );
            }
            if event == "cancellation" {
                assert_eq!(
                    backend.guest_thread_group_exit_status(),
                    Some(ExitStatus::Exited(7))
                );
            }
        }
    }

    mod cancellation_wake_tests {
        use std::sync::Weak;
        use std::sync::atomic::AtomicUsize;
        use std::task::Context;

        use super::*;

        #[test]
        fn subscriptions_cover_registration_before_and_after_publication() {
            for exit_group in [false, true] {
                let group = GuestThreadGroup::default();
                let first = group.subscribe_cancellation();
                let second = group.subscribe_cancellation();
                let unpolled = first.clone();
                drop(group.subscribe_cancellation());
                assert!(first.clone().now_or_never().is_none());
                assert!(second.clone().now_or_never().is_none());
                assert!(!group.cancelled.load(Ordering::Acquire));

                if exit_group {
                    group.request_exit_group(ExitStatus::Exited(19));
                } else {
                    group.cancel_workers();
                }
                assert_eq!(first.now_or_never(), Some(Ok(())));
                assert_eq!(second.now_or_never(), Some(Ok(())));
                assert_eq!(unpolled.now_or_never(), Some(Ok(())));

                // A late subscriber must see the published predicate on its
                // recheck even though its new notification is still pending.
                let late = group.subscribe_cancellation();
                assert!(group.cancelled.load(Ordering::Acquire));
                assert_eq!(
                    group.exit_status(),
                    exit_group.then_some(ExitStatus::Exited(19))
                );
                assert!(late.clone().now_or_never().is_none());
                if exit_group {
                    group.request_exit_group(ExitStatus::Exited(23));
                } else {
                    group.cancel_workers();
                }
                assert_eq!(late.now_or_never(), Some(Ok(())));
                assert_eq!(
                    group.exit_status(),
                    exit_group.then_some(ExitStatus::Exited(19)),
                    "notification must preserve the first exit status"
                );
            }
        }

        #[test]
        fn root_can_resubscribe_after_worker_only_cancellation() {
            let group = GuestThreadGroup::default();
            let old = group.subscribe_cancellation();
            group.cancel_workers();
            assert_eq!(old.now_or_never(), Some(Ok(())));

            // The root's existing exit predicate ignores worker-only cancel.
            let next = group.subscribe_cancellation();
            assert_eq!(group.exit_status(), None);
            assert!(group.cancelled.load(Ordering::Acquire));
            assert!(next.clone().now_or_never().is_none());

            group.request_exit_group(ExitStatus::Exited(31));
            assert_eq!(next.now_or_never(), Some(Ok(())));
            assert_eq!(group.exit_status(), Some(ExitStatus::Exited(31)));
            assert!(group.subscribe_cancellation().now_or_never().is_none());
        }

        #[test]
        fn subscriptions_survive_exec_rearm_and_wake_on_later_cancellation() {
            let group = GuestThreadGroup::default();
            let old = group.subscribe_cancellation();
            group.record_worker_failure(2);
            group.request_exit_group(ExitStatus::Exited(41));
            assert_eq!(old.now_or_never(), Some(Ok(())));
            assert!(group.cancelled_after_failure.load(Ordering::Acquire));

            let before_rearm = group.subscribe_cancellation();
            group.join_workers();
            group.rearm_after_exec();
            assert!(!group.cancelled.load(Ordering::Acquire));
            assert!(!group.cancelled_after_failure.load(Ordering::Acquire));
            assert_eq!(group.exit_status(), None);
            assert!(before_rearm.clone().now_or_never().is_none());
            let after_rearm = group.subscribe_cancellation();
            assert!(after_rearm.clone().now_or_never().is_none());

            group.cancel_workers();
            assert_eq!(before_rearm.now_or_never(), Some(Ok(())));
            assert_eq!(after_rearm.now_or_never(), Some(Ok(())));
            assert!(group.cancelled.load(Ordering::Acquire));
            assert!(!group.cancelled_after_failure.load(Ordering::Acquire));
            assert_eq!(group.exit_status(), None);
        }

        struct CancellationWakeProbe {
            group: Weak<GuestThreadGroup>,
            expected_status: Option<ExitStatus>,
            expected_failure: bool,
            wakes: AtomicUsize,
        }

        impl futures::task::ArcWake for CancellationWakeProbe {
            fn wake_by_ref(probe: &Arc<Self>) {
                let group = probe.group.upgrade().unwrap();
                assert!(group.cancelled.load(Ordering::Acquire));
                assert_eq!(
                    group.cancelled_after_failure.load(Ordering::Acquire),
                    probe.expected_failure
                );
                assert_eq!(
                    *group.exit_status.try_lock().unwrap(),
                    probe.expected_status
                );
                assert!(group.root.try_lock().is_ok());
                assert!(group.workers.try_lock().is_ok());
                assert!(group.worker_handles.try_lock().is_ok());
                assert!(group.worker_start_gates.try_lock().is_ok());
                assert!(group.worker_errors.try_lock().is_ok());
                assert!(group.reported_worker_panics.try_lock().is_ok());
                assert!(group.completed_worker_panics.try_lock().is_ok());
                assert!(group.failure_state.try_lock().is_ok());
                assert!(group.transport_slots.try_lock().is_ok());
                assert!(group.cancellation_wake.try_lock().is_ok());
                assert!(group.subscribe_cancellation().now_or_never().is_none());
                probe.wakes.fetch_add(1, Ordering::Relaxed);
            }
        }

        #[test]
        fn wake_callbacks_observe_published_state_outside_group_locks() {
            for after_failure in [false, true] {
                for exit_group in [false, true] {
                    let group = Arc::new(GuestThreadGroup::default());
                    if after_failure {
                        group.record_worker_failure(2);
                    }
                    let probe = Arc::new(CancellationWakeProbe {
                        group: Arc::downgrade(&group),
                        expected_status: exit_group.then_some(ExitStatus::Exited(47)),
                        expected_failure: after_failure,
                        wakes: AtomicUsize::new(0),
                    });
                    let waker = futures::task::waker(probe.clone());
                    let mut subscription = group.subscribe_cancellation();
                    assert!(
                        subscription
                            .poll_unpin(&mut Context::from_waker(&waker))
                            .is_pending()
                    );
                    assert_eq!(probe.wakes.load(Ordering::Relaxed), 0);
                    if exit_group {
                        group.request_exit_group(ExitStatus::Exited(47));
                    } else {
                        group.cancel_workers();
                    }
                    assert!(probe.wakes.load(Ordering::Relaxed) > 0);
                    assert_eq!(subscription.now_or_never(), Some(Ok(())));
                }
            }
        }
    }

    mod initialization_tests {
        use std::io::Seek;
        use std::io::SeekFrom;
        use std::io::Write;
        use std::os::unix::fs::MetadataExt;
        use std::process::Child;
        use std::process::Command;
        use std::process::Stdio;
        use std::sync::atomic::AtomicU64;
        use std::time::Duration;
        use std::time::Instant;

        use super::*;

        const MARK: u64 = 0x5431_0000;
        const STAGES: [&str; 9] = [
            "open",
            "create-vm",
            "run-size",
            "cpuid",
            "enable-cap",
            "memory",
            "create-vcpu",
            "run-mmap",
            "set-cpuid",
        ];

        struct ChildGuard(Child, Option<i32>);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let deadline = Instant::now() + Duration::from_secs(2);
                if let Some(tid) = self.1 {
                    loop {
                        let mut status = 0;
                        let result = unsafe {
                            libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG)
                        };
                        if result < 0
                            || result == tid
                                && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status))
                        {
                            break;
                        }
                        if result == tid && libc::WIFSTOPPED(status) {
                            unsafe {
                                libc::ptrace(libc::PTRACE_CONT, tid, 0, libc::SIGKILL);
                            }
                        }
                        if Instant::now() >= deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                while self.0.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                assert!(
                    self.0.try_wait().unwrap().is_some(),
                    "traced child cleanup exceeded two seconds"
                );
            }
        }

        fn marker(number: u64, first: u64, second: u64, third: u64) {
            unsafe {
                libc::syscall(libc::SYS_getpid, MARK + number, first, second, third);
            }
        }

        #[test]
        fn initialization_child() {
            let Ok(directory) = std::env::var("REVERIE_INIT_TEST_DIRECTORY") else {
                return;
            };
            let configuration = std::env::var("REVERIE_INIT_TEST_CASE").unwrap();
            let fields: Vec<_> = configuration.split(',').collect();
            let stage = fields[0];
            let failures: usize = fields[1].parse().unwrap();
            let errno: i32 = fields[2].parse().unwrap();
            let directory = std::path::PathBuf::from(directory);
            let memory = GuestMemory::new(0, 0x20_0000).unwrap();
            let mut expected: Vec<u8> = (0..memory.len())
                .map(|index| (index.wrapping_mul(37) ^ (index >> 9)) as u8)
                .collect();
            memory.write_raw(0, &expected).unwrap();
            memory.enable_user_access();
            memory.map_user_permissions(0, 4096, true, false).unwrap();
            memory
                .map_user_permissions(4096, 4096, false, false)
                .unwrap();
            memory.map_user_permissions(8192, 4096, true, true).unwrap();
            let peer = memory.clone();
            let address = memory.host_address();
            let mut input = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.join("stdin"))
                .unwrap();
            input.write_all(b"retained-input-with-position").unwrap();
            input.seek(SeekFrom::Start(7)).unwrap();
            let input_observer = input.try_clone().unwrap();
            let metadata = input.metadata().unwrap();
            let policy = CpuidPolicy::default();
            let request = Arc::new(AtomicU64::new(0));
            let acknowledgement = Arc::new(AtomicU64::new(0));
            let peer_request = request.clone();
            let peer_acknowledgement = acknowledgement.clone();
            let writer_memory = memory.clone();
            let writer = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(15);
                loop {
                    match peer_request.load(Ordering::Acquire) {
                        1 => {
                            writer_memory.write_raw(0x10_000, &[0xe7; 4096]).unwrap();
                            peer_acknowledgement.store(1, Ordering::Release);
                        }
                        2 => break,
                        _ => (),
                    }
                    assert!(Instant::now() < deadline, "peer deadline");
                    std::thread::yield_now();
                }
            });
            let tid = unsafe { libc::syscall(libc::SYS_gettid) };
            assert_eq!(unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) }, 0);
            // The parent must not wait on this nonleader TID until it is a
            // tracee; publishing before TRACEME permits an immediate ECHILD.
            std::fs::write(directory.join("tid"), tid.to_string()).unwrap();
            unsafe {
                libc::raise(libc::SIGSTOP);
            }
            marker(
                0,
                address,
                Arc::as_ptr(&request) as u64,
                Arc::as_ptr(&acknowledgement) as u64,
            );
            let mut result =
                KvmBackend::new_with_memory_and_cpuid_policy(memory, policy, Some(input));
            marker(1, 0, 0, 0);
            if acknowledgement.load(Ordering::Acquire) == 1 {
                expected[0x10_000..0x11_000].fill(0xe7);
            }
            request.store(2, Ordering::Release);
            writer.join().unwrap();
            let mut actual = vec![0; expected.len()];
            peer.read_raw(0, &mut actual).unwrap();
            assert_eq!(actual, expected, "complete shared backing changed");
            assert_eq!(peer.host_address(), address);
            assert!(peer.put_user_i32(0, 0).is_err());
            assert!(peer.read(4096, &mut [0; 4]).is_err());
            peer.put_user_i32(
                8192,
                i32::from_ne_bytes(expected[8192..8196].try_into().unwrap()),
            )
            .unwrap();
            assert_eq!(input_observer.metadata().unwrap().ino(), metadata.ino());
            assert_eq!(input_observer.metadata().unwrap().dev(), metadata.dev());
            assert_eq!((&input_observer).stream_position().unwrap(), 7);
            match &result {
                Ok(backend) => {
                    assert!(
                        errno == libc::EINTR && failures < 3 || failures == 0,
                        "unexpected success"
                    );
                    assert_eq!(backend.memory.host_address(), address);
                    assert_eq!(backend.cpuid_policy, policy);
                    assert_eq!(
                        backend.stdin.as_ref().unwrap().metadata().unwrap().ino(),
                        metadata.ino()
                    );
                    assert!(backend.thread_slot.is_none());
                    assert!(
                        backend
                            .thread_group
                            .transport_slots
                            .lock()
                            .unwrap()
                            .iter()
                            .all(|used| !used)
                    );
                    assert!(backend.thread_group.workers.lock().unwrap().is_empty());
                    assert!(backend.static_elf.is_none());
                    assert!(backend.exit_collector.is_none());
                    assert_eq!(backend.vcpu.get_regs().unwrap().rip, 0xfff0);
                }
                Err(Error::HostIo(error)) if stage == "sigaction" => {
                    assert_eq!(error.raw_os_error(), Some(errno))
                }
                Err(Error::HypercallExitUnsupported) if stage == "capability" => (),
                Err(Error::UnsupportedCpuidProfile(_)) if stage == "policy" => (),
                Err(Error::Kvm(error)) => {
                    assert!(
                        failures >= 3 || errno != libc::EINTR,
                        "eligible EINTR was not recovered: {configuration}"
                    );
                    assert_eq!(error.errno(), errno);
                }
                Err(error) => panic!("unexpected error: {error:?}"),
            }
            if stage == "post-registers" || stage == "guest" {
                let backend = result.as_mut().unwrap();
                marker(3, 0, 0, 0);
                let installed = backend.install_real_mode_program(8192, &[0xf4]);
                if stage == "post-registers" {
                    assert!(
                        matches!(installed, Err(Error::Kvm(error)) if error.errno() == libc::EINTR)
                    );
                } else {
                    installed.unwrap();
                    marker(4, 0, 0, 0);
                    backend
                        .run(|_, _| panic!("unexpected guest syscall"))
                        .unwrap();
                }
                marker(1, 0, 0, 0);
            }
            let mut retained_wrapper_memory = None;
            if stage == "thread-registers" || stage == "process-registers" {
                let mut parent = result.unwrap();
                parent.memory.clear_user_access();
                configure_long_mode(
                    &mut parent.memory,
                    &parent.vcpu,
                    0x10_0000,
                    0x1f_f000,
                    parent.hypercall_instruction,
                )
                .unwrap();
                let registers = parent.vcpu.get_regs().unwrap();
                let xsave = parent.vcpu.get_xsave().unwrap();
                let group = parent.thread_group.clone();
                let memory = if stage == "process-registers" {
                    parent.memory.snapshot().unwrap()
                } else {
                    parent.memory.clone()
                };
                retained_wrapper_memory = Some(memory.clone());
                let mut parent_before = vec![0; peer.len()];
                peer.read_raw(0, &mut parent_before).unwrap();
                drop(parent);
                marker(5, memory.host_address(), 0, 0);
                result = if stage == "thread-registers" {
                    KvmBackend::from_thread_state(
                        memory,
                        registers,
                        xsave,
                        None,
                        policy,
                        2,
                        group.clone(),
                    )
                } else {
                    KvmBackend::from_process_snapshot(KvmProcessSnapshot {
                        memory,
                        registers,
                        xsave,
                        stdin: None,
                        cpuid_policy: policy,
                    })
                };
                marker(1, 0, 0, 0);
                assert!(matches!(&result, Err(Error::Kvm(error)) if error.errno() == libc::EINTR));
                assert!(
                    group
                        .transport_slots
                        .lock()
                        .unwrap()
                        .iter()
                        .all(|used| !used),
                    "failed setup leaked a slot"
                );
                assert!(group.workers.lock().unwrap().is_empty());
                assert!(group.worker_handles.lock().unwrap().is_empty());
                if stage == "process-registers" {
                    let mut parent_after = vec![0; peer.len()];
                    peer.read_raw(0, &mut parent_after).unwrap();
                    assert_eq!(parent_before, parent_after);
                }
            }
            drop(result);
            marker(2, 0, 0, 0);
            drop(retained_wrapper_memory);
            println!("INITIALIZATION CHILD VERIFIED {configuration}");
        }

        fn traced_read(tid: i32, address: u64) -> u64 {
            unsafe {
                *libc::__errno_location() = 0;
                let result = libc::ptrace(libc::PTRACE_PEEKDATA, tid, address, 0);
                assert_eq!(*libc::__errno_location(), 0);
                result as u64
            }
        }

        fn traced_write(tid: i32, address: u64, value: u64) {
            assert_eq!(
                unsafe { libc::ptrace(libc::PTRACE_POKEDATA, tid, address, value) },
                0
            );
        }

        fn traced_path(tid: i32, address: u64) -> Vec<u8> {
            let mut bytes = Vec::new();
            for offset in (0..4096).step_by(8) {
                for byte in traced_read(tid, address + offset).to_ne_bytes() {
                    if byte == 0 {
                        return bytes;
                    }
                    bytes.push(byte);
                }
            }
            panic!("unterminated traced path");
        }

        fn fd_link(pid: u32, fd: u64) -> String {
            std::fs::read_link(format!("/proc/{pid}/fd/{fd}"))
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default()
        }

        fn resources(pid: u32) -> (Vec<(String, String)>, Vec<String>) {
            let mut descriptors: Vec<_> = std::fs::read_dir(format!("/proc/{pid}/fd"))
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let target = std::fs::read_link(entry.path())
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    (name, target)
                })
                .filter(|(_, target)| {
                    target == "/dev/kvm"
                        || target.starts_with("anon_inode:") && target.contains("kvm")
                })
                .collect();
            descriptors.sort();
            let mappings = std::fs::read_to_string(format!("/proc/{pid}/maps"))
                .unwrap()
                .lines()
                .filter(|line| line.contains("kvm-vcpu"))
                .map(str::to_owned)
                .collect();
            (descriptors, mappings)
        }

        fn wait_stop(tid: i32, deadline: Instant) -> i32 {
            loop {
                let mut status = 0;
                let result =
                    unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
                assert!(result >= 0, "waitpid: {}", std::io::Error::last_os_error());
                if result == tid {
                    return status;
                }
                assert!(Instant::now() < deadline, "traced child deadline");
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        fn run_case(stage: &str, failures: usize, errno: i32) -> bool {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let directory = std::env::temp_dir().join(format!(
                "reverie-init-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&directory).unwrap();
            let configuration = format!("{stage},{failures},{errno}");
            let output = File::create(directory.join("output")).unwrap();
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vm::tests::initialization_tests::initialization_child",
                    "--nocapture",
                ])
                .env("REVERIE_INIT_TEST_DIRECTORY", &directory)
                .env("REVERIE_INIT_TEST_CASE", &configuration)
                .stdout(Stdio::from(output.try_clone().unwrap()))
                .stderr(Stdio::from(output))
                .spawn()
                .unwrap();
            let mut child = ChildGuard(child, None);
            let pid = child.0.id();
            let deadline = Instant::now() + Duration::from_secs(15);
            let tid = loop {
                if let Ok(text) = std::fs::read_to_string(directory.join("tid"))
                    && let Ok(tid) = text.parse::<i32>()
                {
                    break tid;
                }
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "child exited before trace: {}",
                    std::fs::read_to_string(directory.join("output")).unwrap()
                );
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            };
            child.1 = Some(tid);
            let status = wait_stop(tid, deadline);
            assert!(libc::WIFSTOPPED(status));
            assert_eq!(
                unsafe {
                    libc::ptrace(
                        libc::PTRACE_SETOPTIONS,
                        tid,
                        0,
                        libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL,
                    )
                },
                0
            );
            let mut active = false;
            let mut attempts = 0;
            let mut injected = 0;
            let mut pending = false;
            let mut request = 0;
            let mut acknowledgement = 0;
            let mut completed = false;
            let mut post_initialization = false;
            let mut handler_calls = 0;
            let mut cpuid_buffer = 0;
            let mut backing = Vec::new();
            let mut registration_address = 0;
            let mut wrapper_phase = false;
            let mut events = Vec::new();
            loop {
                assert_eq!(unsafe { libc::ptrace(libc::PTRACE_SYSCALL, tid, 0, 0) }, 0);
                let status = wait_stop(tid, deadline);
                if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                    break;
                }
                assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP | 0x80);
                let mut info = [0_u64; 16];
                assert!(
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_GET_SYSCALL_INFO,
                            tid,
                            std::mem::size_of_val(&info),
                            info.as_mut_ptr(),
                        )
                    } > 0
                );
                let entry = info[0] as u8 == 1;
                let mut registers: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe { libc::ptrace(libc::PTRACE_GETREGS, tid, 0, &mut registers) },
                    0
                );
                if !entry {
                    if pending {
                        registers.rax = (-(errno as i64)) as u64;
                        assert_eq!(
                            unsafe { libc::ptrace(libc::PTRACE_SETREGS, tid, 0, &registers) },
                            0
                        );
                        pending = false;
                    } else if cpuid_buffer != 0 {
                        assert_eq!(registers.rax, 0);
                        let entries = traced_read(tid, cpuid_buffer) as u32;
                        assert!(entries > 0 && entries <= KVM_MAX_CPUID_ENTRIES as u32);
                        let mut changed = false;
                        for index in 0..entries {
                            let entry_address = cpuid_buffer + 8 + u64::from(index) * 40;
                            if traced_read(tid, entry_address) as u32 == 1 {
                                let edx = traced_read(tid, entry_address + 24);
                                traced_write(tid, entry_address + 24, edx & !(1 << 26));
                                changed = true;
                            }
                        }
                        assert!(changed);
                        injected += 1;
                        cpuid_buffer = 0;
                    }
                    continue;
                }
                if registers.orig_rax == libc::SYS_getpid as u64
                    && (MARK..=MARK + 5).contains(&registers.rdi)
                {
                    match registers.rdi - MARK {
                        0 => {
                            active = true;
                            request = registers.rdx;
                            acknowledgement = registers.r10;
                            registration_address = registers.rsi;
                            assert_eq!(resources(pid), (vec![], vec![]));
                            backing = std::fs::read_to_string(format!("/proc/{pid}/maps"))
                                .unwrap()
                                .lines()
                                .filter(|line| line.contains("memfd:reverie-kvm-guest-memory"))
                                .map(str::to_owned)
                                .collect();
                            assert_eq!(backing.len(), 1);
                        }
                        1 => {
                            active = false;
                            events.push(format!("result {:?}", resources(pid)));
                        }
                        2 => {
                            assert_eq!(
                                resources(pid),
                                (vec![], vec![]),
                                "resources after result drop"
                            );
                            completed = true;
                        }
                        3 => {
                            active = true;
                            post_initialization = true;
                        }
                        4 => {
                            active = false;
                        }
                        5 => {
                            active = true;
                            wrapper_phase = true;
                            registration_address = registers.rsi;
                            assert_eq!(resources(pid), (vec![], vec![]));
                            backing = std::fs::read_to_string(format!("/proc/{pid}/maps"))
                                .unwrap()
                                .lines()
                                .filter(|line| line.contains("memfd:reverie-kvm-guest-memory"))
                                .map(str::to_owned)
                                .collect();
                        }
                        _ => unreachable!(),
                    }
                    let current_backing: Vec<_> =
                        std::fs::read_to_string(format!("/proc/{pid}/maps"))
                            .unwrap()
                            .lines()
                            .filter(|line| line.contains("memfd:reverie-kvm-guest-memory"))
                            .map(str::to_owned)
                            .collect();
                    assert_eq!(
                        current_backing, backing,
                        "backing mapping/device/inode changed"
                    );
                }
                if !active {
                    continue;
                }
                assert_ne!(
                    registers.orig_rax,
                    libc::SYS_memfd_create as u64,
                    "memory allocated inside retry"
                );
                assert_ne!(
                    registers.orig_rax,
                    libc::SYS_dup as u64,
                    "input duplicated inside retry"
                );
                assert_ne!(
                    registers.orig_rax,
                    libc::SYS_dup2 as u64,
                    "input duplicated inside retry"
                );
                assert_ne!(
                    registers.orig_rax,
                    libc::SYS_dup3 as u64,
                    "input duplicated inside retry"
                );
                assert!(
                    !(registers.orig_rax == libc::SYS_fcntl as u64
                        && [libc::F_DUPFD as u64, libc::F_DUPFD_CLOEXEC as u64]
                            .contains(&registers.rsi)),
                    "input duplicated inside retry"
                );
                let operation = if registers.orig_rax == libc::SYS_openat as u64
                    && traced_path(tid, registers.rsi) == b"/dev/kvm"
                {
                    assert!(
                        !post_initialization,
                        "post-initialization failure restarted constructor"
                    );
                    assert_eq!(
                        resources(pid),
                        (vec![], vec![]),
                        "failed attempt resources survived into a new open"
                    );
                    attempts += 1;
                    "open"
                } else if registers.orig_rax == libc::SYS_ioctl as u64 {
                    match registers.rsi & 0xffff {
                        0xae01 => "create-vm",
                        0xae04 => "run-size",
                        0xae05 => "cpuid",
                        0xaea3 => "enable-cap",
                        0xae46 => "memory",
                        0xae41 => "create-vcpu",
                        0xae90 => "set-cpuid",
                        0xae03 => "capability",
                        0xae82 if wrapper_phase => {
                            post_initialization = true;
                            stage
                        }
                        0xae82 if post_initialization => "post-registers",
                        0xae80 => panic!("KVM_RUN during initialization"),
                        _ => "other-ioctl",
                    }
                } else if registers.orig_rax == libc::SYS_mmap as u64
                    && fd_link(pid, registers.r8).contains("kvm-vcpu")
                {
                    "run-mmap"
                } else if registers.orig_rax == libc::SYS_rt_sigaction as u64
                    && registers.rdi == libc::SIGURG as u64
                {
                    "sigaction"
                } else {
                    continue;
                };
                if operation == "sigaction" {
                    handler_calls += 1;
                    assert_eq!(handler_calls, 1, "handler installation repeated");
                }
                if operation == "cpuid" {
                    assert_eq!(
                        traced_read(tid, registers.rdx),
                        KVM_MAX_CPUID_ENTRIES as u64,
                        "fresh CPUID capacity/padding"
                    );
                    for offset in (8..8 + KVM_MAX_CPUID_ENTRIES * 40).step_by(8) {
                        assert_eq!(
                            traced_read(tid, registers.rdx + offset as u64),
                            0,
                            "fresh CPUID scratch"
                        );
                    }
                    if stage == "policy" {
                        cpuid_buffer = registers.rdx;
                    }
                }
                if operation == "memory" {
                    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
                    let current: Vec<_> = maps
                        .lines()
                        .filter(|line| line.contains("memfd:reverie-kvm-guest-memory"))
                        .map(str::to_owned)
                        .collect();
                    assert_eq!(current, backing);
                    assert_eq!(
                        traced_read(tid, registers.rdx + 24),
                        registration_address,
                        "registered a different backing"
                    );
                }
                let current_resources = resources(pid);
                events.push(format!(
                    "attempt={attempts} operation={operation} resources={current_resources:?}"
                ));
                if operation == stage && injected < failures {
                    let expected_descriptors = match operation {
                        "open" | "sigaction" => 0,
                        "create-vm" => 1,
                        "run-mmap" | "set-cpuid" | "post-registers" | "thread-registers"
                        | "process-registers" => 3,
                        _ => 2,
                    };
                    assert_eq!(
                        current_resources.0.len(),
                        expected_descriptors,
                        "real resource prefix at {operation}: {current_resources:?}"
                    );
                    assert_eq!(
                        current_resources.1.len(),
                        usize::from(operation == "set-cpuid" || post_initialization),
                        "real run mapping at {operation}"
                    );
                    if injected == 0 && !post_initialization {
                        traced_write(tid, request, 1);
                        while traced_read(tid, acknowledgement) != 1 {
                            assert!(Instant::now() < deadline, "peer write deadline");
                            std::thread::yield_now();
                        }
                    }
                    injected += 1;
                    registers.orig_rax = u64::MAX;
                    assert_eq!(
                        unsafe { libc::ptrace(libc::PTRACE_SETREGS, tid, 0, &registers) },
                        0
                    );
                    pending = true;
                }
            }
            let status = child.0.wait().unwrap();
            let expected_attempts = if stage == "sigaction" {
                0
            } else if wrapper_phase {
                2
            } else if errno != libc::EINTR
                || ["capability", "policy", "post-registers", "guest"].contains(&stage)
            {
                1
            } else {
                (failures + 1).min(3)
            };
            let output = std::fs::read_to_string(directory.join("output")).unwrap();
            let passed = status.success()
                && completed
                && handler_calls == 1
                && attempts == expected_attempts
                && injected == failures.min(expected_attempts.max(1));
            println!(
                "INITIALIZATION CASE {configuration} attempts={attempts} injected={injected} expected={expected_attempts} status={status} completed={completed} evidence={} passed={passed}\n{}\n{output}",
                directory.display(),
                events.join("\n")
            );
            passed
        }

        fn available() -> bool {
            match KvmBackend::new(0x20_0000) {
                Ok(_) => true,
                Err(error) => {
                    assert!(
                        std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                        "KVM required: {error}"
                    );
                    eprintln!("skipping initialization KVM controls: {error}");
                    false
                }
            }
        }

        #[test]
        fn initialization_once_eintr_stage_matrix() {
            if !available() {
                return;
            }
            let mut failures = Vec::new();
            for stage in STAGES {
                if !run_case(stage, 1, libc::EINTR) {
                    failures.push(stage);
                }
            }
            assert!(failures.is_empty(), "unrecovered stages: {failures:?}");
        }

        #[test]
        fn initialization_bound_and_error_stage_matrix() {
            if !available() {
                return;
            }
            let mut failed = Vec::new();
            for stage in STAGES {
                for (count, errno) in [
                    (2, libc::EINTR),
                    (3, libc::EINTR),
                    (1, libc::EIO),
                    (1, libc::ENOMEM),
                ] {
                    if !run_case(stage, count, errno) {
                        failed.push(format!("{stage},{count},{errno}"));
                    }
                }
            }
            for stage in ["sigaction", "capability"] {
                if !run_case(stage, 1, libc::EINTR) {
                    failed.push(stage.to_owned());
                }
            }
            assert!(failed.is_empty(), "failed cases: {failed:?}");
        }

        #[test]
        fn initialization_policy_and_post_commit_boundaries() {
            if !available() {
                return;
            }
            let cases = [
                ("policy", 1),
                ("post-registers", 1),
                ("guest", 0),
                ("thread-registers", 1),
                ("process-registers", 1),
            ];
            let mut failed = Vec::new();
            for (stage, count) in cases {
                if !run_case(stage, count, libc::EINTR) {
                    failed.push(stage);
                }
            }
            assert!(failed.is_empty(), "boundary controls failed: {failed:?}");
        }
    }

    #[derive(Default)]
    struct SlotReleaseLog {
        group: Arc<GuestThreadGroup>,
        reused: Mutex<Option<usize>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for SlotReleaseLog {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _from: Pid, (): ()) {
            let slot = self
                .group
                .reserve_transport_slot(10_000)
                .expect("exiting worker slot was not released before on_exit_thread");
            self.group.release_transport_slot(slot);
            *self.reused.lock().expect("slot result lock poisoned") = Some(slot);
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct SlotReleaseTool;

    #[reverie::tool]
    impl Tool for SlotReleaseTool {
        type GlobalState = SlotReleaseLog;
        type ThreadState = ();

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            _tid: Pid,
            global: &G,
            _thread_state: Self::ThreadState,
            _status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc(()).await;
            Ok(())
        }
    }

    #[derive(Default)]
    struct CancellationLifecycleLog {
        events: Mutex<Vec<u8>>,
        clear_tid: Mutex<Option<(GuestMemory, u64)>>,
        clear_tid_value_at_thread_exit: Mutex<Option<i32>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for CancellationLifecycleLog {
        type Request = u8;
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _from: Pid, event: u8) {
            if event == 2 {
                let mut bytes = [0; std::mem::size_of::<i32>()];
                let clear_tid = self.clear_tid.lock().unwrap();
                let (memory, address) = clear_tid
                    .as_ref()
                    .expect("thread-exit observation must have a CHILD_CLEARTID address");
                memory.read(*address, &mut bytes).unwrap();
                *self.clear_tid_value_at_thread_exit.lock().unwrap() =
                    Some(i32::from_le_bytes(bytes));
            }
            self.events.lock().unwrap().push(event);
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct CancellationLifecycleTool;

    #[reverie::tool]
    impl Tool for CancellationLifecycleTool {
        type GlobalState = CancellationLifecycleLog;
        type ThreadState = ();

        async fn handle_thread_start<G: reverie::Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            guest.send_rpc(1).await;
            Ok(())
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            _tid: Pid,
            global: &G,
            _state: Self::ThreadState,
            _status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc(2).await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            _pid: Pid,
            global: &G,
            _status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc(3).await;
            Ok(())
        }
    }

    #[test]
    fn completed_syscall_boundary_accepts_only_the_two_transport_rip_forms() {
        const HYPERCALL_ADDRESS: u64 = 0x100;
        let memory = GuestMemory::new(0, 0x1000).unwrap();
        memory.write_raw(HYPERCALL_ADDRESS, &VMCALL).unwrap();

        let mut at_hypercall: kvm_regs = unsafe { std::mem::zeroed() };
        at_hypercall.rip = HYPERCALL_ADDRESS;
        at_hypercall.rax = 0xfeed;
        let normalized = normalize_completed_syscall_boundary_registers(
            &memory,
            at_hypercall,
            VMCALL,
            HYPERCALL_ADDRESS,
        )
        .unwrap();
        assert_eq!(normalized.rip, HYPERCALL_ADDRESS + VMCALL.len() as u64);
        assert_eq!(normalized.rax, 0);

        let mut after_hypercall = at_hypercall;
        after_hypercall.rip = HYPERCALL_ADDRESS + VMCALL.len() as u64;
        let normalized = normalize_completed_syscall_boundary_registers(
            &memory,
            after_hypercall,
            VMCALL,
            HYPERCALL_ADDRESS,
        )
        .unwrap();
        assert_eq!(normalized.rip, after_hypercall.rip);
        assert_eq!(normalized.rax, 0);

        let mut wrong_rip = at_hypercall;
        wrong_rip.rip += 1;
        assert!(
            normalize_completed_syscall_boundary_registers(
                &memory,
                wrong_rip,
                VMCALL,
                HYPERCALL_ADDRESS,
            )
            .is_err()
        );
        memory.write_raw(HYPERCALL_ADDRESS, &[0x90; 3]).unwrap();
        assert!(
            normalize_completed_syscall_boundary_registers(
                &memory,
                at_hypercall,
                VMCALL,
                HYPERCALL_ADDRESS,
            )
            .is_err()
        );
    }

    #[test]
    fn process_action_continuation_policy_is_exhaustive() {
        let fork = ProcessAction::Fork {
            child_pid: 2,
            child_stack: None,
            parent_tid: None,
            child_tid: None,
            clear_child_tid: None,
            clear_sighand: false,
            share_address_space: false,
        };
        let thread = ProcessAction::Thread {
            child_tid: 3,
            child_stack: 0x8000,
            parent_tid: None,
            child_tid_address: None,
            clear_child_tid: None,
            tls: None,
        };
        let exec = ProcessAction::Exec {
            executable_path: std::path::PathBuf::new(),
            executable_file: None,
            image: Vec::new(),
            argv: Vec::new(),
            envp: Vec::new(),
        };

        assert!(matches!(
            ProcessActionContinuation::from_captured(&fork, CompletedSyscallBoundary::for_test()),
            ProcessActionContinuation::Restore(_)
        ));
        assert!(matches!(
            ProcessActionContinuation::from_captured(&thread, CompletedSyscallBoundary::for_test()),
            ProcessActionContinuation::Restore(_)
        ));
        assert!(matches!(
            ProcessActionContinuation::from_captured(&exec, CompletedSyscallBoundary::for_test()),
            ProcessActionContinuation::Exec(_)
        ));
        assert!(fork.returns_to_original_image());
        assert!(thread.returns_to_original_image());
        assert!(!exec.returns_to_original_image());
    }

    #[test]
    fn completed_boundary_restores_exact_real_kvm_transport_state() {
        const ENTRY: u64 = 0x1000;
        const FRAME: u64 = 0x2000;
        let mut backend = match KvmBackend::new(0x10_000) {
            Ok(backend) => backend,
            Err(error) => {
                if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                    panic!("KVM is required: {error}");
                }
                eprintln!("skipping completed-boundary KVM test: {error}");
                return;
            }
        };
        backend
            .install_syscall(
                ENTRY,
                FRAME,
                SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]),
            )
            .unwrap();

        let trampoline_hypercall = syscall_hypercall_address(
            backend.hypercall_instruction,
            backend.syscall_trampoline_address,
            backend.syscall_frame_address,
        );
        let trampoline_offset = trampoline_hypercall - backend.syscall_trampoline_address;
        backend.syscall_trampoline_address = ENTRY + 12 - trampoline_offset;

        let frame_address = match backend
            .vcpu
            .run()
            .unwrap()
            .expect("test entry admission was unexpectedly closed")
        {
            VcpuExit::Hypercall(exit) => {
                assert_eq!(exit.nr, VMCALL_SYSCALL_TRANSPORT);
                *exit.ret = 0;
                exit.args[0]
            }
            exit => panic!("expected syscall hypercall, got {exit:?}"),
        };
        let boundary = CompletedSyscallBoundary::capture(&backend, frame_address, None).unwrap();
        let expected = boundary.clone();

        backend
            .memory
            .write_raw(frame_address, &[0xa5; FRAME_SIZE])
            .unwrap();
        let mut poisoned_registers = backend.vcpu.get_regs().unwrap();
        poisoned_registers.r12 ^= 0x1234_5678;
        poisoned_registers.r13 ^= 0x8765_4321;
        backend.vcpu.set_regs(&poisoned_registers).unwrap();
        let mut poisoned_special = backend.vcpu.get_sregs().unwrap();
        poisoned_special.cr2 ^= 0x4000;
        backend.vcpu.set_sregs(&poisoned_special).unwrap();

        boundary.restore(&mut backend).unwrap();
        let mut restored_frame = [0; FRAME_SIZE];
        backend
            .memory
            .read_raw(frame_address, &mut restored_frame)
            .unwrap();
        assert_eq!(restored_frame, expected.frame);
        assert_eq!(backend.vcpu.get_regs().unwrap(), expected.registers);
        assert_eq!(
            backend.vcpu.get_sregs().unwrap(),
            expected.special_registers
        );
    }
    fn test_exec_action() -> ProcessAction {
        ProcessAction::Exec {
            executable_path: std::path::PathBuf::new(),
            executable_file: None,
            image: Vec::new(),
            argv: Vec::new(),
            envp: Vec::new(),
        }
    }

    #[test]
    fn synthetic_returning_exec_outcome_restores_boundary_and_stages_actual_result() {
        let Some((mut backend, _executor, boundary)) = backend_at_completed_tool_boundary() else {
            return;
        };
        let expected_registers = boundary.registers;
        let expected_special_registers = boundary.special_registers;
        let mut expected_frame = boundary.frame;
        let action = test_exec_action();
        let continuation = CompletedSyscallBoundary::capture_for_action(
            &backend,
            boundary.frame_address,
            None,
            &action,
        )
        .unwrap();
        let expected_result = -i64::from(libc::ENOTSUP);
        let result_offset = crate::syscall::RESULT_WORD * std::mem::size_of::<u64>();
        expected_frame[result_offset..result_offset + std::mem::size_of::<u64>()]
            .copy_from_slice(&(expected_result as u64).to_le_bytes());

        poison_test_boundary(&mut backend, boundary.frame_address);
        let result = continuation.finish(
            &mut backend,
            Ok(ProcessActionOutcome::returned(expected_result)),
        );
        let outcome = result.unwrap();

        assert_eq!(
            outcome,
            ProcessActionOutcome {
                image_replaced: false,
                syscall_result: expected_result,
                cancelled: false,
            }
        );
        let mut restored_frame = [0; FRAME_SIZE];
        backend
            .memory
            .read_raw(backend.syscall_frame_address, &mut restored_frame)
            .unwrap();
        assert_eq!(restored_frame, expected_frame);
        assert_eq!(backend.vcpu.get_regs().unwrap(), expected_registers);

        assert_eq!(
            backend.vcpu.get_sregs().unwrap(),
            expected_special_registers
        );
    }

    #[test]
    fn synthetic_tool_injected_refused_exec_restores_outer_result_before_handler_return() {
        let Some((mut backend, _executor, boundary)) = backend_at_completed_tool_boundary() else {
            return;
        };
        let expected = boundary.clone();
        let action = test_exec_action();
        let continuation = ProcessActionContinuation::from_captured(&action, boundary);
        let expected_exec_result = -i64::from(libc::ENOTSUP);

        poison_test_boundary(&mut backend, expected.frame_address);
        let result = continuation.finish(
            &mut backend,
            Ok(ProcessActionOutcome::returned(expected_exec_result)),
        );
        let outcome = result.unwrap();
        assert_eq!(
            outcome,
            ProcessActionOutcome {
                image_replaced: false,
                syscall_result: expected_exec_result,
                cancelled: false,
            },
            "the injected Exec result belongs to the Tool"
        );

        let mut restored_frame = [0; FRAME_SIZE];
        backend
            .memory
            .read_raw(expected.frame_address, &mut restored_frame)
            .unwrap();
        assert_eq!(restored_frame, expected.frame);
        assert_eq!(backend.vcpu.get_regs().unwrap(), expected.registers);
        assert_eq!(
            backend.vcpu.get_sregs().unwrap(),
            expected.special_registers
        );

        let handler_result = 73;
        expected
            .stage_action_result(&backend, handler_result)
            .unwrap();
        let mut returned_frame = [0; FRAME_SIZE];
        backend
            .memory
            .read_raw(expected.frame_address, &mut returned_frame)
            .unwrap();
        let result_offset = crate::syscall::RESULT_WORD * std::mem::size_of::<u64>();
        let mut expected_returned_frame = expected.frame;
        expected_returned_frame[result_offset..result_offset + std::mem::size_of::<u64>()]
            .copy_from_slice(&(handler_result as u64).to_le_bytes());
        assert_eq!(returned_frame, expected_returned_frame);
        assert_eq!(
            &returned_frame[result_offset..result_offset + std::mem::size_of::<u64>()],
            &(handler_result as u64).to_le_bytes(),
            "a later enclosing-return stage must overwrite the private injected Exec result"
        );
    }

    fn poison_test_boundary(backend: &mut KvmBackend, frame_address: u64) {
        backend
            .memory
            .write_raw(frame_address, &[0xa5; FRAME_SIZE])
            .unwrap();
        let mut registers = backend.vcpu.get_regs().unwrap();
        registers.rax ^= 0x7654;
        registers.rbx ^= 0x4321;
        backend.vcpu.set_regs(&registers).unwrap();
        let mut special = backend.vcpu.get_sregs().unwrap();
        special.fs.base ^= 0x1000;
        backend.vcpu.set_sregs(&special).unwrap();
    }

    #[test]
    fn synthetic_exec_replacement_and_error_do_not_restore_boundary() {
        for failed in [false, true] {
            let Some((mut backend, _executor, boundary)) = backend_at_completed_tool_boundary()
            else {
                return;
            };
            let action = test_exec_action();
            let frame_address = boundary.frame_address;
            let continuation = ProcessActionContinuation::from_captured(&action, boundary);
            poison_test_boundary(&mut backend, frame_address);
            let registers = backend.vcpu.get_regs().unwrap();
            let special = backend.vcpu.get_sregs().unwrap();
            let result = continuation.finish(
                &mut backend,
                if failed {
                    Err(Error::UnexpectedVcpuExit(
                        "synthetic action failure".to_owned(),
                    ))
                } else {
                    Ok(ProcessActionOutcome::replaced())
                },
            );
            if failed {
                assert!(
                    matches!(result, Err(Error::UnexpectedVcpuExit(message)) if message == "synthetic action failure")
                );
            } else {
                assert_eq!(result.unwrap(), ProcessActionOutcome::replaced());
            }
            let mut frame = [0; FRAME_SIZE];
            backend.memory.read_raw(frame_address, &mut frame).unwrap();
            assert_eq!(frame, [0xa5; FRAME_SIZE]);
            assert_eq!(backend.vcpu.get_regs().unwrap(), registers);
            assert_eq!(backend.vcpu.get_sregs().unwrap(), special);
        }
    }

    #[test]
    fn real_fork_and_thread_wrappers_restore_both_capture_modes() {
        for thread in [false, true] {
            for direct in [false, true] {
                for explicit_registers in [false, true] {
                    let Some((mut backend, mut executor, boundary)) =
                        backend_at_completed_tool_boundary()
                    else {
                        return;
                    };
                    backend.thread_ownership = ThreadOwnership::Tool;
                    let user = process_syscall_return_registers(
                        &backend.memory,
                        backend.vcpu.get_regs().unwrap(),
                        boundary.frame_address,
                        0,
                        None,
                    )
                    .unwrap();
                    let action = if thread {
                        ProcessAction::Thread {
                            child_tid: 2,
                            child_stack: user.rsp,
                            parent_tid: None,
                            child_tid_address: None,
                            clear_child_tid: None,
                            tls: None,
                        }
                    } else {
                        ProcessAction::Fork {
                            child_pid: 2,
                            child_stack: None,
                            parent_tid: None,
                            child_tid: None,
                            clear_child_tid: None,
                            clear_sighand: false,
                            share_address_space: false,
                        }
                    };
                    let returned_registers = explicit_registers.then_some(user);
                    let captured = CompletedSyscallBoundary::capture(
                        &backend,
                        boundary.frame_address,
                        returned_registers,
                    )
                    .unwrap();
                    let continuation = if direct {
                        CompletedSyscallBoundary::capture_for_action(
                            &backend,
                            boundary.frame_address,
                            returned_registers,
                            &action,
                        )
                        .unwrap()
                    } else {
                        ProcessActionContinuation::from_captured(&action, captured.clone())
                    };
                    let mut expected_frame = captured.frame;
                    let mut expected_registers = captured.registers;
                    if direct {
                        if explicit_registers {
                            for (word, value) in [
                                (1, user.rdi),
                                (2, user.rsi),
                                (3, user.rdx),
                                (4, user.r10),
                                (5, user.r8),
                                (6, user.r9),
                                (7, 2),
                                (8, user.rip),
                                (9, user.rflags),
                                (10, user.rbx),
                            ] {
                                expected_frame[word * 8..word * 8 + 8]
                                    .copy_from_slice(&value.to_le_bytes());
                            }
                            expected_registers.rbp = user.rbp;
                            expected_registers.rsp = user.rsp;
                            expected_registers.r12 = user.r12;
                            expected_registers.r13 = user.r13;
                            expected_registers.r14 = user.r14;
                            expected_registers.r15 = user.r15;
                        } else {
                            expected_frame[56..64].copy_from_slice(&2_u64.to_le_bytes());
                        }
                    }
                    let starts = Arc::new(Mutex::new(Vec::new()));
                    let context = ToolContext::<crate::StraceTool> {
                        process_state: Arc::new(crate::StraceTool),
                        pid: Pid::from_raw(1),
                        tid: Pid::from_raw(1),
                        thread_state: &(),
                        global_state: Some(Arc::new(crate::StraceLog::default())),
                        config: (),
                        subscriptions: reverie::Subscription::none(),
                        pending_child_starts: starts.clone(),
                    };
                    let result = futures::executor::block_on(
                        backend.run_process_action_with_tool_at_boundary(
                            &mut executor,
                            action,
                            context,
                            continuation,
                        ),
                    );
                    let start_count = starts.lock().unwrap().len();
                    let child_present = if thread {
                        backend
                            .thread_group
                            .worker_handles
                            .lock()
                            .unwrap()
                            .iter()
                            .any(|worker| worker.tid == 2)
                    } else {
                        executor.has_pending_child_process(2)
                    };
                    let cleanup = backend.discard_unstarted_tool_children(&mut executor, &starts);
                    assert_eq!(result.unwrap(), ProcessActionOutcome::returned(2));
                    cleanup.unwrap();
                    assert_eq!(start_count, 1);
                    assert!(child_present);
                    assert!(starts.lock().unwrap().is_empty());
                    assert!(!executor.has_pending_child_process(2));
                    assert!(
                        backend
                            .thread_group
                            .worker_handles
                            .lock()
                            .unwrap()
                            .is_empty()
                    );
                    let mut frame = [0; FRAME_SIZE];
                    backend
                        .memory
                        .read_raw(captured.frame_address, &mut frame)
                        .unwrap();
                    assert_eq!(frame, expected_frame);
                    assert_eq!(backend.vcpu.get_regs().unwrap(), expected_registers);
                    assert_eq!(
                        backend.vcpu.get_sregs().unwrap(),
                        captured.special_registers
                    );
                    if !direct {
                        captured.stage_action_result(&backend, 73).unwrap();
                        if explicit_registers {
                            for (word, value) in [
                                (1, user.rdi),
                                (2, user.rsi),
                                (3, user.rdx),
                                (4, user.r10),
                                (5, user.r8),
                                (6, user.r9),
                                (7, 73),
                                (8, user.rip),
                                (9, user.rflags),
                                (10, user.rbx),
                            ] {
                                expected_frame[word * 8..word * 8 + 8]
                                    .copy_from_slice(&value.to_le_bytes());
                            }
                        } else {
                            expected_frame[56..64].copy_from_slice(&73_u64.to_le_bytes());
                        }
                        backend
                            .memory
                            .read_raw(captured.frame_address, &mut frame)
                            .unwrap();
                        assert_eq!(frame, expected_frame);
                    }
                }
            }
        }
    }

    fn test_executor() -> ElfExecutor {
        ElfExecutor::new(
            crate::executor::test_loaded_state_for_vm(
                &std::env::current_dir().expect("test current directory"),
            ),
            false,
        )
    }

    #[test]
    fn read_zero_vm_routes_duplicated_and_rebound_stdin_through_terminal_context() {
        for rebound in [false, true] {
            let backend =
                KvmBackend::new(0x10000).expect("terminal read dispatch control requires /dev/kvm");
            let raw = unsafe { libc::eventfd(9, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            assert!(raw >= 0);
            let mut state =
                crate::executor::test_loaded_state_for_vm(&std::env::current_dir().unwrap());
            // SAFETY: successful eventfd transfers one owned descriptor.
            state.stdin = Some(unsafe { File::from_raw_fd(raw) });
            let mut executor = ElfExecutor::new(state, false);
            let memory = &backend.memory;
            let alias =
                executor.execute(&SyscallRequest::new(libc::SYS_dup as u64, [0; 6]), memory);
            assert_eq!(alias, 3);
            let fd = if rebound {
                assert_eq!(
                    executor.execute(
                        &SyscallRequest::new(libc::SYS_dup2 as u64, [alias as u64, 0, 0, 0, 0, 0]),
                        memory,
                    ),
                    0
                );
                0
            } else {
                alias as u64
            };
            let flags_request = SyscallRequest::new(
                libc::SYS_fcntl as u64,
                [fd, libc::F_GETFL as u64, 0, 0, 0, 0],
            );
            let flags = executor.execute(&flags_request, memory);
            assert!(flags >= 0);
            assert_ne!(flags & libc::O_NONBLOCK as i64, 0);
            backend
                .thread_group
                .terminal_reads
                .request_exit_group(ExitStatus::Exited(37));
            // Eventfd makes the old missing-context branch fail promptly with
            // EINVAL. Actual blocked entry and physical retirement are covered
            // separately by the executor's inotify controls.
            let request = SyscallRequest::new(
                libc::SYS_read as u64,
                [0x5a5a_5a5a_0000_0000 | fd, 0x100, 0, 0, 0, 0],
            );
            assert!(matches!(
                backend.execute_static_elf_syscall(&mut executor, &request, memory),
                Err(Error::TerminalReadCancelled)
            ));
            assert_eq!(executor.execute(&flags_request, memory), flags);
            assert_eq!(
                executor.execute(
                    &SyscallRequest::new(libc::SYS_read as u64, [fd, 0x100, 8, 0, 0, 0]),
                    memory,
                ),
                8
            );
            let mut value = [0_u8; 8];
            memory.read(0x100, &mut value).unwrap();
            assert_eq!(u64::from_ne_bytes(value), 9);
            backend
                .thread_group
                .terminal_reads
                .teardown_result()
                .unwrap();
            backend.thread_group.terminal_reads.rearm_after_exec();
        }
    }

    // Exercise the real fork preparation with different leader/worker frames.
    // No guest runs: register readback isolates the initial return from all
    // later wait/publication behavior, while the guest tests cover that path.
    #[test]
    fn fork_child_restores_issuing_thread_frame_from_private_snapshot() {
        for from_worker in [false, true] {
            for child_stack in [None, Some(0xde_0000)] {
                let mut parent =
                    KvmBackend::new(16 * 1024 * 1024).expect("fork transport control requires KVM");
                parent
                    .install_static_elf(&minimal_test_elf(&[HLT]), "/bin/fork-transport")
                    .unwrap();
                let leader = ElfExecutor::new(parent.static_elf.take().unwrap(), false);
                let sibling = leader.thread_child(2).unwrap();
                let initial = parent.vcpu.get_regs().unwrap();
                let mut worker = KvmBackend::from_thread_state(
                    parent.memory.clone(),
                    initial,
                    parent.vcpu.get_xsave().unwrap(),
                    None,
                    parent.cpuid_policy,
                    2,
                    parent.thread_group.clone(),
                )
                .unwrap();
                assert_ne!(parent.syscall_frame_address, worker.syscall_frame_address);
                assert_eq!(parent.memory.host_address(), worker.memory.host_address());
                let user_registers = |seed, stack, flags| kvm_regs {
                    rax: seed,
                    rbx: seed + 1,
                    rcx: initial.rip + seed,
                    rdx: seed + 2,
                    rsi: seed + 3,
                    rdi: seed + 4,
                    rsp: stack,
                    rbp: seed + 5,
                    r8: seed + 6,
                    r9: seed + 7,
                    r10: seed + 8,
                    r11: flags,
                    r12: seed + 9,
                    r13: seed + 10,
                    r14: seed + 11,
                    r15: seed + 12,
                    rip: initial.rip + seed,
                    rflags: flags,
                };
                let leader_user = user_registers(0x10, 0xe0_0000, 0x202);
                let worker_user = user_registers(0x80, 0xdf_0000, 0x246);
                stage_process_syscall_return(
                    &mut parent.memory,
                    &parent.vcpu,
                    parent.syscall_frame_address,
                    leader_user,
                )
                .unwrap();
                stage_process_syscall_return(
                    &mut worker.memory,
                    &worker.vcpu,
                    worker.syscall_frame_address,
                    worker_user,
                )
                .unwrap();
                let read_frame = |memory: &GuestMemory, address| {
                    let mut frame = [0; FRAME_SIZE];
                    memory.read_raw(address, &mut frame).unwrap();
                    frame
                };
                let leader_frame = read_frame(&parent.memory, parent.syscall_frame_address);
                let worker_frame = read_frame(&worker.memory, worker.syscall_frame_address);
                assert_ne!(leader_frame, worker_frame);
                let leader_before = parent.vcpu.get_regs().unwrap();
                let worker_before = worker.vcpu.get_regs().unwrap();
                let (issuer, executor, mut expected) = if from_worker {
                    (&mut worker, &sibling, worker_user)
                } else {
                    (&mut parent, &leader, leader_user)
                };
                let child = issuer
                    .prepare_forked_process(
                        executor,
                        3,
                        child_stack,
                        None,
                        None,
                        None,
                        false,
                        false,
                        false,
                        None,
                    )
                    .unwrap();
                expected.rax = 0;
                if let Some(stack) = child_stack {
                    expected.rsp = stack;
                }
                assert_eq!(child.backend.vcpu.get_regs().unwrap(), expected);
                assert_ne!(
                    child.backend.memory.host_address(),
                    parent.memory.host_address()
                );
                assert_eq!(
                    child.backend.syscall_trampoline_address,
                    SYSCALL_TRAMPOLINE_ADDRESS
                );
                assert_eq!(child.backend.syscall_frame_address, SYSCALL_FRAME_ADDRESS);
                // IA32_LSTAR must still select the new process's root transport.
                let mut msrs = kvm_bindings::Msrs::from_entries(&[kvm_bindings::kvm_msr_entry {
                    index: 0xc000_0082,
                    ..Default::default()
                }])
                .unwrap();
                assert_eq!(child.backend.vcpu.get_msrs(&mut msrs).unwrap(), 1);
                assert_eq!(msrs.as_slice()[0].data, SYSCALL_TRAMPOLINE_ADDRESS);
                for (address, frame) in [
                    (parent.syscall_frame_address, leader_frame),
                    (worker.syscall_frame_address, worker_frame),
                ] {
                    assert_eq!(read_frame(&parent.memory, address), frame);
                    assert_eq!(read_frame(&child.backend.memory, address), frame);
                }
                assert_eq!(parent.vcpu.get_regs().unwrap(), leader_before);
                assert_eq!(worker.vcpu.get_regs().unwrap(), worker_before);
            }
        }
    }

    // Exercise real sibling dispatch and the production private-fork snapshot
    // without entering KVM_RUN. Both thread VMs share the parent mapping; the
    // forked VM must inherit its completed layout and then remain independent.
    #[test]
    fn fork_from_stale_sibling_inherits_completed_brk_growth() {
        let mut parent =
            KvmBackend::new(16 * 1024 * 1024).expect("fork cursor control requires KVM");
        parent
            .install_static_elf(&minimal_test_elf(&[0xf4]), "/bin/fork-cursor")
            .unwrap();
        let mut leader = ElfExecutor::new(parent.static_elf.take().unwrap(), false);
        let query = SyscallRequest::new(libc::SYS_brk as u64, [0, 0, 0, 0, 0, 0]);
        let initial = leader.execute(&query, &parent.memory);
        assert!(initial > 0);
        let mut sibling = leader.thread_child(2).unwrap();
        let mut sibling_backend = KvmBackend::from_thread_state(
            parent.memory.clone(),
            parent.vcpu.get_regs().unwrap(),
            parent.vcpu.get_xsave().unwrap(),
            None,
            parent.cpuid_policy,
            2,
            parent.thread_group.clone(),
        )
        .unwrap();
        assert_eq!(sibling.execute(&query, &sibling_backend.memory), initial);
        let registers = sibling_backend.vcpu.get_regs().unwrap();
        stage_process_syscall_return(
            &mut sibling_backend.memory,
            &sibling_backend.vcpu,
            sibling_backend.syscall_frame_address,
            registers,
        )
        .unwrap();

        let grown = initial as u64 + 2 * PAGE_SIZE;
        assert_eq!(
            leader.execute(
                &SyscallRequest::new(libc::SYS_brk as u64, [grown, 0, 0, 0, 0, 0]),
                &parent.memory,
            ),
            grown as i64
        );
        let word = initial as u64 + 64;
        parent.memory.write(word, b"parent").unwrap();
        // Do not refresh the sibling with another allocation syscall here:
        // its local ELF fields predate the leader's completed brk growth.
        let mut child = sibling_backend
            .prepare_forked_process(
                &sibling, 3, None, None, None, None, false, false, false, None,
            )
            .unwrap();
        assert_eq!(
            child.executor.execute(&query, &child.backend.memory),
            grown as i64,
            "forked child must inherit a completed sibling brk growth"
        );
        let mut inherited = [0; 6];
        child.backend.memory.read(word, &mut inherited).unwrap();
        assert_eq!(&inherited, b"parent");
        child.backend.memory.write(word, b"child!").unwrap();
        parent.memory.read(word, &mut inherited).unwrap();
        assert_eq!(&inherited, b"parent");

        let child_break = grown + PAGE_SIZE;
        assert_eq!(
            child.executor.execute(
                &SyscallRequest::new(libc::SYS_brk as u64, [child_break, 0, 0, 0, 0, 0]),
                &child.backend.memory,
            ),
            child_break as i64
        );
        assert_eq!(
            child.executor.execute(&query, &child.backend.memory),
            child_break as i64
        );
        assert_eq!(leader.execute(&query, &parent.memory), grown as i64);
        assert_eq!(
            sibling.execute(&query, &sibling_backend.memory),
            grown as i64
        );
    }

    #[derive(Default)]
    struct ForkFailureIdentityLog {
        events: Mutex<Vec<reverie::BackendFailure>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for ForkFailureIdentityLog {
        type Request = ();
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _from: Pid, (): ()) {}

        fn report_backend_failure(&self, event: reverie::BackendFailure) {
            self.events.lock().unwrap().push(event);
        }
    }

    // This control requires KVM construction and snapshot/register ioctls. It
    // calls the actual shared fork boundary with parking disabled and never
    // executes a guest instruction. Keep it separate from no-VM selectors.
    #[test]
    fn nested_host_fork_failure_uses_descendant_process_and_worker_identity() {
        let mut parent =
            KvmBackend::new(16 * 1024 * 1024).expect("nested fork identity control requires KVM");
        parent
            .install_static_elf(&minimal_test_elf(&[0xf4]), "/bin/fork-failure-identity")
            .unwrap();
        let executor = ElfExecutor::new(parent.static_elf.take().unwrap(), false);
        let registers = parent.vcpu.get_regs().unwrap();
        stage_process_syscall_return(
            &mut parent.memory,
            &parent.vcpu,
            parent.syscall_frame_address,
            registers,
        )
        .unwrap();
        assert_eq!(parent.thread_ownership, ThreadOwnership::Host);

        let ordinary = parent
            .prepare_forked_process(
                &executor, 9, None, None, None, None, false, false, false, None,
            )
            .unwrap();
        assert!(ordinary.backend.tool_failure.is_none());
        drop(ordinary);

        let global = Arc::new(ForkFailureIdentityLog::default());
        let failure = crate::failure::RunFailure::new(&global);
        parent.set_tool_failure(Some(crate::failure::FailureContext::new(
            failure.clone(),
            Pid::from_raw(1),
            Pid::from_raw(1),
        )));
        let mut child = parent
            .prepare_forked_process(
                &executor, 2, None, None, None, None, false, false, false, None,
            )
            .unwrap();
        let descendant = child
            .backend
            .prepare_forked_process(
                &child.executor,
                3,
                None,
                None,
                None,
                None,
                false,
                false,
                false,
                None,
            )
            .unwrap();
        assert_eq!(child.backend.thread_ownership, ThreadOwnership::Host);
        assert_eq!(descendant.backend.thread_ownership, ThreadOwnership::Host);
        let context = descendant.backend.tool_failure.as_ref().unwrap().clone();
        assert!(Arc::ptr_eq(&context.run, &failure));
        let expected = reverie::BackendFailure {
            pid: Pid::from_raw(3),
            tid: Pid::from_raw(4),
            phase: "host-owned worker",
        };
        let retirement_log = global.clone();
        let returned = std::thread::spawn(move || {
            let result: Result<()> = finish_host_worker_outcome(
                Some(&context),
                Pid::from_raw(4),
                Err(Error::GuestClock("nested host worker".to_owned())),
                |failed| {
                    assert!(failed);
                    assert_eq!(*retirement_log.events.lock().unwrap(), vec![expected]);
                },
            );
            result
        })
        .join()
        .unwrap()
        .unwrap_err();
        let primary = failure.published_primary().expect("worker did not publish");
        assert!(
            matches!(primary.as_ref(), Error::GuestClock(message) if message == "nested host worker")
        );
        assert!(returned.retains_primary(&primary));
        assert_eq!(*global.events.lock().unwrap(), vec![expected]);
    }

    #[test]
    fn finish_forked_process_refuses_unreaped_descendant() {
        let mut parent =
            KvmBackend::new(16 * 1024 * 1024).expect("direct fork family control requires KVM");
        parent
            .install_static_elf(&minimal_test_elf(&[0xf4]), "/bin/fork-family-reparenting")
            .unwrap();
        let mut executor = ElfExecutor::new(parent.static_elf.take().unwrap(), false);
        let registers = parent.vcpu.get_regs().unwrap();
        stage_process_syscall_return(
            &mut parent.memory,
            &parent.vcpu,
            parent.syscall_frame_address,
            registers,
        )
        .unwrap();

        let mut child = parent
            .prepare_forked_process(
                &executor, 2, None, None, None, None, false, false, false, None,
            )
            .unwrap();
        let owner = child.executor.signal_task_identity().unwrap().process;
        let mut descendant = child.executor.fork_child(3, false, false).unwrap();
        let descendant_id = descendant.signal_task_identity().unwrap().process;
        descendant.retire_current_thread(ExitStatus::Exited(9), false);
        child
            .executor
            .retire_current_thread(ExitStatus::Exited(7), false);

        let error = parent
            .finish_forked_process(&mut executor, child, ExitStatus::Exited(7), vec![], vec![])
            .unwrap_err();
        assert!(matches!(
            error,
            Error::DescendantReparentingUnsupported { process, child }
                if process == owner && child == descendant_id
        ));
    }

    /// A peer's exit_group makes the root terminal while its caller is blocked
    /// in a Direct fork. The outside init adopts and reaps the child, so the
    /// fork completes detached rather than returning into the terminal caller.
    fn direct_fork_orphaned_by_a_terminal_root(
        reported: ExitStatus,
    ) -> (Result<ForkedProcessCompletion>, ElfExecutor) {
        let mut parent =
            KvmBackend::new(16 * 1024 * 1024).expect("direct fork family control requires KVM");
        parent.set_root_pid(3).unwrap();
        parent
            .install_static_elf(&minimal_test_elf(&[0xf4]), "/bin/fork-family-detached")
            .unwrap();
        let mut executor = ElfExecutor::new(parent.static_elf.take().unwrap(), true);
        let registers = parent.vcpu.get_regs().unwrap();
        stage_process_syscall_return(
            &mut parent.memory,
            &parent.vcpu,
            parent.syscall_frame_address,
            registers,
        )
        .unwrap();

        let mut child = parent
            .prepare_forked_process(
                &executor, 4, None, None, None, None, false, false, false, None,
            )
            .unwrap();
        let child_id = child.executor.signal_task_identity().unwrap().process;
        executor.retire_current_thread(ExitStatus::Exited(1), false);
        child
            .executor
            .retire_current_thread(ExitStatus::Exited(7), false);
        assert!(matches!(
            child.executor.process_family_exit().unwrap(),
            crate::executor::ProcessFamilyExit::ReapedByNamespaceInit {
                status: ExitStatus::Exited(7)
            }
        ));
        let result = parent.finish_forked_process(
            &mut executor,
            child,
            reported,
            b"orphan out".to_vec(),
            b"orphan err".to_vec(),
        );
        executor
            .fixture_child_wait_context()
            .assert_namespace_reaped_child_for_test(child_id, ExitStatus::Exited(7));
        (result, executor)
    }

    #[test]
    fn finish_forked_process_detaches_a_child_reaped_by_namespace_init() {
        let (result, mut executor) = direct_fork_orphaned_by_a_terminal_root(ExitStatus::Exited(7));
        assert!(matches!(result, Ok(ForkedProcessCompletion::Detached)));
        assert_eq!(
            executor.take_output(),
            (b"orphan out".to_vec(), b"orphan err".to_vec()),
            "a detached child's output still reaches the run",
        );
        assert_eq!(
            executor.fixture_child_wait_context().get(&4),
            None,
            "init reaped the child, so its former parent has nothing to wait for",
        );
        assert!(executor.signal_task_identity().is_none());
        let memory = GuestMemory::new(0, 4096).unwrap();
        assert!(
            matches!(
                executor.execute_checked(
                    &SyscallRequest::new(
                        libc::SYS_wait4 as u64,
                        [4, 0, libc::WNOHANG as u64, 0, 0, 0],
                    ),
                    &memory,
                ),
                Err(Error::RunAborted)
            ),
            "a terminal caller cannot issue another guest wait"
        );
    }

    #[test]
    fn finish_forked_process_refuses_a_detached_status_mismatch() {
        let (result, mut executor) = direct_fork_orphaned_by_a_terminal_root(ExitStatus::Exited(8));
        assert!(matches!(
            result,
            Err(Error::UnexpectedVcpuExit(message))
                if message.contains("family status disagrees")
        ));
        assert_eq!(executor.take_output(), (Vec::new(), Vec::new()));
    }

    #[derive(Default)]
    struct FatalProcessMemoryLog {
        memory: Mutex<Option<GuestMemory>>,
        observations: Mutex<Vec<(i32, Vec<u8>)>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for FatalProcessMemoryLog {
        type Request = i32;
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, _from: Pid, status: i32) {
            let mut bytes = vec![0; 4096];
            self.memory
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .read(0x80_0000, &mut bytes)
                .unwrap();
            self.observations.lock().unwrap().push((status, bytes));
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct FatalProcessMemoryTool;

    #[reverie::tool]
    impl Tool for FatalProcessMemoryTool {
        type GlobalState = FatalProcessMemoryLog;
        type ThreadState = ();

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            _tid: Pid,
            global: &G,
            _state: (),
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc(status.into_raw()).await;
            Ok(())
        }
    }

    fn check_fatal_page_zero_registration(with_tool: bool, writable: bool) {
        let mut parent = match KvmBackend::new(16 * 1024 * 1024) {
            Ok(backend) => backend,
            Err(error) => {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "KVM is required: {error}"
                );
                eprintln!("skipping fatal-process KVM test: {error}");
                return;
            }
        };
        let mut code = vec![0xb8];
        code.extend_from_slice(&(libc::SYS_getpid as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x31, 0xc0, 0x48, 0x8b, 0x00, 0x0f, 0x0b]);
        parent
            .install_static_elf(&minimal_test_elf(&code), "/bin/fatal-process-memory")
            .unwrap();
        let mut executor = ElfExecutor::new(parent.static_elf.take().unwrap(), true);
        match parent
            .vcpu
            .run()
            .unwrap()
            .expect("test entry admission was unexpectedly closed")
        {
            VcpuExit::Hypercall(exit) => {
                assert_eq!(exit.nr, VMCALL_SYSCALL_TRANSPORT);
                *exit.ret = 0;
            }
            other => panic!("unexpected initial boundary: {other:?}"),
        }
        parent
            .memory
            .map_user_permissions(0x80_0000, 4096, true, writable)
            .unwrap();
        parent.memory.write(0x80_0000, &[0x5a; 4096]).unwrap();
        let mut child = parent
            .prepare_forked_process(
                &executor, 2, None, None, None, None, false, false, true, None,
            )
            .unwrap();
        assert_eq!(
            child.executor.execute(
                &SyscallRequest::new(libc::SYS_set_tid_address as u64, [0x80_0000, 0, 0, 0, 0, 0]),
                &child.backend.memory
            ),
            2
        );
        let memory = child.backend.memory.clone();
        let log = Arc::new(FatalProcessMemoryLog::default());
        *log.memory.lock().unwrap() = Some(memory.clone());
        let (status, stdout, stderr) = if with_tool {
            futures::executor::block_on(child.backend.run_static_elf_process_with_tool(
                &mut child.executor,
                Pid::from_raw(2),
                Pid::from_raw(2),
                Arc::new(FatalProcessMemoryTool),
                (),
                log.clone(),
                &(),
                &reverie::Subscription::none(),
                false,
                None,
            ))
            .unwrap()
        } else {
            child
                .backend
                .run_static_elf_process(&mut child.executor)
                .unwrap()
        };
        let mut before_wrapper = [0; 4096];
        memory.read(0x80_0000, &mut before_wrapper).unwrap();
        parent
            .finish_forked_process(&mut executor, child, status, stdout.clone(), stderr.clone())
            .unwrap();
        let mut after_wrapper = [0; 4096];
        memory.read(0x80_0000, &mut after_wrapper).unwrap();
        assert_eq!(status.into_raw(), libc::SIGSEGV | 0x80);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        if with_tool {
            assert_eq!(
                *log.observations.lock().unwrap(),
                vec![(libc::SIGSEGV | 0x80, vec![0x5a; 4096])]
            );
        } else {
            assert!(log.observations.lock().unwrap().is_empty());
        }
        assert_eq!(before_wrapper, [0x5a; 4096]);
        assert_eq!(after_wrapper, [0x5a; 4096]);
        parent
            .memory
            .map_user_permissions(0x80_0000, 4096, true, true)
            .unwrap();
        let request = SyscallRequest::new(
            libc::SYS_wait4 as u64,
            [2, 0x80_0000, libc::WNOHANG as u64, 0, 0, 0],
        );
        assert_eq!(executor.execute(&request, &parent.memory), 2);
        let mut wait_status = [0; 4];
        parent.memory.read(0x80_0000, &mut wait_status).unwrap();
        assert_eq!(i32::from_ne_bytes(wait_status), libc::SIGSEGV | 0x80);
    }

    #[test]
    fn fatal_page_zero_registration_direct_ro() {
        check_fatal_page_zero_registration(false, false);
    }

    #[test]
    fn fatal_page_zero_registration_direct_rw() {
        check_fatal_page_zero_registration(false, true);
    }

    #[test]
    fn fatal_page_zero_registration_tool_ro() {
        check_fatal_page_zero_registration(true, false);
    }

    #[test]
    fn fatal_page_zero_registration_tool_rw() {
        check_fatal_page_zero_registration(true, true);
    }

    #[test]
    fn page_fault_action_restores_complete_stopped_context() {
        for thread in [false, true] {
            for missing_global in [false, true] {
                let mut backend = match KvmBackend::new(16 * 1024 * 1024) {
                    Ok(backend) => backend,
                    Err(error) => {
                        assert!(
                            std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                            "KVM is required: {error}"
                        );
                        eprintln!("skipping page-fault boundary KVM test: {error}");
                        return;
                    }
                };
                backend
                    .install_static_elf(
                        &minimal_test_elf(&[0x31, 0xc0, 0x48, 0x8b, 0x00]),
                        "/page-fault-boundary",
                    )
                    .unwrap();
                let mut executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
                backend.thread_ownership = ThreadOwnership::Tool;
                let mut registers = backend.vcpu.get_regs().unwrap();
                registers.rcx = 0x7777;
                registers.r11 = 0x8888;
                backend.vcpu.set_regs(&registers).unwrap();
                assert!(matches!(
                    backend
                        .vcpu
                        .run()
                        .unwrap()
                        .expect("test entry admission was unexpectedly closed"),
                    VcpuExit::Hlt
                ));
                let fault = backend.capture_page_zero_fault(&executor).unwrap().unwrap();
                let mut frame_before = [0; PAGE_SIZE as usize];
                let mut exception_before = [0; PAGE_SIZE as usize];
                backend
                    .memory
                    .read_raw(backend.syscall_frame_address, &mut frame_before)
                    .unwrap();
                let exception_page = fault.halted_registers.rsp & !(PAGE_SIZE - 1);
                backend
                    .memory
                    .read_raw(exception_page, &mut exception_before)
                    .unwrap();
                let action = if thread {
                    ProcessAction::Thread {
                        child_tid: 2,
                        child_stack: fault.registers.rsp - 4096,
                        parent_tid: None,
                        child_tid_address: None,
                        clear_child_tid: None,
                        tls: None,
                    }
                } else {
                    ProcessAction::Fork {
                        child_pid: 2,
                        child_stack: None,
                        parent_tid: None,
                        child_tid: None,
                        clear_child_tid: None,
                        clear_sighand: false,
                        share_address_space: false,
                    }
                };
                let starts = Arc::new(Mutex::new(Vec::new()));
                let context = ToolContext::<crate::StraceTool> {
                    process_state: Arc::new(crate::StraceTool),
                    pid: Pid::from_raw(1),
                    tid: Pid::from_raw(1),
                    thread_state: &(),
                    global_state: (!missing_global).then(|| Arc::new(crate::StraceLog::default())),
                    config: (),
                    subscriptions: reverie::Subscription::none(),
                    pending_child_starts: starts.clone(),
                };
                let result =
                    futures::executor::block_on(backend.run_process_action_with_tool_from_fault(
                        &mut executor,
                        action,
                        context,
                        &fault,
                    ));
                let child_count = starts.lock().unwrap().len();
                let cleanup = backend.discard_unstarted_tool_children(&mut executor, &starts);
                if missing_global {
                    assert!(result.is_err());
                    assert_eq!(child_count, 0);
                } else {
                    assert_eq!(result.unwrap(), ProcessActionOutcome::returned(2));
                    assert_eq!(child_count, 1);
                }
                cleanup.unwrap();
                assert!(starts.lock().unwrap().is_empty());
                assert!(!executor.has_pending_child_process(2));
                assert!(
                    backend
                        .thread_group
                        .worker_handles
                        .lock()
                        .unwrap()
                        .is_empty()
                );
                let mut frame_after = [0; PAGE_SIZE as usize];
                let mut exception_after = [0; PAGE_SIZE as usize];
                backend
                    .memory
                    .read_raw(backend.syscall_frame_address, &mut frame_after)
                    .unwrap();
                backend
                    .memory
                    .read_raw(exception_page, &mut exception_after)
                    .unwrap();
                assert_eq!(frame_after, frame_before);
                assert_eq!(exception_after, exception_before);
                assert_eq!(backend.vcpu.get_regs().unwrap(), fault.halted_registers);
                assert_eq!(backend.vcpu.get_sregs().unwrap(), fault.special_registers);
                assert_eq!(backend.vcpu.get_xsave().unwrap().region, fault.xsave.region);
            }
        }
    }

    fn check_fatal_process_registration_preserves_memory(with_tool: bool, writable: bool) {
        let mut parent = match KvmBackend::new(16 * 1024 * 1024) {
            Ok(backend) => backend,
            Err(error) => {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "KVM is required: {error}"
                );
                eprintln!("skipping fatal-process KVM test: {error}");
                return;
            }
        };
        let mut code = vec![0xb8];
        code.extend_from_slice(&(libc::SYS_getpid as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x31, 0xe4, 0xb8]);
        code.extend_from_slice(&(libc::SYS_rt_sigreturn as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        parent
            .install_static_elf(&minimal_test_elf(&code), "/bin/fatal-process-memory")
            .unwrap();
        let mut executor = ElfExecutor::new(parent.static_elf.take().unwrap(), true);
        match parent
            .vcpu
            .run()
            .unwrap()
            .expect("test entry admission was unexpectedly closed")
        {
            VcpuExit::Hypercall(exit) => {
                assert_eq!(exit.nr, VMCALL_SYSCALL_TRANSPORT);
                *exit.ret = 0;
            }
            other => panic!("unexpected initial boundary: {other:?}"),
        }
        parent
            .memory
            .map_user_permissions(0x80_0000, 4096, true, writable)
            .unwrap();
        parent.memory.write(0x80_0000, &[0x5a; 4096]).unwrap();
        let mut child = parent
            .prepare_forked_process(
                &executor, 2, None, None, None, None, false, false, true, None,
            )
            .unwrap();
        assert_eq!(
            child.executor.execute(
                &SyscallRequest::new(libc::SYS_set_tid_address as u64, [0x80_0000, 0, 0, 0, 0, 0]),
                &child.backend.memory
            ),
            2
        );
        let memory = child.backend.memory.clone();
        let log = Arc::new(FatalProcessMemoryLog::default());
        *log.memory.lock().unwrap() = Some(memory.clone());
        let (status, stdout, stderr) = if with_tool {
            futures::executor::block_on(child.backend.run_static_elf_process_with_tool(
                &mut child.executor,
                Pid::from_raw(2),
                Pid::from_raw(2),
                Arc::new(FatalProcessMemoryTool),
                (),
                log.clone(),
                &(),
                &reverie::Subscription::none(),
                false,
                None,
            ))
            .unwrap()
        } else {
            child
                .backend
                .run_static_elf_process(&mut child.executor)
                .unwrap()
        };
        let mut before_wrapper = [0; 4096];
        memory.read(0x80_0000, &mut before_wrapper).unwrap();
        parent
            .finish_forked_process(&mut executor, child, status, stdout.clone(), stderr.clone())
            .unwrap();
        let mut after_wrapper = [0; 4096];
        memory.read(0x80_0000, &mut after_wrapper).unwrap();
        assert_eq!(status.into_raw(), libc::SIGSEGV | 0x80);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
        if with_tool {
            assert_eq!(
                *log.observations.lock().unwrap(),
                vec![(libc::SIGSEGV | 0x80, vec![0x5a; 4096])]
            );
        } else {
            assert!(log.observations.lock().unwrap().is_empty());
        }
        assert_eq!(before_wrapper, [0x5a; 4096]);
        assert_eq!(after_wrapper, [0x5a; 4096]);
        parent
            .memory
            .map_user_permissions(0x80_0000, 4096, true, true)
            .unwrap();
        let request = SyscallRequest::new(
            libc::SYS_wait4 as u64,
            [2, 0x80_0000, libc::WNOHANG as u64, 0, 0, 0],
        );
        assert_eq!(executor.execute(&request, &parent.memory), 2);
        let mut wait_status = [0; 4];
        parent.memory.read(0x80_0000, &mut wait_status).unwrap();
        assert_eq!(i32::from_ne_bytes(wait_status), libc::SIGSEGV | 0x80);
    }

    #[test]
    fn fatal_process_registration_preserves_rw_memory_with_tool() {
        check_fatal_process_registration_preserves_memory(true, true);
    }

    #[test]
    fn fatal_process_registration_preserves_ro_memory_with_tool() {
        check_fatal_process_registration_preserves_memory(true, false);
    }

    #[test]
    fn fatal_process_registration_preserves_rw_memory_direct() {
        check_fatal_process_registration_preserves_memory(false, true);
    }

    #[test]
    fn fatal_process_registration_preserves_ro_memory_direct() {
        check_fatal_process_registration_preserves_memory(false, false);
    }

    #[derive(Default)]
    struct FatalWorkerMemoryLog {
        memory: Mutex<Option<GuestMemory>>,
        group: Mutex<Option<Arc<GuestThreadGroup>>>,
        address: Mutex<u64>,
        observations: Mutex<Vec<(i32, usize, Vec<u8>)>>,
        start_ready: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        start_release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        wake_observed: Mutex<Option<std::sync::mpsc::Receiver<Option<usize>>>>,
        wake_slots: Mutex<Vec<Option<usize>>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for FatalWorkerMemoryLog {
        type Request = i32;
        type Response = ();
        type Config = bool;

        async fn receive_rpc(&self, _from: Pid, status: i32) {
            if status == -1 {
                if let Some(sender) = self.start_ready.lock().unwrap().take() {
                    sender.send(()).unwrap();
                    self.start_release
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap()
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                }
                return;
            }
            if let Some(receiver) = self.wake_observed.lock().unwrap().take() {
                self.wake_slots.lock().unwrap().push(
                    receiver
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap_or(None),
                );
            }
            let group = self.group.lock().unwrap().as_ref().unwrap().clone();
            let slot = group.reserve_transport_slot(3).unwrap();
            group.release_transport_slot(slot);
            let mut memory = self.memory.lock().unwrap();
            let memory = memory.as_mut().unwrap();
            let mut bytes = vec![0; 8192];
            memory.read_raw(0x80_0000, &mut bytes).unwrap();
            self.observations
                .lock()
                .unwrap()
                .push((status, slot, bytes));
            memory
                .write_raw(
                    *self.address.lock().unwrap(),
                    &0x6b6b_6b6b_i32.to_ne_bytes(),
                )
                .unwrap();
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct FatalWorkerMemoryTool {
        fail_callback: bool,
    }

    #[reverie::tool]
    impl Tool for FatalWorkerMemoryTool {
        type GlobalState = FatalWorkerMemoryLog;
        type ThreadState = ();

        fn new(_pid: Pid, fail_callback: &bool) -> Self {
            Self {
                fail_callback: *fail_callback,
            }
        }

        async fn handle_thread_start<G: reverie::Guest<Self>>(
            &self,
            guest: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            guest.send_rpc(-1).await;
            Ok(())
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            _tid: Pid,
            global: &G,
            _state: (),
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc(status.into_raw()).await;
            if self.fail_callback {
                return Err(reverie::syscalls::Errno::EIO.into());
            }
            Ok(())
        }
    }

    fn qualify_waiter_enrollment(
        host: u64,
        result_receiver: &std::sync::mpsc::Receiver<(i64, Option<i32>)>,
    ) {
        // This additional wait only obtains diagnostics after enrollment has
        // already failed. It never retries or extends the futex's own bound.
        let waiter_result = || result_receiver.recv_timeout(std::time::Duration::from_secs(1));
        let parking = std::sync::atomic::AtomicI32::new(0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            let moved = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    host,
                    libc::FUTEX_CMP_REQUEUE,
                    0,
                    1_usize,
                    parking.as_ptr(),
                    0x5a5a_5a5a_i32,
                )
            };
            assert!(
                (0..=1).contains(&moved),
                "futex enrollment returned {moved}: {}; waiter result: {:?}",
                std::io::Error::last_os_error(),
                waiter_result()
            );
            if moved == 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "waiter did not enroll; waiter result: {:?}",
                waiter_result()
            );
            std::thread::yield_now();
        }
        let returned = unsafe {
            libc::syscall(
                libc::SYS_futex,
                parking.as_ptr(),
                libc::FUTEX_CMP_REQUEUE,
                0,
                1_usize,
                host,
                0,
            )
        };
        assert_eq!(
            returned,
            1,
            "waiter must be queued at its original word; waiter result: {:?}",
            waiter_result()
        );
        assert_eq!(parking.load(Ordering::Relaxed), 0);
    }

    fn check_fatal_worker_memory(mode: u8, fail_callback: bool, cancel_before_start: bool) {
        check_fatal_worker_memory_with_waiter_delay(
            mode,
            fail_callback,
            cancel_before_start,
            std::time::Duration::ZERO,
        );
    }

    fn check_fatal_worker_memory_with_waiter_delay(
        mode: u8,
        fail_callback: bool,
        cancel_before_start: bool,
        waiter_delay: std::time::Duration,
    ) {
        let Some((mut parent, mut executor, boundary)) = backend_at_completed_tool_boundary()
        else {
            return;
        };
        let mut code = vec![0x31, 0xe4, 0xb8];
        code.extend_from_slice(&(libc::SYS_rt_sigreturn as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, 0x0f, 0x0b]);
        let registers = process_syscall_return_registers(
            &parent.memory,
            parent.vcpu.get_regs().unwrap(),
            boundary.frame_address,
            0,
            None,
        )
        .unwrap();
        parent.memory.write_raw(registers.rip, &code).unwrap();
        parent
            .memory
            .map_user_permissions(0x80_0000, 8192, true, true)
            .unwrap();
        parent.memory.write(0x80_0000, &[0x5a; 8192]).unwrap();
        let offset = if mode == 3 { 4094 } else { 64 };
        let address = 0x80_0000 + offset;
        match mode {
            0 => {}
            1 => parent
                .memory
                .map_user_permissions(0x80_0000, 4096, true, false)
                .unwrap(),
            2 => parent
                .memory
                .map_user_permissions(0x80_0000, 4096, false, false)
                .unwrap(),
            3 => parent
                .memory
                .map_user_permissions(0x80_1000, 4096, true, false)
                .unwrap(),
            _ => unreachable!(),
        }
        let log = Arc::new(FatalWorkerMemoryLog::default());
        *log.memory.lock().unwrap() = Some(parent.memory.clone());
        *log.group.lock().unwrap() = Some(parent.thread_group.clone());
        *log.address.lock().unwrap() = address;
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        if cancel_before_start {
            *log.start_ready.lock().unwrap() = Some(started_sender);
            *log.start_release.lock().unwrap() = Some(release_receiver);
        }
        let starts = Arc::new(Mutex::new(Vec::new()));
        parent.thread_ownership = ThreadOwnership::Tool;
        let context = ToolContext::<FatalWorkerMemoryTool> {
            process_state: Arc::new(FatalWorkerMemoryTool { fail_callback }),
            pid: Pid::from_raw(1),
            tid: Pid::from_raw(1),
            thread_state: &(),
            global_state: Some(log.clone()),
            config: fail_callback,
            subscriptions: reverie::Subscription::none(),
            pending_child_starts: starts.clone(),
        };
        let action = ProcessAction::Thread {
            child_tid: 2,
            child_stack: registers.rsp,
            parent_tid: None,
            child_tid_address: None,
            clear_child_tid: Some(address),
            tls: None,
        };
        let outcome = futures::executor::block_on(parent.run_process_action_with_tool_at_boundary(
            &mut executor,
            action,
            context,
            ProcessActionContinuation::Restore(Box::new(boundary)),
        ))
        .unwrap();
        assert_eq!(outcome, ProcessActionOutcome::returned(2));
        let waiter = if mode < 2 {
            let memory = parent.memory.clone();
            let group = parent.thread_group.clone();
            let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
            let (wake_sender, wake_receiver) = std::sync::mpsc::channel();
            let (result_sender, result_receiver) = std::sync::mpsc::channel();
            *log.wake_observed.lock().unwrap() = Some(wake_receiver);
            let waiter = std::thread::spawn(move || {
                let host = memory.host_address() + address - memory.guest_base();
                let bound = libc::timespec {
                    tv_sec: 1,
                    tv_nsec: 0,
                };
                ready_sender.send(()).unwrap();
                std::thread::sleep(waiter_delay);
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_futex,
                        host,
                        libc::FUTEX_WAIT,
                        0x5a5a_5a5a_i32,
                        &bound,
                        0,
                        0,
                    )
                };
                let error = if result < 0 {
                    std::io::Error::last_os_error().raw_os_error()
                } else {
                    None
                };
                // Retain the exact syscall result even when enrollment fails
                // before the test reaches JoinHandle::join below.
                let _ = result_sender.send((result, error));
                let slot = if result == 0 {
                    let slot = group.reserve_transport_slot(4).unwrap();
                    group.release_transport_slot(slot);
                    Some(slot)
                } else {
                    None
                };
                wake_sender.send(slot).unwrap();
                (result, error)
            });
            ready_receiver
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            qualify_waiter_enrollment(
                parent.memory.host_address() + address - parent.memory.guest_base(),
                &result_receiver,
            );
            Some(waiter)
        } else {
            None
        };
        crate::runtime::start_pending_children(&starts).unwrap();
        if cancel_before_start {
            started_receiver
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
            parent.thread_group.cancel_workers();
            release_sender.send(()).unwrap();
        }
        parent.thread_group.join_workers();
        let wake = waiter.map(|waiter| waiter.join().unwrap());
        let observations = log.observations.lock().unwrap().clone();
        let mut expected = vec![0x5a; 8192];
        if mode == 0 {
            expected[offset as usize..offset as usize + 4].fill(0);
        }
        let expected_status = if cancel_before_start {
            0
        } else {
            libc::SIGSEGV | 0x80
        };
        assert_eq!(observations, vec![(expected_status, 0, expected.clone())]);
        expected[offset as usize..offset as usize + 4].fill(0x6b);
        let mut actual = vec![0; 8192];
        parent.memory.read_raw(0x80_0000, &mut actual).unwrap();
        assert_eq!(actual, expected);
        if mode < 2 {
            assert_eq!(wake, Some((0, None)));
            assert_eq!(*log.wake_slots.lock().unwrap(), vec![Some(0)]);
        }
    }

    #[test]
    fn fatal_worker_rw_store_wake_and_slot_release() {
        check_fatal_worker_memory(0, false, false);
    }
    #[test]
    fn fatal_worker_ro_failed_store_still_wakes() {
        check_fatal_worker_memory(1, false, false);
    }
    #[test]
    fn fatal_worker_ro_delayed_waiter_qualifies() {
        check_fatal_worker_memory_with_waiter_delay(
            1,
            false,
            false,
            std::time::Duration::from_millis(150),
        );
    }
    #[test]
    fn fatal_worker_rw_delayed_waiter_qualifies() {
        check_fatal_worker_memory_with_waiter_delay(
            0,
            false,
            false,
            std::time::Duration::from_millis(150),
        );
    }
    #[test]
    fn fatal_worker_none_preserves_full_memory() {
        check_fatal_worker_memory(2, false, false);
    }
    #[test]
    fn fatal_worker_crossing_scalar_preserves_full_memory() {
        check_fatal_worker_memory(3, false, false);
    }
    #[test]
    fn fatal_worker_callback_error_prevents_second_store() {
        check_fatal_worker_memory(0, true, false);
    }
    #[test]
    fn fatal_worker_cancelled_start_preserves_clear_order() {
        check_fatal_worker_memory(0, false, true);
    }

    #[test]
    fn failed_boundary_finalization_cancels_and_joins_each_typed_child() {
        let mut backend = match KvmBackend::new(0x10_000) {
            Ok(backend) => backend,
            Err(error) => {
                if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                    panic!("KVM is required: {error}");
                }
                eprintln!("skipping boundary-cleanup KVM test: {error}");
                return;
            }
        };
        let mut executor = test_executor();
        let starts = Arc::new(Mutex::new(Vec::new()));

        let fork_cancelled = Arc::new(AtomicBool::new(false));
        let fork_cancelled_in_child = fork_cancelled.clone();
        let (fork_sender, fork_receiver) = std::sync::mpsc::channel();
        let fork_gate = ChildStartGate::new(fork_sender);
        let fork_completion = Arc::new(ChildCompletionSlot::default());
        let fork_handle = ChildThread::spawn(move || match fork_receiver.recv() {
            Ok(ChildStartCommand::CancelAfterFailure) => {
                fork_cancelled_in_child.store(true, Ordering::Release);
                Ok(())
            }
            other => Err(Error::UnexpectedVcpuExit(format!(
                "unstarted test process received {other:?}"
            ))),
        });
        executor.register_child_process_with_gate(
            41,
            fork_gate.clone(),
            fork_completion,
            fork_handle,
        );
        starts
            .lock()
            .unwrap()
            .push(PendingChildStart::fork_process(41, fork_gate));

        let thread_cancelled = Arc::new(AtomicBool::new(false));
        let thread_cancelled_in_child = thread_cancelled.clone();
        let (thread_sender, thread_receiver) = std::sync::mpsc::channel();
        let thread_gate = ChildStartGate::new(thread_sender);
        let thread_handle = std::thread::spawn(move || {
            match thread_receiver.recv() {
                Ok(ChildStartCommand::CancelAfterFailure) => {
                    thread_cancelled_in_child.store(true, Ordering::Release);
                }
                other => panic!("unstarted test thread received {other:?}"),
            }
            Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
        });
        backend
            .thread_group
            .add_unstarted_worker(42, thread_gate.clone(), thread_handle);
        starts
            .lock()
            .unwrap()
            .push(PendingChildStart::tool_thread(42, thread_gate));

        let mut boundary = CompletedSyscallBoundary::for_test();
        boundary.frame_address = backend.memory.guest_end();
        let error = backend
            .finish_tool_process_action_at_boundary(
                &mut executor,
                &starts,
                ProcessActionContinuation::Restore(Box::new(boundary)),
                Ok(ProcessActionOutcome::returned(42)),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidGuestAddress { address, length, .. }
                if address == backend.memory.guest_end() && length == FRAME_SIZE
        ));
        assert!(fork_cancelled.load(Ordering::Acquire));
        assert!(thread_cancelled.load(Ordering::Acquire));
        assert!(starts.lock().unwrap().is_empty());
        assert!(!executor.discard_unstarted_child_process(41).unwrap());
        assert!(!backend.thread_group.discard_unstarted_worker(42).unwrap());
    }

    #[test]
    fn injected_boundary_error_defers_each_child_until_callback_destruction() {
        use std::sync::atomic::AtomicUsize;

        struct CallbackGuard(Arc<AtomicBool>);
        impl Drop for CallbackGuard {
            fn drop(&mut self) {
                assert!(!self.0.swap(true, Ordering::SeqCst));
            }
        }

        for exec_failure in [false, true] {
            let mut backend = KvmBackend::new(0x10_000).expect("this control requires /dev/kvm");
            let mut executor = test_executor();
            let starts = Arc::new(Mutex::new(Vec::new()));
            let log = Arc::new(GateFailureLog::default());
            let failure = crate::failure::RunFailure::new(&log);
            backend.set_tool_failure(Some(crate::failure::FailureContext::new(
                failure.clone(),
                Pid::from_raw(1),
                Pid::from_raw(1),
            )));
            let destroyed = Arc::new(AtomicBool::new(false));
            let consumed = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
            let child_error = Arc::new(Error::GuestClock("child cleanup error".to_owned()));

            let (fork_sender, fork_receiver) = std::sync::mpsc::channel();
            let fork_gate = ChildStartGate::new(fork_sender);
            let child_destroyed = destroyed.clone();
            let child_consumed = consumed.clone();
            let child_failure = failure.clone();
            let fork_handle = ChildThread::spawn(move || {
                assert_eq!(
                    fork_receiver.recv().unwrap(),
                    ChildStartCommand::CancelAfterFailure
                );
                assert!(child_destroyed.load(Ordering::SeqCst));
                assert!(child_failure.published_primary().is_some());
                assert_eq!(child_consumed[0].fetch_add(1, Ordering::SeqCst), 0);
                Err(Error::RunAborted)
            });
            executor.register_child_process_with_gate(
                41,
                fork_gate.clone(),
                Arc::new(ChildCompletionSlot::default()),
                fork_handle,
            );
            starts
                .lock()
                .unwrap()
                .push(PendingChildStart::fork_process(41, fork_gate.clone()));

            let (thread_sender, thread_receiver) = std::sync::mpsc::channel();
            let thread_gate = ChildStartGate::new(thread_sender);
            let child_destroyed = destroyed.clone();
            let child_consumed = consumed.clone();
            let child_failure = failure.clone();
            let child_cause = child_error.clone();
            let thread_handle = std::thread::spawn(move || {
                assert_eq!(
                    thread_receiver.recv().unwrap(),
                    ChildStartCommand::CancelAfterFailure
                );
                assert!(child_destroyed.load(Ordering::SeqCst));
                assert!(child_failure.published_primary().is_some());
                assert_eq!(child_consumed[1].fetch_add(1, Ordering::SeqCst), 0);
                Err(Error::SharedFailure(child_cause))
            });
            backend
                .thread_group
                .add_unstarted_worker(42, thread_gate.clone(), thread_handle);
            starts
                .lock()
                .unwrap()
                .push(PendingChildStart::tool_thread(42, thread_gate.clone()));

            let action_cleanup = Arc::new(Error::GuestClock("action cleanup error".to_owned()));
            let action_cause = Arc::new(
                Error::HostIo(std::io::Error::from_raw_os_error(libc::EAGAIN))
                    .with_cleanup(vec![Error::SharedFailure(action_cleanup)]),
            );
            let action_error = Error::SharedFailure(action_cause.clone());
            let action_error = if exec_failure {
                Error::ExecWorkerTeardown(Box::new(action_error))
            } else {
                action_error
            };
            let callback = CallbackGuard(destroyed.clone());
            // An action error must win without attempting this invalid restore.
            let mut boundary = CompletedSyscallBoundary::for_test();
            boundary.frame_address = backend.memory.guest_end();
            let error = backend
                .finish_injected_tool_process_action_at_boundary(
                    ProcessActionContinuation::Restore(Box::new(boundary)),
                    Err(action_error),
                )
                .unwrap_err();
            let inner = match (&error, exec_failure) {
                (Error::ExecWorkerTeardown(inner), true) => inner.as_ref(),
                (error, false) => error,
                _ => panic!("injected action lost its exec teardown disposition"),
            };
            let Error::SharedFailure(actual) = inner else {
                panic!("injected action changed its original typed error");
            };
            assert!(Arc::ptr_eq(actual, &action_cause));
            assert!(!destroyed.load(Ordering::SeqCst));
            assert!(failure.published_primary().is_none());
            assert!(log.failures.lock().unwrap().is_empty());
            assert_eq!(starts.lock().unwrap().len(), 2);
            assert!(fork_gate.is_pending());
            assert!(thread_gate.is_pending());
            assert_eq!(consumed[0].load(Ordering::SeqCst), 0);
            assert_eq!(consumed[1].load(Ordering::SeqCst), 0);
            assert!(executor.has_pending_child_process(41));
            assert!(backend.thread_group.has_worker_handles());

            drop(callback);
            let error =
                backend.cleanup_unstarted_tool_children_after_error(&mut executor, &starts, error);
            let inner = match (&error, exec_failure) {
                (Error::ExecWorkerTeardown(inner), true) => inner.as_ref(),
                (error, false) => error,
                _ => panic!("outer cleanup lost its exec teardown disposition"),
            };
            let Error::WithCleanup { primary, cleanup } = inner else {
                panic!("outer cleanup lost the child's real error");
            };
            assert!(primary.retains_primary(&action_cause));
            assert_eq!(cleanup.len(), 1);
            assert!(cleanup[0].retains_primary(&child_error));
            assert!(matches!(
                error.primary(),
                Error::HostIo(error) if error.raw_os_error() == Some(libc::EAGAIN)
            ));
            assert_eq!(log.failures.lock().unwrap().len(), 1);
            assert_eq!(consumed[0].load(Ordering::SeqCst), 1);
            assert_eq!(consumed[1].load(Ordering::SeqCst), 1);
            assert!(starts.lock().unwrap().is_empty());
            assert!(!executor.has_pending_child_process(41));
            assert!(!backend.thread_group.has_worker_handles());
            let error =
                backend.cleanup_unstarted_tool_children_after_error(&mut executor, &starts, error);
            assert!(error.retains_primary(&action_cause));
            assert_eq!(log.failures.lock().unwrap().len(), 1);
            assert_eq!(consumed[0].load(Ordering::SeqCst), 1);
            assert_eq!(consumed[1].load(Ordering::SeqCst), 1);
        }
    }

    #[derive(Default)]
    struct GateFailureLog {
        events: Mutex<Vec<(u8, i32, i32)>>,
        failures: Mutex<Vec<reverie::BackendFailure>>,
        wake: Mutex<Option<futures::channel::oneshot::Sender<()>>>,
        notification: Option<crate::failure::FailureSubscription>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    #[reverie::global_tool]
    impl GlobalTool for GateFailureLog {
        type Request = (u8, i32);
        type Response = ();
        type Config = ();

        async fn receive_rpc(&self, from: Pid, (kind, status): Self::Request) {
            self.events
                .lock()
                .unwrap()
                .push((kind, from.as_raw(), status));
        }

        fn report_backend_failure(&self, event: reverie::BackendFailure) {
            self.failures.lock().unwrap().push(event);
            // Model a Tool that has finished its terminal transition and woken
            // its subscribers, but has not yet returned to the local publisher.
            if let Some(wake) = self.wake.lock().unwrap().take() {
                let _ = wake.send(());
            }
            if let Some(release) = self.release.lock().unwrap().take() {
                release.recv().unwrap();
            }
        }

        async fn wait_for_backend_failure(&self) {
            if let Some(notification) = &self.notification {
                let _ = notification.clone().await;
            } else {
                std::future::pending::<()>().await;
            }
        }
    }

    #[derive(Default)]
    struct GateFailureTool;

    #[reverie::tool]
    impl Tool for GateFailureTool {
        type GlobalState = GateFailureLog;
        type ThreadState = i32;

        fn init_thread_state(&self, tid: Pid, _: Option<(Pid, &i32)>) -> i32 {
            tid.as_raw()
        }

        async fn handle_thread_start<G: reverie::Guest<Self>>(
            &self,
            _: &mut G,
        ) -> std::result::Result<(), reverie::Error> {
            panic!("cancelled constructed child entered its start callback")
        }

        async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
            &self,
            tid: Pid,
            global: &G,
            state: i32,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            assert_eq!(tid.as_raw(), state);
            global.send_rpc((1, conventional_exit_code(status))).await;
            Ok(())
        }

        async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
            self,
            _: Pid,
            global: &G,
            status: ExitStatus,
        ) -> std::result::Result<(), reverie::Error> {
            global.send_rpc((2, conventional_exit_code(status))).await;
            Ok(())
        }
    }

    // Install all rescue ownership before constructing a gated OS child.
    struct GateFailureCleanup {
        backend: KvmBackend,
        executor: ElfExecutor,
        starts: SharedChildStarts,
        release: Option<std::sync::mpsc::Sender<()>>,
        publisher: Option<std::thread::JoinHandle<Error>>,
        done: Option<std::sync::mpsc::Sender<()>>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for GateFailureCleanup {
        fn drop(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
            if let Some(publisher) = self.publisher.take() {
                let _ = publisher.join();
            }
            if let Some(done) = self.done.take() {
                let _ = done.send(());
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
            let _ = self
                .backend
                .discard_unstarted_tool_children(&mut self.executor, &self.starts);
            self.backend.cancel_guest_threads();
            let _ = self.executor.join_child_processes_after_failure();
        }
    }

    #[test]
    fn real_fork_and_thread_cancel_keep_status_while_terminal_hook_is_returning() {
        use futures::FutureExt;
        for thread in [false, true] {
            for fatal in [false, true] {
                let Some((backend, executor, boundary)) = backend_at_completed_tool_boundary()
                else {
                    return;
                };
                let starts = Arc::new(Mutex::new(Vec::new()));
                let mut cleanup = GateFailureCleanup {
                    backend,
                    executor,
                    starts: starts.clone(),
                    release: None,
                    publisher: None,
                    done: None,
                    watchdog: None,
                };
                cleanup.backend.thread_ownership = ThreadOwnership::Tool;
                let (wake, notification) = futures::channel::oneshot::channel();
                let (release, wait_release) = std::sync::mpsc::channel();
                cleanup.release = Some(release.clone());
                let global = Arc::new(GateFailureLog {
                    wake: Mutex::new(Some(wake)),
                    notification: Some(notification.shared()),
                    release: Mutex::new(Some(wait_release)),
                    ..Default::default()
                });
                let failure = crate::failure::RunFailure::new(&global);
                let context = crate::failure::FailureContext::new(
                    failure.clone(),
                    Pid::from_raw(1),
                    Pid::from_raw(1),
                );
                cleanup.backend.set_tool_failure(Some(context.clone()));
                let action = if thread {
                    ProcessAction::Thread {
                        child_tid: 2,
                        child_stack: boundary.registers.rsp,
                        parent_tid: None,
                        child_tid_address: None,
                        clear_child_tid: None,
                        tls: None,
                    }
                } else {
                    ProcessAction::Fork {
                        child_pid: 2,
                        child_stack: None,
                        parent_tid: None,
                        child_tid: None,
                        clear_child_tid: None,
                        clear_sighand: false,
                        share_address_space: false,
                    }
                };
                let continuation = ProcessActionContinuation::from_captured(&action, boundary);
                let tool_context = ToolContext::<GateFailureTool> {
                    process_state: Arc::new(GateFailureTool),
                    pid: Pid::from_raw(1),
                    tid: Pid::from_raw(1),
                    thread_state: &1,
                    global_state: Some(global.clone()),
                    config: (),
                    subscriptions: reverie::Subscription::none(),
                    pending_child_starts: starts.clone(),
                };
                let result = futures::executor::block_on(
                    cleanup.backend.run_process_action_with_tool_at_boundary(
                        &mut cleanup.executor,
                        action,
                        tool_context,
                        continuation,
                    ),
                )
                .unwrap();
                assert_eq!(result, ProcessActionOutcome::returned(2));
                assert_eq!(starts.lock().unwrap().len(), 1);
                let rescued = Arc::new(AtomicBool::new(false));
                let result = if fatal {
                    let (done, wait_done) = std::sync::mpsc::channel();
                    cleanup.done = Some(done);
                    let watchdog_rescued = rescued.clone();
                    let watchdog_global = global.clone();
                    cleanup.watchdog = Some(std::thread::spawn(move || {
                        if wait_done
                            .recv_timeout(std::time::Duration::from_secs(2))
                            .is_err()
                        {
                            watchdog_rescued.store(true, Ordering::Release);
                            if let Some(wake) = watchdog_global.wake.lock().unwrap().take() {
                                let _ = wake.send(());
                            }
                            let _ = release.send(());
                        }
                    }));
                    cleanup.publisher = Some(std::thread::spawn(move || {
                        context.publish(
                            "controlled terminal transition",
                            Error::GuestClock("gate primary".to_owned()),
                        )
                    }));
                    futures::executor::block_on(global.wait_for_backend_failure());
                    assert!(failure.published_primary().is_none());
                    assert!(
                        failure.subscribe().now_or_never().is_none(),
                        "local wake escaped the Tool hook"
                    );
                    let result = cleanup.backend.cleanup_unstarted_tool_children_after_error(
                        &mut cleanup.executor,
                        &starts,
                        Error::RunAborted,
                    );
                    assert!(
                        failure.published_primary().is_none(),
                        "child cleanup waited for hook return"
                    );
                    Err(result)
                } else {
                    cleanup
                        .backend
                        .discard_unstarted_tool_children(&mut cleanup.executor, &starts)
                };
                let status = if fatal { 255 } else { 0 };
                let mut expected = vec![(1, 2, status)];
                if !thread {
                    expected.push((2, 2, status));
                }
                assert_eq!(*global.events.lock().unwrap(), expected);
                assert!(starts.lock().unwrap().is_empty());
                assert!(!cleanup.executor.has_pending_child_process(2));
                assert!(!cleanup.backend.thread_group.has_worker_handles());
                if fatal {
                    assert!(
                        !rescued.load(Ordering::Acquire),
                        "watchdog released a blocked cleanup"
                    );
                    cleanup.release.take().unwrap().send(()).unwrap();
                    let published = cleanup.publisher.take().unwrap().join().unwrap();
                    cleanup.done.take().unwrap().send(()).unwrap();
                    cleanup.watchdog.take().unwrap().join().unwrap();
                    assert!(
                        matches!(published.primary(), Error::GuestClock(message) if message == "gate primary")
                    );
                    let result = failure.complete(result).unwrap_err();
                    assert!(
                        matches!(result.primary(), Error::GuestClock(message) if message == "gate primary")
                    );
                    assert_eq!(
                        *global.failures.lock().unwrap(),
                        vec![reverie::BackendFailure {
                            pid: Pid::from_raw(1),
                            tid: Pid::from_raw(1),
                            phase: "controlled terminal transition",
                        }]
                    );
                } else {
                    result.unwrap();
                    assert!(global.failures.lock().unwrap().is_empty());
                }
            }
        }
    }

    pub(crate) fn minimal_test_elf(code: &[u8]) -> Vec<u8> {
        const LOAD_ADDRESS: u64 = 0x20_0000;
        const CODE_OFFSET: usize = 0x1000;
        let mut image = vec![0; CODE_OFFSET + code.len()];
        let put_u16 = |image: &mut [u8], offset: usize, value: u16| {
            image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        };
        let put_u32 = |image: &mut [u8], offset: usize, value: u32| {
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        let put_u64 = |image: &mut [u8], offset: usize, value: u64| {
            image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };

        image[..4].copy_from_slice(b"\x7fELF");
        image[4] = 2;
        image[5] = 1;
        image[6] = 1;
        put_u16(&mut image, 16, 2);
        put_u16(&mut image, 18, 62);
        put_u32(&mut image, 20, 1);
        put_u64(&mut image, 24, LOAD_ADDRESS);
        put_u64(&mut image, 32, 64);
        put_u16(&mut image, 52, 64);
        put_u16(&mut image, 54, 56);
        put_u16(&mut image, 56, 1);
        put_u32(&mut image, 64, 1);
        put_u32(&mut image, 68, 5);
        put_u64(&mut image, 72, CODE_OFFSET as u64);
        put_u64(&mut image, 80, LOAD_ADDRESS);
        put_u64(&mut image, 88, LOAD_ADDRESS);
        put_u64(&mut image, 96, code.len() as u64);
        put_u64(&mut image, 104, 0x2000);
        put_u64(&mut image, 112, 0x1000);
        image[CODE_OFFSET..].copy_from_slice(code);
        image
    }

    #[test]
    fn timestamp_boundary_respects_hardware_instruction_fetch_fault_priority() {
        const BOUNDARY: u64 = 0x40_0000;
        for rdtscp in [false, true] {
            let mut backend = match KvmBackend::new(16 * 1024 * 1024) {
                Ok(backend) => backend,
                Err(Error::Kvm(error))
                    if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) =>
                {
                    assert!(
                        std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                        "timestamp boundary requires KVM: {error}"
                    );
                    eprintln!("skipping timestamp boundary: KVM unavailable: {error}");
                    return;
                }
                Err(error) => panic!("timestamp boundary setup failed: {error}"),
            };
            let opcode = if rdtscp {
                &[0x0f, 0x01, 0xf9][..]
            } else {
                &[0x0f, 0x31][..]
            };
            let mut code = vec![0x90; 0x20_0000 - 2];
            code.extend_from_slice(opcode);
            let mut image = minimal_test_elf(&code);
            image[24..32].copy_from_slice(&(BOUNDARY - 2).to_le_bytes());
            image[104..112].copy_from_slice(&(code.len() as u64).to_le_bytes());
            backend
                .install_static_elf(&image, "/bin/timestamp-fetch-boundary")
                .unwrap();
            // The next 2 MiB page is present/user but NX in the actual guest
            // page tables, not merely denied by a host-side test fetch closure.
            backend
                .memory
                .write_raw(
                    0x4000 + 2 * 8,
                    &(BOUNDARY | 0x87 | (1_u64 << 63)).to_le_bytes(),
                )
                .unwrap();
            backend.set_rdtsc_interception(true).unwrap();
            assert!(matches!(
                backend
                    .vcpu
                    .run()
                    .unwrap()
                    .expect("test entry admission was unexpectedly closed"),
                VcpuExit::Hlt
            ));
            let fault = backend.static_elf_exception().unwrap().unwrap();
            assert_eq!(fault.instruction_pointer, BOUNDARY - 2);
            assert_eq!(fault.vector, if rdtscp { 14 } else { 13 });
            let timestamp = backend.timestamp_counter_exception().unwrap();
            if rdtscp {
                assert!(
                    timestamp.is_none(),
                    "inaccessible third byte must not dispatch"
                );
            } else {
                let timestamp = timestamp.expect("two-byte instruction must not fetch next page");
                assert_eq!(timestamp.instruction.request, reverie::Rdtsc::Tsc);
                assert_eq!(timestamp.instruction.length, 2);
            }
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct NonElfTimestampTool;

    #[reverie::tool]
    impl Tool for NonElfTimestampTool {
        type GlobalState = ();
        type ThreadState = ();

        fn subscriptions(_: &()) -> reverie::Subscription {
            let mut subscriptions = reverie::Subscription::none();
            subscriptions.rdtsc();
            subscriptions
        }

        async fn handle_rdtsc_event<G: reverie::Guest<Self>>(
            &self,
            _guest: &mut G,
            _request: reverie::Rdtsc,
        ) -> std::result::Result<reverie::RdtscResult, reverie::syscalls::Errno> {
            panic!("the public non-ELF loop has no timestamp dispatch contract");
        }
    }

    #[test]
    fn non_elf_tool_loop_disarms_prior_timestamp_interception() {
        for prior_interception in [true, false] {
            let mut backend = match KvmBackend::new(16 * 1024 * 1024) {
                Ok(backend) => backend,
                Err(Error::Kvm(error))
                    if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) =>
                {
                    assert!(
                        std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                        "non-ELF timestamp ownership requires KVM: {error}"
                    );
                    eprintln!("skipping non-ELF timestamp ownership: KVM unavailable: {error}");
                    return;
                }
                Err(error) => panic!("non-ELF timestamp ownership setup failed: {error}"),
            };
            // Establish real hardware CR4.TSD plus the matching backend bit.
            // This tests entry-state ownership; it is not an ELF-image reuse test.
            backend.set_rdtsc_interception(prior_interception).unwrap();
            let request = SyscallRequest::new(libc::SYS_getpid as u64, [0; 6]);
            backend.install_syscall(0x1002, 0x2000, request).unwrap();
            backend.memory.write(0x1000, &[0x0f, 0x31]).unwrap();
            let mut registers = backend.vcpu.get_regs().unwrap();
            registers.rip = 0x1000;
            backend.vcpu.set_regs(&registers).unwrap();
            assert_eq!(backend.intercept_rdtsc, prior_interception);
            assert_eq!(
                backend.vcpu.get_sregs().unwrap().cr4 & (1 << 2) != 0,
                prior_interception
            );
            let mut calls = 0;
            futures::executor::block_on(backend.run_with_tool::<NonElfTimestampTool, _>(
                (),
                |actual: &SyscallRequest, _: &GuestMemory| {
                    assert_eq!(*actual, request);
                    calls += 1;
                    41
                },
            ))
            .unwrap();
            assert_eq!(calls, 1, "RDTSC must reach the following real vmcall");
            assert!(!backend.intercept_rdtsc);
            assert_eq!(backend.vcpu.get_sregs().unwrap().cr4 & (1 << 2), 0);
        }
    }

    fn backend_at_completed_tool_boundary()
    -> Option<(KvmBackend, ElfExecutor, CompletedSyscallBoundary)> {
        const MEMORY_SIZE: usize = 16 * 1024 * 1024;
        let mut backend = match KvmBackend::new(MEMORY_SIZE) {
            Ok(backend) => backend,
            Err(error) => {
                if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                    panic!("KVM is required: {error}");
                }
                eprintln!("skipping production-boundary cleanup KVM test: {error}");
                return None;
            }
        };
        let mut code = vec![0xb8]; // mov eax, SYS_getpid
        code.extend_from_slice(&(libc::SYS_getpid as u32).to_le_bytes());
        code.extend_from_slice(&[0x0f, 0x05, HLT]); // syscall; hlt
        backend
            .install_static_elf(&minimal_test_elf(&code), "/bin/boundary-cleanup-test")
            .unwrap();
        // This fixture later enters Tool lifecycle hooks. Start accounting
        // before its manual first guest entry, just as the production runner does.
        backend.vcpu.track_clock().unwrap();
        let mut executor = ElfExecutor::new(backend.static_elf.take().unwrap(), false);
        let frame_address = match backend
            .vcpu
            .run()
            .unwrap()
            .expect("test entry admission was unexpectedly closed")
        {
            VcpuExit::Hypercall(exit) => {
                assert_eq!(exit.nr, VMCALL_SYSCALL_TRANSPORT);
                *exit.ret = 0;
                exit.args[0]
            }
            exit => panic!("expected syscall hypercall, got {exit:?}"),
        };
        let boundary = CompletedSyscallBoundary::capture(&backend, frame_address, None).unwrap();
        // Keep the executor mutable in the return type to emphasize that the
        // wrapper owns both action registration and its rollback.
        executor.set_current_user_stack_pointer(boundary.registers.rsp);
        Some((backend, executor, boundary))
    }

    #[test]
    fn page_zero_translation_preserves_neighbor_and_upper_pages() {
        let Some((backend, _executor, _boundary)) = backend_at_completed_tool_boundary() else {
            return;
        };
        for address in (PAGE_SIZE..backend.memory.guest_end()).step_by(PAGE_SIZE as usize) {
            let translated = backend.vcpu.translate_gva(address).unwrap();
            assert_eq!(translated.valid, 1, "address {address:#x}");
            assert_eq!(translated.physical_address, address);
        }
        for address in [0, 1, PAGE_SIZE - 1] {
            assert_eq!(
                backend.vcpu.translate_gva(address).unwrap().valid,
                0,
                "address {address:#x}"
            );
        }
    }

    fn check_page_zero_table_lifetime(mode: &str) {
        let Some((mut parent, mut executor, _boundary)) = backend_at_completed_tool_boundary()
        else {
            return;
        };
        let mut before = [0_u8; PAGE_SIZE as usize];
        parent.memory.read_raw(0, &mut before).unwrap();
        match mode {
            "fork" => {
                let child =
                    KvmBackend::from_process_snapshot(parent.snapshot_process().unwrap()).unwrap();
                let mut after = [0_u8; PAGE_SIZE as usize];
                parent.memory.read_raw(0, &mut after).unwrap();
                assert_eq!(after, before);
                assert_eq!(child.vcpu.translate_gva(0).unwrap().valid, 0);
                assert_eq!(
                    child
                        .vcpu
                        .translate_gva(PAGE_SIZE)
                        .unwrap()
                        .physical_address,
                    PAGE_SIZE
                );
            }
            "thread" => {
                let child = KvmBackend::from_thread_state(
                    parent.memory.clone(),
                    parent.vcpu.get_regs().unwrap(),
                    parent.vcpu.get_xsave().unwrap(),
                    None,
                    parent.cpuid_policy,
                    2001,
                    parent.thread_group.clone(),
                )
                .unwrap();
                let mut after = [0_u8; PAGE_SIZE as usize];
                child.memory.read_raw(0, &mut after).unwrap();
                assert_eq!(after, before);
                assert_eq!(child.vcpu.translate_gva(0).unwrap().valid, 0);
                assert_eq!(
                    child
                        .vcpu
                        .translate_gva(child.syscall_frame_address)
                        .unwrap()
                        .physical_address,
                    child.syscall_frame_address
                );
            }
            "exec" => {
                parent
                    .exec_process(
                        &mut executor,
                        (Path::new("/page-zero-exec"), None),
                        &minimal_test_elf(&[HLT]),
                        &["/page-zero-exec".to_owned()],
                        &[],
                    )
                    .unwrap();
                assert_eq!(parent.vcpu.translate_gva(0).unwrap().valid, 0);
                assert_eq!(
                    parent
                        .vcpu
                        .translate_gva(parent.tool_stack_top() - PAGE_SIZE)
                        .unwrap()
                        .physical_address,
                    parent.tool_stack_top() - PAGE_SIZE
                );
            }
            _ => panic!("unknown page-zero lifetime mode"),
        }
    }

    #[test]
    fn page_zero_table_fork_lifetime() {
        check_page_zero_table_lifetime("fork");
    }

    #[test]
    fn page_zero_table_thread_lifetime() {
        check_page_zero_table_lifetime("thread");
    }

    #[test]
    fn page_zero_table_exec_lifetime() {
        check_page_zero_table_lifetime("exec");
    }

    #[test]
    fn started_tool_worker_observes_cancellation_after_start_lifecycle() {
        let Some((mut backend, root_executor, boundary)) = backend_at_completed_tool_boundary()
        else {
            return;
        };
        backend.is_guest_thread = true;
        let mut executor = root_executor.thread_child(2).unwrap();

        backend.thread_ownership = ThreadOwnership::Tool;
        let thread_group = backend.thread_group.clone();
        let global_state = Arc::new(CancellationLifecycleLog::default());
        let observed_state = global_state.clone();
        let clear_tid = boundary.registers.rsp - 16;
        backend
            .memory
            .write(clear_tid, &123_i32.to_le_bytes())
            .unwrap();
        executor.set_clear_child_tid(Some(clear_tid));
        *global_state.clear_tid.lock().unwrap() = Some((backend.memory.clone(), clear_tid));
        let registers = backend.vcpu.get_regs().unwrap();
        let (start_sender, start_receiver) = std::sync::mpsc::channel();
        let start_gate = ChildStartGate::new(start_sender);
        let (started_sender, started_receiver) = std::sync::mpsc::channel();
        let (continue_sender, continue_receiver) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Start);
            started_sender.send(()).unwrap();
            continue_receiver.recv().unwrap();
            let config = ();
            let subscriptions = reverie::Subscription::none();
            let (status, stdout, stderr) =
                futures::executor::block_on(backend.run_static_elf_process_with_tool(
                    &mut executor,
                    Pid::from_raw(1),
                    Pid::from_raw(2),
                    Arc::new(CancellationLifecycleTool),
                    (),
                    global_state,
                    &config,
                    &subscriptions,
                    false,
                    None,
                ))
                .unwrap();
            assert_eq!(status, ExitStatus::SUCCESS);
            assert!(stdout.is_empty());
            assert!(stderr.is_empty());
            assert_eq!(backend.vcpu.get_regs().unwrap(), registers);
            Ok((status, stdout, stderr))
        });
        thread_group.add_unstarted_worker(2, start_gate.clone(), handle);

        assert_eq!(start_gate.start(), Ok(true));
        started_receiver.recv().unwrap();
        // The gate is Started but the worker has not registered its pthread.
        // Cancellation must be observed after handle_thread_start and before
        // the first vCPU entry even though the pthread scan cannot see it yet.
        thread_group.cancel_workers();
        continue_sender.send(()).unwrap();
        thread_group.join_workers();

        assert_eq!(
            *observed_state.events.lock().unwrap(),
            vec![1, 2],
            "handle_thread_start must precede thread exit lifecycle",
        );
        assert_eq!(
            *observed_state
                .clear_tid_value_at_thread_exit
                .lock()
                .unwrap(),
            Some(0),
            "CHILD_CLEARTID must be zero before on_exit_thread",
        );
    }

    fn assert_production_wrapper_cleans_failed_action(
        action: ProcessAction,
        child: PendingChildKind,
    ) {
        let Some((mut backend, mut executor, mut boundary)) = backend_at_completed_tool_boundary()
        else {
            return;
        };
        if matches!(action, ProcessAction::Thread { .. }) {
            backend.thread_ownership = ThreadOwnership::Tool;
        }
        boundary.frame_address = backend.memory.guest_end();
        let starts = Arc::new(Mutex::new(Vec::new()));
        let thread_state = ();
        let global_state = Arc::new(crate::StraceLog::default());
        let context = ToolContext::<crate::StraceTool> {
            process_state: Arc::new(crate::StraceTool),
            pid: Pid::from_raw(1),
            tid: Pid::from_raw(1),
            thread_state: &thread_state,
            global_state: Some(global_state),
            config: (),
            subscriptions: reverie::Subscription::none(),
            pending_child_starts: starts.clone(),
        };
        let error = futures::executor::block_on(backend.run_process_action_with_tool_at_boundary(
            &mut executor,
            action,
            context,
            ProcessActionContinuation::Restore(Box::new(boundary)),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            Error::InvalidGuestAddress { address, length, .. }
                if address == backend.memory.guest_end() && length == FRAME_SIZE
        ));

        let starts_were_empty = starts.lock().unwrap().is_empty();
        let child_was_absent = match child {
            PendingChildKind::ForkProcess(pid) => {
                let absent = !executor.has_pending_child_process(pid);
                if !absent {
                    // Keep a failing mutation bounded even if it wrongly started
                    // the child instead of cancelling and removing it.
                    let _ = executor.join_all_child_processes();
                }
                absent
            }
            PendingChildKind::ToolThread(tid) => {
                let present = backend
                    .thread_group
                    .worker_handles
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|worker| worker.tid == tid);
                if present {
                    let gates = backend
                        .thread_group
                        .worker_handles
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|worker| worker.tid == tid)
                        .filter_map(|worker| worker.start.clone())
                        .collect::<Vec<_>>();
                    for gate in gates {
                        let _ = gate.cancel();
                    }
                    let _ = backend.thread_group.discard_unstarted_worker(tid);
                }
                !present
            }
        };
        assert!(
            starts_were_empty,
            "wrapper left an unresolved child-start entry"
        );
        assert!(
            child_was_absent,
            "wrapper left the failed action registered"
        );
    }

    #[test]
    fn production_wrapper_cleans_fork_after_boundary_restore_failure() {
        assert_production_wrapper_cleans_failed_action(
            ProcessAction::Fork {
                child_pid: 41,
                child_stack: None,
                parent_tid: None,
                child_tid: None,
                clear_child_tid: None,
                clear_sighand: false,
                share_address_space: false,
            },
            PendingChildKind::ForkProcess(41),
        );
    }

    #[test]
    fn production_wrapper_cleans_tool_thread_after_boundary_restore_failure() {
        assert_production_wrapper_cleans_failed_action(
            ProcessAction::Thread {
                child_tid: 42,
                child_stack: 0x80_0000,
                parent_tid: None,
                child_tid_address: None,
                clear_child_tid: None,
                tls: None,
            },
            PendingChildKind::ToolThread(42),
        );
    }

    #[test]
    fn callback_local_start_does_not_release_an_unrelated_shared_fork() {
        let mut backend = match KvmBackend::new(0x10_000) {
            Ok(backend) => backend,
            Err(error) => {
                if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                    panic!("KVM is required: {error}");
                }
                eprintln!("skipping callback-local child-start test: {error}");
                return;
            }
        };
        let mut leader = test_executor();
        let mut sibling = leader.thread_child(2).unwrap();

        let (first_sender, first_receiver) = std::sync::mpsc::channel();
        let first_gate = ChildStartGate::new(first_sender);
        let mut child = leader.fork_child(41, false, false).unwrap();
        let child_id = child.signal_task_identity().unwrap().process;
        child.retire_current_thread(ExitStatus::SUCCESS, false);
        let first_completion = Arc::new(ChildCompletionSlot::default());
        leader
            .publish_child_wait(
                child_id,
                ChildCompletion::Waitable(ExitStatus::SUCCESS),
                &first_completion,
                false,
            )
            .unwrap();
        leader.register_child_process_with_gate(
            41,
            first_gate.clone(),
            first_completion,
            ChildThread::spawn(|| Ok(())),
        );

        let (second_sender, second_receiver) = std::sync::mpsc::channel();
        let second_gate = ChildStartGate::new(second_sender);
        sibling.register_child_process_with_gate(
            42,
            second_gate,
            Arc::new(ChildCompletionSlot::default()),
            ChildThread::spawn(|| Ok(())),
        );

        let starts = Arc::new(Mutex::new(vec![PendingChildStart::fork_process(
            41, first_gate,
        )]));
        backend
            .start_pending_tool_children(&mut leader, &starts)
            .unwrap();
        assert!(starts.lock().unwrap().is_empty());
        assert_eq!(first_receiver.recv().unwrap(), ChildStartCommand::Start);
        assert_eq!(
            second_receiver.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty),
            "completing one callback must not start another callback's shared child",
        );
        assert!(sibling.discard_unstarted_child_process(42).unwrap());
        assert_eq!(second_receiver.recv().unwrap(), ChildStartCommand::Cancel);
        leader.join_all_child_processes().unwrap();
    }

    #[test]
    fn partial_start_failure_keeps_later_child_reachable_for_cleanup() {
        let mut backend = match KvmBackend::new(0x10_000) {
            Ok(backend) => backend,
            Err(error) => {
                if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                    panic!("KVM is required: {error}");
                }
                eprintln!("skipping child-start cleanup KVM test: {error}");
                return;
            }
        };
        let mut executor = test_executor();
        let starts = Arc::new(Mutex::new(Vec::new()));

        let (first_sender, first_receiver) = std::sync::mpsc::channel();
        let first_gate = ChildStartGate::new(first_sender);
        let (first_started_sender, first_started_receiver) = std::sync::mpsc::channel();
        let (first_release_sender, first_release_receiver) = std::sync::mpsc::channel();
        let first_handle = std::thread::spawn(move || {
            assert_eq!(first_receiver.recv().unwrap(), ChildStartCommand::Start);
            first_started_sender.send(()).unwrap();
            first_release_receiver.recv().unwrap();
            Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
        });
        backend
            .thread_group
            .add_unstarted_worker(51, first_gate.clone(), first_handle);
        starts
            .lock()
            .unwrap()
            .push(PendingChildStart::tool_thread(51, first_gate));

        let (lost_sender, lost_receiver) = std::sync::mpsc::channel();
        drop(lost_receiver);
        let lost_gate = ChildStartGate::new(lost_sender);
        let lost_handle = ChildThread::spawn(|| Ok(()));
        executor.register_child_process_with_gate(
            52,
            lost_gate.clone(),
            Arc::new(ChildCompletionSlot::default()),
            lost_handle,
        );
        starts
            .lock()
            .unwrap()
            .push(PendingChildStart::fork_process(52, lost_gate));

        let later_cancelled = Arc::new(AtomicBool::new(false));
        let later_cancelled_in_child = later_cancelled.clone();
        let (later_sender, later_receiver) = std::sync::mpsc::channel();
        let later_gate = ChildStartGate::new(later_sender);
        let later_handle = std::thread::spawn(move || {
            assert_eq!(
                later_receiver.recv().unwrap(),
                ChildStartCommand::CancelAfterFailure
            );
            later_cancelled_in_child.store(true, Ordering::Release);
            Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
        });
        backend
            .thread_group
            .add_unstarted_worker(53, later_gate.clone(), later_handle);
        starts
            .lock()
            .unwrap()
            .push(PendingChildStart::tool_thread(53, later_gate));

        let error = backend
            .start_pending_tool_children(&mut executor, &starts)
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("registered KVM child lost its parent start gate"));
        assert!(message.contains("cleanup also failed"));
        assert!(later_cancelled.load(Ordering::Acquire));
        assert!(starts.lock().unwrap().is_empty());
        assert!(!executor.discard_unstarted_child_process(52).unwrap());
        assert!(!backend.thread_group.discard_unstarted_worker(53).unwrap());
        first_started_receiver.recv().unwrap();
        assert_eq!(backend.thread_group.worker_handles.lock().unwrap().len(), 1);
        assert!(!executor.has_pending_child_process(52));
        first_release_sender.send(()).unwrap();
        backend.thread_group.join_workers();
    }

    #[test]
    fn cancelled_child_cleanup_retains_real_errors_and_ordinary_cancellation() {
        for fork in [false, true] {
            for failed in [false, true] {
                for real_cleanup in [false, true] {
                    let Some((mut backend, mut executor, _)) = backend_at_completed_tool_boundary()
                    else {
                        return;
                    };
                    let starts = Arc::new(Mutex::new(Vec::new()));
                    let (sender, receiver) = std::sync::mpsc::channel();
                    let gate = ChildStartGate::new(sender);
                    let expected = if failed {
                        ChildStartCommand::CancelAfterFailure
                    } else {
                        ChildStartCommand::Cancel
                    };
                    let hook_error =
                        Arc::new(Error::HostIo(std::io::Error::from_raw_os_error(libc::EIO)));
                    let child_error = if real_cleanup {
                        Error::WithCleanup {
                            primary: Arc::new(Error::RunAborted),
                            cleanup: vec![hook_error.clone()],
                        }
                    } else {
                        Error::RunAborted
                    };
                    let consumed = Arc::new(AtomicBool::new(false));
                    let child_consumed = consumed.clone();
                    let child = move || {
                        assert_eq!(
                            receiver
                                .recv_timeout(std::time::Duration::from_secs(5))
                                .unwrap(),
                            expected
                        );
                        child_consumed.store(true, Ordering::Release);
                        child_error
                    };
                    if fork {
                        executor.register_child_process_with_gate(
                            41,
                            gate.clone(),
                            Arc::new(ChildCompletionSlot::default()),
                            ChildThread::spawn(move || Err(child())),
                        );
                        starts
                            .lock()
                            .unwrap()
                            .push(PendingChildStart::fork_process(41, gate));
                    } else {
                        backend.thread_group.add_unstarted_worker(
                            42,
                            gate.clone(),
                            std::thread::spawn(move || Err(child())),
                        );
                        starts
                            .lock()
                            .unwrap()
                            .push(PendingChildStart::tool_thread(42, gate));
                    }
                    let children = backend.cancel_unstarted_tool_children(&starts, failed);
                    let result =
                        backend.discard_cancelled_tool_children(&mut executor, children, failed);
                    assert!(consumed.load(Ordering::Acquire));
                    assert!(starts.lock().unwrap().is_empty());
                    assert!(!executor.has_pending_child_process(41));
                    assert!(
                        backend
                            .thread_group
                            .worker_handles
                            .lock()
                            .unwrap()
                            .is_empty()
                    );
                    assert!(
                        backend
                            .thread_group
                            .worker_start_gates
                            .lock()
                            .unwrap()
                            .is_empty()
                    );
                    if real_cleanup {
                        let Error::WithCleanup { primary, cleanup } = result.unwrap_err() else {
                            panic!("cancelled child's real cleanup cause was changed or lost");
                        };
                        assert!(matches!(*primary, Error::RunAborted));
                        assert_eq!(cleanup.len(), 1);
                        assert!(Arc::ptr_eq(&cleanup[0], &hook_error));
                    } else if failed {
                        result.unwrap();
                    } else {
                        assert!(matches!(result, Err(Error::RunAborted)));
                    }
                }
            }
        }
    }

    #[test]
    fn exec_teardown_disposition_survives_unstarted_child_cleanup() {
        let Some((mut backend, mut executor, _)) = backend_at_completed_tool_boundary() else {
            return;
        };
        for exec_teardown in [false, true] {
            for failed_cleanup in [false, true] {
                let starts = Arc::new(Mutex::new(Vec::new()));
                let (sender, receiver) = std::sync::mpsc::channel();
                if failed_cleanup {
                    // The gate can be cancelled, but its child is deliberately
                    // absent from the registry: preserve that cleanup error.
                    starts.lock().unwrap().push(PendingChildStart::tool_thread(
                        99,
                        ChildStartGate::new(sender),
                    ));
                }
                let primary = Error::Reverie(reverie::syscalls::Errno::EIO.into());
                let original = primary.to_string();
                let primary = if exec_teardown {
                    Error::ExecWorkerTeardown(Box::new(primary))
                } else {
                    primary
                };
                let error = backend.cleanup_unstarted_tool_children_after_error(
                    &mut executor,
                    &starts,
                    primary,
                );
                assert_eq!(matches!(error, Error::ExecWorkerTeardown(_)), exec_teardown);
                let message = error.to_string();
                assert_eq!(message.matches(&original).count(), 1, "{message}");
                assert!(starts.lock().unwrap().is_empty());
                if failed_cleanup {
                    assert_eq!(
                        receiver.recv().unwrap(),
                        ChildStartCommand::CancelAfterFailure
                    );
                    assert!(message.contains("unstarted-child cleanup also failed"));
                    assert!(message.contains("guest thread 99 was not registered"));
                } else {
                    assert_eq!(message, original);
                }
            }
        }
    }

    #[test]
    fn root_guest_pid_must_be_positive() {
        assert_eq!(validate_root_pid(1).unwrap(), 1);
        assert_eq!(validate_root_pid(3).unwrap(), 3);
        assert!(matches!(
            validate_root_pid(0),
            Err(Error::InvalidGuestPid(0))
        ));
        assert!(matches!(
            validate_root_pid(-1),
            Err(Error::InvalidGuestPid(-1))
        ));
    }

    #[test]
    fn root_parent_pid_matches_ptrace_namespace_convention() {
        // Conventional root guest (detcore ROOT_DETPID == 3) is parented to the
        // namespace init, so getppid() == 1 exactly as under the ptrace backend.
        assert_eq!(root_parent_pid(3), 1);
        // Any non-init root guest is likewise parented to init.
        assert_eq!(root_parent_pid(2), 1);
        assert_eq!(root_parent_pid(42), 1);
        // A guest that is itself the namespace init has no parent (getppid == 0).
        assert_eq!(root_parent_pid(CONTAINER_INIT_PID), 0);
    }

    #[test]
    fn guest_thread_transport_slots_are_bounded_and_reusable() {
        let group = GuestThreadGroup::default();
        let mut slots = Vec::new();
        for tid in 2..2 + MAX_GUEST_THREADS as i32 {
            slots.push(group.reserve_transport_slot(tid).unwrap());
        }
        assert_eq!(slots, (0..MAX_GUEST_THREADS as usize).collect::<Vec<_>>());
        assert!(matches!(
            group.reserve_transport_slot(10_000),
            Err(Error::GuestThreadLimitExceeded(10_000))
        ));

        let released = slots[slots.len() / 2];
        group.release_transport_slot(released);
        assert_eq!(group.reserve_transport_slot(10_001).unwrap(), released);
    }

    #[test]
    fn tool_exit_releases_transport_slot_before_exit_callback() {
        match Kvm::new() {
            Ok(_) => {}
            Err(error) if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) => {
                eprintln!("skipping KVM slot-release test: cannot open /dev/kvm: {error}");
                return;
            }
            Err(error) => panic!("failed to probe /dev/kvm: {error}"),
        }

        let group = Arc::new(GuestThreadGroup::default());
        for tid in 2..MAX_GUEST_THREADS as i32 + 1 {
            group.reserve_transport_slot(tid).unwrap();
        }
        let exiting_slot = group.reserve_transport_slot(10_000).unwrap();
        assert_eq!(exiting_slot, MAX_GUEST_THREADS as usize - 1);

        let mut backend = KvmBackend::new(16 * 1024 * 1024).unwrap();
        backend.thread_group = group.clone();
        backend.thread_slot = Some(exiting_slot);
        backend.is_guest_thread = true;
        let log = SlotReleaseLog {
            group,
            reused: Mutex::new(None),
        };

        futures::executor::block_on(backend.notify_tool_exit(
            Arc::new(SlotReleaseTool),
            (Pid::from_raw(3), Pid::from_raw(10_000)),
            &log,
            &(),
            (),
            ExitStatus::SUCCESS,
        ))
        .unwrap();

        assert_eq!(backend.thread_slot, None);
        assert_eq!(*log.reused.lock().unwrap(), Some(exiting_slot));
    }

    #[test]
    fn process_snapshot_hides_internal_tool_scratch_pages() {
        let memory = GuestMemory::new(0, (BOOT_RESERVED_END + PAGE_SIZE) as usize).unwrap();
        let root_bottom = TOOL_STACK_TOP - TOOL_STACK_SIZE;
        let first_worker_bottom = thread_tool_stack_top(0) - TOOL_STACK_SIZE;
        let last_worker_bottom =
            thread_tool_stack_top(MAX_GUEST_THREADS as usize - 1) - TOOL_STACK_SIZE;
        let ordinary_page = BOOT_RESERVED_END;

        memory
            .map_user_range(root_bottom, TOOL_STACK_SIZE, false)
            .unwrap();
        memory
            .map_user_range(first_worker_bottom, TOOL_STACK_SIZE, false)
            .unwrap();
        memory
            .map_user_range(last_worker_bottom, TOOL_STACK_SIZE, false)
            .unwrap();
        memory
            .map_user_range(ordinary_page, PAGE_SIZE, false)
            .unwrap();
        let snapshot = memory.snapshot().unwrap();

        hide_tool_scratch_pages(&snapshot).unwrap();

        assert!(memory.user_range_is_mapped(root_bottom, TOOL_STACK_SIZE));
        assert!(!snapshot.user_range_is_mapped(root_bottom, TOOL_STACK_SIZE));
        assert!(!snapshot.user_range_is_mapped(first_worker_bottom, TOOL_STACK_SIZE));
        assert!(!snapshot.user_range_is_mapped(last_worker_bottom, TOOL_STACK_SIZE));
        assert!(snapshot.user_range_is_mapped(ordinary_page, PAGE_SIZE));
    }

    #[test]
    fn guest_thread_group_joins_registered_workers() {
        let group = Arc::new(GuestThreadGroup::default());
        let outer_finished = Arc::new(AtomicBool::new(false));
        let nested_finished = Arc::new(AtomicBool::new(false));
        let worker_group = group.clone();
        let worker_finished = outer_finished.clone();
        let child_finished = nested_finished.clone();
        group.add_worker_handle(
            2,
            std::thread::spawn(move || {
                worker_group.add_worker_handle(
                    3,
                    std::thread::spawn(move || {
                        child_finished.store(true, Ordering::Release);
                        Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
                    }),
                );
                worker_finished.store(true, Ordering::Release);
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );

        group.join_workers();

        assert!(outer_finished.load(Ordering::Acquire));
        assert!(nested_finished.load(Ordering::Acquire));
        assert!(group.worker_handles.lock().unwrap().is_empty());
    }

    #[test]
    fn worker_exec_action_preserves_cancelled_group_without_parking() {
        check_worker_exec_action_preserves_cancelled_group(false);
    }

    #[test]
    fn worker_exec_action_preserves_cancelled_group_before_parking() {
        check_worker_exec_action_preserves_cancelled_group(true);
    }

    fn check_worker_exec_action_preserves_cancelled_group(park_syscall_return: bool) {
        match Kvm::new() {
            Ok(_) => {}
            Err(error) if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) => {
                assert!(
                    std::env::var_os("REVERIE_REQUIRE_KVM").is_none(),
                    "worker exec action test requires /dev/kvm: {error}"
                );
                eprintln!("skipping KVM worker exec action test: cannot open /dev/kvm: {error}");
                return;
            }
            Err(error) => panic!("failed to probe /dev/kvm: {error}"),
        }

        let mut image = vec![0; 0x1001];
        image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        for (offset, value) in [(16, 2_u16), (18, 62), (52, 64), (54, 56), (56, 1)] {
            image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [(20, 1_u32), (64, 1), (68, 5)] {
            image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (offset, value) in [
            (24, 0x20_0000_u64),
            (32, 64),
            (72, 0x1000),
            (80, 0x20_0000),
            (88, 0x20_0000),
            (96, 1),
            (104, 0x1000),
            (112, 0x1000),
        ] {
            image[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        image[0x1000] = HLT;
        let mut parent = KvmBackend::new(16 * 1024 * 1024).unwrap();
        parent
            .install_static_elf(&image, "/worker-exec-guard")
            .unwrap();
        let leader = ElfExecutor::new(parent.static_elf.take().unwrap(), false);
        let mut executor = leader.thread_child(7).unwrap();
        let group = parent.thread_group.clone();
        let mut worker = KvmBackend::from_thread_state(
            parent.memory.clone(),
            parent.vcpu.get_regs().unwrap(),
            parent.vcpu.get_xsave().unwrap(),
            None,
            parent.cpuid_policy,
            7,
            group.clone(),
        )
        .unwrap();
        assert!(worker.is_guest_thread);
        assert!(group.root.lock().unwrap().is_none());
        assert!(group.workers.lock().unwrap().is_empty());
        assert!(group.worker_handles.lock().unwrap().is_empty());
        group.cancelled.store(true, Ordering::Release);
        *group.exit_status.lock().unwrap() = Some(ExitStatus::Exited(127));
        let slots = group.transport_slots.lock().unwrap().clone();
        let thread_slot = worker.thread_slot;
        worker.set_backend_stats_request(BackendStatsRequest::ENABLED);
        let stats = worker.backend_stats();
        let registers = worker.vcpu.get_regs().unwrap();
        let special_registers = worker.vcpu.get_sregs().unwrap();
        let xsave = worker.vcpu.get_xsave().unwrap();
        let mut before = vec![0; worker.memory.len()];
        worker.memory.read_raw(0, &mut before).unwrap();

        let result = worker.run_process_action(
            &mut executor,
            ProcessAction::Exec {
                executable_path: Path::new("/worker-exec-guard").to_owned(),
                executable_file: None,
                image,
                argv: vec!["/worker-exec-guard".to_owned()],
                envp: Vec::new(),
            },
            park_syscall_return,
        );

        let mut after = vec![0; worker.memory.len()];
        worker.memory.read_raw(0, &mut after).unwrap();
        eprintln!(
            "park={park_syscall_return} result={result:?} cancelled={} exit_status={:?} registers_unchanged={} memory_unchanged={}",
            group.cancelled.load(Ordering::Acquire),
            group.exit_status(),
            worker.vcpu.get_regs().unwrap() == registers,
            after == before,
        );
        assert!(matches!(result, Err(Error::GuestThreadExecUnsupported)));
        assert!(group.cancelled.load(Ordering::Acquire));
        assert_eq!(group.exit_status(), Some(ExitStatus::Exited(127)));
        assert!(Arc::ptr_eq(&worker.thread_group, &group));
        assert_eq!(worker.thread_slot, thread_slot);
        assert_eq!(*group.transport_slots.lock().unwrap(), slots);
        assert!(group.root.lock().unwrap().is_none());
        assert!(group.workers.lock().unwrap().is_empty());
        assert!(group.worker_handles.lock().unwrap().is_empty());
        assert_eq!(worker.vcpu.get_regs().unwrap(), registers);
        assert_eq!(worker.vcpu.get_sregs().unwrap(), special_registers);
        assert_eq!(worker.vcpu.get_xsave().unwrap().region, xsave.region);
        assert_eq!(worker.backend_stats(), stats);
        assert!(
            after == before,
            "worker exec action altered shared guest memory"
        );
        for (number, expected) in [(libc::SYS_getpid, 1), (libc::SYS_gettid, 7)] {
            assert_eq!(
                executor.execute(&SyscallRequest::new(number as u64, [0; 6]), &worker.memory),
                expected,
            );
        }
        assert!(executor.take_process_action().is_none());
    }

    #[test]
    fn exec_cancellation_joins_and_rearms_the_thread_group() {
        let group = Arc::new(GuestThreadGroup::default());
        let worker_group = group.clone();
        let worker_finished = Arc::new(AtomicBool::new(false));
        let finished = worker_finished.clone();
        let (start_sender, start_receiver) = std::sync::mpsc::channel();
        let gate = ChildStartGate::new(start_sender);
        group.add_unstarted_worker(
            2,
            gate.clone(),
            std::thread::spawn(move || {
                assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Start);
                while !worker_group.cancelled.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
                finished.store(true, Ordering::Release);
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        gate.start().unwrap();
        *group.exit_status.lock().unwrap() = Some(ExitStatus::Exited(127));
        group.record_worker_failure(2);
        assert!(!group.cancelled.load(Ordering::Acquire));
        group.begin_natural_join();
        assert!(group.cancelled.load(Ordering::Acquire));

        group.cancel_workers();
        group.join_workers();
        group.rearm_after_exec();

        assert!(worker_finished.load(Ordering::Acquire));
        assert!(group.worker_start_gates.lock().unwrap().is_empty());
        assert!(group.worker_handles.lock().unwrap().is_empty());
        assert_eq!(group.exit_status(), None);
        assert!(!group.cancelled.load(Ordering::Acquire));
        assert!(!group.take_worker_error_report(2));
        group.begin_natural_join();
        assert!(
            !group.cancelled.load(Ordering::Acquire),
            "exec discarded the earlier failure"
        );
    }

    #[test]
    fn post_preflight_interpreter_failure_is_fatal_after_image_reset() {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::ffi::OsStringExt;

        const MEMORY_SIZE: usize = 64 * 1024 * 1024;
        let mut backend = match KvmBackend::new(MEMORY_SIZE) {
            Ok(backend) => backend,
            Err(Error::Kvm(error))
                if matches!(error.errno(), libc::ENOENT | libc::EACCES | libc::EPERM) =>
            {
                if std::env::var_os("REVERIE_REQUIRE_KVM").is_some() {
                    panic!("post-preflight exec test requires usable /dev/kvm: {error}");
                }
                return;
            }
            Err(error) => panic!("failed to create KVM backend: {error}"),
        };

        let mut image = std::fs::read("/usr/bin/true").unwrap();
        backend
            .install_static_elf_with_args(&image, &["true"], &[])
            .unwrap();
        let elf = goblin::elf::Elf::parse(&image).unwrap();
        let interpreter = elf.interpreter.unwrap().to_owned();
        let header = elf
            .program_headers
            .iter()
            .find(|header| header.p_type == goblin::elf::program_header::PT_INTERP)
            .unwrap();
        let interpreter_offset = usize::try_from(header.p_offset).unwrap();
        let interpreter_capacity = usize::try_from(header.p_filesz).unwrap();
        drop(elf);

        let suffix = std::process::id();
        let mut interpreter_path = format!("/tmp/kvmld-{suffix}").into_bytes();
        assert!(interpreter_path.len() < interpreter_capacity);
        interpreter_path.resize(interpreter_capacity - 1, b'x');
        let interpreter_copy =
            std::path::PathBuf::from(std::ffi::OsString::from_vec(interpreter_path));
        let executable = std::env::temp_dir().join(format!("kvmexec-{suffix}"));
        struct Cleanup(Vec<std::path::PathBuf>);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for path in &self.0 {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let mut cleanup = Cleanup(Vec::new());
        let mut interpreter_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&interpreter_copy)
            .unwrap();
        cleanup.0.push(interpreter_copy.clone());
        interpreter_file
            .write_all(&std::fs::read(interpreter).unwrap())
            .unwrap();
        drop(interpreter_file);
        let interpreter_path = interpreter_copy.as_os_str().as_bytes();
        assert_eq!(interpreter_path.len(), interpreter_capacity - 1);
        image[interpreter_offset..interpreter_offset + interpreter_capacity].fill(0);
        image[interpreter_offset..interpreter_offset + interpreter_path.len()]
            .copy_from_slice(interpreter_path);
        let mut executable_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&executable)
            .unwrap();
        cleanup.0.push(executable.clone());
        executable_file.write_all(&image).unwrap();
        drop(executable_file);

        let stack_bottom = backend.memory.guest_end() - crate::elf::STACK_LIMIT;
        let path_address = stack_bottom;
        let path = executable.as_os_str().as_bytes();
        backend.memory.write(path_address, path).unwrap();
        backend
            .memory
            .write(path_address + path.len() as u64, &[0])
            .unwrap();
        let argv_address = stack_bottom + 0x100;
        backend
            .memory
            .write(argv_address, &path_address.to_ne_bytes())
            .unwrap();
        backend
            .memory
            .write(argv_address + 8, &0_u64.to_ne_bytes())
            .unwrap();
        let envp_address = argv_address + 16;
        backend
            .memory
            .write(envp_address, &0_u64.to_ne_bytes())
            .unwrap();

        let loaded = backend.static_elf.take().unwrap();
        let mut executor = ElfExecutor::new(loaded, false);
        let request = SyscallRequest::new(
            libc::SYS_execve as u64,
            [path_address, argv_address, envp_address, 0, 0, 0],
        );
        assert_eq!(executor.execute(&request, &backend.memory), 0);
        let action = executor
            .take_process_action()
            .expect("successful preflight must schedule exec");

        // Removing the interpreter after the executor's successful preflight
        // forces a rare failure beyond exec's point of no return. The backend
        // must fail instead of resuming the now-reset old image, matching Linux
        // semantics when exec fails after tearing down the old address space.
        std::fs::remove_file(&interpreter_copy).unwrap();
        let sentinel_address = stack_bottom + PAGE_SIZE;
        const SENTINEL: [u8; 16] = *b"old-image-state!";
        backend.memory.write(sentinel_address, &SENTINEL).unwrap();
        let retained = backend.memory.clone();
        let error = backend
            .run_process_action(&mut executor, action, false)
            .unwrap_err();
        assert!(
            matches!(
                &error,
                Error::UnsupportedElf(message) if message.contains("interpreter")
            ),
            "unexpected exec error: {error:?}"
        );
        let mut observed = [0; SENTINEL.len()];
        assert!(
            !backend
                .memory
                .user_range_is_mapped(sentinel_address, SENTINEL.len() as u64)
        );
        retained.read_raw(sentinel_address, &mut observed).unwrap();
        assert_eq!(observed, [0; SENTINEL.len()]);
    }

    #[test]

    fn cancelling_named_tool_thread_joins_only_that_unstarted_worker() {
        let group = Arc::new(GuestThreadGroup::default());
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_in_worker = cancelled.clone();
        let (cancel_sender, cancel_receiver) = std::sync::mpsc::channel();
        let cancel_gate = ChildStartGate::new(cancel_sender);
        group.add_unstarted_worker(
            2,
            cancel_gate.clone(),
            std::thread::spawn(move || {
                match cancel_receiver.recv() {
                    Ok(ChildStartCommand::Cancel) => {
                        cancelled_in_worker.store(true, Ordering::Release)
                    }
                    other => panic!("unstarted worker received {other:?}"),
                }
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );

        let sibling_finished = Arc::new(AtomicBool::new(false));
        let sibling_finished_in_worker = sibling_finished.clone();
        let (sibling_start_sender, sibling_start_receiver) = std::sync::mpsc::channel();
        let (sibling_release_sender, sibling_release_receiver) = std::sync::mpsc::channel();
        group.add_worker_handle(
            3,
            std::thread::spawn(move || {
                assert_eq!(
                    sibling_start_receiver.recv().unwrap(),
                    ChildStartCommand::Start
                );
                sibling_release_receiver.recv().unwrap();
                sibling_finished_in_worker.store(true, Ordering::Release);
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        sibling_start_sender.send(ChildStartCommand::Start).unwrap();

        let pending = PendingChildStart::tool_thread(2, cancel_gate);
        assert!(matches!(
            pending.cancel(),
            PendingChildCancellation::NewlyCancelled {
                child: PendingChildKind::ToolThread(2),
                delivery_failed: false
            }
        ));
        assert!(group.discard_unstarted_worker(2).unwrap());
        assert!(!group.worker_start_gates.lock().unwrap().contains_key(&2));
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(group.worker_handles.lock().unwrap().len(), 1);
        assert_eq!(group.worker_handles.lock().unwrap()[0].tid, 3);
        assert!(!group.discard_unstarted_worker(99).unwrap());
        assert!(!sibling_finished.load(Ordering::Acquire));

        sibling_release_sender.send(()).unwrap();
        group.join_workers();
        assert!(sibling_finished.load(Ordering::Acquire));
    }

    fn failure_and_join_order(failure_first: bool) {
        let group = Arc::new(GuestThreadGroup::default());
        let worker_group = group.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = finished.clone();
        group.add_worker_handle(
            2,
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !worker_group.cancelled.load(Ordering::Acquire) {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "failed natural join left a worker running"
                    );
                    std::thread::yield_now();
                }
                worker_finished.store(true, Ordering::Release);
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        if failure_first {
            group.record_worker_failure(3);
            assert!(!group.cancelled.load(Ordering::Acquire));
            group.begin_natural_join();
        } else {
            group.begin_natural_join();
            assert!(!group.cancelled.load(Ordering::Acquire));
            group.record_worker_failure(3);
        }
        group.join_workers();
        assert!(finished.load(Ordering::Acquire));
        assert!(group.worker_handles.lock().unwrap().is_empty());
        assert!(group.take_worker_error_report(3));
        assert!(
            !group.take_worker_error_report(3),
            "initiating diagnostic is consumed once"
        );
        group.record_worker_failure(2);
        assert!(
            !group.take_worker_error_report(2),
            "cancelled peers remain suppressed"
        );
    }

    #[test]
    fn completed_failure_interrupts_a_later_natural_join() {
        failure_and_join_order(true);
    }

    #[test]
    fn later_failure_interrupts_an_existing_natural_join() {
        failure_and_join_order(false);
    }

    #[test]
    fn failure_cancels_pending_start_in_batch_being_joined() {
        let group = Arc::new(GuestThreadGroup::default());
        let (sender, receiver) = std::sync::mpsc::channel();
        let gate = ChildStartGate::new(sender);
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        group.add_unstarted_worker(
            2,
            gate.clone(),
            std::thread::spawn(move || {
                assert_eq!(
                    receiver
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap(),
                    ChildStartCommand::CancelAfterFailure
                );
                done_sender.send(()).unwrap();
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        let joining_group = group.clone();
        let joining = std::thread::spawn(move || {
            joining_group.begin_natural_join();
            joining_group.join_workers();
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !group.worker_handles.lock().unwrap().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "join never took its batch"
            );
            std::thread::yield_now();
        }
        assert!(group.worker_start_gates.lock().unwrap().contains_key(&2));
        assert!(!joining.is_finished());
        assert!(!gate.is_cancelled());
        group.record_worker_failure(3);
        done_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        joining.join().unwrap();
        group.teardown_result().unwrap();
        assert!(group.worker_start_gates.lock().unwrap().is_empty());
        assert!(group.worker_handles.lock().unwrap().is_empty());
    }

    #[test]
    fn callback_error_preserves_registered_child_taken_by_join() {
        let Some((mut backend, mut executor, _)) = backend_at_completed_tool_boundary() else {
            return;
        };
        let group = backend.thread_group.clone();
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (sender, receiver) = std::sync::mpsc::channel();
        let gate = ChildStartGate::new(sender);
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        group.add_unstarted_worker(
            2,
            gate.clone(),
            std::thread::spawn(move || {
                assert_eq!(
                    receiver
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap(),
                    ChildStartCommand::CancelAfterFailure
                );
                release_receiver
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );
        starts
            .lock()
            .unwrap()
            .push(PendingChildStart::tool_thread(2, gate));
        let joining_group = group.clone();
        let joining = std::thread::spawn(move || {
            joining_group.begin_natural_join();
            joining_group.join_workers();
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !group.worker_handles.lock().unwrap().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "join never took its batch"
            );
            std::thread::yield_now();
        }
        let primary = Error::Reverie(reverie::syscalls::Errno::EIO.into());
        let original = primary.to_string();
        let error =
            backend.cleanup_unstarted_tool_children_after_error(&mut executor, &starts, primary);
        assert!(!joining.is_finished());
        release_sender.send(()).unwrap();
        joining.join().unwrap();
        group.teardown_result().unwrap();
        assert!(starts.lock().unwrap().is_empty());
        assert!(group.worker_start_gates.lock().unwrap().is_empty());
        assert!(group.worker_handles.lock().unwrap().is_empty());
        assert_eq!(error.to_string(), original);
    }

    #[test]
    fn callback_cleanup_recognizes_completed_cancelled_child() {
        for cancelled_before_cleanup in [false, true] {
            let Some((mut backend, mut executor, _)) = backend_at_completed_tool_boundary() else {
                return;
            };
            let group = backend.thread_group.clone();
            let starts = Arc::new(Mutex::new(Vec::new()));
            let (sender, receiver) = std::sync::mpsc::channel();
            let gate = ChildStartGate::new(sender);
            group.add_unstarted_worker(
                2,
                gate.clone(),
                std::thread::spawn(move || {
                    assert_eq!(
                        receiver
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .unwrap(),
                        ChildStartCommand::Cancel
                    );
                    Err(Error::UnexpectedVcpuExit(
                        "controlled cancelled worker cleanup failure".to_owned(),
                    ))
                }),
            );
            starts
                .lock()
                .unwrap()
                .push(PendingChildStart::tool_thread(2, gate));
            let joining_group = group.clone();
            let joining = std::thread::spawn(move || joining_group.join_workers());
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !group.worker_handles.lock().unwrap().is_empty() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "join never took its batch"
                );
                std::thread::yield_now();
            }
            if cancelled_before_cleanup {
                group.cancel_workers();
                joining.join().unwrap();
                assert!(group.worker_start_gates.lock().unwrap().is_empty());
                let primary = Error::Reverie(reverie::syscalls::Errno::EIO.into());
                let original = primary.to_string();
                let error = backend.cleanup_unstarted_tool_children_after_error(
                    &mut executor,
                    &starts,
                    primary,
                );
                assert_eq!(error.to_string(), original);
            } else {
                let children = backend.cancel_unstarted_tool_children(&starts, false);
                joining.join().unwrap();
                assert!(group.worker_start_gates.lock().unwrap().is_empty());
                backend
                    .discard_cancelled_tool_children(&mut executor, children, false)
                    .unwrap();
            }
            let error = group.teardown_result().unwrap_err().to_string();
            assert_eq!(
                error
                    .matches("controlled cancelled worker cleanup failure")
                    .count(),
                1,
                "{error}"
            );
            assert!(starts.lock().unwrap().is_empty());
            assert!(group.worker_handles.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn worker_failure_publication_recovers_poisoned_state() {
        let group = Arc::new(GuestThreadGroup::default());
        let poisoning = group.clone();
        assert!(
            std::thread::spawn(move || {
                let _state = poisoning.failure_state.lock().unwrap();
                panic!("controlled worker failure-state poison");
            })
            .join()
            .is_err()
        );
        group.begin_natural_join();
        group.record_worker_failure(3);
        assert!(group.cancelled.load(Ordering::Acquire));
        assert!(group.take_worker_error_report(3));
        assert!(!group.take_worker_error_report(3));
    }

    #[test]
    fn pending_start_registered_after_cancellation_is_drained() {
        for fatal in [false, true] {
            let group = Arc::new(GuestThreadGroup::default());
            let poisoning = group.clone();
            assert!(
                std::thread::spawn(move || {
                    let _gates = poisoning.worker_start_gates.lock().unwrap();
                    panic!("controlled start-gate registry poison");
                })
                .join()
                .is_err()
            );
            if fatal {
                group.record_worker_failure(3);
            }
            group.cancel_workers();
            let (sender, receiver) = std::sync::mpsc::channel();
            let gate = ChildStartGate::new(sender);
            group.add_unstarted_worker(
                2,
                gate.clone(),
                std::thread::spawn(move || {
                    assert_eq!(
                        receiver
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .unwrap(),
                        if fatal {
                            ChildStartCommand::CancelAfterFailure
                        } else {
                            ChildStartCommand::Cancel
                        }
                    );
                    Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
                }),
            );
            assert!(gate.is_cancelled());
            group.join_workers();
            group.teardown_result().unwrap();
            assert!(
                group
                    .worker_start_gates
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_empty()
            );
            assert!(group.worker_handles.lock().unwrap().is_empty());
            group.rearm_after_exec();
            assert!(!group.cancelled.load(Ordering::Acquire));
            assert!(!group.cancelled_after_failure.load(Ordering::Acquire));
        }
    }

    #[test]
    fn natural_join_preserves_a_registered_pending_start() {
        let group = Arc::new(GuestThreadGroup::default());
        let (start_sender, start_receiver) = std::sync::mpsc::channel();
        let gate = ChildStartGate::new(start_sender);
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        group.add_unstarted_worker(
            2,
            gate.clone(),
            std::thread::spawn(move || {
                assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Start);
                done_sender.send(()).unwrap();
                Ok((ExitStatus::Exited(73), Vec::new(), Vec::new()))
            }),
        );
        let joining_group = group.clone();
        let joining = std::thread::spawn(move || joining_group.join_workers());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !group.worker_handles.lock().unwrap().is_empty() {
            assert!(
                std::time::Instant::now() < deadline,
                "natural join did not take the registered handle"
            );
            std::thread::yield_now();
        }
        assert!(
            !joining.is_finished(),
            "pending worker cannot have completed"
        );
        assert!(
            !gate.is_cancelled(),
            "natural join cancelled a committed start"
        );
        gate.start().unwrap();
        done_receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        joining.join().unwrap();
        group.teardown_result().unwrap();
        assert!(group.worker_start_gates.lock().unwrap().is_empty());
        assert!(group.worker_handles.lock().unwrap().is_empty());
    }

    #[test]
    fn pending_gated_worker_is_cancelled_before_teardown_join() {
        let group = Arc::new(GuestThreadGroup::default());
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_in_worker = cancelled.clone();
        let (start_sender, start_receiver) = std::sync::mpsc::channel();
        let start_gate = ChildStartGate::new(start_sender);
        group.add_unstarted_worker(
            2,
            start_gate,
            std::thread::spawn(move || {
                assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Cancel);
                cancelled_in_worker.store(true, Ordering::Release);
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );

        group.cancel_workers();
        group.join_workers();

        assert!(cancelled.load(Ordering::Acquire));
        assert!(group.worker_handles.lock().unwrap().is_empty());
    }
    #[test]
    fn both_clear_tid_paths_keep_distinct_store_and_queued_wake_contracts() {
        use std::time::Duration;
        use std::time::Instant;

        use io_uring::IoUring;
        use io_uring::Probe;
        use io_uring::opcode;
        use io_uring::types;
        const PARK: u64 = 0x1000;
        const WORD: u64 = 0x2000;
        const PAGE: u64 = 0x1000;
        const HOST_REQUIREMENTS: &str = "clear-TID test setup requires Linux 6.7+, \
            CONFIG_IO_URING and CONFIG_FUTEX, IORING_OP_FUTEX_WAIT, and permitted \
            io_uring_setup/register/enter (including extended-argument timeouts); \
            io_uring must be enabled for this user and allowed by seccomp";
        fn host_futex(
            address: usize,
            operation: i32,
            value: u32,
            fourth: usize,
            second: usize,
            compare: u32,
        ) -> i64 {
            unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    address,
                    operation,
                    value,
                    fourth,
                    second,
                    compare,
                ) as i64
            }
        }
        // This creates a stopped VM only. No guest/vCPU is run by this control.
        let mut backend = KvmBackend::new(0x1_0000).expect("clear-TID path control requires KVM");
        let mut executor = ElfExecutor::new(
            crate::executor::test_loaded_state_for_vm(std::path::Path::new("/")),
            false,
        );
        for registered_worker in [false, true] {
            for policy in [0, 1, 2] {
                // writable, readonly, inaccessible
                backend.memory.clear_user_access();
                backend
                    .memory
                    .map_user_range(PARK, 3 * PAGE, false)
                    .unwrap();
                backend
                    .memory
                    .write_raw(PARK, &0_i32.to_ne_bytes())
                    .unwrap();
                backend
                    .memory
                    .write_raw(WORD, &7_i32.to_ne_bytes())
                    .unwrap();
                if policy == 1 {
                    backend
                        .memory
                        .map_user_permissions(WORD, PAGE, true, false)
                        .unwrap();
                } else if policy == 2 {
                    backend.memory.unmap_user_range(WORD, PAGE).unwrap();
                }
                backend.memory.enable_user_access();
                let parking = backend
                    .memory
                    .user()
                    .retain_translated_range(PARK, 4)
                    .unwrap();
                let word = backend
                    .memory
                    .user()
                    .retain_translated_range(WORD, 4)
                    .unwrap();
                // Drop the ring before these retained address leases, including
                // on failure: closing initiates cancellation. A queued request's
                // wake/cancel path uses its futex key, not the userspace word.
                let mut ring = IoUring::new(2)
                    .unwrap_or_else(|error| panic!("{HOST_REQUIREMENTS}; io_uring_setup: {error}"));
                let mut probe = Probe::new();
                ring.submitter()
                    .register_probe(&mut probe)
                    .unwrap_or_else(|error| panic!("{HOST_REQUIREMENTS}; opcode probe: {error}"));
                assert!(
                    probe.is_supported(opcode::FutexWait::CODE),
                    "{HOST_REQUIREMENTS}"
                );
                assert!(ring.params().is_feature_ext_arg(), "{HOST_REQUIREMENTS}");
                // Probe the exact timed-enter form before enrolling a waiter or
                // invoking the production helper. This empty-ring, zero-time
                // poll submits no request and must report ETIME. In particular,
                // a seccomp denial of GETEVENTS | EXT_ARG is a setup failure.
                let setup_timeout = types::Timespec::new();
                let setup_args = types::SubmitArgs::new().timespec(&setup_timeout);
                let setup_enter = ring.submitter().submit_with_args(1, &setup_args);
                assert_eq!(
                    setup_enter
                        .as_ref()
                        .err()
                        .and_then(|error| error.raw_os_error()),
                    Some(libc::ETIME),
                    "{HOST_REQUIREMENTS}; empty-ring timed io_uring_enter probe: \
                     expected ETIME, got {setup_enter:?}"
                );

                // FUTEX2_SIZE_U32, with no FUTEX2_PRIVATE flag: the production
                // helper uses the shared FUTEX_WAKE operation.
                const FUTEX2_SIZE_U32: u32 = 2;
                let request_id = 0x6960 + u64::from(registered_worker) * 3 + policy;
                let request = opcode::FutexWait::new(
                    parking.address() as *const u32,
                    0,
                    u64::from(u32::MAX),
                    FUTEX2_SIZE_U32,
                )
                .build()
                .user_data(request_id);
                clear_tid_diagnostic::arm();
                let wait_deadline = Instant::now() + Duration::from_secs(5);
                // SAFETY: both address leases outlive the ring. PARK is initialized
                // and unchanged while submitted; wake/cancel later uses its key.
                unsafe { ring.submission().push(&request).unwrap() };
                assert_eq!(
                    ring.submit().unwrap_or_else(|error| panic!(
                        "{HOST_REQUIREMENTS}; io_uring_enter submission: {error}"
                    )),
                    1
                );
                let enrollment_deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let early_completion = ring.completion().next();
                    assert!(
                        early_completion.is_none(),
                        "{HOST_REQUIREMENTS}; futex wait completed before enrollment: \
                         {early_completion:?}"
                    );
                    let moved = host_futex(
                        parking.address(),
                        libc::FUTEX_CMP_REQUEUE,
                        0,
                        1,
                        word.address(),
                        0,
                    );
                    assert!(moved == 0 || moved == 1);
                    if moved == 1 {
                        break;
                    }
                    assert!(
                        Instant::now() < enrollment_deadline,
                        "clear-TID waiter was not queued"
                    );
                    std::thread::yield_now();
                }
                // Linux io_uring/futex.c keeps this request's futex_q enrolled
                // until wake or cancellation; it has no sleeping FUTEX_WAIT
                // syscall that can restart at PARK after requeue. Require the
                // same request to complete with an actual wake, not a timeout.
                // https://github.com/rrnewton/reverie/issues/696
                // https://github.com/torvalds/linux/blob/v7.1/io_uring/futex.c
                if registered_worker {
                    executor.set_clear_child_tid(Some(WORD));
                    backend.clear_registered_worker_tid_before_exit(&mut executor);
                    assert_eq!(executor.take_clear_child_tid(), None);
                } else {
                    clear_tid_and_wake(&mut backend.memory, Some(WORD));
                }
                let wake = clear_tid_diagnostic::take();
                let mut bytes = [0; 4];
                backend.memory.read_raw(WORD, &mut bytes).unwrap();
                let stored = policy != 2 && (!registered_worker || policy == 0);
                assert_eq!(i32::from_ne_bytes(bytes), if stored { 0 } else { 7 });
                if policy == 2 {
                    // No wake: prove the same waiter is still queued, then
                    // drain it explicitly so no request survives the test.
                    assert_eq!(
                        host_futex(
                            word.address(),
                            libc::FUTEX_CMP_REQUEUE,
                            0,
                            1,
                            parking.address(),
                            7
                        ),
                        1
                    );
                    assert_eq!(
                        host_futex(parking.address(), libc::FUTEX_WAKE, 1, 0, 0, 0),
                        1
                    );
                }
                let remaining = wait_deadline
                    .checked_duration_since(Instant::now())
                    .expect("clear-TID wake exceeded the unchanged five-second deadline");
                let timeout = types::Timespec::from(remaining);
                let args = types::SubmitArgs::new().timespec(&timeout);
                let completion_wait = ring.submitter().submit_with_args(1, &args);
                assert_eq!(
                    completion_wait.as_ref().ok(),
                    Some(&0),
                    "expected completion within the single five-second deadline; \
                     registered_worker={registered_worker} policy={policy} \
                     completion_wait={completion_wait:?} wake={wake:?}"
                );
                let completion = ring.completion().next().expect("missing futex completion");
                assert_eq!(
                    completion.user_data(),
                    request_id,
                    "wrong futex request completed"
                );
                assert_eq!(
                    completion.result(),
                    0,
                    "expected an actual wake, never a timeout; \
                     registered_worker={registered_worker} policy={policy} \
                     completion={completion:?} wake={wake:?}"
                );
                assert!(
                    ring.completion().next().is_none(),
                    "unexpected extra completion"
                );
            }
            // An unaligned word crosses writable and readonly pages. Futex
            // itself rejects the alignment, but the two full-store contracts
            // remain distinct; neither may accidentally write only a prefix.
            backend.memory.clear_user_access();
            backend.memory.map_user_range(WORD, PAGE, false).unwrap();
            backend
                .memory
                .map_user_permissions(WORD + PAGE, PAGE, true, false)
                .unwrap();
            backend.memory.enable_user_access();
            let address = WORD + PAGE - 2;
            backend.memory.write_raw(address, &[0xa5; 4]).unwrap();
            if registered_worker {
                executor.set_clear_child_tid(Some(address));
                backend.clear_registered_worker_tid_before_exit(&mut executor);
                assert_eq!(executor.take_clear_child_tid(), None);
            } else {
                clear_tid_and_wake(&mut backend.memory, Some(address));
            }
            let mut bytes = [0; 4];
            backend.memory.read_raw(address, &mut bytes).unwrap();
            assert_eq!(bytes, if registered_worker { [0xa5; 4] } else { [0; 4] });
            let unaligned = backend
                .memory
                .user()
                .retain_translated_range(address, 4)
                .unwrap();
            assert_eq!(
                host_futex(unaligned.address(), libc::FUTEX_WAKE, 1, 0, 0, 0),
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINVAL)
            );
        }
    }

    #[test]
    fn clone_tid_stores_and_clear_are_best_effort() {
        const TID_ADDRESS: u64 = 0x100;

        let mut memory = GuestMemory::new(0, 4096).unwrap();
        write_tid_best_effort(&mut memory, Some(TID_ADDRESS), 7);
        let mut bytes = [0; std::mem::size_of::<i32>()];
        memory.read(TID_ADDRESS, &mut bytes).unwrap();
        assert_eq!(i32::from_le_bytes(bytes), 7);

        write_tid_best_effort(&mut memory, Some(TID_ADDRESS), 0);
        memory.read(TID_ADDRESS, &mut bytes).unwrap();
        assert_eq!(i32::from_le_bytes(bytes), 0);

        write_tid_best_effort(&mut memory, Some(4095), 9);
        write_tid_best_effort(&mut memory, None, 9);
    }

    #[test]
    fn nested_pending_worker_is_cancelled_in_the_next_join_batch() {
        let group = Arc::new(GuestThreadGroup::default());
        let nested_cancelled = Arc::new(AtomicBool::new(false));
        let nested_cancelled_in_worker = nested_cancelled.clone();
        let parent_group = group.clone();
        group.add_worker_handle(
            1,
            std::thread::spawn(move || {
                let (start_sender, start_receiver) = std::sync::mpsc::channel();
                let start_gate = ChildStartGate::new(start_sender);
                parent_group.add_unstarted_worker(
                    2,
                    start_gate,
                    std::thread::spawn(move || {
                        assert_eq!(start_receiver.recv().unwrap(), ChildStartCommand::Cancel);
                        nested_cancelled_in_worker.store(true, Ordering::Release);
                        Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
                    }),
                );
                Ok((ExitStatus::SUCCESS, Vec::new(), Vec::new()))
            }),
        );

        group.cancel_workers();
        group.join_workers();

        assert!(nested_cancelled.load(Ordering::Acquire));
        assert!(group.worker_handles.lock().unwrap().is_empty());
    }

    include!("vm/public_tool_panic_tests.rs");
    include!("vm/instruction_callback_panic_tests.rs");
}

#[cfg(test)]
#[path = "terminal_vm_tests.rs"]
mod terminal_tests;

#[cfg(test)]
mod terminal_direct_error_tests {
    use std::os::fd::FromRawFd;
    use std::sync::mpsc;
    use std::task::Poll;
    use std::time::Duration;

    use super::*;

    #[test]
    fn public_direct_errors_join_terminal_readers_and_keep_primary_and_cleanup() {
        for captured in [false, true] {
            let mut backend = KvmBackend::new(16 * 1024 * 1024)
                .expect("public Direct cleanup control requires KVM");
            backend
                .install_static_elf(&minimal_test_elf(&[0xf4]), "/bin/direct-read-cleanup")
                .unwrap();
            let group = backend.thread_group.clone();
            let registry = group.terminal_reads.clone();
            let primary = Arc::new(Error::GuestClock("controlled Direct entry failure".into()));
            // This tests typed error transfer after a real helper cancellation.
            // It does not claim that a real pthread operation returned EIO.
            let cleanup = Arc::new(Error::TerminalReadControl {
                operation: "test-controlled reader teardown diagnostic",
                source: std::io::Error::from_raw_os_error(libc::EIO),
                terminal_exit: None,
            });
            let worker_cleanup = cleanup.clone();
            let returned = Arc::new(AtomicBool::new(false));
            let worker_returned = returned.clone();
            let endpoint_restored = Arc::new(AtomicBool::new(false));
            let worker_endpoint_restored = endpoint_restored.clone();
            let (ready, registered) = mpsc::channel();
            let worker = std::thread::spawn(move || {
                // Keep the test worker's entry watch independent: only the
                // group's terminal cancellation may retire this real reader.
                let memory = GuestMemory::new(0, 4096).unwrap();
                let raw_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
                assert!(raw_fd >= 0);
                let mut endpoint = Some(unsafe { File::from_raw_fd(raw_fd) });
                let mut polls = 0;
                let mut observer = crate::terminal_read::ReadContext::new(
                    registry,
                    true,
                    crate::entry::driver::EntryDriverWatch::for_memory(&memory),
                    Some(Box::pin(std::future::poll_fn(move |_| {
                        polls += 1;
                        if polls == 2 {
                            // This boundary follows C handle publication.
                            ready.send(()).unwrap();
                        }
                        Poll::Pending
                    }))),
                    Arc::new(crate::failure::tool_panics::ToolPanics::default()),
                    false,
                );
                let task = reverie::SignalTaskIdentity {
                    process: reverie::SignalProcessId {
                        tgid: Pid::from_raw(11),
                        generation: 12,
                    },
                    tid: Pid::from_raw(13),
                    task_generation: 14,
                };
                let mut bytes = Vec::<u8>::new();
                let result = observer.read(
                    &mut endpoint,
                    task,
                    SyscallRequest::new(libc::SYS_read as u64, [0, 0x100, 0, 0, 0, 0]),
                    bytes.as_mut_ptr() as usize,
                    0,
                );
                assert!(matches!(result, Err(Error::TerminalReadCancelled)));
                assert_eq!(endpoint.as_ref().unwrap().as_raw_fd(), raw_fd);
                assert!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } >= 0);
                worker_endpoint_restored.store(true, Ordering::Release);
                worker_returned.store(true, Ordering::Release);
                Err(Error::SharedFailure(worker_cleanup))
            });
            group.add_worker_handle(13, worker);
            registered
                .recv_timeout(Duration::from_secs(5))
                .expect("reader did not publish its C handle");
            assert!(!returned.load(Ordering::Acquire));
            backend
                .memory
                .entry_gate()
                .poison(None, Error::SharedFailure(primary.clone()));
            let result = if captured {
                backend.run_static_elf_captured().map(|_| ())
            } else {
                backend.run_static_elf().map(|_| ())
            };
            let error = result.expect_err("poisoned Direct entry returned success");
            assert!(error.retains_primary(&primary));
            assert!(crate::failure::references_shared_error(&error, &cleanup));
            assert!(returned.load(Ordering::Acquire));
            assert!(endpoint_restored.load(Ordering::Acquire));
            assert!(!group.has_owned_worker_joins());
            assert!(group.cancelled.load(Ordering::Acquire));
            assert!(group.cancelled_after_failure.load(Ordering::Acquire));
            let repeated = group.teardown_result().unwrap_err();
            assert!(crate::failure::references_shared_error(&repeated, &cleanup));
        }
    }
}

#[cfg(test)]
#[path = "vm/entry_owner_tests.rs"]
mod entry_owner_tests;

#[cfg(test)]
#[path = "vm/exec_wait_tests.rs"]
mod exec_wait_tests;
