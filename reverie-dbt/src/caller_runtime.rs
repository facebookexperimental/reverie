/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Caller-selected, coordinated Tool runtime for one initial application thread.
//!
//! The Tool is constructed only in the admitted application callback. The
//! background reader selects and retains configuration but owns no Tool or
//! GlobalState. Fork, successor exec and signal/instruction interception are
//! not supplied by this initial domain.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use reverie::CallbackDecision;
use reverie::CallbackPhase;
use reverie::Error;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Pid;
use reverie::Tool;
use reverie::ToolConfiguration;
use reverie::ToolProcess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_rpc_transport::tool_activation::ExitOrigin;
use reverie_rpc_transport::tool_activation::FinishedReceipt;
use reverie_rpc_transport::tool_activation::ToolControl;

use crate::DbtGuest;
use crate::DbtRuntimeCallbacks;
use crate::MemoryReader;
use crate::RegisterReader;
use crate::RegisterWriter;
use crate::SyscallInvoker;
use crate::caller_abi::CALLER_CAPABILITIES;
use crate::caller_abi::ImageDescriptor;
use crate::caller_abi::ReadySnapshot;
use crate::caller_abi::TerminalFact;
use crate::caller_effects::CallerEffects;

struct Configuration<T: Tool> {
    selected: ToolConfiguration<T>,
    digest: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Starting,
    Running,
    Consuming,
    Finished,
}

struct RootAttachment<T: Tool> {
    process: ToolProcess<T>,
    state: Option<T::ThreadState>,
    primary: crate::sync_rpc::CallerPrimary,
    effects: Arc<CallerEffects>,
    context: usize,
    pid: i32,
    tid: i32,
    image: u64,
    phase: Phase,
}

/// The checked common prefix of the native per-thread allocation.
#[repr(C)]
pub struct CallerCounters {
    /// Native conditional-branch observation.
    pub branches: u64,
    /// Syscalls observed by this runtime.
    pub observed_syscalls: u64,
    /// Syscalls whose result or operands the Tool supplied.
    pub rewritten_syscalls: u64,
    /// Owned root attachment, installed only by actual application admission.
    pub runtime_state: *mut c_void,
}

const _: () = assert!(std::mem::offset_of!(CallerCounters, runtime_state) == 24);

/// One concrete caller type, instantiated by [`crate::export_caller_tool`].
/// This holds configuration/diagnostics and one admission identity, never T.
pub struct CallerRuntime<T: Tool> {
    identity: [u8; 32],
    configuration: OnceLock<Configuration<T>>,
    callbacks: OnceLock<DbtRuntimeCallbacks>,
    generation: AtomicU64,
    ready: AtomicI32,
    root: AtomicU64,
    finished: AtomicI32,
    observed: AtomicU64,
    branches: AtomicU64,
    rewritten: AtomicU64,
}

impl<T: Tool> CallerRuntime<T> {
    /// Create the static runtime with its producer-bound input identity.
    pub const fn new(identity: [u8; 32]) -> Self {
        Self {
            identity,
            configuration: OnceLock::new(),
            callbacks: OnceLock::new(),
            generation: AtomicU64::new(0),
            ready: AtomicI32::new(0),
            root: AtomicU64::new(0),
            finished: AtomicI32::new(0),
            observed: AtomicU64::new(0),
            branches: AtomicU64::new(0),
            rewritten: AtomicU64::new(0),
        }
    }

    /// Publish the immutable native-only instruction contract, without I/O.
    pub fn image_init(&self) -> ImageDescriptor {
        if self
            .generation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.fail("caller-successor-image-unsupported");
            return ImageDescriptor::default();
        }
        ImageDescriptor {
            capabilities: CALLER_CAPABILITIES,
            runtime_input_identity: self.identity,
            ..ImageDescriptor::legacy(1)
        }
    }

    fn fail(&self, reason: &str) {
        self.ready.store(-1, Ordering::Release);
        if let Some(callbacks) = self.callbacks.get() {
            let message = format!("reverie-dbt: {reason}\n");
            unsafe { (callbacks.emit)(message.as_ptr(), message.len()) };
        }
    }

    fn rpc_failure_callback(&self) -> Result<crate::RuntimeRpcTransportFatal, Error> {
        self.callbacks
            .get()
            .and_then(|callbacks| callbacks.rpc_transport_fatal)
            .ok_or_else(|| crate::caller_error("caller RPC failure owner missing"))
    }

    fn rpc_transport_failure(
        &self,
        context: usize,
        fatal: crate::RuntimeRpcTransportFatal,
        _error: reverie_rpc_transport::RpcError,
    ) -> ! {
        // CallerPrimary::send has already returned and released its lease.
        // No formatting, panic hook, RPC, or guest descriptor is involved in
        // reporting this loss of controller ownership.
        self.ready.store(-1, Ordering::Release);
        unsafe { fatal(context) }
    }

    /// Receive and retain typed configuration on the existing helper.
    ///
    /// # Safety
    /// `argument` must point to a complete current callback table. The native
    /// owner must check this image's exported ABI and exact callback size
    /// before entering Rust; an old 96-byte table must never be copied here.
    pub unsafe fn background_init(&self, argument: *mut c_void, mode: u32) -> i32 {
        if argument.is_null() || mode != crate::DbtStartupMode::Coordinated as u32 {
            self.fail("caller-coordinated-startup-required");
            return -1;
        }
        let callbacks = unsafe { *(argument.cast::<DbtRuntimeCallbacks>()) };
        if self.callbacks.set(callbacks).is_err() {
            self.fail("caller-background-initialization-repeated");
            return -1;
        }
        if callbacks.rpc_transport_fatal.is_none() {
            self.fail("caller RPC failure owner missing");
            return -1;
        }
        crate::install_guest_compare_exchange(callbacks.compare_exchange_u32);
        crate::install_controller_capture_control(callbacks.controller_capture_control);
        crate::install_runtime_private_memory(callbacks.runtime_private_memory);
        crate::install_branch_fact_query(callbacks.branch_fact);
        let result = (|| {
            let path = std::env::var_os(crate::sync_rpc::RPC_SOCKET_ENV)
                .ok_or_else(|| "caller coordinator socket missing".to_owned())?;
            let (config, digest) = crate::sync_rpc::read_initial_config_with_digest::<
                <T::GlobalState as GlobalTool>::Config,
            >(std::path::Path::new(&path))
            .map_err(|error| error.to_string())?;
            let selected = ToolConfiguration::<T>::select(Arc::new(config));
            self.configuration
                .set(Configuration { selected, digest })
                .map_err(|_| "caller configuration published twice".to_owned())?;
            Ok::<_, String>(())
        })();
        match result {
            Ok(()) => {
                self.ready.store(1, Ordering::Release);
                0
            }
            Err(error) => {
                self.fail(&error);
                -1
            }
        }
    }

    /// Acquire readiness. Pending and Failed do not write a snapshot.
    ///
    /// # Safety
    /// `output` must be writable for one ReadySnapshot when non-null.
    pub unsafe fn ready(&self, image: u64, output: *mut ReadySnapshot) -> i32 {
        let state = self.ready.load(Ordering::Acquire);
        if state != 1 {
            return state;
        }
        if image == 0 || image != self.generation.load(Ordering::Acquire) || output.is_null() {
            return -1;
        }
        let Some(config) = self.configuration.get() else {
            return -1;
        };
        let events = u32::from(config.selected.subscriptions().has_cpuid())
            | (u32::from(config.selected.subscriptions().has_rdtsc()) << 1);
        unsafe {
            output.write(ReadySnapshot {
                size: std::mem::size_of::<ReadySnapshot>() as u32,
                selected_event_bits: events,
                raw_config_digest: config.digest,
                owner_generation: image,
            });
        }
        1
    }

    /// Admit the actual initial application owner and run its real hooks.
    ///
    /// # Safety
    /// Native validated the allocation prefix, callback context and identities;
    /// counters is uniquely borrowed by this application thread for the call.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn thread_init(
        &self,
        counters: *mut CallerCounters,
        context: usize,
        tid: i32,
        pid: i32,
        ppid: i32,
        branches: u64,
        defer: i32,
        invoke: SyscallInvoker,
        read: RegisterReader,
        write: RegisterWriter,
    ) -> i32 {
        if defer != 0 {
            return 0;
        }
        let ready = self.ready.load(Ordering::Acquire);
        if ready == 0 {
            return 1;
        }
        if ready != 1 {
            return -1;
        }
        let result = unsafe {
            self.admit(
                counters, context, tid, pid, ppid, branches, invoke, read, write,
            )
        };
        match result {
            Ok(()) => 0,
            Err(error) => {
                self.fail(&error.to_string());
                -1
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    unsafe fn admit(
        &self,
        counters: *mut CallerCounters,
        context: usize,
        tid: i32,
        pid: i32,
        ppid: i32,
        branches: u64,
        invoke: SyscallInvoker,
        read: RegisterReader,
        write: RegisterWriter,
    ) -> Result<(), Error> {
        if counters.is_null() || context == 0 || tid <= 0 || tid != pid || ppid > 0 {
            return Err(crate::caller_error(
                "caller-initial-single-thread-owner-required",
            ));
        }
        let counters = unsafe { &mut *counters };
        if !counters.runtime_state.is_null() {
            return Err(crate::caller_error("caller-application-admission-repeated"));
        }
        let config = self
            .configuration
            .get()
            .ok_or_else(|| crate::caller_error("caller-owner-not-published"))?;
        if config.selected.subscriptions().has_cpuid()
            || config.selected.subscriptions().has_rdtsc()
        {
            return Err(crate::caller_error(
                "caller-instruction-subscription-unsupported",
            ));
        }
        // Read on the actual application callback, not the helper's process.
        let arguments = [libc::PR_GET_SECCOMP as u64, 0, 0, 0, 0, 0];
        let seccomp = unsafe {
            invoke(
                context,
                libc::SYS_prctl,
                arguments.as_ptr(),
                reverie::InjectionPurpose::Application as u32,
            )
        };
        if seccomp != 0 {
            return Err(crate::caller_error("caller-inherited-seccomp-unsupported"));
        }
        let identity = (u64::from(pid as u32) << 32) | u64::from(tid as u32);
        self.root
            .compare_exchange(0, identity, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| crate::caller_error("caller-second-application-owner-refused"))?;
        let primary = crate::sync_rpc::CallerPrimary::prepare(context, invoke, pid, config.digest)
            .map_err(Error::from)?;
        primary
            .control(
                context,
                invoke,
                &ToolControl::Claim {
                    digest: config.digest,
                },
            )
            .map_err(|error| Error::from(std::io::Error::other(error)))?;
        let process = ToolProcess::adopt_selected(
            config.selected.new_process(Pid::from_raw(pid)),
            config.selected.clone(),
        );
        let state = process.init_thread_state(Pid::from_raw(tid), None);
        let image = self.generation.load(Ordering::Acquire);
        let callbacks = self
            .callbacks
            .get()
            .ok_or_else(|| crate::caller_error("caller callbacks missing"))?;
        let mut attachment = Box::new(RootAttachment {
            process,
            state: Some(state),
            primary,
            effects: Arc::new(CallerEffects::new(
                context,
                pid,
                tid,
                image,
                callbacks.admit_terminal,
            )),
            context,
            pid,
            tid,
            image,
            phase: Phase::Starting,
        });
        // Publication precedes hooks and Started, but is not activation itself.
        counters.runtime_state = (&mut *attachment as *mut RootAttachment<T>).cast();
        let hooks = run_start_hooks(self, &mut attachment, config, branches, invoke, read, write);
        if let Err(error) = hooks {
            counters.runtime_state = std::ptr::null_mut();
            return Err(error);
        }
        if let Err(error) = attachment.primary.control(
            context,
            invoke,
            &ToolControl::Started {
                digest: config.digest,
            },
        ) {
            counters.runtime_state = std::ptr::null_mut();
            return Err(Error::from(std::io::Error::other(error)));
        }
        attachment.phase = Phase::Running;
        counters.runtime_state = Box::into_raw(attachment).cast();
        crate::acknowledge_tool_admission(context);
        Ok(())
    }

    /// Dispatch the actual selected Tool through the existing caller Guest.
    ///
    /// # Safety
    /// All pointers are the live native callback's checked input/output records.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn pre_syscall(
        &self,
        context: usize,
        counters: *mut CallerCounters,
        tid: i32,
        pid: i32,
        image: u64,
        number: i64,
        args: *const u64,
        branches: u64,
        result: *mut i64,
        deferred_number: *mut i64,
        deferred_args: *mut u64,
        invoke: SyscallInvoker,
        read: RegisterReader,
        write: RegisterWriter,
        memory: MemoryReader,
    ) -> i32 {
        let outcome = (|| {
            let attachment = unsafe { self.attachment(counters, context, pid, tid, image) }?;
            if attachment.phase != Phase::Running {
                return Err(crate::caller_error("caller syscall outside running phase"));
            }
            let args = unsafe { *args.cast::<[u64; 6]>() };
            if crate::caller_effects::unsupported_operation(number, &args, false) {
                return Err(crate::caller_error(
                    "caller-application-lifecycle-unsupported",
                ));
            }
            let config = self
                .configuration
                .get()
                .ok_or_else(|| crate::caller_error("caller configuration missing"))?;
            self.observed.fetch_add(1, Ordering::Relaxed);
            self.branches.store(branches, Ordering::Relaxed);
            let syscall = raw_syscall(number, args)?;
            if !config
                .selected
                .subscriptions()
                .iter_syscalls()
                .any(|selected| selected == syscall.number())
            {
                if let Some(value) =
                    crate::sync_rpc::protect_guest_operation(context, invoke, number, &args, false)
                {
                    unsafe { result.write(value) };
                    return Ok(1);
                }
                return Ok(0);
            }
            let rpc = CallerRpc::<T> {
                owner: self,
                fatal: self.rpc_failure_callback()?,
                primary: &attachment.primary,
                config: config.selected.config(),
                context,
                invoke,
                tid: Pid::from_raw(tid),
            };
            let state = attachment
                .state
                .as_mut()
                .ok_or_else(|| crate::caller_error("caller thread state consumed"))?;
            let guest = DbtGuest::<T>::new_with_rpc(
                context,
                Pid::from_raw(tid),
                Pid::from_raw(pid),
                None,
                branches,
                state,
                &rpc,
                invoke,
                read,
                write,
            )
            .with_memory_reader(memory)
            .with_caller_effects(Arc::clone(&attachment.effects), true);
            match crate::run_caller_syscall_with_guest(&attachment.process, guest, syscall)? {
                crate::CallerSyscallOutcome::Suppress(value) => {
                    self.rewritten.fetch_add(1, Ordering::Relaxed);
                    unsafe { result.write(value) };
                    Ok(1)
                }
                crate::CallerSyscallOutcome::ExecuteOriginal(call) => {
                    self.rewritten.fetch_add(1, Ordering::Relaxed);
                    unsafe { crate::write_deferred_syscall(call, deferred_number, deferred_args) };
                    Ok(2)
                }
                crate::CallerSyscallOutcome::Terminal(fact) => {
                    self.rewritten.fetch_add(1, Ordering::Relaxed);
                    unsafe {
                        deferred_number.write(fact.sysno);
                        std::ptr::copy_nonoverlapping(fact.args.as_ptr(), deferred_args, 6);
                    }
                    Ok(2)
                }
            }
        })();
        match outcome {
            Ok(action) => action,
            Err(error) => {
                self.fail(&error.to_string());
                -1
            }
        }
    }

    unsafe fn attachment<'a>(
        &self,
        counters: *mut CallerCounters,
        context: usize,
        pid: i32,
        tid: i32,
        image: u64,
    ) -> Result<&'a mut RootAttachment<T>, Error> {
        let counters = unsafe { counters.as_mut() }
            .ok_or_else(|| crate::caller_error("caller native prefix absent"))?;
        let attachment = unsafe { counters.runtime_state.cast::<RootAttachment<T>>().as_mut() }
            .ok_or_else(|| crate::caller_error("caller application not admitted"))?;
        if attachment.context != context
            || attachment.pid != pid
            || attachment.tid != tid
            || attachment.image != image
        {
            return Err(crate::caller_error("caller native owner mismatch"));
        }
        Ok(attachment)
    }

    /// Consume real state only for the native validated terminal reservation.
    ///
    /// # Safety
    /// Native revalidated and prepared the exact fact after all Guest borrows
    /// ended. The record and prefix are live and uniquely owned for this call.
    pub unsafe fn thread_exit(
        &self,
        counters: *mut CallerCounters,
        context: usize,
        tid: i32,
        invoke: SyscallInvoker,
        fact: *const TerminalFact,
    ) -> i32 {
        let outcome = (|| {
            let fact = unsafe { fact.as_ref() }
                .ok_or_else(|| crate::caller_error("caller exit lacks terminal provenance"))?;
            if fact.kind != 1 {
                return Err(crate::caller_error("caller unobserved terminal event"));
            }
            let attachment =
                unsafe { self.attachment(counters, context, fact.pid, tid, fact.image) }?;
            if !fact.matches_owner(context, attachment.pid, tid, attachment.image) {
                return Err(crate::caller_error("caller terminal fact mismatch"));
            }
            if attachment.phase == Phase::Finished {
                return if attachment.effects.ending() == Some(*fact) {
                    Ok(())
                } else {
                    Err(crate::caller_error("caller completed ending changed"))
                };
            }
            if attachment.phase != Phase::Running || !attachment.effects.establish_final(*fact) {
                return Err(crate::caller_error("caller final ending was not admitted"));
            }
            attachment.phase = Phase::Consuming;
            let state = attachment
                .state
                .take()
                .ok_or_else(|| crate::caller_error("caller thread state already consumed"))?;
            let config = self
                .configuration
                .get()
                .ok_or_else(|| crate::caller_error("caller config absent at exit"))?;
            let rpc = CallerRpc::<T> {
                owner: self,
                fatal: self.rpc_failure_callback()?,
                primary: &attachment.primary,
                config: config.selected.config(),
                context,
                invoke,
                tid: Pid::from_raw(tid),
            };
            let status = reverie::exit_status_from_raw(fact.args[0]);
            let tail = crate::TailInjectResult::default();
            crate::run_ready(
                attachment
                    .process
                    .on_exit_thread(Pid::from_raw(tid), &rpc, state, status),
                &tail,
            )
            .ok_or_else(|| crate::caller_error("caller exit hook unexpectedly deferred"))??;
            crate::run_ready(
                attachment
                    .process
                    .on_exit_process(Pid::from_raw(fact.pid), &rpc, status),
                &tail,
            )
            .ok_or_else(|| {
                crate::caller_error("caller process exit hook unexpectedly deferred")
            })??;
            let receipt = FinishedReceipt::explicit_exit(
                (fact.args[0] & 0xff) as u8,
                fact.sysno,
                if fact.origin == 1 {
                    ExitOrigin::Original
                } else {
                    ExitOrigin::Deferred
                },
            )
            .map_err(|error| Error::from(std::io::Error::other(error)))?;
            attachment
                .primary
                .control(
                    context,
                    invoke,
                    &ToolControl::Finished {
                        digest: config.digest,
                        receipt,
                    },
                )
                .map_err(|error| Error::from(std::io::Error::other(error)))?;
            attachment.phase = Phase::Finished;
            self.finished.store(1, Ordering::Release);
            Ok::<_, Error>(())
        })();
        match outcome {
            Ok(()) => 0,
            Err(error) => {
                self.fail(&error.to_string());
                -1
            }
        }
    }

    /// A statusless notification cannot manufacture a consuming lifecycle.
    pub fn process_exit(&self) {
        // An originating failure already owns teardown. A late statusless
        // notification must not replace its diagnostic or start more work.
        if self.ready.load(Ordering::Acquire) == -1 {
            return;
        }
        if self.finished.load(Ordering::Acquire) != 1 {
            self.fail("caller process ended without acknowledged consuming lifecycle");
        }
    }

    /// Number of application syscall callbacks, without sending any Tool RPC.
    pub fn observed_syscalls(&self) -> u64 {
        self.observed.load(Ordering::Relaxed)
    }

    /// Last actual native branch observation, without Tool RPC.
    pub fn observed_branches(&self) -> u64 {
        self.branches.load(Ordering::Relaxed)
    }

    /// Number of selected callbacks that supplied a result or replacement.
    pub fn rewritten_syscalls(&self) -> u64 {
        self.rewritten.load(Ordering::Relaxed)
    }

    /// Fail a required native role outside this caller domain before its effect.
    pub fn unsupported(&self, role: &'static str) -> i32 {
        self.fail(role);
        -1
    }
}

struct CallerRpc<'a, T: Tool> {
    owner: &'a CallerRuntime<T>,
    fatal: crate::RuntimeRpcTransportFatal,
    primary: &'a crate::sync_rpc::CallerPrimary,
    config: &'a <T::GlobalState as GlobalTool>::Config,
    context: usize,
    invoke: SyscallInvoker,
    tid: Pid,
}

#[reverie::tool]
impl<T: Tool> GlobalRPC<T::GlobalState> for CallerRpc<'_, T> {
    async fn send_rpc(
        &self,
        request: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        match self.primary.send::<T::GlobalState>(
            self.context,
            self.invoke,
            self.tid,
            self.config,
            request,
        ) {
            Ok(response) => response,
            Err(error) => self
                .owner
                .rpc_transport_failure(self.context, self.fatal, error),
        }
    }
    fn try_send_rpc_sync(
        &self,
        request: <T::GlobalState as GlobalTool>::Request,
    ) -> Result<<T::GlobalState as GlobalTool>::Response, <T::GlobalState as GlobalTool>::Request>
    {
        match self.primary.send::<T::GlobalState>(
            self.context,
            self.invoke,
            self.tid,
            self.config,
            request,
        ) {
            Ok(response) => Ok(response),
            Err(error) => self
                .owner
                .rpc_transport_failure(self.context, self.fatal, error),
        }
    }
    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.config
    }
}

fn raw_syscall(number: i64, args: [u64; 6]) -> Result<Syscall, Error> {
    let number = i32::try_from(number)
        .map_err(|_| crate::caller_error("caller syscall number out of range"))?;
    if number < 0 || number & 0x4000_0000 != 0 {
        return Err(crate::caller_error(
            "caller syscall number is not an x86_64 Linux syscall",
        ));
    }
    Ok(Syscall::from_raw(
        Sysno::from(number),
        SyscallArgs::new(
            args[0] as usize,
            args[1] as usize,
            args[2] as usize,
            args[3] as usize,
            args[4] as usize,
            args[5] as usize,
        ),
    ))
}

fn run_start_hooks<T: Tool>(
    owner: &CallerRuntime<T>,
    attachment: &mut RootAttachment<T>,
    config: &Configuration<T>,
    branches: u64,
    invoke: SyscallInvoker,
    read: RegisterReader,
    write: RegisterWriter,
) -> Result<(), Error> {
    let rpc = CallerRpc::<T> {
        owner,
        fatal: owner.rpc_failure_callback()?,
        primary: &attachment.primary,
        config: config.selected.config(),
        context: attachment.context,
        invoke,
        tid: Pid::from_raw(attachment.tid),
    };
    let mut guest = DbtGuest::<T>::new_with_rpc(
        attachment.context,
        Pid::from_raw(attachment.tid),
        Pid::from_raw(attachment.pid),
        None,
        branches,
        attachment.state.as_mut().unwrap(),
        &rpc,
        invoke,
        read,
        write,
    )
    .with_caller_effects(Arc::clone(&attachment.effects), false);
    let tail = Arc::clone(&guest.tail_inject_result);
    match crate::run_caller_callback(
        attachment.process.handle_thread_start(&mut guest),
        &tail,
        &attachment.effects,
        CallbackPhase::Callback,
    ) {
        CallbackDecision::Ready(result) => result?,
        CallbackDecision::Refused(reason) => return Err(crate::caller_error(reason)),
        _ => {
            return Err(crate::caller_error(
                "caller unsupported thread-start completion",
            ));
        }
    }
    match crate::run_caller_callback(
        attachment.process.handle_post_exec(&mut guest),
        &tail,
        &attachment.effects,
        CallbackPhase::Callback,
    ) {
        CallbackDecision::Ready(result) => result.map_err(Error::from),
        CallbackDecision::Refused(reason) => Err(crate::caller_error(reason)),
        _ => Err(crate::caller_error(
            "caller unsupported post-exec completion",
        )),
    }
}

#[cfg(test)]
mod tests;
