/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::future::poll_fn;
use std::pin::Pin;
use std::pin::pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Poll;

use kvm_bindings::kvm_regs;
use kvm_ioctls::VcpuExit;
use reverie::Auxv;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Stack;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::SyscallInfo;

use crate::Error;
use crate::GuestMemory;
use crate::KvmBackend;
use crate::Result;
use crate::SyscallRequest;
use crate::VMCALL_SYSCALL_TRANSPORT;
use crate::bootstrap::SYSCALL_FRAME_ADDRESS;
use crate::bootstrap::TOOL_STACK_TOP;
use crate::bootstrap::configure_process_syscall_return;
use crate::bootstrap::set_user_segment_base;
use crate::executor::ElfExecutor;
use crate::executor::ProcessAction;
use crate::executor::is_thread_clone_request;

const STACK_CAPACITY: usize = 4096;
const TOOL_STACK_BOTTOM: u64 = TOOL_STACK_TOP - STACK_CAPACITY as u64;

enum HandlerSignal {
    TailInjected {
        result: std::result::Result<i64, Errno>,
        image_replaced: bool,
        process_exited: bool,
    },
    RuntimeError(Error),
}

type SharedHandlerSignal = Arc<Mutex<Option<HandlerSignal>>>;

// AUTONOMOUS-BOT-IMPLEMENTED: Keep root syscalls that share worker state in one backend.
// TODO-HUMAN-REVIEW(PR-173): Review KVM root syscall ownership.
fn is_backend_owned_syscall(number: u64) -> bool {
    // KVM guest workers run outside Detcore's scheduler. Root futexes must
    // use the same host-backed words as workers, or Detcore deadlocks.
    number == libc::SYS_futex as u64
        // QEMU's root event loop waits on worker eventfds. KVM syscall
        // injection cannot perform ppoll, so use translated host descriptors.
        || number == libc::SYS_ppoll as u64
        // Workers can create descriptors that the root event loop consumes.
        // Scalar and vectored reads must use that shared descriptor table.
        || number == libc::SYS_read as u64
        || number == libc::SYS_readv as u64
}

/// Executes a syscall on behalf of a KVM guest.
///
/// A full KVM backend will delegate this operation to its guest kernel. The
/// current bare-guest prototype accepts an executor explicitly so that Reverie
/// tools can use `Guest::inject` and `Guest::tail_inject` with the same contract
/// as the ptrace backend.
pub trait SyscallExecutor: Send + Sync {
    /// Executes `request` and returns its raw Linux syscall result.
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64;
}

impl<F> SyscallExecutor for F
where
    F: FnMut(&SyscallRequest, &GuestMemory) -> i64 + Send + Sync,
{
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64 {
        self(request, memory)
    }
}

enum InjectionCompletion {
    Returns,
    DoesNotReturn {
        image_replaced: bool,
        process_exited: bool,
    },
}

// TODO-HUMAN-REVIEW(PR-192): Review awaitable KVM injection Tool context.
pub(crate) struct ToolContext<'a, T: Tool> {
    pub(crate) pid: Pid,
    pub(crate) thread_state: &'a T::ThreadState,
    // TODO-HUMAN-REVIEW(PR-235): Review shared GlobalTool ownership across KVM forks.
    pub(crate) global_state: Option<Arc<T::GlobalState>>,
    pub(crate) config: <T::GlobalState as GlobalTool>::Config,
    pub(crate) subscriptions: Subscription,
}

// TODO-HUMAN-REVIEW(PR-192): Review async KVM process-action completion.
trait GuestSyscallExecutor<T: Tool>: Send + Sync {
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64;

    fn complete_injection<'a>(
        &'a mut self,
        _context: ToolContext<'a, T>,
    ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
    where
        T: 'a,
    {
        Box::pin(async { Ok(InjectionCompletion::Returns) })
    }
}

struct DirectSyscallExecutor<'a> {
    executor: &'a mut dyn SyscallExecutor,
}

impl<T: Tool> GuestSyscallExecutor<T> for DirectSyscallExecutor<'_> {
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64 {
        self.executor.execute(request, memory)
    }
}

#[derive(Clone, Copy)]
struct ProcessBoundary {
    frame_address: u64,
    return_slot: usize,
}

enum ProcessExecutionContext {
    InitialExec(SyscallRequest),
    InitialExecCompleted,
    Lifecycle,
    SyscallBoundary(ProcessBoundary),
    SyscallReturn,
}

struct StaticElfSyscallExecutor<'a> {
    backend: &'a mut KvmBackend,
    executor: &'a mut ElfExecutor,
    memory: GuestMemory,
    process_context: ProcessExecutionContext,
    last_result: Option<i64>,
    process_completed: &'a mut bool,
}

impl<T> GuestSyscallExecutor<T> for StaticElfSyscallExecutor<'_>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    fn execute(&mut self, request: &SyscallRequest, memory: &GuestMemory) -> i64 {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(PR-233): Review synthetic initial exec completion.
        if matches!(
            &self.process_context,
            ProcessExecutionContext::InitialExec(expected) if expected == request
        ) {
            self.last_result = Some(0);
            self.process_context = ProcessExecutionContext::InitialExecCompleted;
            return 0;
        }
        let result = self.executor.execute(request, memory);
        self.last_result = Some(result);
        result
    }

    fn complete_injection<'a>(
        &'a mut self,
        context: ToolContext<'a, T>,
    ) -> Pin<Box<dyn Future<Output = Result<InjectionCompletion>> + Send + 'a>>
    where
        T: 'a,
    {
        Box::pin(async move {
            if matches!(
                self.process_context,
                ProcessExecutionContext::InitialExecCompleted
            ) {
                *self.process_completed = true;
                return Ok(InjectionCompletion::DoesNotReturn {
                    image_replaced: true,
                    process_exited: false,
                });
            }
            let Some(action) = self.executor.take_process_action() else {
                return Ok(if self.executor.has_pending_exit() {
                    InjectionCompletion::DoesNotReturn {
                        image_replaced: false,
                        process_exited: true,
                    }
                } else {
                    InjectionCompletion::Returns
                });
            };
            let image_replaced = matches!(&action, ProcessAction::Exec { .. });
            hide_tool_scratch(&self.memory)?;
            let action_result: Result<()> = async {
                match self.process_context {
                    ProcessExecutionContext::SyscallBoundary(boundary) => {
                        let result = self
                            .last_result
                            .expect("process action must have an injected syscall result");
                        SyscallRequest::write_result(
                            &mut self.memory,
                            boundary.frame_address,
                            result,
                        )?;
                        // SAFETY: return_slot points into this stopped vCPU's stable
                        // KVM_RUN mapping. Publish it before re-entering the vCPU.
                        unsafe {
                            (boundary.return_slot as *mut u64).write(0);
                        }
                        self.backend
                            .run_process_action_with_tool(self.executor, action, true, context)
                            .await?;
                        self.process_context = ProcessExecutionContext::SyscallReturn;
                        Ok(())
                    }
                    ProcessExecutionContext::SyscallReturn => {
                        self.backend
                            .run_process_action_with_tool(self.executor, action, false, context)
                            .await?;
                        Ok(())
                    }
                    ProcessExecutionContext::InitialExec(_)
                    | ProcessExecutionContext::Lifecycle => match action {
                        ProcessAction::Exec { image, argv, envp } => {
                            self.backend
                                .exec_process(self.executor, &image, &argv, &envp)?;
                            Ok(())
                        }
                        _ => Err(Error::UnexpectedVcpuExit(
                            "fork/clone injection requires a guest syscall boundary".to_owned(),
                        )),
                    },
                    ProcessExecutionContext::InitialExecCompleted => unreachable!(
                        "synthetic initial exec completes before process actions are inspected"
                    ),
                }
            }
            .await;
            let expose_result = expose_tool_scratch(&self.memory);
            action_result?;
            expose_result?;
            *self.process_completed = true;
            if image_replaced || self.executor.has_pending_exit() {
                Ok(InjectionCompletion::DoesNotReturn {
                    image_replaced,
                    process_exited: self.executor.has_pending_exit(),
                })
            } else {
                Ok(InjectionCompletion::Returns)
            }
        })
    }
}

struct KvmGlobal<'a, G: GlobalTool> {
    pid: Pid,
    state: &'a G,
    config: &'a G::Config,
}

#[reverie::tool]
impl<G: GlobalTool> GlobalRPC<G> for KvmGlobal<'_, G> {
    async fn send_rpc(&self, message: G::Request) -> G::Response {
        self.state.receive_rpc(self.pid, message).await
    }

    fn config(&self) -> &G::Config {
        self.config
    }
}

struct KvmGuest<'a, T: Tool> {
    pid: Pid,
    memory: GuestMemory,
    auxv: &'a [(libc::c_ulong, libc::c_ulong)],
    registers: libc::user_regs_struct,
    thread_state: &'a mut T::ThreadState,
    executor: &'a mut dyn GuestSyscallExecutor<T>,
    global_state: &'a T::GlobalState,
    shared_global_state: Option<Arc<T::GlobalState>>,
    config: &'a <T::GlobalState as GlobalTool>::Config,
    subscriptions: &'a Subscription,
    handler_signal: SharedHandlerSignal,
    stack_checked_out: Arc<AtomicBool>,
}

impl<'a, T: Tool> KvmGuest<'a, T> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        pid: Pid,
        memory: GuestMemory,
        auxv: &'a [(libc::c_ulong, libc::c_ulong)],
        registers: libc::user_regs_struct,
        thread_state: &'a mut T::ThreadState,
        executor: &'a mut dyn GuestSyscallExecutor<T>,
        global_state: &'a T::GlobalState,
        shared_global_state: Option<Arc<T::GlobalState>>,
        config: &'a <T::GlobalState as GlobalTool>::Config,
        subscriptions: &'a Subscription,
        handler_signal: SharedHandlerSignal,
        stack_checked_out: Arc<AtomicBool>,
    ) -> Self {
        Self {
            pid,
            memory,
            auxv,
            registers,
            thread_state,
            executor,
            global_state,
            shared_global_state,
            config,
            subscriptions,
            handler_signal,
            stack_checked_out,
        }
    }

    fn signal_handler(&self, signal: HandlerSignal) {
        *self
            .handler_signal
            .lock()
            .expect("KVM handler signal lock poisoned") = Some(signal);
    }
}

#[reverie::tool]
impl<T: Tool> GlobalRPC<T::GlobalState> for KvmGuest<'_, T> {
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        self.global_state.receive_rpc(self.pid, message).await
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.config
    }
}

#[reverie::tool]
impl<T: Tool> Guest<T> for KvmGuest<'_, T> {
    type Memory = GuestMemory;
    type Stack = KvmStack;

    fn tid(&self) -> Pid {
        self.pid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
        None
    }

    fn memory(&self) -> Self::Memory {
        self.memory.clone()
    }

    fn auxv(&self) -> Auxv {
        Auxv::from_entries(self.auxv.iter().copied())
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.thread_state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.thread_state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        self.registers
    }

    async fn stack(&mut self) -> Self::Stack {
        KvmStack::new(self.memory.clone(), self.stack_checked_out.clone())
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> std::result::Result<i64, Errno> {
        let request = SyscallRequest::from_syscall(syscall);
        let result = raw_to_result(self.executor.execute(&request, &self.memory));
        if result.is_ok() {
            let context = ToolContext {
                pid: self.pid,
                thread_state: self.thread_state,
                global_state: self.shared_global_state.clone(),
                config: self.config.clone(),
                subscriptions: self.subscriptions.clone(),
            };
            match self.executor.complete_injection(context).await {
                Ok(InjectionCompletion::DoesNotReturn {
                    image_replaced,
                    process_exited,
                }) => {
                    // TODO-HUMAN-REVIEW(PR-156): Review non-returning exec/exit injection.
                    // Successful exec and exit injection cannot resume the old
                    // handler after their process state transition completes.
                    self.signal_handler(HandlerSignal::TailInjected {
                        result,
                        image_replaced,
                        process_exited,
                    });
                    return std::future::pending().await;
                }
                Ok(InjectionCompletion::Returns) => {}
                Err(error) => {
                    self.signal_handler(HandlerSignal::RuntimeError(error));
                    return std::future::pending().await;
                }
            }
        }
        result
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        let result = self.inject(syscall).await;
        self.signal_handler(HandlerSignal::TailInjected {
            result,
            image_replaced: false,
            process_exited: false,
        });
        std::future::pending().await
    }

    fn set_timer(&mut self, _schedule: TimerSchedule) -> std::result::Result<(), reverie::Error> {
        Ok(())
    }

    fn set_timer_precise(
        &mut self,
        _schedule: TimerSchedule,
    ) -> std::result::Result<(), reverie::Error> {
        Ok(())
    }

    fn read_clock(&mut self) -> std::result::Result<u64, reverie::Error> {
        // The single-vCPU process personality does not yet expose a PMU. Returning
        // a stable zero clock preserves deterministic syscall time while the
        // executor remains cooperative at every syscall boundary.
        Ok(0)
    }
}

/// A stack allocator backed by a low page reserved for Tool injection buffers.
pub struct KvmStack {
    memory: GuestMemory,
    top: u64,
    stack_pointer: u64,
    capacity: usize,
    writes: Vec<(u64, Vec<u8>)>,
    checked_out: Arc<AtomicBool>,
}

impl KvmStack {
    fn new(memory: GuestMemory, checked_out: Arc<AtomicBool>) -> Self {
        assert!(
            !checked_out.swap(true, Ordering::SeqCst),
            "cannot retrieve a KVM guest stack while its previous guard is live",
        );
        let top = if memory.guest_base() <= TOOL_STACK_TOP && memory.guest_end() >= TOOL_STACK_TOP {
            TOOL_STACK_TOP
        } else {
            memory.guest_end()
        };
        let capacity = usize::try_from(top - memory.guest_base())
            .unwrap_or(usize::MAX)
            .min(STACK_CAPACITY);
        Self {
            capacity,
            memory,
            top,
            stack_pointer: top,
            writes: Vec::new(),
            checked_out,
        }
    }

    fn allocate<'stack, T>(&mut self, bytes: Vec<u8>) -> AddrMut<'stack, T> {
        let alignment = std::mem::align_of::<T>() as u64;
        let unaligned = self
            .stack_pointer
            .checked_sub(bytes.len() as u64)
            .expect("KVM guest stack address underflow");
        let address = unaligned & !(alignment - 1);
        assert!(
            self.top - address <= self.capacity as u64,
            "KVM guest stack overflow: capacity={} requested={}",
            self.capacity,
            self.top - address,
        );
        self.stack_pointer = address;
        self.writes.push((address, bytes));
        AddrMut::from_raw(address as usize)
            .expect("KVM guest stack allocation produced a null address")
    }
}

/// Guard returned after KVM guest stack writes are committed.
pub struct KvmStackGuard {
    checked_out: Arc<AtomicBool>,
}

impl Drop for KvmStackGuard {
    fn drop(&mut self) {
        assert!(
            self.checked_out.swap(false, Ordering::SeqCst),
            "KVM stack guard dropped without a checked-out stack",
        );
    }
}

impl Stack for KvmStack {
    type StackGuard = KvmStackGuard;

    fn size(&self) -> usize {
        (self.top - self.stack_pointer) as usize
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn push<'stack, T>(&mut self, value: T) -> Addr<'stack, T> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(&value).cast::<u8>(),
                std::mem::size_of::<T>(),
            )
        }
        .to_vec();
        self.allocate(bytes).into()
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        self.allocate(vec![0; std::mem::size_of::<T>()])
    }

    fn commit(self) -> std::result::Result<Self::StackGuard, Errno> {
        for (address, bytes) in self.writes {
            self.memory
                .write_raw(address, &bytes)
                .map_err(|_| Errno::EFAULT)?;
        }
        Ok(KvmStackGuard {
            checked_out: self.checked_out,
        })
    }
}

impl MemoryAccess for KvmStack {
    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        self.memory.read_vectored(read_from, write_to)
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> std::result::Result<usize, Errno> {
        self.memory.write_vectored(read_from, write_to)
    }
}

enum HandlerOutcome<T> {
    Returned(T),
    TailInjected {
        result: std::result::Result<i64, Errno>,
        image_replaced: bool,
        process_exited: bool,
    },
    RuntimeError(Error),
}

async fn drive_handler<T>(
    future: impl Future<Output = T>,
    handler_signal: SharedHandlerSignal,
) -> HandlerOutcome<T> {
    let mut future = pin!(future);
    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Ready(result) => Poll::Ready(HandlerOutcome::Returned(result)),
        Poll::Pending => match handler_signal
            .lock()
            .expect("KVM handler signal lock poisoned")
            .take()
        {
            Some(HandlerSignal::TailInjected {
                result,
                image_replaced,
                process_exited,
            }) => Poll::Ready(HandlerOutcome::TailInjected {
                result,
                image_replaced,
                process_exited,
            }),
            Some(HandlerSignal::RuntimeError(error)) => {
                Poll::Ready(HandlerOutcome::RuntimeError(error))
            }
            None => Poll::Pending,
        },
    })
    .await
}

fn expose_tool_scratch(memory: &GuestMemory) -> Result<()> {
    memory.map_user_range(TOOL_STACK_BOTTOM, STACK_CAPACITY as u64, false)
}

fn hide_tool_scratch(memory: &GuestMemory) -> Result<()> {
    memory.unmap_user_range(TOOL_STACK_BOTTOM, STACK_CAPACITY as u64)
}

// TODO-HUMAN-REVIEW(PR-156): Review repeated post-exec lifecycle delivery.
#[allow(clippy::too_many_arguments)]
async fn run_post_exec_handler<T>(
    backend: &mut KvmBackend,
    tool: &T,
    pid: Pid,
    memory: &GuestMemory,
    auxv: &mut Vec<(libc::c_ulong, libc::c_ulong)>,
    thread_state: &mut T::ThreadState,
    executor: &mut ElfExecutor,
    global_state: Arc<T::GlobalState>,
    config: &<T::GlobalState as GlobalTool>::Config,
    subscriptions: &Subscription,
    stack_checked_out: &Arc<AtomicBool>,
) -> Result<()>
where
    T: Tool + 'static,
    T::ThreadState: 'static,
    T::GlobalState: 'static,
    <T::GlobalState as GlobalTool>::Config: 'static,
{
    loop {
        let handler_signal = Arc::new(Mutex::new(None));
        expose_tool_scratch(memory)?;
        let registers = kvm_registers(backend.vcpu.get_regs()?, 0);
        let mut _process_completed = false;
        let outcome = {
            let mut guest_executor = StaticElfSyscallExecutor {
                backend,
                executor,
                memory: memory.clone(),
                process_context: ProcessExecutionContext::Lifecycle,
                last_result: None,
                process_completed: &mut _process_completed,
            };
            let mut guest = KvmGuest::<T>::new(
                pid,
                memory.clone(),
                auxv,
                registers,
                thread_state,
                &mut guest_executor,
                global_state.as_ref(),
                Some(global_state.clone()),
                config,
                subscriptions,
                handler_signal.clone(),
                stack_checked_out.clone(),
            );
            drive_handler(tool.handle_post_exec(&mut guest), handler_signal).await
        };
        hide_tool_scratch(memory)?;
        match outcome {
            HandlerOutcome::Returned(Ok(())) => return Ok(()),
            HandlerOutcome::Returned(Err(error)) => return Err(Error::PostExec(error)),
            HandlerOutcome::RuntimeError(error) => return Err(error),
            HandlerOutcome::TailInjected {
                process_exited: true,
                ..
            } => return Ok(()),
            HandlerOutcome::TailInjected {
                image_replaced: true,
                ..
            } => *auxv = executor.auxv().to_vec(),
            HandlerOutcome::TailInjected { .. } => {
                return Err(Error::UnexpectedVcpuExit(
                    "post-exec handler tail-injected a syscall".to_owned(),
                ));
            }
        }
    }
}

fn initial_exec_request(memory: &GuestMemory, stack_pointer: u64) -> Result<SyscallRequest> {
    fn read_word(memory: &GuestMemory, address: u64) -> Result<u64> {
        let mut bytes = [0; std::mem::size_of::<u64>()];
        memory.read(address, &mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    let argc = read_word(memory, stack_pointer)?;
    let argv = stack_pointer
        .checked_add(std::mem::size_of::<u64>() as u64)
        .ok_or(Error::LongModeMemoryTooSmall)?;
    let path = read_word(memory, argv)?;
    let envp = argc
        .checked_add(1)
        .and_then(|words| words.checked_mul(std::mem::size_of::<u64>() as u64))
        .and_then(|offset| argv.checked_add(offset))
        .ok_or(Error::LongModeMemoryTooSmall)?;

    Ok(SyscallRequest::new(
        libc::SYS_execve as u64,
        [path, argv, envp, 0, 0, 0],
    ))
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-233): Review synthetic initial exec Tool delivery.
#[allow(clippy::too_many_arguments)]
async fn run_initial_exec_handler<T: Tool>(
    backend: &mut KvmBackend,
    tool: &T,
    pid: Pid,
    memory: &GuestMemory,
    auxv: &[(libc::c_ulong, libc::c_ulong)],
    thread_state: &mut T::ThreadState,
    executor: &mut ElfExecutor,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    subscriptions: &Subscription,
    stack_checked_out: &Arc<AtomicBool>,
) -> Result<()> {
    let request = initial_exec_request(memory, executor.initial_stack_pointer())?;
    let syscall = request.into_syscall()?;
    let mut registers = kvm_registers(backend.vcpu.get_regs()?, request.number());
    registers.rdi = request.args()[0];
    registers.rsi = request.args()[1];
    registers.rdx = request.args()[2];

    let handler_signal = Arc::new(Mutex::new(None));
    expose_tool_scratch(memory)?;
    let mut _process_completed = false;
    let outcome = {
        let mut guest_executor = StaticElfSyscallExecutor {
            backend,
            executor,
            memory: memory.clone(),
            process_context: ProcessExecutionContext::InitialExec(request),
            last_result: None,
            process_completed: &mut _process_completed,
        };
        let mut guest = KvmGuest::<T>::new(
            pid,
            memory.clone(),
            auxv,
            registers,
            thread_state,
            &mut guest_executor,
            global_state,
            config,
            subscriptions,
            handler_signal.clone(),
            stack_checked_out.clone(),
        );
        drive_handler(
            tool.handle_syscall_event(&mut guest, syscall),
            handler_signal,
        )
        .await
    };
    hide_tool_scratch(memory)?;

    match outcome {
        HandlerOutcome::Returned(result) => result.map(|_| ()).map_err(Error::Reverie),
        HandlerOutcome::TailInjected {
            result: Ok(_),
            process_exited: true,
            ..
        } => Ok(()),
        HandlerOutcome::TailInjected {
            result: Ok(_),
            image_replaced: true,
            ..
        } => Ok(()),
        HandlerOutcome::TailInjected {
            result: Err(error), ..
        } => Err(Error::Reverie(error.into())),
        HandlerOutcome::TailInjected { .. } => Err(Error::UnexpectedVcpuExit(
            "initial exec handler tail-injected without completing exec".to_owned(),
        )),
        HandlerOutcome::RuntimeError(error) => Err(error),
    }
}

async fn notify_tool_exit<T: Tool>(
    tool: T,
    pid: Pid,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    thread_state: T::ThreadState,
    status: ExitStatus,
) -> Result<()> {
    let global = KvmGlobal {
        pid,
        state: global_state,
        config,
    };
    tool.on_exit_thread(pid, &global, thread_state, status)
        .await
        .map_err(Error::Reverie)?;
    tool.on_exit_process(pid, &global, status)
        .await
        .map_err(Error::Reverie)
}

impl KvmBackend {
    /// Runs the installed guest program through a shared Reverie `Tool`.
    ///
    /// The executor supplies Linux syscall semantics that a future guest kernel
    /// will provide. Tool lifecycle, typed syscall dispatch, thread state,
    /// global RPC, memory, stack, injection, and tail injection use the same
    /// Reverie contracts as the ptrace backend.
    pub async fn run_with_tool<T, E>(
        &mut self,
        config: <T::GlobalState as GlobalTool>::Config,
        mut executor: E,
    ) -> Result<T::GlobalState>
    where
        T: Tool,
        E: SyscallExecutor,
    {
        let pid = Pid::from_raw(self.root_pid);
        let global_state = T::GlobalState::init_global_state(&config).await;
        let tool = T::new(pid, &config);
        let subscriptions = T::subscriptions(&config);
        let mut thread_state = tool.init_thread_state(pid, None);
        let memory = self.memory.clone();
        let auxv = Vec::new();
        let stack_checked_out = Arc::new(AtomicBool::new(false));

        let registers = kvm_registers(self.vcpu.get_regs()?, 0);
        let handler_signal = Arc::new(Mutex::new(None));
        expose_tool_scratch(&memory)?;
        let start_outcome = {
            let mut guest_executor = DirectSyscallExecutor {
                executor: &mut executor,
            };
            let mut guest = KvmGuest::<T>::new(
                pid,
                memory.clone(),
                &auxv,
                registers,
                &mut thread_state,
                &mut guest_executor,
                &global_state,
                None,
                &config,
                &subscriptions,
                handler_signal.clone(),
                stack_checked_out.clone(),
            );
            drive_handler(tool.handle_thread_start(&mut guest), handler_signal).await
        };
        hide_tool_scratch(&memory)?;
        match start_outcome {
            HandlerOutcome::Returned(result) => result.map_err(Error::Reverie)?,
            HandlerOutcome::RuntimeError(error) => return Err(error),
            HandlerOutcome::TailInjected { .. } => {}
        }

        loop {
            match self.vcpu.run()? {
                VcpuExit::Hypercall(exit) => {
                    if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                        return Err(Error::UnexpectedHypercall(exit.nr));
                    }
                    let frame_address = exit.args[0];
                    let return_slot = std::ptr::from_mut(exit.ret) as usize;
                    let registers = self.vcpu.get_regs()?;
                    let request = SyscallRequest::read_from(&memory, frame_address)?;
                    let syscall = request.into_syscall()?;
                    let subscribed = subscriptions
                        .iter_syscalls()
                        .any(|number| number == syscall.number());
                    let result = if subscribed {
                        let handler_signal = Arc::new(Mutex::new(None));
                        expose_tool_scratch(&memory)?;
                        let outcome = {
                            let mut guest_executor = DirectSyscallExecutor {
                                executor: &mut executor,
                            };
                            let mut guest = KvmGuest::<T>::new(
                                pid,
                                memory.clone(),
                                &auxv,
                                kvm_registers(registers, request.number()),
                                &mut thread_state,
                                &mut guest_executor,
                                &global_state,
                                None,
                                &config,
                                &subscriptions,
                                handler_signal.clone(),
                                stack_checked_out.clone(),
                            );
                            drive_handler(
                                tool.handle_syscall_event(&mut guest, syscall),
                                handler_signal,
                            )
                            .await
                        };
                        hide_tool_scratch(&memory)?;
                        match outcome {
                            HandlerOutcome::Returned(result) => handler_result_to_raw(result)?,
                            HandlerOutcome::TailInjected { result, .. } => result_to_raw(result),
                            HandlerOutcome::RuntimeError(error) => return Err(error),
                        }
                    } else {
                        executor.execute(&request, &memory)
                    };
                    // SAFETY: return_slot points into this vCPU's stable KVM_RUN
                    // mapping. The vCPU remains stopped and is not run again while
                    // the tool callback is active.
                    unsafe {
                        (return_slot as *mut u64).write(result as u64);
                    }
                }
                VcpuExit::Hlt => {
                    let status = ExitStatus::SUCCESS;
                    let global = KvmGlobal {
                        pid,
                        state: &global_state,
                        config: &config,
                    };
                    tool.on_exit_thread(pid, &global, thread_state, status)
                        .await
                        .map_err(Error::Reverie)?;
                    tool.on_exit_process(pid, &global, status)
                        .await
                        .map_err(Error::Reverie)?;
                    return Ok(global_state);
                }
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            }
        }
    }

    /// Runs an installed static ELF through a Reverie `Tool`.
    ///
    /// This is the integration of the M1 ELF guest kernel
    /// ([`Self::run_static_elf`]) with the tool-interception path of
    /// [`Self::run_with_tool`]. A static ELF loaded by
    /// [`Self::install_static_elf`]/[`Self::install_static_elf_with_args`] runs
    /// in long mode. Root-thread syscalls selected by the tool's subscriptions
    /// are delivered to `Tool::handle_syscall_event`, including deferred
    /// fork/clone/exec/wait operations. A successful injected exec replaces the
    /// image without resuming the old handler. Forked process children receive
    /// their own process/thread tool state and dispatch subscribed syscalls through
    /// the same global state. `CLONE_THREAD` workers still execute directly through
    /// the KVM personality.
    /// Tool `inject`/`tail_inject` calls are serviced by the ELF guest kernel
    /// ([`ElfExecutor`]). Unlike [`Self::run_with_tool`], results are written
    /// back into the guest's syscall frame (the trampoline reads them and
    /// `SYSRET`s) and the guest exits via `exit`/`exit_group` rather than `HLT`.
    ///
    /// Returns the tool's global state, guest exit code, stdout, and stderr.
    pub async fn run_static_elf_with_tool<T>(
        &mut self,
        config: <T::GlobalState as GlobalTool>::Config,
        capture_output: bool,
    ) -> Result<(T::GlobalState, i32, Vec<u8>, Vec<u8>)>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        let mut loaded = self.static_elf.take().ok_or(Error::StaticElfNotInstalled)?;
        if capture_output {
            loaded.stdin = Some(std::fs::File::open("/dev/null")?);
        }
        let pid = Pid::from_raw(self.root_pid);
        let global_state = Arc::new(T::GlobalState::init_global_state(&config).await);
        let tool = T::new(pid, &config);
        let subscriptions = T::subscriptions(&config);
        let thread_state = tool.init_thread_state(pid, None);
        let mut executor = ElfExecutor::new(loaded, capture_output);
        let result = self
            .run_static_elf_process_with_tool(
                &mut executor,
                pid,
                tool,
                thread_state,
                global_state.clone(),
                &config,
                &subscriptions,
                true,
            )
            .await?;
        let global_state = Arc::try_unwrap(global_state).map_err(|_| {
            Error::UnexpectedVcpuExit("KVM child retained global Tool state after exit".to_owned())
        })?;
        let (exit_code, stdout, stderr) = result;
        Ok((global_state, exit_code, stdout, stderr))
    }

    // TODO-HUMAN-REVIEW(PR-192): Review recursive KVM process Tool runtime.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_static_elf_process_with_tool<T>(
        &mut self,
        executor: &mut ElfExecutor,
        pid: Pid,
        tool: T,
        mut thread_state: T::ThreadState,
        global_state: Arc<T::GlobalState>,
        config: &<T::GlobalState as GlobalTool>::Config,
        subscriptions: &Subscription,
        initial_post_exec: bool,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)>
    where
        T: Tool + 'static,
        T::ThreadState: 'static,
        T::GlobalState: 'static,
        <T::GlobalState as GlobalTool>::Config: 'static,
    {
        let _registration = self.register_guest_thread()?;
        let mut auxv = executor.auxv().to_vec();
        // Clones share the MAP_SHARED guest mapping; a mutable handle lets the
        // loop write syscall results back into the guest's frame.
        let mut memory = self.memory.clone();
        let stack_checked_out = Arc::new(AtomicBool::new(false));

        let registers = kvm_registers(self.vcpu.get_regs()?, 0);
        let handler_signal = Arc::new(Mutex::new(None));
        expose_tool_scratch(&memory)?;
        let mut _process_completed = false;
        let start_outcome = {
            let mut guest_executor = StaticElfSyscallExecutor {
                backend: self,
                executor,
                memory: memory.clone(),
                process_context: ProcessExecutionContext::Lifecycle,
                last_result: None,
                process_completed: &mut _process_completed,
            };
            let mut guest = KvmGuest::<T>::new(
                pid,
                memory.clone(),
                &auxv,
                registers,
                &mut thread_state,
                &mut guest_executor,
                global_state.as_ref(),
                Some(global_state.clone()),
                config,
                subscriptions,
                handler_signal.clone(),
                stack_checked_out.clone(),
            );
            drive_handler(tool.handle_thread_start(&mut guest), handler_signal).await
        };
        hide_tool_scratch(&memory)?;
        match start_outcome {
            HandlerOutcome::Returned(result) => result.map_err(Error::Reverie)?,
            HandlerOutcome::RuntimeError(error) => return Err(error),
            HandlerOutcome::TailInjected { .. } => {}
        }
        auxv = executor.auxv().to_vec();
        if let Some(exit) = executor.take_exit() {
            if exit.group {
                self.request_guest_thread_group_exit(exit.code);
            }
            self.cancel_guest_threads();
            notify_tool_exit(
                tool,
                pid,
                global_state.as_ref(),
                config,
                thread_state,
                ExitStatus::Exited(exit.code),
            )
            .await?;
            let (stdout, stderr) = executor.take_output();
            return Ok((exit.code, stdout, stderr));
        }

        if initial_post_exec {
            // The root ELF image is already installed when this backend begins.
            // Present the same initial exec syscall and successful-exec lifecycle
            // boundaries as ptrace without loading the installed image twice.
            if subscriptions
                .iter_syscalls()
                .any(|number| number == reverie::syscalls::Sysno::execve)
            {
                run_initial_exec_handler(
                    self,
                    &tool,
                    pid,
                    &memory,
                    &auxv,
                    &mut thread_state,
                    executor,
                    global_state,
                    config,
                    subscriptions,
                    &stack_checked_out,
                )
                .await?;
                auxv = executor.auxv().to_vec();
                if let Some(exit) = executor.take_exit() {
                    if exit.group {
                        self.request_guest_thread_group_exit(exit.code);
                    }
                    self.cancel_guest_threads();
                    notify_tool_exit(
                        tool,
                        pid,
                        global_state,
                        config,
                        thread_state,
                        ExitStatus::Exited(exit.code),
                    )
                    .await?;
                    let (stdout, stderr) = executor.take_output();
                    return Ok((exit.code, stdout, stderr));
                }
            }
            let post_exec_error = run_post_exec_handler(
                self,
                &tool,
                pid,
                &memory,
                &mut auxv,
                &mut thread_state,
                executor,
                global_state.clone(),
                config,
                subscriptions,
                &stack_checked_out,
            )
            .await
            .err();
            if let Some(error) = post_exec_error {
                notify_tool_exit(
                    tool,
                    pid,
                    global_state.as_ref(),
                    config,
                    thread_state,
                    ExitStatus::Exited(255),
                )
                .await?;
                return Err(error);
            }
        }

        if let Some((segment, address)) = executor.take_segment() {
            set_user_segment_base(&self.vcpu, segment, address)?;
        }
        if let Some(exit) = executor.take_exit() {
            if exit.group {
                self.request_guest_thread_group_exit(exit.code);
            }
            self.cancel_guest_threads();
            notify_tool_exit(
                tool,
                pid,
                global_state.as_ref(),
                config,
                thread_state,
                ExitStatus::Exited(exit.code),
            )
            .await?;
            let (stdout, stderr) = executor.take_output();
            return Ok((exit.code, stdout, stderr));
        }

        loop {
            if let Some(code) = self.guest_thread_group_exit_code() {
                self.cancel_guest_threads();
                notify_tool_exit(
                    tool,
                    pid,
                    global_state.as_ref(),
                    config,
                    thread_state,
                    ExitStatus::Exited(code),
                )
                .await?;
                let (stdout, stderr) = executor.take_output();
                return Ok((code, stdout, stderr));
            }
            let vcpu_exit = match self.vcpu.run() {
                Ok(exit) => exit,
                Err(error) if error.errno() == libc::EINTR => continue,
                Err(error) => return Err(error.into()),
            };
            let (frame_address, return_slot) = match vcpu_exit {
                VcpuExit::Hypercall(exit) => {
                    if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                        return Err(Error::UnexpectedHypercall(exit.nr));
                    }
                    (exit.args[0], std::ptr::from_mut(exit.ret) as usize)
                }
                VcpuExit::Hlt => {
                    if self.try_resume_vmware_backdoor_probe()? {
                        continue;
                    }
                    return Err(self.static_elf_halt_error()?);
                }
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            };
            if frame_address != SYSCALL_FRAME_ADDRESS {
                return Err(Error::UnexpectedVcpuExit(format!(
                    "syscall frame is at unexpected address {frame_address:#x}"
                )));
            }
            let registers = self.vcpu.get_regs()?;
            let request = SyscallRequest::read_from(&memory, frame_address)?;
            let syscall = request.into_syscall()?;
            // TODO-HUMAN-REVIEW(PR-156): Review root process-syscall Tool dispatch.
            // KVM CLONE_THREAD workers currently execute directly through the
            // backend personality. Sending only the parent through Detcore's
            // clone handler waits forever for a child Tool start that this
            // direct-worker path cannot issue.
            let backend_owned = (is_backend_owned_syscall(request.number())
                && !executor.is_random_device_read(&request))
                || is_thread_clone_request(&request, &memory);
            let subscribed = !backend_owned
                && subscriptions
                    .iter_syscalls()
                    .any(|number| number == syscall.number());
            let (result, handler_replaced_image, handler_process_completed) = if subscribed {
                let handler_signal = Arc::new(Mutex::new(None));
                let mut handler_process_completed = false;
                expose_tool_scratch(&memory)?;
                let outcome = {
                    let mut guest_executor = StaticElfSyscallExecutor {
                        backend: self,
                        executor,
                        memory: memory.clone(),
                        process_context: ProcessExecutionContext::SyscallBoundary(
                            ProcessBoundary {
                                frame_address,
                                return_slot,
                            },
                        ),
                        last_result: None,
                        process_completed: &mut handler_process_completed,
                    };
                    let mut guest = KvmGuest::<T>::new(
                        pid,
                        memory.clone(),
                        &auxv,
                        kvm_registers(registers, request.number()),
                        &mut thread_state,
                        &mut guest_executor,
                        global_state.as_ref(),
                        Some(global_state.clone()),
                        config,
                        subscriptions,
                        handler_signal.clone(),
                        stack_checked_out.clone(),
                    );
                    drive_handler(
                        tool.handle_syscall_event(&mut guest, syscall),
                        handler_signal,
                    )
                    .await
                };
                hide_tool_scratch(&memory)?;
                match outcome {
                    HandlerOutcome::Returned(result) => (
                        handler_result_to_raw(result)?,
                        false,
                        handler_process_completed,
                    ),
                    HandlerOutcome::TailInjected {
                        result,
                        image_replaced,
                        ..
                    } => (
                        result_to_raw(result),
                        image_replaced,
                        handler_process_completed,
                    ),
                    HandlerOutcome::RuntimeError(error) => return Err(error),
                }
            } else {
                (executor.execute(&request, &memory), false, false)
            };
            // The ring0 trampoline reads the result from the frame and then
            // SYSRETs, so the hypercall return slot is unused here.
            SyscallRequest::write_result(&mut memory, frame_address, result)?;
            // SAFETY: return_slot points into this vCPU's stable KVM_RUN mapping.
            // The vCPU is stopped whenever the slot is written.
            unsafe {
                (return_slot as *mut u64).write(0);
            }
            if handler_process_completed && !handler_replaced_image {
                configure_process_syscall_return(
                    &memory,
                    &self.vcpu,
                    SYSCALL_FRAME_ADDRESS,
                    result,
                    None,
                )?;
            }
            let pending_segment = executor.take_segment();
            let mut pending_exit = executor.take_exit();
            let pending_process = executor.take_process_action();

            if let Some((segment, address)) = pending_segment {
                set_user_segment_base(&self.vcpu, segment, address)?;
            }
            let mut replaced_image = handler_replaced_image;
            if let Some(action) = pending_process {
                replaced_image |= matches!(&action, ProcessAction::Exec { .. });
                let context: ToolContext<'_, T> = ToolContext {
                    pid,
                    thread_state: &thread_state,
                    global_state: Some(global_state.clone()),
                    config: config.clone(),
                    subscriptions: subscriptions.clone(),
                };
                self.run_process_action_with_tool(executor, action, true, context)
                    .await?;
            }
            if replaced_image {
                auxv = executor.auxv().to_vec();
                let post_exec_error = run_post_exec_handler(
                    self,
                    &tool,
                    pid,
                    &memory,
                    &mut auxv,
                    &mut thread_state,
                    executor,
                    global_state.clone(),
                    config,
                    subscriptions,
                    &stack_checked_out,
                )
                .await
                .err();
                if let Some(error) = post_exec_error {
                    notify_tool_exit(
                        tool,
                        pid,
                        global_state.as_ref(),
                        config,
                        thread_state,
                        ExitStatus::Exited(255),
                    )
                    .await?;
                    return Err(error);
                }
            }
            if let Some((segment, address)) = executor.take_segment() {
                set_user_segment_base(&self.vcpu, segment, address)?;
            }
            pending_exit = pending_exit.or_else(|| executor.take_exit());
            if let Some(exit) = pending_exit {
                executor.join_all_child_processes()?;
                if exit.group {
                    self.request_guest_thread_group_exit(exit.code);
                }
                self.cancel_guest_threads();
                notify_tool_exit(
                    tool,
                    pid,
                    global_state.as_ref(),
                    config,
                    thread_state,
                    ExitStatus::Exited(exit.code),
                )
                .await?;
                let (stdout, stderr) = executor.take_output();
                return Ok((exit.code, stdout, stderr));
            }
        }
    }
}

fn handler_result_to_raw(result: std::result::Result<i64, reverie::Error>) -> Result<i64> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            let errno = error.into_errno().map_err(Error::Reverie)?;
            Ok(-(i64::from(errno.into_raw())))
        }
    }
}

fn raw_to_result(result: i64) -> std::result::Result<i64, Errno> {
    Errno::from_ret(result as usize).map(|value| value as i64)
}

fn result_to_raw(result: std::result::Result<i64, Errno>) -> i64 {
    match result {
        Ok(value) => value,
        Err(error) => -(error.into_raw() as i64),
    }
}

fn kvm_registers(registers: kvm_regs, syscall_number: u64) -> libc::user_regs_struct {
    libc::user_regs_struct {
        r15: registers.r15,
        r14: registers.r14,
        r13: registers.r13,
        r12: registers.r12,
        rbp: registers.rbp,
        rbx: registers.rbx,
        r11: registers.r11,
        r10: registers.r10,
        r9: registers.r9,
        r8: registers.r8,
        rax: registers.rax,
        rcx: registers.rcx,
        rdx: registers.rdx,
        rsi: registers.rsi,
        rdi: registers.rdi,
        orig_rax: syscall_number,
        rip: registers.rip,
        cs: 0,
        eflags: registers.rflags,
        rsp: registers.rsp,
        ss: 0,
        fs_base: 0,
        gs_base: 0,
        ds: 0,
        es: 0,
        fs: 0,
        gs: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_linux_error_results() {
        assert_eq!(raw_to_result(7), Ok(7));
        assert_eq!(raw_to_result(-(libc::EIO as i64)), Err(Errno::EIO));
        assert_eq!(result_to_raw(Err(Errno::EFAULT)), -(libc::EFAULT as i64));
    }

    #[test]
    fn worker_shared_syscalls_are_backend_owned() {
        for number in [
            libc::SYS_futex,
            libc::SYS_ppoll,
            libc::SYS_read,
            libc::SYS_readv,
        ] {
            assert!(is_backend_owned_syscall(number as u64));
        }
        assert!(!is_backend_owned_syscall(libc::SYS_clock_gettime as u64));
    }

    #[test]
    fn stack_commits_to_shared_guest_memory() {
        let memory = GuestMemory::new(0x1000, STACK_CAPACITY).unwrap();
        let mut stack = KvmStack::new(memory.clone(), Arc::new(AtomicBool::new(false)));
        let address = stack.push(0x1122_3344_u32);
        stack.commit().unwrap();

        let value = memory.read_value(address).unwrap();
        assert_eq!(value, 0x1122_3344_u32);
    }
}
