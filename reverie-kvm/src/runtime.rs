/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::future::Future;
use std::future::poll_fn;
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
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::SYSCALL_FRAME_ADDRESS;
use crate::bootstrap::set_user_segment_base;
use crate::executor::ElfExecutor;

const GUEST_PID: i32 = 1;
const STACK_CAPACITY: usize = 4096;
const TOOL_STACK_TOP: u64 = BOOT_RESERVED_END;

type TailResult = Arc<Mutex<Option<std::result::Result<i64, Errno>>>>;

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
    executor: &'a mut dyn SyscallExecutor,
    global_state: &'a T::GlobalState,
    config: &'a <T::GlobalState as GlobalTool>::Config,
    tail_result: TailResult,
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
        executor: &'a mut dyn SyscallExecutor,
        global_state: &'a T::GlobalState,
        config: &'a <T::GlobalState as GlobalTool>::Config,
        tail_result: TailResult,
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
            config,
            tail_result,
            stack_checked_out,
        }
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
        raw_to_result(self.executor.execute(&request, &self.memory))
    }

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        let result = self.inject(syscall).await;
        *self
            .tail_result
            .lock()
            .expect("KVM tail-injection result lock poisoned") = Some(result);
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
        let top =
            if memory.guest_base() <= BOOT_RESERVED_END && memory.guest_end() >= TOOL_STACK_TOP {
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

    fn commit(mut self) -> std::result::Result<Self::StackGuard, Errno> {
        for (address, bytes) in self.writes {
            self.memory
                .write(address, &bytes)
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
    TailInjected(std::result::Result<i64, Errno>),
}

async fn drive_handler<T>(
    future: impl Future<Output = T>,
    tail_result: TailResult,
) -> HandlerOutcome<T> {
    let mut future = pin!(future);
    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Ready(result) => Poll::Ready(HandlerOutcome::Returned(result)),
        Poll::Pending => match tail_result
            .lock()
            .expect("KVM tail-injection result lock poisoned")
            .take()
        {
            Some(result) => Poll::Ready(HandlerOutcome::TailInjected(result)),
            None => Poll::Pending,
        },
    })
    .await
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
        let pid = Pid::from_raw(GUEST_PID);
        let global_state = T::GlobalState::init_global_state(&config).await;
        let tool = T::new(pid, &config);
        let subscriptions = T::subscriptions(&config);
        let mut thread_state = tool.init_thread_state(pid, None);
        let memory = self.memory.clone();
        let auxv = Vec::new();
        let stack_checked_out = Arc::new(AtomicBool::new(false));

        let registers = kvm_registers(self.vcpu.get_regs()?, 0);
        let tail_result = Arc::new(Mutex::new(None));
        let start_outcome = {
            let mut guest = KvmGuest::<T>::new(
                pid,
                memory.clone(),
                &auxv,
                registers,
                &mut thread_state,
                &mut executor,
                &global_state,
                &config,
                tail_result.clone(),
                stack_checked_out.clone(),
            );
            drive_handler(tool.handle_thread_start(&mut guest), tail_result).await
        };
        if let HandlerOutcome::Returned(result) = start_outcome {
            result.map_err(Error::Reverie)?;
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
                        let tail_result = Arc::new(Mutex::new(None));
                        let outcome = {
                            let mut guest = KvmGuest::<T>::new(
                                pid,
                                memory.clone(),
                                &auxv,
                                kvm_registers(registers, request.number()),
                                &mut thread_state,
                                &mut executor,
                                &global_state,
                                &config,
                                tail_result.clone(),
                                stack_checked_out.clone(),
                            );
                            drive_handler(
                                tool.handle_syscall_event(&mut guest, syscall),
                                tail_result,
                            )
                            .await
                        };
                        match outcome {
                            HandlerOutcome::Returned(result) => handler_result_to_raw(result)?,
                            HandlerOutcome::TailInjected(result) => result_to_raw(result),
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
    /// in long mode; each guest `SYSCALL` traps through the ring0 trampoline and
    /// is delivered to the tool's `handle_syscall_event`, and the tool's
    /// `inject`/`tail_inject` calls are serviced by the ELF guest kernel
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
        T: Tool,
    {
        let mut loaded = self.static_elf.take().ok_or(Error::StaticElfNotInstalled)?;
        if capture_output {
            loaded.stdin = Some(std::fs::File::open("/dev/null")?);
        }
        let auxv = loaded.auxv.clone();
        let pid = Pid::from_raw(GUEST_PID);
        let global_state = T::GlobalState::init_global_state(&config).await;
        let tool = T::new(pid, &config);
        let subscriptions = T::subscriptions(&config);
        let mut thread_state = tool.init_thread_state(pid, None);
        // Clones share the MAP_SHARED guest mapping; a mutable handle lets the
        // loop write syscall results back into the guest's frame.
        let mut memory = self.memory.clone();
        let stack_checked_out = Arc::new(AtomicBool::new(false));
        let mut executor = ElfExecutor::new(loaded, capture_output);

        let registers = kvm_registers(self.vcpu.get_regs()?, 0);
        let tail_result = Arc::new(Mutex::new(None));
        let start_outcome = {
            let mut guest = KvmGuest::<T>::new(
                pid,
                memory.clone(),
                &auxv,
                registers,
                &mut thread_state,
                &mut executor,
                &global_state,
                &config,
                tail_result.clone(),
                stack_checked_out.clone(),
            );
            drive_handler(tool.handle_thread_start(&mut guest), tail_result).await
        };
        if let HandlerOutcome::Returned(result) = start_outcome {
            result.map_err(Error::Reverie)?;
        }

        // The ELF image is already installed when this backend begins. Present
        // the same successful-exec lifecycle boundary as ptrace before running it.
        let registers = kvm_registers(self.vcpu.get_regs()?, 0);
        let tail_result = Arc::new(Mutex::new(None));
        let post_exec_outcome = {
            let mut guest = KvmGuest::<T>::new(
                pid,
                memory.clone(),
                &auxv,
                registers,
                &mut thread_state,
                &mut executor,
                &global_state,
                &config,
                tail_result.clone(),
                stack_checked_out.clone(),
            );
            drive_handler(tool.handle_post_exec(&mut guest), tail_result).await
        };
        let post_exec_error = match post_exec_outcome {
            HandlerOutcome::Returned(Ok(())) => None,
            HandlerOutcome::Returned(Err(error)) => Some(Error::PostExec(error)),
            HandlerOutcome::TailInjected(_) => Some(Error::UnexpectedVcpuExit(
                "tool tail-injected a syscall from handle_post_exec".to_string(),
            )),
        };
        if let Some(error) = post_exec_error {
            notify_tool_exit(
                tool,
                pid,
                &global_state,
                &config,
                thread_state,
                ExitStatus::Exited(255),
            )
            .await?;
            return Err(error);
        }

        if let Some((segment, address)) = executor.take_segment() {
            set_user_segment_base(&self.vcpu, segment, address)?;
        }
        if let Some(code) = executor.take_exit() {
            notify_tool_exit(
                tool,
                pid,
                &global_state,
                &config,
                thread_state,
                ExitStatus::Exited(code),
            )
            .await?;
            let (stdout, stderr) = executor.take_output();
            return Ok((global_state, code, stdout, stderr));
        }

        loop {
            let (pending_segment, pending_exit) = match self.vcpu.run()? {
                VcpuExit::Hypercall(exit) => {
                    if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                        return Err(Error::UnexpectedHypercall(exit.nr));
                    }
                    let frame_address = exit.args[0];
                    // Capture the hypercall return slot as a raw pointer so the
                    // `&mut exit` borrow ends before `self.vcpu.get_regs()`.
                    let return_slot = std::ptr::from_mut(exit.ret) as usize;
                    if frame_address != SYSCALL_FRAME_ADDRESS {
                        return Err(Error::UnexpectedVcpuExit(format!(
                            "syscall frame is at unexpected address {frame_address:#x}"
                        )));
                    }
                    let registers = self.vcpu.get_regs()?;
                    let request = SyscallRequest::read_from(&memory, frame_address)?;
                    let syscall = request.into_syscall()?;
                    let subscribed = subscriptions
                        .iter_syscalls()
                        .any(|number| number == syscall.number());
                    let result = if subscribed {
                        let tail_result = Arc::new(Mutex::new(None));
                        let outcome = {
                            let mut guest = KvmGuest::<T>::new(
                                pid,
                                memory.clone(),
                                &auxv,
                                kvm_registers(registers, request.number()),
                                &mut thread_state,
                                &mut executor,
                                &global_state,
                                &config,
                                tail_result.clone(),
                                stack_checked_out.clone(),
                            );
                            drive_handler(
                                tool.handle_syscall_event(&mut guest, syscall),
                                tail_result,
                            )
                            .await
                        };
                        match outcome {
                            HandlerOutcome::Returned(result) => handler_result_to_raw(result)?,
                            HandlerOutcome::TailInjected(result) => result_to_raw(result),
                        }
                    } else {
                        executor.execute(&request, &memory)
                    };
                    // The ring0 trampoline reads the result from the frame and
                    // then SYSRETs, so the hypercall return slot is unused here.
                    SyscallRequest::write_result(&mut memory, frame_address, result)?;
                    // SAFETY: return_slot points into this vCPU's stable KVM_RUN
                    // mapping; the vCPU is stopped and not re-run while the tool
                    // callback is active.
                    unsafe {
                        (return_slot as *mut u64).write(0);
                    }
                    (executor.take_segment(), executor.take_exit())
                }
                VcpuExit::Hlt => return Err(self.static_elf_halt_error()?),
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            };

            if let Some((segment, address)) = pending_segment {
                set_user_segment_base(&self.vcpu, segment, address)?;
            }
            if let Some(code) = pending_exit {
                notify_tool_exit(
                    tool,
                    pid,
                    &global_state,
                    &config,
                    thread_state,
                    ExitStatus::Exited(code),
                )
                .await?;
                let (stdout, stderr) = executor.take_output();
                return Ok((global_state, code, stdout, stderr));
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
    fn stack_commits_to_shared_guest_memory() {
        let memory = GuestMemory::new(0x1000, STACK_CAPACITY).unwrap();
        let mut stack = KvmStack::new(memory.clone(), Arc::new(AtomicBool::new(false)));
        let address = stack.push(0x1122_3344_u32);
        stack.commit().unwrap();

        let value = memory.read_value(address).unwrap();
        assert_eq!(value, 0x1122_3344_u32);
    }
}
