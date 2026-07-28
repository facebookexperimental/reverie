/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::fs::File;
use std::os::fd::FromRawFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

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
use reverie::Pid;
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
use crate::bootstrap::configure_long_mode;
use crate::bootstrap::configure_long_mode_with_syscall_area;
use crate::bootstrap::configure_process_syscall_return;
use crate::bootstrap::configure_user_segments;
use crate::bootstrap::exception_from_halt;
use crate::bootstrap::exception_pushes_error_code;
use crate::bootstrap::set_syscall_return_park;
use crate::bootstrap::set_user_segment_base;
use crate::elf::LoadedStaticElf;
use crate::elf::load_static_elf;
use crate::executor::ElfExecutor;
use crate::executor::ProcessAction;
use crate::runtime::SyscallExecutor;
use crate::runtime::ToolContext;
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

extern "C" fn interrupt_guest_worker(_signal: libc::c_int) {}

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

#[derive(Default)]
// TODO-HUMAN-REVIEW(PR-172): Review process-wide KVM worker cancellation state.
struct GuestThreadGroup {
    cancelled: AtomicBool,
    // AUTONOMOUS-BOT-IMPLEMENTED: Propagate worker exit_group to the root vCPU.
    // TODO-HUMAN-REVIEW(PR-177): Review KVM thread-group exit ordering.
    exit_code: Mutex<Option<i32>>,
    root: Mutex<Option<libc::pthread_t>>,
    workers: Mutex<Vec<libc::pthread_t>>,
    // AUTONOMOUS-BOT-IMPLEMENTED: Join cancelled KVM workers before root teardown returns.
    // TODO-HUMAN-REVIEW(PR-178): Review KVM worker join ordering.
    worker_handles: Mutex<Vec<std::thread::JoinHandle<()>>>,
    transport_slots: Mutex<Vec<bool>>,
}

impl GuestThreadGroup {
    fn exit_code(&self) -> Option<i32> {
        *self.exit_code.lock().expect("KVM exit-group lock poisoned")
    }

    fn request_exit_group(&self, code: i32) {
        self.exit_code
            .lock()
            .expect("KVM exit-group lock poisoned")
            .get_or_insert(code);
        self.cancelled.store(true, Ordering::Release);

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
    }

    fn add_worker_handle(&self, handle: std::thread::JoinHandle<()>) {
        self.worker_handles
            .lock()
            .expect("KVM guest worker-handle lock poisoned")
            .push(handle);
    }

    fn join_workers(&self) {
        // A worker may register a nested clone while an earlier batch is joining.
        loop {
            let handles = std::mem::take(
                &mut *self
                    .worker_handles
                    .lock()
                    .expect("KVM guest worker-handle lock poisoned"),
            );
            if handles.is_empty() {
                return;
            }
            for handle in handles {
                if handle.join().is_err() {
                    eprintln!("reverie-kvm guest thread panicked during teardown");
                }
            }
        }
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
            .expect("KVM transport-slot lock poisoned");
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

impl Drop for GuestThreadRegistration {
    fn drop(&mut self) {
        if self.root {
            let mut root = self
                .group
                .root
                .lock()
                .expect("KVM guest root lock poisoned");
            if *root == Some(self.pthread) {
                *root = None;
            }
        } else {
            self.group
                .workers
                .lock()
                .expect("KVM guest worker lock poisoned")
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

/// A single-vCPU KVM backend used to exercise the syscall transport.
pub struct KvmBackend {
    // Field order ensures the vCPU and VM are dropped before registered memory.
    pub(crate) vcpu: VcpuFd,
    vm: VmFd,
    pub(crate) memory: GuestMemory,
    _kvm: Kvm,
    cpuid_policy: CpuidPolicy,
    hypercall_instruction: [u8; 3],
    syscall_trampoline_address: u64,
    syscall_frame_address: u64,
    thread_group: Arc<GuestThreadGroup>,
    thread_slot: Option<usize>,
    is_guest_thread: bool,
    pub(crate) static_elf: Option<LoadedStaticElf>,
    stdin: Option<File>,
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

impl KvmBackend {
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

    fn new_with_memory_and_cpuid_policy(
        memory: GuestMemory,
        cpuid_policy: CpuidPolicy,
        stdin: Option<File>,
    ) -> Result<Self> {
        install_worker_interrupt_handler()?;
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
        Ok(Self {
            vcpu,
            vm,
            memory,
            _kvm: kvm,
            cpuid_policy,
            hypercall_instruction,
            syscall_trampoline_address: SYSCALL_TRAMPOLINE_ADDRESS,
            syscall_frame_address: SYSCALL_FRAME_ADDRESS,
            thread_group: Arc::new(GuestThreadGroup::default()),
            thread_slot: None,
            is_guest_thread: false,
            static_elf: None,
            stdin,
        })
    }

    /// Installs an arbitrary real-mode program and selects it as the vCPU entry point.
    pub fn install_real_mode_program(&mut self, entry_point: u64, code: &[u8]) -> Result<()> {
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
        Ok(())
    }

    /// Returns the VM's guest memory.
    pub fn memory(&self) -> &GuestMemory {
        &self.memory
    }

    /// Returns mutable access to the VM's guest memory.
    pub fn memory_mut(&mut self) -> &mut GuestMemory {
        &mut self.memory
    }

    /// Loads a static ELF executable and prepares the vCPU to enter it in long mode.
    ///
    /// The initial process personality supports x86-64 `ET_EXEC` images without a
    /// `PT_INTERP` segment. Dynamic executables require a userspace dynamic linker
    /// and are deliberately rejected.
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

    /// Loads an ELF with explicit arguments, environment, and working directory.
    pub fn install_static_elf_with_context(
        &mut self,
        image: &[u8],
        argv: &[&str],
        envp: &[&str],
        cwd: &Path,
    ) -> Result<()> {
        let mut loaded = load_static_elf(&mut self.memory, image, argv, envp, cwd)?;
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
        Ok(())
    }

    fn snapshot_process(&self) -> Result<KvmProcessSnapshot> {
        Ok(KvmProcessSnapshot {
            memory: self.memory.snapshot()?,
            registers: self.vcpu.get_regs()?,
            xsave: self.vcpu.get_xsave()?,
            stdin: self.stdin.as_ref().map(File::try_clone).transpose()?,
            cpuid_policy: self.cpuid_policy,
        })
    }

    fn from_process_snapshot(snapshot: KvmProcessSnapshot) -> Result<Self> {
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
        image: &[u8],
        argv: &[String],
        envp: &[String],
    ) -> Result<()> {
        let user_length = usize::try_from(self.memory.guest_end() - BOOT_RESERVED_END)
            .expect("guest memory length must fit usize");
        self.memory.zero_raw(BOOT_RESERVED_END, user_length)?;

        let argv = argv.iter().map(String::as_str).collect::<Vec<_>>();
        let envp = envp.iter().map(String::as_str).collect::<Vec<_>>();
        let mut loaded = load_static_elf(&mut self.memory, image, &argv, &envp, executor.cwd())?;
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
        park_syscall_return: bool,
    ) -> Result<ForkedProcess> {
        let mut child_executor = executor.fork_child(child_pid, clear_sighand)?;
        child_executor.set_clear_child_tid(clear_child_tid);
        if park_syscall_return {
            set_syscall_return_park(
                &mut self.memory,
                self.hypercall_instruction,
                self.syscall_trampoline_address,
                self.syscall_frame_address,
                true,
            )?;
            let parked = match self.vcpu.run()? {
                VcpuExit::Hlt => Ok(()),
                exit => Err(Error::UnexpectedVcpuExit(format!(
                    "parent did not park at fork: {exit:?}"
                ))),
            };
            set_syscall_return_park(
                &mut self.memory,
                self.hypercall_instruction,
                self.syscall_trampoline_address,
                self.syscall_frame_address,
                false,
            )?;
            parked?;
        }
        let child_snapshot = self.snapshot_process()?;
        write_tid_best_effort(&mut self.memory, parent_tid, child_pid);

        let mut child = Self::from_process_snapshot(child_snapshot)?;
        write_tid_best_effort(&mut child.memory, child_tid, child_pid);
        let (fs_base, gs_base) = child_executor.segment_bases();
        set_user_segment_base(&child.vcpu, SegmentBase::Fs, fs_base)?;
        set_user_segment_base(&child.vcpu, SegmentBase::Gs, gs_base)?;
        configure_process_syscall_return(
            &child.memory,
            &child.vcpu,
            child.syscall_frame_address,
            0,
            child_stack,
        )?;
        Ok(ForkedProcess {
            pid: child_pid,
            backend: child,
            executor: child_executor,
        })
    }

    fn finish_forked_process(
        &mut self,
        executor: &mut ElfExecutor,
        mut child: ForkedProcess,
        code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    ) -> Result<()> {
        // A process clone has a private snapshot, so no surviving task can
        // observe this clear; preserve the child-side ABI.
        write_tid_best_effort(
            &mut child.backend.memory,
            child.executor.take_clear_child_tid(),
            0,
        );
        executor.record_child_exit(child.pid, code);
        executor.append_output(stdout, stderr);
        configure_process_syscall_return(
            &self.memory,
            &self.vcpu,
            self.syscall_frame_address,
            i64::from(child.pid),
            None,
        )
    }

    // TODO-HUMAN-REVIEW(PR-156): Review process actions completed during Tool injection.
    pub(crate) fn run_process_action(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        park_syscall_return: bool,
    ) -> Result<()> {
        match action {
            ProcessAction::Fork {
                child_pid,
                child_stack,
                parent_tid,
                child_tid,
                clear_child_tid,
                clear_sighand,
            } => {
                let mut child = self.prepare_forked_process(
                    executor,
                    child_pid,
                    child_stack,
                    parent_tid,
                    child_tid,
                    clear_child_tid,
                    clear_sighand,
                    park_syscall_return,
                )?;
                let (code, stdout, stderr) =
                    child.backend.run_static_elf_process(&mut child.executor)?;
                self.finish_forked_process(executor, child, code, stdout, stderr)?;
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
                let parent_registers = self.vcpu.get_regs()?;
                let parent_xsave = self.vcpu.get_xsave()?;
                let (parent_fs, parent_gs) = executor.segment_bases();
                let mut parent_syscall_frame = vec![0; FRAME_SIZE];
                self.memory
                    .read_raw(self.syscall_frame_address, &mut parent_syscall_frame)?;

                if park_syscall_return {
                    set_syscall_return_park(
                        &mut self.memory,
                        self.hypercall_instruction,
                        self.syscall_trampoline_address,
                        self.syscall_frame_address,
                        true,
                    )?;
                    let parked = match self.vcpu.run()? {
                        VcpuExit::Hlt => Ok(()),
                        exit => Err(Error::UnexpectedVcpuExit(format!(
                            "parent did not park at thread clone: {exit:?}"
                        ))),
                    };
                    set_syscall_return_park(
                        &mut self.memory,
                        self.hypercall_instruction,
                        self.syscall_trampoline_address,
                        self.syscall_frame_address,
                        false,
                    )?;
                    parked?;
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

                self.vcpu.set_regs(&parent_registers)?;
                configure_process_syscall_return(
                    &self.memory,
                    &self.vcpu,
                    self.syscall_frame_address,
                    i64::from(child_tid),
                    None,
                )?;

                let handle = std::thread::Builder::new()
                    .name(format!("reverie-kvm-guest-{child_tid}"))
                    .spawn(move || {
                        let result = child.run_static_elf_process(&mut child_executor);
                        clear_tid_and_wake(
                            &mut child.memory,
                            child_executor.take_clear_child_tid(),
                        );
                        let cancelled = child.thread_group.cancelled.load(Ordering::Acquire);
                        if let Err(error) = result
                            && !cancelled
                        {
                            eprintln!("reverie-kvm guest thread {child_tid} failed: {error}");
                        }
                    })?;
                self.thread_group.add_worker_handle(handle);
            }
            ProcessAction::Exec { image, argv, envp } => {
                if park_syscall_return {
                    set_syscall_return_park(
                        &mut self.memory,
                        self.hypercall_instruction,
                        self.syscall_trampoline_address,
                        self.syscall_frame_address,
                        true,
                    )?;
                    let parked = match self.vcpu.run()? {
                        VcpuExit::Hlt => Ok(()),
                        exit => Err(Error::UnexpectedVcpuExit(format!(
                            "process did not park before exec: {exit:?}"
                        ))),
                    };
                    set_syscall_return_park(
                        &mut self.memory,
                        self.hypercall_instruction,
                        self.syscall_trampoline_address,
                        self.syscall_frame_address,
                        false,
                    )?;
                    parked?;
                }
                self.exec_process(executor, &image, &argv, &envp)?;
            }
        }
        Ok(())
    }

    // TODO-HUMAN-REVIEW(PR-192): Review tool lifecycle for KVM fork children.
    pub(crate) async fn run_process_action_with_tool<T: Tool>(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
        park_syscall_return: bool,
        context: ToolContext<'_, T>,
    ) -> Result<()> {
        let ProcessAction::Fork {
            child_pid,
            child_stack,
            parent_tid,
            child_tid,
            clear_child_tid,
            clear_sighand,
        } = action
        else {
            return self.run_process_action(executor, action, park_syscall_return);
        };

        let mut child = self.prepare_forked_process(
            executor,
            child_pid,
            child_stack,
            parent_tid,
            child_tid,
            clear_child_tid,
            clear_sighand,
            park_syscall_return,
        )?;

        let child_pid = Pid::from_raw(child.pid);
        let child_tool = T::new(child_pid, context.config);
        let child_thread_state =
            child_tool.init_thread_state(child_pid, Some((context.pid, context.thread_state)));
        let (code, stdout, stderr) = Box::pin(child.backend.run_static_elf_process_with_tool(
            &mut child.executor,
            child_pid,
            child_tool,
            child_thread_state,
            context.global_state,
            context.config,
            context.subscriptions,
            false,
        ))
        .await?;
        self.finish_forked_process(executor, child, code, stdout, stderr)
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

    /// Runs the installed static ELF and its forked children until the root exits.
    pub fn run_static_elf(&mut self) -> Result<i32> {
        let loaded = self.static_elf.take().ok_or(Error::StaticElfNotInstalled)?;
        let mut executor = ElfExecutor::new(loaded, false);
        let (code, _, _) = self.run_static_elf_process(&mut executor)?;
        Ok(code)
    }

    /// Runs the installed ELF process tree and captures its standard output streams.
    pub fn run_static_elf_captured(&mut self) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let loaded = self.static_elf.take().ok_or(Error::StaticElfNotInstalled)?;
        let mut executor = ElfExecutor::new(loaded, true);
        self.run_static_elf_process(&mut executor)
    }

    fn run_static_elf_process(
        &mut self,
        executor: &mut ElfExecutor,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let _registration = self.register_guest_thread()?;
        loop {
            if let Some(code) = self.guest_thread_group_exit_code() {
                if !self.is_guest_thread {
                    self.cancel_guest_threads();
                }
                let (stdout, stderr) = executor.take_output();
                return Ok((code, stdout, stderr));
            }
            if self.is_guest_thread && self.thread_group.cancelled.load(Ordering::Acquire) {
                return Ok((0, Vec::new(), Vec::new()));
            }
            let vcpu_exit = match self.vcpu.run() {
                Ok(exit) => exit,
                Err(error) if error.errno() == libc::EINTR => continue,
                Err(error) => return Err(error.into()),
            };
            let (segment_update, process_action) = match vcpu_exit {
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
                    let result = executor.execute(&request, &self.memory);
                    SyscallRequest::write_result(&mut self.memory, frame_address, result)?;
                    // SAFETY: return_slot points into this stopped vCPU's stable KVM_RUN mapping.
                    unsafe {
                        (return_slot as *mut u64).write(0);
                    }
                    (executor.take_segment(), executor.take_process_action())
                }
                VcpuExit::Hlt => {
                    if self.try_resume_vmware_backdoor_probe()? {
                        continue;
                    }
                    return Err(self.static_elf_halt_error()?);
                }
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            };

            if let Some((segment, address)) = segment_update {
                set_user_segment_base(&self.vcpu, segment, address)?;
            }

            if let Some(action) = process_action {
                self.run_process_action(executor, action, true)?;
            }

            if let Some(exit) = executor.take_exit() {
                if exit.group {
                    self.request_guest_thread_group_exit(exit.code);
                }
                if !self.is_guest_thread {
                    self.cancel_guest_threads();
                }
                let (stdout, stderr) = executor.take_output();
                return Ok((exit.code, stdout, stderr));
            }
        }
    }

    pub(crate) fn register_guest_thread(&self) -> Result<GuestThreadRegistration> {
        let restore_blocked_signal = set_guest_interrupt_signal_mask(libc::SIG_UNBLOCK)?;
        // SAFETY: pthread_self returns the live calling thread's identifier.
        let pthread = unsafe { libc::pthread_self() };
        if self.is_guest_thread {
            self.thread_group
                .workers
                .lock()
                .expect("KVM guest worker lock poisoned")
                .push(pthread);
        } else {
            let previous = self
                .thread_group
                .root
                .lock()
                .expect("KVM guest root lock poisoned")
                .replace(pthread);
            assert!(previous.is_none(), "KVM guest root already registered");
        }
        Ok(GuestThreadRegistration {
            group: self.thread_group.clone(),
            pthread,
            root: !self.is_guest_thread,
            restore_blocked_signal,
        })
    }

    pub(crate) fn guest_thread_group_exit_code(&self) -> Option<i32> {
        self.thread_group.exit_code()
    }

    pub(crate) fn request_guest_thread_group_exit(&self, code: i32) {
        self.thread_group.request_exit_group(code);
    }

    // TODO-HUMAN-REVIEW(PR-172): Review signal-driven KVM worker cancellation.
    pub(crate) fn cancel_guest_threads(&self) {
        self.thread_group.cancelled.store(true, Ordering::Release);
        {
            let workers = self
                .thread_group
                .workers
                .lock()
                .expect("KVM guest worker lock poisoned");
            for &worker in workers.iter() {
                // SAFETY: worker was registered by a live guest host thread. The
                // registry lock prevents it from unregistering and exiting before
                // pthread_kill consumes the ID. The no-op handler exists only to
                // interrupt its blocking host syscall.
                unsafe {
                    libc::pthread_kill(worker, worker_interrupt_signal());
                }
            }
        }
        if !self.is_guest_thread {
            self.thread_group.join_workers();
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
    pub fn run<F>(&mut self, mut handler: F) -> Result<()>
    where
        F: FnMut(Syscall, &GuestMemory) -> i64,
    {
        loop {
            match self.vcpu.run()? {
                VcpuExit::Hypercall(exit) => {
                    if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                        return Err(Error::UnexpectedHypercall(exit.nr));
                    }
                    let syscall =
                        SyscallRequest::read_from(&self.memory, exit.args[0])?.into_syscall()?;
                    *exit.ret = handler(syscall, &self.memory) as u64;
                }
                VcpuExit::Hlt => return Ok(()),
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            }
        }
    }

    /// Exposes the VM fd for future backend setup without transferring ownership.
    pub fn vm_fd(&self) -> &VmFd {
        &self.vm
    }
}

impl Drop for KvmBackend {
    fn drop(&mut self) {
        if let Some(slot) = self.thread_slot.take() {
            self.thread_group.release_transport_slot(slot);
        }
        if !self.is_guest_thread {
            self.cancel_guest_threads();
        }
    }
}

fn write_tid_best_effort(memory: &mut GuestMemory, address: Option<u64>, tid: i32) {
    if let Some(address) = address {
        // Linux creates the child even if a clone TID store faults.
        let _ = memory.write(address, &tid.to_le_bytes());
    }
}

// TODO-HUMAN-REVIEW(PR-172): Review CHILD_CLEARTID store and shared futex wake ordering.
fn clear_tid_and_wake(memory: &mut GuestMemory, address: Option<u64>) {
    let Some(address) = address else {
        return;
    };
    // Linux treats a failed CHILD_CLEARTID store as best-effort and skips the
    // wake when the user address is invalid.
    if memory.write(address, &0_i32.to_le_bytes()).is_err() {
        return;
    }
    let Some(offset) = address.checked_sub(memory.guest_base()) else {
        return;
    };
    let Some(host_address) = memory.host_address().checked_add(offset) else {
        return;
    };
    // SAFETY: the successful write above validates the complete futex word,
    // and GuestMemory keeps its shared host mapping alive for this call.
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            host_address,
            1, // FUTEX_WAKE; the kernel's CHILD_CLEARTID wake is not private.
            1,
            0,
            0,
            0,
        );
    }
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
mod tests {
    use super::*;

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
    fn guest_thread_group_joins_registered_workers() {
        let group = Arc::new(GuestThreadGroup::default());
        let outer_finished = Arc::new(AtomicBool::new(false));
        let nested_finished = Arc::new(AtomicBool::new(false));
        let worker_group = group.clone();
        let worker_finished = outer_finished.clone();
        let child_finished = nested_finished.clone();
        group.add_worker_handle(std::thread::spawn(move || {
            worker_group.add_worker_handle(std::thread::spawn(move || {
                child_finished.store(true, Ordering::Release);
            }));
            worker_finished.store(true, Ordering::Release);
        }));

        group.join_workers();

        assert!(outer_finished.load(Ordering::Acquire));
        assert!(nested_finished.load(Ordering::Acquire));
        assert!(group.worker_handles.lock().unwrap().is_empty());
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
}
