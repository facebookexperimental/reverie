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

use crate::CpuidPolicy;
use crate::Error;
use crate::GuestMemory;
use crate::Result;
use crate::Syscall;
use crate::SyscallRequest;
use crate::bootstrap::BOOT_RESERVED_END;
use crate::bootstrap::SYSCALL_FRAME_ADDRESS;
use crate::bootstrap::SegmentBase;
use crate::bootstrap::configure_long_mode;
use crate::bootstrap::configure_process_syscall_return;
use crate::bootstrap::exception_from_halt;
use crate::bootstrap::set_syscall_return_park;
use crate::bootstrap::set_user_segment_base;
use crate::elf::LoadedStaticElf;
use crate::elf::load_static_elf;
use crate::executor::ElfExecutor;
use crate::executor::ProcessAction;
use crate::runtime::SyscallExecutor;

/// KVM currently permits userspace exits for this standardized hypercall.
/// The prototype uses it as a transport opcode and places the syscall frame
/// address in the first hypercall argument.
pub const VMCALL_SYSCALL_TRANSPORT: u64 = 12;

const SYSCALL_FRAME_STRIDE: u64 = 4096;
const PAGE_SIZE: u64 = 4096;
const VMCALL: [u8; 3] = [0x0f, 0x01, 0xc1];
const VMMCALL: [u8; 3] = [0x0f, 0x01, 0xd9];
const HLT: u8 = 0xf4;

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

    fn exec_process(
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

    pub(crate) fn run_process_action(
        &mut self,
        executor: &mut ElfExecutor,
        action: ProcessAction,
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
                let mut child_executor = executor.fork_child(child_pid, clear_sighand)?;
                child_executor.set_clear_child_tid(clear_child_tid);
                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, true)?;
                let parked = match self.vcpu.run()? {
                    VcpuExit::Hlt => Ok(()),
                    exit => Err(Error::UnexpectedVcpuExit(format!(
                        "parent did not park at fork: {exit:?}"
                    ))),
                };
                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, false)?;
                parked?;
                let child_snapshot = self.snapshot_process()?;
                write_tid_best_effort(&mut self.memory, parent_tid, child_pid);

                let mut child = Self::from_process_snapshot(child_snapshot)?;
                write_tid_best_effort(&mut child.memory, child_tid, child_pid);
                let (fs_base, gs_base) = child_executor.segment_bases();
                set_user_segment_base(&child.vcpu, SegmentBase::Fs, fs_base)?;
                set_user_segment_base(&child.vcpu, SegmentBase::Gs, gs_base)?;
                configure_process_syscall_return(&child.memory, &child.vcpu, 0, child_stack)?;
                let (code, stdout, stderr) = child.run_static_elf_process(&mut child_executor)?;
                // A process clone has a private snapshot, so no surviving task can
                // observe this clear; preserve the child-side ABI.
                write_tid_best_effort(&mut child.memory, child_executor.take_clear_child_tid(), 0);
                executor.record_child_exit(child_pid, code);
                executor.append_output(stdout, stderr);
                configure_process_syscall_return(
                    &self.memory,
                    &self.vcpu,
                    i64::from(child_pid),
                    None,
                )?;
            }
            ProcessAction::Thread {
                child_tid,
                child_stack,
                parent_tid,
                child_tid_address,
                clear_child_tid,
                tls,
            } => {
                // TODO-HUMAN-REVIEW(PR-132): Review sequential thread execution and
                // parent architectural-state restoration on the shared vCPU.
                let parent_registers = self.vcpu.get_regs()?;
                let parent_xsave = self.vcpu.get_xsave()?;
                let parent_thread_id = executor.thread_id();
                let (parent_fs, parent_gs) = executor.segment_bases();
                let parent_clear_child_tid = executor.take_clear_child_tid();
                let mut parent_syscall_frame = vec![0; PAGE_SIZE as usize];
                self.memory
                    .read_raw(SYSCALL_FRAME_ADDRESS, &mut parent_syscall_frame)?;

                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, true)?;
                let parked = match self.vcpu.run()? {
                    VcpuExit::Hlt => Ok(()),
                    exit => Err(Error::UnexpectedVcpuExit(format!(
                        "parent did not park at thread clone: {exit:?}"
                    ))),
                };
                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, false)?;
                parked?;

                write_tid_best_effort(&mut self.memory, parent_tid, child_tid);
                write_tid_best_effort(&mut self.memory, child_tid_address, child_tid);
                let child_fs = tls.unwrap_or(parent_fs);
                executor.set_thread_context(child_tid, child_fs, parent_gs);
                executor.set_clear_child_tid(clear_child_tid);
                set_user_segment_base(&self.vcpu, SegmentBase::Fs, child_fs)?;
                set_user_segment_base(&self.vcpu, SegmentBase::Gs, parent_gs)?;
                configure_process_syscall_return(&self.memory, &self.vcpu, 0, Some(child_stack))?;

                let (code, stdout, stderr) = self.run_static_elf_process(executor)?;
                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, true)?;
                let child_parked = match self.vcpu.run()? {
                    VcpuExit::Hlt => Ok(()),
                    exit => Err(Error::UnexpectedVcpuExit(format!(
                        "child thread did not park after exit: {exit:?}"
                    ))),
                };
                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, false)?;
                child_parked?;
                let exited_group = executor.take_exit_group();
                write_tid_best_effort(&mut self.memory, executor.take_clear_child_tid(), 0);
                executor.set_clear_child_tid(parent_clear_child_tid);
                executor.set_thread_context(parent_thread_id, parent_fs, parent_gs);
                executor.append_output(stdout, stderr);
                // SAFETY: this guest setup does not enable dynamically sized XSTATE features.
                unsafe { self.vcpu.set_xsave(&parent_xsave)? };

                if exited_group {
                    executor.set_exit(code, true);
                } else {
                    self.memory
                        .write_raw(SYSCALL_FRAME_ADDRESS, &parent_syscall_frame)?;
                    set_user_segment_base(&self.vcpu, SegmentBase::Fs, parent_fs)?;
                    set_user_segment_base(&self.vcpu, SegmentBase::Gs, parent_gs)?;
                    self.vcpu.set_regs(&parent_registers)?;
                    configure_process_syscall_return(
                        &self.memory,
                        &self.vcpu,
                        i64::from(child_tid),
                        None,
                    )?;
                }
            }
            ProcessAction::Exec { image, argv, envp } => {
                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, true)?;
                let parked = match self.vcpu.run()? {
                    VcpuExit::Hlt => Ok(()),
                    exit => Err(Error::UnexpectedVcpuExit(format!(
                        "process did not park before exec: {exit:?}"
                    ))),
                };
                set_syscall_return_park(&mut self.memory, self.hypercall_instruction, false)?;
                parked?;
                self.exec_process(executor, &image, &argv, &envp)?;
            }
        }
        Ok(())
    }

    pub(crate) fn static_elf_halt_error(&self) -> Result<Error> {
        let registers = self.vcpu.get_regs()?;
        if let Some((vector, instruction_pointer)) =
            exception_from_halt(registers.rip, registers.rax, registers.rbx)
        {
            return Ok(Error::GuestException {
                vector,
                instruction_pointer,
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
        loop {
            let (segment_update, process_action) = match self.vcpu.run()? {
                VcpuExit::Hypercall(exit) => {
                    if exit.nr != VMCALL_SYSCALL_TRANSPORT {
                        return Err(Error::UnexpectedHypercall(exit.nr));
                    }
                    let frame_address = exit.args[0];
                    if frame_address != SYSCALL_FRAME_ADDRESS {
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
                VcpuExit::Hlt => return Err(self.static_elf_halt_error()?),
                exit => return Err(Error::UnexpectedVcpuExit(format!("{exit:?}"))),
            };

            if let Some((segment, address)) = segment_update {
                set_user_segment_base(&self.vcpu, segment, address)?;
            }

            if let Some(action) = process_action {
                self.run_process_action(executor, action)?;
            }

            if let Some(code) = executor.take_exit() {
                let (stdout, stderr) = executor.take_output();
                return Ok((code, stdout, stderr));
            }
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

fn write_tid_best_effort(memory: &mut GuestMemory, address: Option<u64>, tid: i32) {
    if let Some(address) = address {
        // Linux creates the child even if a clone TID store faults.
        let _ = memory.write(address, &tid.to_le_bytes());
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
