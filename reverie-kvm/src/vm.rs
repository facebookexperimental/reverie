/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use kvm_bindings::CpuId;
use kvm_bindings::KVM_MAX_CPUID_ENTRIES;
use kvm_bindings::kvm_enable_cap;
use kvm_bindings::kvm_userspace_memory_region;
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

/// KVM currently permits userspace exits for this standardized hypercall.
/// The prototype uses it as a transport opcode and places the syscall frame
/// address in the first hypercall argument.
pub const VMCALL_SYSCALL_TRANSPORT: u64 = 12;

const SYSCALL_FRAME_STRIDE: u64 = 4096;
const VMCALL: [u8; 3] = [0x0f, 0x01, 0xc1];
const VMMCALL: [u8; 3] = [0x0f, 0x01, 0xd9];
const HLT: u8 = 0xf4;

/// A single-vCPU KVM backend used to exercise the syscall transport.
pub struct KvmBackend {
    // Field order ensures the vCPU and VM are dropped before registered memory.
    pub(crate) vcpu: VcpuFd,
    vm: VmFd,
    pub(crate) memory: GuestMemory,
    _kvm: Kvm,
    hypercall_instruction: [u8; 3],
}

impl KvmBackend {
    /// Creates a VM with one real-mode vCPU and a memory slot starting at GPA 0x1000.
    pub fn new(memory_size: usize) -> Result<Self> {
        Self::new_with_cpuid_policy(memory_size, CpuidPolicy::default())
    }

    /// Creates a VM with a caller-selected CPUID feature policy.
    pub fn new_with_cpuid_policy(memory_size: usize, cpuid_policy: CpuidPolicy) -> Result<Self> {
        let kvm = Kvm::new()?;
        let vm = kvm.create_vm()?;
        if !vm.check_extension(Cap::ExitHypercall) {
            return Err(Error::HypercallExitUnsupported);
        }

        let mut cpuid = kvm.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)?;
        cpuid_policy.apply(&mut cpuid);
        let hypercall_instruction = supported_hypercall_instruction(&cpuid)?;
        let cap = kvm_enable_cap {
            cap: Cap::ExitHypercall as u32,
            args: [1_u64 << VMCALL_SYSCALL_TRANSPORT, 0, 0, 0],
            ..Default::default()
        };
        vm.enable_cap(&cap)?;

        let memory = GuestMemory::new(0x1000, memory_size)?;
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
            hypercall_instruction,
        })
    }

    /// Installs an arbitrary real-mode program and selects it as the vCPU entry point.
    pub fn install_real_mode_program(&mut self, entry_point: u64, code: &[u8]) -> Result<()> {
        self.memory.write(entry_point, code)?;

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
