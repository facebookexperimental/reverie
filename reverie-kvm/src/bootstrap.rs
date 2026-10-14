/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use kvm_bindings::Msrs;
use kvm_bindings::kvm_fpu;
use kvm_bindings::kvm_msr_entry;
use kvm_bindings::kvm_segment;
use kvm_ioctls::VcpuFd;

use crate::Error;
use crate::GuestMemory;
use crate::Result;
use crate::VMCALL_SYSCALL_TRANSPORT;
use crate::syscall::FRAME_SIZE;
use crate::syscall::FULL_RETURN_WORD;
use crate::syscall::IRET_FRAME_WORD;
use crate::syscall::RESULT_WORD;
use crate::syscall::RETURN_FLAGS_WORD;
use crate::syscall::RETURN_R11_WORD;
use crate::syscall::RETURN_RCX_WORD;
use crate::syscall::RETURN_RIP_WORD;
use crate::syscall::SAVED_RBX_WORD;

const PAGE_SIZE: u64 = 4096;
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const PAGE_DIRECTORY_SPAN: u64 = 1024 * 1024 * 1024;
const PAGE_DIRECTORY_ADDRESSES: [u64; 3] = [0x4000, 0x9000, 0xe000];
const FIRST_PAGE_TABLE_ADDRESS: u64 = 0;
const MAX_IDENTITY_MAP: u64 = PAGE_DIRECTORY_SPAN * PAGE_DIRECTORY_ADDRESSES.len() as u64;

const GDT_ADDRESS: u64 = 0x1000;
const PML4_ADDRESS: u64 = 0x2000;
const PDPT_ADDRESS: u64 = 0x3000;
pub(crate) const SYSCALL_TRAMPOLINE_ADDRESS: u64 = 0x5000;
pub(crate) const SYSCALL_FRAME_ADDRESS: u64 = 0x6000;
pub(crate) const PROGRAM_HEADERS_ADDRESS: u64 = 0x7000;
const TSS_ADDRESS: u64 = 0x8000;
const IDT_ADDRESS: u64 = 0xa000;
const EXCEPTION_STUB_ADDRESS: u64 = 0xb000;
const EXCEPTION_STACK_BOTTOM: u64 = 0xc000;
const EXCEPTION_STACK_TOP: u64 = 0xd000;
pub(crate) const TOOL_STACK_TOP: u64 = 0xe000;
pub(crate) const TOOL_STACK_SIZE: u64 = PAGE_SIZE;
// Includes the 0xe000..0xf000 third page directory and 160 private
// trampoline/frame pairs used by concurrent KVM guest threads.
// AUTONOMOUS-BOT-IMPLEMENTED: Reserve transport slots for savevm worker pools.
// TODO-HUMAN-REVIEW(PR-173): Review the bounded per-thread transport layout.
pub(crate) const THREAD_SYSCALL_AREA_START: u64 = 0xf000;
pub(crate) const THREAD_SYSCALL_AREA_STRIDE: u64 = 2 * PAGE_SIZE;
pub(crate) const MAX_GUEST_THREADS: u64 = 160;
// AUTONOMOUS-BOT-IMPLEMENTED: Provide a kernel-note vDSO for glibc os-version discovery.
// TODO-HUMAN-REVIEW(PR-266): Review the guest vDSO placement and note contents.
// A single read-only page holding the canonical vDSO
// (`reverie::vdso::canonical_vdso_image`), the image every backend maps in
// place of the host kernel's. glibc's loader reaches it through
// `AT_SYSINFO_EHDR`, reads its kernel-version note (`_dl_discover_osversion`)
// instead of calling `uname(2)`, and looks up its functions, each a stub that
// issues the syscall. The page sits inside the boot-reserved region (below
// `BOOT_RESERVED_END`), so guest brk/mmap never allocate over it and the
// user-memory zeroing leaves it intact. It is covered by the identity map
// (present + user, executable), so the guest reads and runs it directly
// without an executor round-trip.
pub(crate) const VDSO_ADDRESS: u64 =
    THREAD_SYSCALL_AREA_START + THREAD_SYSCALL_AREA_STRIDE * MAX_GUEST_THREADS;
// Keep the established syscall-transport and vDSO addresses unchanged. Each
// worker gets one Tool scratch page after the vDSO, indexed by the same slot
// that owns its private syscall transport.
pub(crate) const THREAD_TOOL_STACK_AREA_START: u64 = VDSO_ADDRESS + PAGE_SIZE;
// The pool of page-table pages that map the user windows (`install_user_windows`):
// the stack window below TASK_SIZE, the mmap window below mmap_base, a PIE
// main image's window at ELF_ET_DYN_BASE, and the split of an identity large
// page that straddles the identity limit. 15 pages keep BOOT_RESERVED_END below
// 2 MiB, where images load.
const WINDOW_TABLE_POOL_ADDRESS: u64 =
    THREAD_TOOL_STACK_AREA_START + TOOL_STACK_SIZE * MAX_GUEST_THREADS;
const WINDOW_TABLE_POOL_PAGES: u64 = 15;
pub(crate) const BOOT_RESERVED_END: u64 =
    WINDOW_TABLE_POOL_ADDRESS + WINDOW_TABLE_POOL_PAGES * PAGE_SIZE;
const _: () = {
    assert!(TOOL_STACK_TOP <= THREAD_SYSCALL_AREA_START);
    assert!(
        THREAD_SYSCALL_AREA_START + THREAD_SYSCALL_AREA_STRIDE * MAX_GUEST_THREADS <= VDSO_ADDRESS
    );
    assert!(VDSO_ADDRESS + PAGE_SIZE <= THREAD_TOOL_STACK_AREA_START);
    assert!(VDSO_ADDRESS == reverie::vdso::CANONICAL_VDSO_ADDRESS);
    assert!(reverie::vdso::CANONICAL_VDSO_SIZE <= PAGE_SIZE);
};

/// Returns the exclusive upper address of the Tool scratch page assigned to a
/// guest thread's transport slot.
pub(crate) fn thread_tool_stack_top(slot: usize) -> u64 {
    assert!(
        slot < MAX_GUEST_THREADS as usize,
        "KVM Tool scratch slot exceeds the guest thread limit"
    );
    THREAD_TOOL_STACK_AREA_START
        + (u64::try_from(slot).expect("KVM Tool scratch slot must fit u64") + 1) * TOOL_STACK_SIZE
}
// AUTONOMOUS-BOT-IMPLEMENTED: Isolate each KVM worker's privilege-transition state.
// TODO-HUMAN-REVIEW(PR-179): Review the packed per-thread TSS/stack layout.
const THREAD_TSS_OFFSET: u64 = PAGE_SIZE / 2;

const EXCEPTION_VECTOR_COUNT: usize = 32;
const IDT_ENTRY_SIZE: usize = 16;
const EXCEPTION_STUB_STRIDE: u64 = 16;

const KERNEL_CODE_SELECTOR: u16 = 0x08;
const KERNEL_DATA_SELECTOR: u16 = 0x10;
const USER_DATA_SELECTOR: u16 = 0x1b;
const USER_CODE_SELECTOR: u16 = 0x23;
const TSS_SELECTOR: u16 = 0x28;

const CR0_PE: u64 = 1 << 0;
const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR0_ET: u64 = 1 << 4;
const CR0_NE: u64 = 1 << 5;
const CR0_PG: u64 = 1 << 31;
const CR4_TSD: u64 = 1 << 2;
const CR4_PAE: u64 = 1 << 5;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_OSXSAVE: u64 = 1 << 18;
const XCR0_X87: u64 = 1 << 0;
const XCR0_SSE: u64 = 1 << 1;
const XCR0_YMM: u64 = 1 << 2;
const EFER_SCE: u64 = 1 << 0;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const EFER_NXE: u64 = 1 << 11;

const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_CSTAR: u32 = 0xc000_0083;
const MSR_SYSCALL_MASK: u32 = 0xc000_0084;
const SYSCALL_MASK: u64 = (1 << 8) | (1 << 9) | (1 << 10);
// SYSRET loads SS with STAR[63:48] + 8 and forces RPL 3 on Intel but not on
// AMD, so the SYSRET base carries RPL 3 (as Linux's __USER32_CS does) to give
// the guest the same SS on both vendors.
const STAR: u64 =
    (((KERNEL_DATA_SELECTOR | 3) as u64) << 48) | ((KERNEL_CODE_SELECTOR as u64) << 32);

#[derive(Clone, Copy, Debug)]
pub(crate) enum SegmentBase {
    Fs,
    Gs,
}

pub(crate) fn configure_long_mode(
    memory: &mut GuestMemory,
    vcpu: &VcpuFd,
    entry_point: u64,
    stack_pointer: u64,
    hypercall_instruction: [u8; 3],
) -> Result<()> {
    configure_long_mode_with_syscall_area(
        memory,
        vcpu,
        entry_point,
        stack_pointer,
        hypercall_instruction,
        SYSCALL_TRAMPOLINE_ADDRESS,
        SYSCALL_FRAME_ADDRESS,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
// TODO-HUMAN-REVIEW(PR-172): Review per-vCPU syscall transport initialization.
pub(crate) fn configure_long_mode_with_syscall_area(
    memory: &mut GuestMemory,
    vcpu: &VcpuFd,
    entry_point: u64,
    stack_pointer: u64,
    hypercall_instruction: [u8; 3],
    syscall_trampoline_address: u64,
    syscall_frame_address: u64,
    initialize_shared_tables: bool,
) -> Result<()> {
    if memory.guest_base() != 0
        || memory.guest_end() <= BOOT_RESERVED_END
        || memory.guest_end() > MAX_IDENTITY_MAP
    {
        return Err(Error::LongModeMemoryTooSmall);
    }

    let task_state = if initialize_shared_tables {
        (TSS_ADDRESS, EXCEPTION_STACK_BOTTOM, EXCEPTION_STACK_TOP)
    } else {
        worker_task_state_layout(syscall_trampoline_address, syscall_frame_address)
    };
    if initialize_shared_tables {
        write_descriptor_tables(memory)?;
        write_page_tables(memory)?;
        write_vdso(memory)?;
    } else {
        write_task_state(memory, task_state.0, task_state.1, task_state.2)?;
    }
    let trampoline = syscall_trampoline(hypercall_instruction, syscall_frame_address);
    assert!(
        initialize_shared_tables || trampoline.len() <= THREAD_TSS_OFFSET as usize,
        "KVM syscall trampoline overlaps its private TSS"
    );
    memory.write_raw(syscall_trampoline_address, &trampoline)?;

    let mut sregs = vcpu.get_sregs()?;
    sregs.gdt.base = GDT_ADDRESS;
    sregs.gdt.limit = (7 * std::mem::size_of::<u64>() - 1) as u16;
    sregs.idt.base = IDT_ADDRESS;
    sregs.idt.limit = (EXCEPTION_VECTOR_COUNT * IDT_ENTRY_SIZE - 1) as u16;
    sregs.cs = code_segment(USER_CODE_SELECTOR, 3);
    let user_data = data_segment(USER_DATA_SELECTOR, 3);
    sregs.ds = user_data;
    sregs.es = user_data;
    sregs.fs = user_data;
    sregs.gs = user_data;
    sregs.ss = user_data;
    // Guest code never reloads TR, so KVM's per-vCPU segment cache can point at
    // private task state while the shared GDT retains the root descriptor.
    sregs.tr = tss_segment(task_state.0);

    sregs.cr0 |= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_PG;
    sregs.cr0 &= !(CR0_EM | CR0_TS);
    sregs.cr3 = PML4_ADDRESS;
    sregs.cr4 |= CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE;
    sregs.efer |= EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
    if initialize_shared_tables {
        // The page tables were just rewritten, and an exec's new layout can
        // unmap identity pages the old image used. Passing through a different
        // CR3 makes KVM reset its MMU, which flushes the guest's cached
        // translations before the vCPU next runs; setting an unchanged CR3
        // alone does not.
        let mut through = sregs;
        through.cr3 = PDPT_ADDRESS;
        vcpu.set_sregs(&through)?;
    }
    vcpu.set_sregs(&sregs)?;

    let mut xcrs = vcpu.get_xcrs()?;
    let xcr0 = xcrs.xcrs[..xcrs.nr_xcrs as usize]
        .iter_mut()
        .find(|xcr| xcr.xcr == 0)
        .ok_or_else(|| {
            Error::UnsupportedCpuidProfile("KVM did not expose guest XCR0".to_string())
        })?;
    xcr0.value |= XCR0_X87 | XCR0_SSE | XCR0_YMM;
    vcpu.set_xcrs(&xcrs)?;

    let fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };
    vcpu.set_fpu(&fpu)?;

    let entries = [
        kvm_msr_entry {
            index: MSR_STAR,
            data: STAR,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_LSTAR,
            data: syscall_trampoline_address,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_CSTAR,
            data: 0,
            ..Default::default()
        },
        kvm_msr_entry {
            index: MSR_SYSCALL_MASK,
            data: SYSCALL_MASK,
            ..Default::default()
        },
    ];
    let msrs = Msrs::from_entries(&entries).expect("fixed MSR array must fit");
    let written = vcpu.set_msrs(&msrs)?;
    if written != entries.len() {
        return Err(Error::IncompleteMsrSetup {
            expected: entries.len(),
            actual: written,
        });
    }

    let regs = initial_guest_registers(entry_point, stack_pointer);
    vcpu.set_regs(&regs)?;
    Ok(())
}

/// Set CPL3 timestamp interception only for the loop that owns its Tool callback.
/// CR4 is updated in place; unrelated execution and paging bits are retained.
pub(crate) fn set_userspace_rdtsc_interception(vcpu: &VcpuFd, enabled: bool) -> Result<()> {
    let mut sregs = vcpu.get_sregs()?;
    if enabled {
        sregs.cr4 |= CR4_TSD;
    } else {
        sregs.cr4 &= !CR4_TSD;
    }
    vcpu.set_sregs(&sregs)?;
    Ok(())
}

/// The register state Linux hands a freshly `exec`'d x86-64 process.
///
/// The kernel zeroes every general-purpose register except `rsp`, and the
/// x86-64 ABI requires the outermost frame pointer to be null so that a
/// frame-pointer walk terminates at the entry frame rather than running off
/// into the initial stack. The only nonzero state here is therefore `rip`,
/// `rsp`, and the reserved and interrupt-enable bits of `rflags`.
///
/// This is a pure function so the ABI contract can be asserted without a VM.
fn initial_guest_registers(entry_point: u64, stack_pointer: u64) -> kvm_bindings::kvm_regs {
    kvm_bindings::kvm_regs {
        rip: entry_point,
        rsp: stack_pointer,
        // Linux enters user space with the reserved bit and IF set.
        rflags: 0x202,
        ..Default::default()
    }
}

pub(crate) fn set_user_segment_base(
    vcpu: &VcpuFd,
    segment: SegmentBase,
    address: u64,
) -> Result<()> {
    let mut sregs = vcpu.get_sregs()?;
    match segment {
        SegmentBase::Fs => sregs.fs.base = address,
        SegmentBase::Gs => sregs.gs.base = address,
    }
    vcpu.set_sregs(&sregs)?;
    Ok(())
}

pub(crate) fn configure_user_segments(vcpu: &VcpuFd) -> Result<()> {
    let mut sregs = vcpu.get_sregs()?;
    let fs_base = sregs.fs.base;
    let gs_base = sregs.gs.base;
    sregs.cs = code_segment(USER_CODE_SELECTOR, 3);
    let user_data = data_segment(USER_DATA_SELECTOR, 3);
    sregs.ds = user_data;
    sregs.es = user_data;
    sregs.ss = user_data;
    sregs.fs = user_data;
    sregs.fs.base = fs_base;
    sregs.gs = user_data;
    sregs.gs.base = gs_base;
    vcpu.set_sregs(&sregs)?;
    Ok(())
}

/// Reconstructs the userspace register file stopped at a syscall boundary.
///
/// The live vCPU is executing the ring-zero VMCALL trampoline, which has
/// overwritten RAX/RBX/RCX/RDX/RSI. The transport frame is authoritative for
/// those registers and for the userspace return RIP and RFLAGS.
pub(crate) fn process_syscall_return_registers(
    memory: &GuestMemory,
    mut registers: kvm_bindings::kvm_regs,
    syscall_frame_address: u64,
    result: i64,
    stack_pointer: Option<u64>,
) -> Result<kvm_bindings::kvm_regs> {
    // One guest-memory copy for the whole span, words 1 through
    // SAVED_RBX_WORD: each copy is admitted against the entry gate, and nine
    // separate word reads cost a quarter of a KVM guest syscall.
    const FIRST: usize = 1;
    const LAST: usize = SAVED_RBX_WORD;
    const _: () = assert!(
        FIRST <= RETURN_RIP_WORD
            && RETURN_RIP_WORD <= LAST
            && FIRST <= RETURN_FLAGS_WORD
            && RETURN_FLAGS_WORD <= LAST
            && 6 <= LAST
    );
    let mut frame = [0u8; (LAST - FIRST + 1) * std::mem::size_of::<u64>()];
    memory.read_raw(
        frame_word_address_u64(syscall_frame_address, FIRST),
        &mut frame,
    )?;
    let word = |index: usize| {
        let start = (index - FIRST) * std::mem::size_of::<u64>();
        u64::from_le_bytes(frame[start..start + 8].try_into().unwrap())
    };
    let return_rip = word(RETURN_RIP_WORD);
    let return_flags = word(RETURN_FLAGS_WORD);
    registers.rax = result as u64;
    registers.rdi = word(1);
    registers.rsi = word(2);
    registers.rdx = word(3);
    registers.r10 = word(4);
    registers.r8 = word(5);
    registers.r9 = word(6);
    registers.rbx = word(SAVED_RBX_WORD);
    registers.rcx = return_rip;
    registers.r11 = return_flags;
    registers.rip = return_rip;
    registers.rflags = return_flags;
    if let Some(stack_pointer) = stack_pointer {
        registers.rsp = stack_pointer;
    }
    Ok(registers)
}

// TODO-HUMAN-REVIEW(PR-172): Review syscall-frame selection for concurrent vCPUs.
pub(crate) fn configure_process_syscall_return(
    memory: &GuestMemory,
    vcpu: &VcpuFd,
    syscall_frame_address: u64,
    result: i64,
    stack_pointer: Option<u64>,
) -> Result<()> {
    configure_user_segments(vcpu)?;
    let regs = process_syscall_return_registers(
        memory,
        vcpu.get_regs()?,
        syscall_frame_address,
        result,
        stack_pointer,
    )?;
    vcpu.set_regs(&regs)?;
    Ok(())
}

/// Stages a userspace register file for the trampoline that is currently
/// stopped at its VMCALL. KVM completes that instruction before observing a
/// register write, so changing CS/RIP here would resume the remaining ring-zero
/// trampoline under user segments. Instead, put every trampoline-restored
/// register in its transport word and change only the registers it preserves.
pub(crate) fn stage_process_syscall_return(
    memory: &mut GuestMemory,
    vcpu: &VcpuFd,
    syscall_frame_address: u64,
    registers: kvm_bindings::kvm_regs,
) -> Result<()> {
    for (word, value) in [
        (RESULT_WORD, registers.rax),
        (1, registers.rdi),
        (2, registers.rsi),
        (3, registers.rdx),
        (4, registers.r10),
        (5, registers.r8),
        (6, registers.r9),
        (RETURN_RIP_WORD, registers.rip),
        (RETURN_FLAGS_WORD, registers.rflags),
        (SAVED_RBX_WORD, registers.rbx),
        // A syscall return is SYSRETQ-shaped; never reuse an older request.
        (FULL_RETURN_WORD, 0),
    ] {
        write_u64(
            memory,
            frame_word_address_u64(syscall_frame_address, word),
            value,
        )?;
    }
    let mut live = vcpu.get_regs()?;
    live.rbp = registers.rbp;
    live.rsp = registers.rsp;
    live.r12 = registers.r12;
    live.r13 = registers.r13;
    live.r14 = registers.r14;
    live.r15 = registers.r15;
    vcpu.set_regs(&live)?;
    Ok(())
}

/// Stages the context `rt_sigreturn` restored. Linux restores every register
/// from the signal frame, and returns with IRET whenever SYSRET could not
/// reproduce it (RCX != RIP or R11 != RFLAGS). That is the normal case for a
/// handler returning to an interrupted CPU exception, where RCX and R11 are
/// live program values; a SYSRET return would silently replace them.
pub(crate) fn stage_process_signal_return(
    memory: &mut GuestMemory,
    vcpu: &VcpuFd,
    syscall_frame_address: u64,
    registers: kvm_bindings::kvm_regs,
) -> Result<()> {
    stage_process_syscall_return(memory, vcpu, syscall_frame_address, registers)?;
    if registers.rcx == registers.rip && registers.r11 == registers.rflags {
        return Ok(());
    }
    for (word, value) in [
        (RETURN_RCX_WORD, registers.rcx),
        (RETURN_R11_WORD, registers.r11),
        (IRET_FRAME_WORD, registers.rip),
        (IRET_FRAME_WORD + 1, u64::from(USER_CODE_SELECTOR)),
        (IRET_FRAME_WORD + 2, registers.rflags),
        (IRET_FRAME_WORD + 3, registers.rsp),
        (IRET_FRAME_WORD + 4, u64::from(USER_DATA_SELECTOR)),
        (FULL_RETURN_WORD, 1),
    ] {
        write_u64(
            memory,
            frame_word_address_u64(syscall_frame_address, word),
            value,
        )?;
    }
    Ok(())
}

pub(crate) fn syscall_hypercall_address(
    hypercall_instruction: [u8; 3],
    syscall_trampoline_address: u64,
    syscall_frame_address: u64,
) -> u64 {
    let trampoline = syscall_trampoline(hypercall_instruction, syscall_frame_address);
    let offset = trampoline
        .windows(hypercall_instruction.len())
        .position(|window| window == hypercall_instruction)
        .expect("syscall trampoline must contain its hypercall");
    syscall_trampoline_address
        .checked_add(offset as u64)
        .expect("syscall hypercall address must not overflow")
}

/// The async owner retains its parking stage when admission is closed. This
/// helper neither waits for reopening nor executes a guest instruction.
// TODO-HUMAN-REVIEW(PR-172): Review per-thread trampoline park/unpark updates.
pub(crate) fn try_set_syscall_return_park(
    memory: &mut GuestMemory,
    hypercall_instruction: [u8; 3],
    syscall_trampoline_address: u64,
    syscall_frame_address: u64,
    park: bool,
) -> Result<Option<()>> {
    let (address, byte) = syscall_return_park_byte(
        hypercall_instruction,
        syscall_trampoline_address,
        syscall_frame_address,
        park,
    );
    memory.try_write_raw(address, &[byte])
}

fn syscall_return_park_byte(
    hypercall_instruction: [u8; 3],
    syscall_trampoline_address: u64,
    syscall_frame_address: u64,
    park: bool,
) -> (u64, u8) {
    let trampoline = syscall_trampoline(hypercall_instruction, syscall_frame_address);
    let return_offset = (syscall_hypercall_address(
        hypercall_instruction,
        syscall_trampoline_address,
        syscall_frame_address,
    ) - syscall_trampoline_address) as usize
        + hypercall_instruction.len();
    let byte = if park {
        0xf4
    } else {
        trampoline[return_offset]
    };
    (syscall_trampoline_address + return_offset as u64, byte)
}

fn write_descriptor_tables(memory: &mut GuestMemory) -> Result<()> {
    let tss_low = gdt_entry(0x008b, TSS_ADDRESS, 0x67);
    let entries = [
        0,
        gdt_entry(0xa09b, 0, 0xfffff),
        gdt_entry(0xc093, 0, 0xfffff),
        gdt_entry(0xc0f3, 0, 0xfffff),
        gdt_entry(0xa0fb, 0, 0xfffff),
        tss_low,
        TSS_ADDRESS >> 32,
    ];
    let mut bytes = Vec::with_capacity(entries.len() * std::mem::size_of::<u64>());
    for entry in entries {
        bytes.extend_from_slice(&entry.to_le_bytes());
    }
    memory.write_raw(GDT_ADDRESS, &bytes)?;
    write_exception_tables(memory)?;
    write_task_state(
        memory,
        TSS_ADDRESS,
        EXCEPTION_STACK_BOTTOM,
        EXCEPTION_STACK_TOP,
    )
}

fn worker_task_state_layout(
    syscall_trampoline_address: u64,
    syscall_frame_address: u64,
) -> (u64, u64, u64) {
    debug_assert_eq!(
        syscall_frame_address,
        syscall_trampoline_address + PAGE_SIZE
    );
    (
        syscall_trampoline_address + THREAD_TSS_OFFSET,
        syscall_frame_address + FRAME_SIZE as u64,
        syscall_frame_address + PAGE_SIZE,
    )
}

fn write_task_state(
    memory: &mut GuestMemory,
    tss_address: u64,
    exception_stack_bottom: u64,
    exception_stack_top: u64,
) -> Result<()> {
    memory.zero_raw(tss_address, 0x68)?;
    write_u64(memory, tss_address + 4, exception_stack_top)?;
    memory.write_raw(tss_address + 0x66, &0x68_u16.to_le_bytes())?;
    let stack_length = usize::try_from(exception_stack_top - exception_stack_bottom)
        .expect("KVM exception stack length must fit usize");
    memory.zero_raw(exception_stack_bottom, stack_length)
}

fn write_exception_tables(memory: &mut GuestMemory) -> Result<()> {
    memory.zero_raw(IDT_ADDRESS, PAGE_SIZE as usize)?;
    memory.zero_raw(EXCEPTION_STUB_ADDRESS, PAGE_SIZE as usize)?;

    for vector in 0..EXCEPTION_VECTOR_COUNT {
        let handler = EXCEPTION_STUB_ADDRESS + vector as u64 * EXCEPTION_STUB_STRIDE;
        let gate = idt_gate(handler);
        memory.write_raw(IDT_ADDRESS + (vector * IDT_ENTRY_SIZE) as u64, &gate)?;
        let stub = exception_stub();
        memory.write_raw(handler, &stub)?;
    }
    Ok(())
}

fn idt_gate(handler: u64) -> [u8; IDT_ENTRY_SIZE] {
    let mut gate = [0; IDT_ENTRY_SIZE];
    gate[0..2].copy_from_slice(&(handler as u16).to_le_bytes());
    gate[2..4].copy_from_slice(&KERNEL_CODE_SELECTOR.to_le_bytes());
    gate[5] = 0x8e;
    gate[6..8].copy_from_slice(&((handler >> 16) as u16).to_le_bytes());
    gate[8..12].copy_from_slice(&((handler >> 32) as u32).to_le_bytes());
    gate
}

fn exception_stub() -> [u8; 1] {
    [0xf4]
}

pub(crate) fn exception_pushes_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

pub(crate) fn exception_from_halt(rip: u64) -> Option<u8> {
    let offset = rip.checked_sub(EXCEPTION_STUB_ADDRESS + 1)?;
    if !offset.is_multiple_of(EXCEPTION_STUB_STRIDE) {
        return None;
    }
    let vector = u8::try_from(offset / EXCEPTION_STUB_STRIDE).ok()?;
    (usize::from(vector) < EXCEPTION_VECTOR_COUNT).then_some(vector)
}

fn write_page_tables(memory: &mut GuestMemory) -> Result<()> {
    memory.zero_raw(FIRST_PAGE_TABLE_ADDRESS, PAGE_SIZE as usize)?;
    for index in 1..PAGE_SIZE / std::mem::size_of::<u64>() as u64 {
        write_u64(
            memory,
            FIRST_PAGE_TABLE_ADDRESS + index * std::mem::size_of::<u64>() as u64,
            (index * PAGE_SIZE) | 0x7,
        )?;
    }
    memory.zero_raw(PML4_ADDRESS, PAGE_SIZE as usize)?;
    memory.zero_raw(PDPT_ADDRESS, PAGE_SIZE as usize)?;
    write_u64(memory, PML4_ADDRESS, PDPT_ADDRESS | 0x7)?;

    // AUTONOMOUS-BOT-IMPLEMENTED: Map a second GiB for large KVM workloads.
    // TODO-HUMAN-REVIEW(PR-173): Review the three-directory identity map.
    let mapped_large_pages = memory.guest_end().div_ceil(LARGE_PAGE_SIZE);
    let entries_per_directory = PAGE_SIZE / std::mem::size_of::<u64>() as u64;
    for (directory_index, directory_address) in PAGE_DIRECTORY_ADDRESSES.into_iter().enumerate() {
        let first_page = directory_index as u64 * entries_per_directory;
        if first_page >= mapped_large_pages {
            break;
        }
        memory.zero_raw(directory_address, PAGE_SIZE as usize)?;
        write_u64(
            memory,
            PDPT_ADDRESS + directory_index as u64 * std::mem::size_of::<u64>() as u64,
            directory_address | 0x7,
        )?;
        let pages_in_directory = (mapped_large_pages - first_page).min(entries_per_directory);
        for index in 0..pages_in_directory {
            write_u64(
                memory,
                directory_address + index * std::mem::size_of::<u64>() as u64,
                if first_page + index == 0 {
                    FIRST_PAGE_TABLE_ADDRESS | 0x7
                } else {
                    ((first_page + index) * LARGE_PAGE_SIZE) | 0x87
                },
            )?;
        }
    }
    // The loader may already have placed windows; keep them.
    install_user_windows(memory)
}

/// Places the top `length` bytes of guest memory at the top of the user address
/// space, where Linux puts the initial stack, and maps every window in the
/// page tables (`install_user_windows`). Returns the window's first user
/// address. `length` must be whole pages and leave the first large page alone.
pub(crate) fn map_user_stack_window(memory: &mut GuestMemory, length: u64) -> Result<u64> {
    if memory
        .guest_end()
        .checked_sub(length)
        .is_none_or(|start| start < LARGE_PAGE_SIZE)
    {
        return Err(Error::LongModeMemoryTooSmall);
    }
    let user_start = memory.establish_user_stack_window(length)?;
    install_user_windows(memory)?;
    Ok(user_start)
}

/// Page-table pages handed out from the window table pool.
struct TablePool {
    next: u64,
}

impl TablePool {
    const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

    fn allocate(&mut self, memory: &mut GuestMemory) -> Result<u64> {
        if self.next == WINDOW_TABLE_POOL_PAGES {
            return Err(Error::LongModeMemoryTooSmall);
        }
        let table = WINDOW_TABLE_POOL_ADDRESS + self.next * PAGE_SIZE;
        self.next += 1;
        memory.zero_raw(table, PAGE_SIZE as usize)?;
        Ok(table)
    }

    /// The table that entry `index` of `table` points to, allocating it when the
    /// entry is empty.
    fn child(&mut self, memory: &mut GuestMemory, table: u64, index: u64) -> Result<u64> {
        let entry_address = table + index * std::mem::size_of::<u64>() as u64;
        let entry = read_u64(memory, entry_address)?;
        if entry != 0 {
            return Ok(entry & Self::ADDRESS_MASK);
        }
        let child = self.allocate(memory)?;
        write_u64(memory, entry_address, child | 0x7)?;
        Ok(child)
    }
}

/// Maps every user window (see `crate::memory::UserWindow`) in the guest page
/// tables, maps the identity addresses below the identity limit and unmaps
/// those at and above it, so no physical page is reachable at two user addresses. A window uses a
/// 2 MiB page wherever a whole aligned block of it maps to an aligned physical
/// block, and 4 KiB pages elsewhere; addresses past a window's user end (the
/// stack window's TASK_SIZE page) stay unmapped, so a guest access faults as on
/// Linux. The tables come from a fixed pool in the boot area and are rebuilt
/// whole each time, so repeating it changes nothing.
pub(crate) fn install_user_windows(memory: &mut GuestMemory) -> Result<()> {
    let (windows, identity_limit) = memory.user_layout();
    let entry = std::mem::size_of::<u64>() as u64;
    let entries = PAGE_SIZE / entry;
    let index = |address: u64, shift: u32| (address >> shift) & (entries - 1);
    // Only the first top-level entry maps identity addresses.
    for slot in 1..entries {
        write_u64(memory, PML4_ADDRESS + slot * entry, 0)?;
    }
    let mut pool = TablePool { next: 0 };
    for window in &windows {
        let mut user = window.user_start;
        while user < window.user_end {
            let physical = window.physical(user);
            let pdpt = pool.child(memory, PML4_ADDRESS, index(user, 39))?;
            let directory = pool.child(memory, pdpt, index(user, 30))?;
            if user.is_multiple_of(LARGE_PAGE_SIZE)
                && physical.is_multiple_of(LARGE_PAGE_SIZE)
                && user + LARGE_PAGE_SIZE <= window.user_end
            {
                write_u64(memory, directory + index(user, 21) * entry, physical | 0x87)?;
                user += LARGE_PAGE_SIZE;
                continue;
            }
            let table = pool.child(memory, directory, index(user, 21))?;
            write_u64(memory, table + index(user, 12) * entry, physical | 0x7)?;
            user += PAGE_SIZE;
        }
    }
    let mapped_large_pages = memory.guest_end().div_ceil(LARGE_PAGE_SIZE);
    // Identity addresses that cover all of memory are mapped as
    // `write_page_tables` maps them, in whole large pages.
    let identity_limit = if identity_limit >= memory.guest_end() {
        mapped_large_pages * LARGE_PAGE_SIZE
    } else {
        identity_limit
    };
    if identity_limit < LARGE_PAGE_SIZE {
        return Err(Error::LongModeMemoryTooSmall);
    }
    // Map the identity addresses below the limit and unmap those at and above
    // it, rewriting every large page after the first (which keeps its page
    // table) so that a limit an earlier layout lowered is raised again. A large
    // page wholly below the limit is mapped, one wholly above it unmapped, and
    // one that straddles it split so that only its pages below the limit stay
    // mapped.
    for large_page in 1..mapped_large_pages {
        let Some(directory_address) = PAGE_DIRECTORY_ADDRESSES.get((large_page / entries) as usize)
        else {
            continue;
        };
        let directory_entry = directory_address + (large_page % entries) * entry;
        let base = large_page * LARGE_PAGE_SIZE;
        if base + LARGE_PAGE_SIZE <= identity_limit {
            write_u64(memory, directory_entry, base | 0x87)?;
            continue;
        }
        if base >= identity_limit {
            write_u64(memory, directory_entry, 0)?;
            continue;
        }
        let table = pool.allocate(memory)?;
        for page in 0..(identity_limit - base) / PAGE_SIZE {
            write_u64(
                memory,
                table + page * entry,
                (base + page * PAGE_SIZE) | 0x7,
            )?;
        }
        write_u64(memory, directory_entry, table | 0x7)?;
    }
    Ok(())
}

// AUTONOMOUS-BOT-IMPLEMENTED: Emit a minimal kernel-note vDSO for glibc.
// TODO-HUMAN-REVIEW(PR-266): Review the synthetic vDSO ELF layout and note.
//
// Deterministic kernel version advertised by the vDSO note. Encoded as
// `(major << 16) | (minor << 8) | patch`, this is `LINUX_VERSION_CODE` for the
// "6.0.0" release the KVM backend reports through `uname(2)`, `/proc/version`,
// and `/proc/sys/kernel/osrelease` (see reverie-kvm/src/executor.rs). Keeping
// the value fixed preserves determinism regardless of the real host kernel.
const GUEST_LINUX_VERSION_MAJOR: u32 = 6;
const GUEST_LINUX_VERSION_MINOR: u32 = 0;
const GUEST_LINUX_VERSION_PATCH: u32 = 0;
const GUEST_LINUX_VERSION_CODE: u32 = (GUEST_LINUX_VERSION_MAJOR << 16)
    | (GUEST_LINUX_VERSION_MINOR << 8)
    | GUEST_LINUX_VERSION_PATCH;
const _: () = assert!(GUEST_LINUX_VERSION_CODE == reverie::vdso::CANONICAL_LINUX_VERSION_CODE);

/// Writes the canonical vDSO at [`VDSO_ADDRESS`]. Its kernel-version note
/// reports [`GUEST_LINUX_VERSION_CODE`], the release the executor's `uname(2)`
/// reports.
fn write_vdso(memory: &mut GuestMemory) -> Result<()> {
    memory.write_raw(VDSO_ADDRESS, reverie::vdso::canonical_vdso_image())
}

fn write_u64(memory: &mut GuestMemory, address: u64, value: u64) -> Result<()> {
    memory.write_raw(address, &value.to_le_bytes())
}

fn read_u64(memory: &GuestMemory, address: u64) -> Result<u64> {
    let mut value = [0; std::mem::size_of::<u64>()];
    memory.read_raw(address, &mut value)?;
    Ok(u64::from_le_bytes(value))
}

fn code_segment(selector: u16, dpl: u8) -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: u32::MAX,
        selector,
        type_: 11,
        present: 1,
        dpl,
        db: 0,
        s: 1,
        l: 1,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn data_segment(selector: u16, dpl: u8) -> kvm_segment {
    kvm_segment {
        base: 0,
        limit: u32::MAX,
        selector,
        type_: 3,
        present: 1,
        dpl,
        db: 1,
        s: 1,
        l: 0,
        g: 1,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn tss_segment(base: u64) -> kvm_segment {
    kvm_segment {
        base,
        limit: 0x67,
        selector: TSS_SELECTOR,
        type_: 11,
        present: 1,
        dpl: 0,
        db: 0,
        s: 0,
        l: 0,
        g: 0,
        avl: 0,
        unusable: 0,
        padding: 0,
    }
}

fn gdt_entry(flags: u64, base: u64, limit: u64) -> u64 {
    ((base & 0xff00_0000) << (56 - 24))
        | ((flags & 0x0000_f0ff) << 40)
        | ((limit & 0x000f_0000) << (48 - 16))
        | ((base & 0x00ff_ffff) << 16)
        | (limit & 0x0000_ffff)
}

fn syscall_trampoline(hypercall_instruction: [u8; 3], syscall_frame_address: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(192);

    store_absolute(&mut code, syscall_frame_address, 0x48, 0x04, 0);
    store_absolute(&mut code, syscall_frame_address, 0x48, 0x3c, 1);
    store_absolute(&mut code, syscall_frame_address, 0x48, 0x34, 2);
    store_absolute(&mut code, syscall_frame_address, 0x48, 0x14, 3);
    store_absolute(&mut code, syscall_frame_address, 0x4c, 0x14, 4);
    store_absolute(&mut code, syscall_frame_address, 0x4c, 0x04, 5);
    store_absolute(&mut code, syscall_frame_address, 0x4c, 0x0c, 6);
    store_absolute(
        &mut code,
        syscall_frame_address,
        0x48,
        0x0c,
        RETURN_RIP_WORD,
    );
    store_absolute(
        &mut code,
        syscall_frame_address,
        0x4c,
        0x1c,
        RETURN_FLAGS_WORD,
    );
    store_absolute(&mut code, syscall_frame_address, 0x48, 0x1c, SAVED_RBX_WORD);

    code.extend_from_slice(&[0x48, 0xc7, 0xc0]);
    code.extend_from_slice(&(VMCALL_SYSCALL_TRANSPORT as u32).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xbb]);
    code.extend_from_slice(&syscall_frame_address.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xc7, 0xc1, 1, 0, 0, 0]);
    code.extend_from_slice(&[0x31, 0xd2, 0x31, 0xf6]);
    code.extend_from_slice(&hypercall_instruction);

    load_absolute(&mut code, syscall_frame_address, 0x48, 0x04, RESULT_WORD);
    load_absolute(&mut code, syscall_frame_address, 0x48, 0x3c, 1);
    load_absolute(&mut code, syscall_frame_address, 0x48, 0x34, 2);
    load_absolute(&mut code, syscall_frame_address, 0x48, 0x14, 3);
    load_absolute(&mut code, syscall_frame_address, 0x4c, 0x14, 4);
    load_absolute(&mut code, syscall_frame_address, 0x4c, 0x04, 5);
    load_absolute(&mut code, syscall_frame_address, 0x4c, 0x0c, 6);
    load_absolute(
        &mut code,
        syscall_frame_address,
        0x48,
        0x0c,
        RETURN_RIP_WORD,
    );
    load_absolute(
        &mut code,
        syscall_frame_address,
        0x4c,
        0x1c,
        RETURN_FLAGS_WORD,
    );
    load_absolute(&mut code, syscall_frame_address, 0x48, 0x1c, SAVED_RBX_WORD);
    // cmp qword ptr [FULL_RETURN_WORD], 0; jne full_return
    code.extend_from_slice(&[0x48, 0x83, 0x3c, 0x25]);
    code.extend_from_slice(
        &frame_word_address(syscall_frame_address, FULL_RETURN_WORD).to_le_bytes(),
    );
    code.extend_from_slice(&[0x00, 0x75, 0x03]);
    // sysretq: RCX becomes RIP and R11 becomes RFLAGS.
    code.extend_from_slice(&[0x48, 0x0f, 0x07]);
    // full_return: consume the request, restore RCX/R11, and IRETQ through
    // the staged frame, as Linux returns to a context SYSRET cannot express.
    // mov qword ptr [FULL_RETURN_WORD], 0
    code.extend_from_slice(&[0x48, 0xc7, 0x04, 0x25]);
    code.extend_from_slice(
        &frame_word_address(syscall_frame_address, FULL_RETURN_WORD).to_le_bytes(),
    );
    code.extend_from_slice(&0_u32.to_le_bytes());
    load_absolute(
        &mut code,
        syscall_frame_address,
        0x48,
        0x0c,
        RETURN_RCX_WORD,
    );
    load_absolute(
        &mut code,
        syscall_frame_address,
        0x4c,
        0x1c,
        RETURN_R11_WORD,
    );
    // mov rsp, IRET frame (sign-extended imm32), then iretq
    code.extend_from_slice(&[0x48, 0xc7, 0xc4]);
    code.extend_from_slice(
        &frame_word_address(syscall_frame_address, IRET_FRAME_WORD).to_le_bytes(),
    );
    code.extend_from_slice(&[0x48, 0xcf]);
    code
}

fn store_absolute(
    code: &mut Vec<u8>,
    syscall_frame_address: u64,
    rex: u8,
    register: u8,
    word: usize,
) {
    code.extend_from_slice(&[rex, 0x89, register, 0x25]);
    code.extend_from_slice(&frame_word_address(syscall_frame_address, word).to_le_bytes());
}

fn load_absolute(
    code: &mut Vec<u8>,
    syscall_frame_address: u64,
    rex: u8,
    register: u8,
    word: usize,
) {
    code.extend_from_slice(&[rex, 0x8b, register, 0x25]);
    code.extend_from_slice(&frame_word_address(syscall_frame_address, word).to_le_bytes());
}

fn frame_word_address(syscall_frame_address: u64, word: usize) -> u32 {
    u32::try_from(frame_word_address_u64(syscall_frame_address, word))
        .expect("syscall frame must fit in an absolute disp32 address")
}

fn frame_word_address_u64(syscall_frame_address: u64, word: usize) -> u64 {
    syscall_frame_address + (word * std::mem::size_of::<u64>()) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SyscallRequest;

    #[test]
    fn trampoline_preserves_syscall_return_state() {
        let code = syscall_trampoline([0x0f, 0x01, 0xc1], SYSCALL_FRAME_ADDRESS);

        assert!(code.windows(3).any(|window| window == [0x0f, 0x01, 0xc1]));
        // The SYSRETQ return is taken unless a full return was staged; the
        // full return consumes its request, restores RCX/R11, and IRETQs.
        let full = frame_word_address(SYSCALL_FRAME_ADDRESS, FULL_RETURN_WORD).to_le_bytes();
        let mut tail = vec![0x48, 0x83, 0x3c, 0x25];
        tail.extend_from_slice(&full);
        tail.extend_from_slice(&[0x00, 0x75, 0x03, 0x48, 0x0f, 0x07]);
        tail.extend_from_slice(&[0x48, 0xc7, 0x04, 0x25]);
        tail.extend_from_slice(&full);
        tail.extend_from_slice(&[0, 0, 0, 0, 0x48, 0x8b, 0x0c, 0x25]);
        tail.extend_from_slice(
            &frame_word_address(SYSCALL_FRAME_ADDRESS, RETURN_RCX_WORD).to_le_bytes(),
        );
        tail.extend_from_slice(&[0x4c, 0x8b, 0x1c, 0x25]);
        tail.extend_from_slice(
            &frame_word_address(SYSCALL_FRAME_ADDRESS, RETURN_R11_WORD).to_le_bytes(),
        );
        tail.extend_from_slice(&[0x48, 0xc7, 0xc4]);
        tail.extend_from_slice(
            &frame_word_address(SYSCALL_FRAME_ADDRESS, IRET_FRAME_WORD).to_le_bytes(),
        );
        tail.extend_from_slice(&[0x48, 0xcf]);
        assert!(code.ends_with(&tail));
        assert!(code.len() < THREAD_TSS_OFFSET as usize);
    }

    #[test]
    fn signal_return_requests_iret_only_when_sysret_would_change_registers() {
        const FRAME: u64 = 0x1000;
        let kvm = kvm_ioctls::Kvm::new();
        let Ok(kvm) = kvm else {
            eprintln!("skipping: cannot open /dev/kvm");
            return;
        };
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        let word = |memory: &GuestMemory, word: usize| {
            read_u64(memory, frame_word_address_u64(FRAME, word)).unwrap()
        };
        let mut registers = kvm_bindings::kvm_regs {
            rip: 0x40_1000,
            rcx: 0x40_1000,
            rflags: 0x246,
            r11: 0x246,
            rsp: 0x7fff_0000,
            ..Default::default()
        };
        // A SYSRET-shaped context keeps the SYSRET return.
        stage_process_signal_return(&mut memory, &vcpu, FRAME, registers).unwrap();
        assert_eq!(word(&memory, FULL_RETURN_WORD), 0);

        registers.rcx = 0x1122_3344_5566_7788;
        registers.r11 = 0x0123_4567_89ab_cdef;
        stage_process_signal_return(&mut memory, &vcpu, FRAME, registers).unwrap();
        assert_eq!(word(&memory, FULL_RETURN_WORD), 1);
        assert_eq!(word(&memory, RETURN_RCX_WORD), registers.rcx);
        assert_eq!(word(&memory, RETURN_R11_WORD), registers.r11);
        assert_eq!(
            (0..5)
                .map(|index| word(&memory, IRET_FRAME_WORD + index))
                .collect::<Vec<_>>(),
            vec![
                registers.rip,
                u64::from(USER_CODE_SELECTOR),
                registers.rflags,
                registers.rsp,
                u64::from(USER_DATA_SELECTOR),
            ]
        );

        // An ordinary syscall return never reuses that request.
        stage_process_syscall_return(&mut memory, &vcpu, FRAME, registers).unwrap();
        assert_eq!(word(&memory, FULL_RETURN_WORD), 0);
    }

    #[test]
    fn signal_context_uses_transport_frame_not_poisoned_trampoline_registers() {
        const FRAME: u64 = 0x1000;
        let mut memory = GuestMemory::new(0, 0x4000).unwrap();
        let request =
            SyscallRequest::new(libc::SYS_kill as u64, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        request.write_to(&mut memory, FRAME).unwrap();
        memory
            .write_raw(
                frame_word_address_u64(FRAME, RETURN_RIP_WORD),
                &0x1234_5678_u64.to_le_bytes(),
            )
            .unwrap();
        memory
            .write_raw(
                frame_word_address_u64(FRAME, RETURN_FLAGS_WORD),
                &0x202_u64.to_le_bytes(),
            )
            .unwrap();
        memory
            .write_raw(
                frame_word_address_u64(FRAME, SAVED_RBX_WORD),
                &0x7777_u64.to_le_bytes(),
            )
            .unwrap();
        let live = kvm_bindings::kvm_regs {
            rax: u64::MAX,
            rbx: u64::MAX,
            rcx: u64::MAX,
            rdx: u64::MAX,
            rsi: u64::MAX,
            r12: 0x1212,
            rsp: 0x7fff_f000,
            ..Default::default()
        };
        let restored = process_syscall_return_registers(&memory, live, FRAME, 0, None).unwrap();
        let context = crate::signal::Sigcontext::from_kvm(
            restored,
            0x7fff_e000,
            crate::signal::KernelSigset::default(),
        );
        assert_eq!(
            (context.rax, context.rdi, context.rsi, context.rdx),
            (0, 0x11, 0x22, 0x33)
        );
        assert_eq!((context.r10, context.r8, context.r9), (0x44, 0x55, 0x66));
        assert_eq!(
            (context.rbx, context.rip, context.rflags),
            (0x7777, 0x1234_5678, 0x202)
        );
    }

    #[test]
    fn sysret_selectors_do_not_depend_on_cpu_vendor() {
        let base = (STAR >> 48) as u16;
        // 64-bit SYSRET sets CS to (base + 16) | 3. SS is (base + 8) | 3 on
        // Intel and base + 8 on AMD.
        assert_eq!((base + 16) | 3, USER_CODE_SELECTOR);
        assert_eq!((base + 8) | 3, USER_DATA_SELECTOR);
        assert_eq!(base + 8, USER_DATA_SELECTOR);
        assert_eq!((STAR >> 32) as u16, KERNEL_CODE_SELECTOR);
    }

    #[test]
    fn descriptor_tables_install_exception_gates_and_kernel_stack() {
        let mut memory = GuestMemory::new(0, 0x20_000).unwrap();

        write_descriptor_tables(&mut memory).unwrap();

        let vector = 6_u64;
        let mut gate = [0; IDT_ENTRY_SIZE];
        memory
            .read(IDT_ADDRESS + vector * IDT_ENTRY_SIZE as u64, &mut gate)
            .unwrap();
        let handler = u64::from(u16::from_le_bytes([gate[0], gate[1]]))
            | (u64::from(u16::from_le_bytes([gate[6], gate[7]])) << 16)
            | (u64::from(u32::from_le_bytes([gate[8], gate[9], gate[10], gate[11]])) << 32);
        assert_eq!(
            handler,
            EXCEPTION_STUB_ADDRESS + vector * EXCEPTION_STUB_STRIDE
        );
        assert_eq!(u16::from_le_bytes([gate[2], gate[3]]), KERNEL_CODE_SELECTOR);
        assert_eq!(gate[5], 0x8e);

        let mut rsp0 = [0; 8];
        memory.read(TSS_ADDRESS + 4, &mut rsp0).unwrap();
        assert_eq!(u64::from_le_bytes(rsp0), EXCEPTION_STACK_TOP);
        let mut io_map_base = [0; 2];
        memory.read(TSS_ADDRESS + 0x66, &mut io_map_base).unwrap();
        assert_eq!(u16::from_le_bytes(io_map_base), 0x68);
    }

    #[test]
    fn worker_task_state_is_private_within_each_transport() {
        let first_trampoline = THREAD_SYSCALL_AREA_START;
        let first_frame = first_trampoline + PAGE_SIZE;
        let second_trampoline = first_trampoline + THREAD_SYSCALL_AREA_STRIDE;
        let second_frame = second_trampoline + PAGE_SIZE;
        let first = worker_task_state_layout(first_trampoline, first_frame);
        let second = worker_task_state_layout(second_trampoline, second_frame);

        assert_eq!(first.0, first_trampoline + THREAD_TSS_OFFSET);
        assert_eq!(first.1, first_frame + FRAME_SIZE as u64);
        assert_eq!(first.2, second_trampoline);
        assert!(first.2 <= second.0);

        let mut memory = GuestMemory::new(0, 0x20_000).unwrap();
        memory
            .write_raw(first.1, &vec![0xff; (first.2 - first.1) as usize])
            .unwrap();
        write_task_state(&mut memory, first.0, first.1, first.2).unwrap();

        let mut rsp0 = [0; 8];
        memory.read(first.0 + 4, &mut rsp0).unwrap();
        assert_eq!(u64::from_le_bytes(rsp0), first.2);
        assert_eq!(tss_segment(first.0).base, first.0);
        let mut stack_edges = [0xff; 2];
        memory.read(first.1, &mut stack_edges[..1]).unwrap();
        memory.read(first.2 - 1, &mut stack_edges[1..]).unwrap();
        assert_eq!(stack_edges, [0, 0]);
    }

    #[test]
    fn worker_tool_stacks_are_reserved_and_disjoint() {
        let first_top = thread_tool_stack_top(0);
        let second_top = thread_tool_stack_top(1);
        let last_top = thread_tool_stack_top(MAX_GUEST_THREADS as usize - 1);

        assert_eq!(first_top - TOOL_STACK_SIZE, THREAD_TOOL_STACK_AREA_START);
        assert_eq!(second_top - first_top, TOOL_STACK_SIZE);
        assert_eq!(last_top, WINDOW_TABLE_POOL_ADDRESS);
        assert_eq!(
            BOOT_RESERVED_END,
            WINDOW_TABLE_POOL_ADDRESS + WINDOW_TABLE_POOL_PAGES * PAGE_SIZE
        );
    }

    #[test]
    fn page_tables_identity_map_three_gibibytes() {
        let mut memory = GuestMemory::new(0, MAX_IDENTITY_MAP as usize).unwrap();

        write_page_tables(&mut memory).unwrap();

        assert_eq!(read_u64(&memory, PDPT_ADDRESS).unwrap(), 0x4000 | 0x7);
        assert_eq!(read_u64(&memory, PDPT_ADDRESS + 8).unwrap(), 0x9000 | 0x7);
        assert_eq!(read_u64(&memory, PDPT_ADDRESS + 16).unwrap(), 0xe000 | 0x7);
        assert_eq!(
            read_u64(&memory, 0x4000 + 511 * 8).unwrap(),
            0x3fe0_0000 | 0x87
        );
        assert_eq!(read_u64(&memory, 0x9000).unwrap(), 0x4000_0000 | 0x87);
        assert_eq!(
            read_u64(&memory, 0x9000 + 511 * 8).unwrap(),
            0x7fe0_0000 | 0x87
        );
        assert_eq!(read_u64(&memory, 0xe000).unwrap(), 0x8000_0000 | 0x87);
        assert_eq!(
            read_u64(&memory, 0xe000 + 511 * 8).unwrap(),
            0xbfe0_0000 | 0x87
        );
    }

    /// The guest-physical address the page tables map `address` to, walking
    /// them as the CPU does.
    fn walk(memory: &GuestMemory, address: u64) -> Option<u64> {
        const MASK: u64 = 0x000f_ffff_ffff_f000;
        let index = |shift: u32| ((address >> shift) & 511) * 8;
        let pml4 = read_u64(memory, PML4_ADDRESS + index(39)).unwrap();
        if pml4 & 1 == 0 {
            return None;
        }
        let pdpt = read_u64(memory, (pml4 & MASK) + index(30)).unwrap();
        if pdpt & 1 == 0 {
            return None;
        }
        let directory = read_u64(memory, (pdpt & MASK) + index(21)).unwrap();
        if directory & 1 == 0 {
            return None;
        }
        if directory & 0x80 != 0 {
            return Some(
                (directory & MASK & !(LARGE_PAGE_SIZE - 1)) | (address & (LARGE_PAGE_SIZE - 1)),
            );
        }
        let table = read_u64(memory, (directory & MASK) + index(12)).unwrap();
        (table & 1 != 0).then_some((table & MASK) | (address & (PAGE_SIZE - 1)))
    }

    /// A new layout's page tables replace the old one's whole: an identity end
    /// raised by a larger image maps the identity pages the old window held,
    /// and lowering it again unmaps them.
    #[test]
    fn page_tables_follow_an_identity_end_that_moves_both_ways() {
        const MIB: u64 = 1024 * 1024;
        let mut memory = GuestMemory::new(0, (64 * MIB) as usize).unwrap();
        write_page_tables(&mut memory).unwrap();
        for main_end in [3 * MIB, 48 * MIB, 3 * MIB] {
            memory.clear_user_layout();
            crate::elf::establish_linux_layout(&mut memory, main_end, MIB, None)
                .unwrap()
                .unwrap();
            map_user_stack_window(&mut memory, 8 * MIB).unwrap();
            let (windows, identity_end) = memory.user_layout();
            assert_eq!(windows.len(), 2);
            for address in (PAGE_SIZE..identity_end).step_by(PAGE_SIZE as usize) {
                assert_eq!(walk(&memory, address), Some(address), "{address:#x}");
            }
            for address in (identity_end..memory.guest_end()).step_by(PAGE_SIZE as usize) {
                assert_eq!(walk(&memory, address), None, "{address:#x}");
            }
            for window in &windows {
                for user in (window.user_start..window.user_end).step_by(PAGE_SIZE as usize) {
                    assert_eq!(walk(&memory, user), Some(window.physical(user)));
                }
            }
        }
    }

    #[test]
    fn page_zero_table_preserves_every_other_identity_entry() {
        let mut memory = GuestMemory::new(0, MAX_IDENTITY_MAP as usize).unwrap();
        write_page_tables(&mut memory).unwrap();
        assert_eq!(read_u64(&memory, PAGE_DIRECTORY_ADDRESSES[0]).unwrap(), 0x7);
        let mut actual = [0_u8; PAGE_SIZE as usize];
        memory.read_raw(0, &mut actual).unwrap();
        let mut expected = [0_u8; PAGE_SIZE as usize];
        for index in 1..512 {
            let entry = (index as u64 * PAGE_SIZE) | 0x7;
            expected[index * 8..index * 8 + 8].copy_from_slice(&entry.to_le_bytes());
        }
        assert_eq!(actual, expected);
        for (directory_index, address) in PAGE_DIRECTORY_ADDRESSES.into_iter().enumerate() {
            for index in 0..512 {
                let ordinal = directory_index * 512 + index;
                let expected = if ordinal == 0 {
                    0x7
                } else {
                    (ordinal as u64 * LARGE_PAGE_SIZE) | 0x87
                };
                assert_eq!(
                    read_u64(&memory, address + index as u64 * 8).unwrap(),
                    expected
                );
            }
        }
    }

    #[test]
    fn page_zero_table_preserves_neighbor_bootstrap_bytes() {
        let mut memory = GuestMemory::new(0, (LARGE_PAGE_SIZE * 2) as usize).unwrap();
        memory
            .write_raw(0, &vec![0xa5; LARGE_PAGE_SIZE as usize])
            .unwrap();
        write_descriptor_tables(&mut memory).unwrap();
        write_vdso(&mut memory).unwrap();
        let mut before = vec![0; LARGE_PAGE_SIZE as usize];
        memory.read_raw(0, &mut before).unwrap();
        write_page_tables(&mut memory).unwrap();
        let mut after = vec![0; LARGE_PAGE_SIZE as usize];
        memory.read_raw(0, &mut after).unwrap();
        for address in (PAGE_SIZE..LARGE_PAGE_SIZE).step_by(PAGE_SIZE as usize) {
            if address == PML4_ADDRESS
                || address == PDPT_ADDRESS
                || address == PAGE_DIRECTORY_ADDRESSES[0]
            {
                continue;
            }
            let start = address as usize;
            let end = start + PAGE_SIZE as usize;
            assert_eq!(&after[start..end], &before[start..end], "page {address:#x}");
        }
        assert_eq!(read_u64(&memory, 0).unwrap(), 0);
        assert_eq!(
            read_u64(&memory, PAGE_SIZE - 8).unwrap(),
            (511 * PAGE_SIZE) | 0x7
        );
    }

    /// The guest's vDSO page holds the canonical image every backend maps.
    #[test]
    fn the_guest_vdso_is_the_canonical_vdso() {
        let mut memory = GuestMemory::new(0, (VDSO_ADDRESS + PAGE_SIZE) as usize).unwrap();
        write_vdso(&mut memory).unwrap();
        let expected = reverie::vdso::canonical_vdso_image();
        let mut image = vec![0; expected.len()];
        memory.read_raw(VDSO_ADDRESS, &mut image).unwrap();
        assert_eq!(image, expected);
    }

    #[test]
    fn exception_halt_identifies_fault_vector_without_clobbering_registers() {
        let invalid_opcode_rip = EXCEPTION_STUB_ADDRESS + 6 * EXCEPTION_STUB_STRIDE + 1;
        assert_eq!(exception_from_halt(invalid_opcode_rip), Some(6));

        let page_fault_rip = EXCEPTION_STUB_ADDRESS + 14 * EXCEPTION_STUB_STRIDE + 1;
        assert_eq!(exception_from_halt(page_fault_rip), Some(14));
        assert_eq!(exception_from_halt(0x1234), None);
        assert_eq!(exception_stub(), [0xf4]);
    }
}

#[cfg(test)]
mod initial_register_tests {
    use super::*;

    /// Linux zeroes every general-purpose register except `rsp` when it starts a
    /// process. A guest that begins in any other state is in a state Linux never
    /// produces, and it disagrees with the ptrace backend, which observes the
    /// kernel's own register setup.
    ///
    /// This previously regressed specifically on `rbp`, which was seeded with the
    /// stack pointer. Measured against the ptrace backend on the same static
    /// guest, that made `rbp` read as the stack pointer under KVM and 0 under
    /// ptrace at `_start`; every other general-purpose register already agreed.
    #[test]
    fn initial_registers_match_the_linux_process_entry_abi() {
        let entry_point = 0x40_1000;
        let stack_pointer = 0x3fff_c520;
        let regs = initial_guest_registers(entry_point, stack_pointer);

        assert_eq!(regs.rip, entry_point, "rip must be the ELF entry point");
        assert_eq!(regs.rsp, stack_pointer, "rsp must be the initial stack");
        assert_eq!(
            regs.rflags, 0x202,
            "rflags must have the reserved bit and interrupt-enable bit set",
        );

        // Name every remaining general-purpose register explicitly rather than
        // trusting `..Default::default()`. Deriving the expectation from the same
        // default that produces the value would make this assertion agree with
        // any future change instead of discriminating against one.
        let zeroed: [(&str, u64); 14] = [
            ("rax", regs.rax),
            ("rbx", regs.rbx),
            ("rcx", regs.rcx),
            ("rdx", regs.rdx),
            ("rsi", regs.rsi),
            ("rdi", regs.rdi),
            ("rbp", regs.rbp),
            ("r8", regs.r8),
            ("r9", regs.r9),
            ("r10", regs.r10),
            ("r11", regs.r11),
            ("r12", regs.r12),
            ("r13", regs.r13),
            ("r14", regs.r14),
        ];
        for (name, value) in zeroed {
            assert_eq!(
                value, 0,
                "{name} must start zeroed to match the Linux process entry ABI",
            );
        }
        assert_eq!(regs.r15, 0, "r15 must start zeroed");
    }
}
