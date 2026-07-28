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
use crate::syscall::RESULT_WORD;
use crate::syscall::RETURN_FLAGS_WORD;
use crate::syscall::RETURN_RIP_WORD;
use crate::syscall::SAVED_RBX_WORD;

const PAGE_SIZE: u64 = 4096;
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const PAGE_DIRECTORY_SPAN: u64 = 1024 * 1024 * 1024;
const PAGE_DIRECTORY_ADDRESSES: [u64; 3] = [0x4000, 0x9000, 0xe000];
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
// Includes the 0xe000..0xf000 third page directory and 160 private
// trampoline/frame pairs used by concurrent KVM guest threads.
// AUTONOMOUS-BOT-IMPLEMENTED: Reserve transport slots for savevm worker pools.
// TODO-HUMAN-REVIEW(PR-173): Review the bounded per-thread transport layout.
pub(crate) const THREAD_SYSCALL_AREA_START: u64 = 0xf000;
pub(crate) const THREAD_SYSCALL_AREA_STRIDE: u64 = 2 * PAGE_SIZE;
pub(crate) const MAX_GUEST_THREADS: u64 = 160;
pub(crate) const BOOT_RESERVED_END: u64 =
    THREAD_SYSCALL_AREA_START + THREAD_SYSCALL_AREA_STRIDE * MAX_GUEST_THREADS;
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

    let star = (u64::from(KERNEL_DATA_SELECTOR) << 48) | (u64::from(KERNEL_CODE_SELECTOR) << 32);
    let entries = [
        kvm_msr_entry {
            index: MSR_STAR,
            data: star,
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

    let regs = kvm_bindings::kvm_regs {
        rip: entry_point,
        rsp: stack_pointer,
        rbp: stack_pointer,
        rflags: 2,
        ..Default::default()
    };
    vcpu.set_regs(&regs)?;
    Ok(())
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

// TODO-HUMAN-REVIEW(PR-172): Review syscall-frame selection for concurrent vCPUs.
pub(crate) fn configure_process_syscall_return(
    memory: &GuestMemory,
    vcpu: &VcpuFd,
    syscall_frame_address: u64,
    result: i64,
    stack_pointer: Option<u64>,
) -> Result<()> {
    configure_user_segments(vcpu)?;

    let return_rip = read_u64(
        memory,
        frame_word_address_u64(syscall_frame_address, RETURN_RIP_WORD),
    )?;
    let return_flags = read_u64(
        memory,
        frame_word_address_u64(syscall_frame_address, RETURN_FLAGS_WORD),
    )?;
    let mut regs = vcpu.get_regs()?;
    regs.rax = result as u64;
    regs.rdi = read_u64(memory, frame_word_address_u64(syscall_frame_address, 1))?;
    regs.rsi = read_u64(memory, frame_word_address_u64(syscall_frame_address, 2))?;
    regs.rdx = read_u64(memory, frame_word_address_u64(syscall_frame_address, 3))?;
    regs.r10 = read_u64(memory, frame_word_address_u64(syscall_frame_address, 4))?;
    regs.r8 = read_u64(memory, frame_word_address_u64(syscall_frame_address, 5))?;
    regs.r9 = read_u64(memory, frame_word_address_u64(syscall_frame_address, 6))?;
    regs.rbx = read_u64(
        memory,
        frame_word_address_u64(syscall_frame_address, SAVED_RBX_WORD),
    )?;
    regs.rcx = return_rip;
    regs.r11 = return_flags;
    regs.rip = return_rip;
    regs.rflags = return_flags;
    if let Some(stack_pointer) = stack_pointer {
        regs.rsp = stack_pointer;
    }
    vcpu.set_regs(&regs)?;
    Ok(())
}

// TODO-HUMAN-REVIEW(PR-172): Review per-thread trampoline park/unpark updates.
pub(crate) fn set_syscall_return_park(
    memory: &mut GuestMemory,
    hypercall_instruction: [u8; 3],
    syscall_trampoline_address: u64,
    syscall_frame_address: u64,
    park: bool,
) -> Result<()> {
    let trampoline = syscall_trampoline(hypercall_instruction, syscall_frame_address);
    let return_offset = trampoline
        .windows(hypercall_instruction.len())
        .position(|window| window == hypercall_instruction)
        .expect("syscall trampoline must contain its hypercall")
        + hypercall_instruction.len();
    let byte = if park {
        0xf4
    } else {
        trampoline[return_offset]
    };
    memory.write_raw(syscall_trampoline_address + return_offset as u64, &[byte])
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
                ((first_page + index) * LARGE_PAGE_SIZE) | 0x87,
            )?;
        }
    }
    Ok(())
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
    code.extend_from_slice(&[0x48, 0x0f, 0x07]);
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

    #[test]
    fn trampoline_preserves_syscall_return_state() {
        let code = syscall_trampoline([0x0f, 0x01, 0xc1], SYSCALL_FRAME_ADDRESS);

        assert!(code.windows(3).any(|window| window == [0x0f, 0x01, 0xc1]));
        assert_eq!(&code[code.len() - 3..], &[0x48, 0x0f, 0x07]);
        assert!(code.len() < THREAD_TSS_OFFSET as usize);
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
