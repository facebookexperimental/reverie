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
use crate::syscall::RESULT_WORD;
use crate::syscall::RETURN_FLAGS_WORD;
use crate::syscall::RETURN_RIP_WORD;
use crate::syscall::SAVED_RBX_WORD;

const PAGE_SIZE: u64 = 4096;
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
const MAX_IDENTITY_MAP: u64 = 1024 * 1024 * 1024;

const GDT_ADDRESS: u64 = 0x1000;
const PML4_ADDRESS: u64 = 0x2000;
const PDPT_ADDRESS: u64 = 0x3000;
const PDE_ADDRESS: u64 = 0x4000;
pub(crate) const SYSCALL_TRAMPOLINE_ADDRESS: u64 = 0x5000;
pub(crate) const SYSCALL_FRAME_ADDRESS: u64 = 0x6000;
pub(crate) const PROGRAM_HEADERS_ADDRESS: u64 = 0x7000;
const TSS_ADDRESS: u64 = 0x8000;
const IDT_ADDRESS: u64 = 0xa000;
const EXCEPTION_STUB_ADDRESS: u64 = 0xb000;
const EXCEPTION_STACK_BOTTOM: u64 = 0xc000;
const EXCEPTION_STACK_TOP: u64 = 0xd000;
// Includes the 0xd000..0xe000 Tool injection scratch page.
pub(crate) const BOOT_RESERVED_END: u64 = 0xe000;

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
    if memory.guest_base() != 0
        || memory.guest_end() <= BOOT_RESERVED_END
        || memory.guest_end() > MAX_IDENTITY_MAP
    {
        return Err(Error::LongModeMemoryTooSmall);
    }

    write_descriptor_tables(memory)?;
    write_page_tables(memory)?;
    let trampoline = syscall_trampoline(hypercall_instruction);
    memory.write(SYSCALL_TRAMPOLINE_ADDRESS, &trampoline)?;

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
    sregs.tr = tss_segment();

    sregs.cr0 |= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_PG;
    sregs.cr0 &= !(CR0_EM | CR0_TS);
    sregs.cr3 = PML4_ADDRESS;
    sregs.cr4 |= CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT;
    sregs.efer |= EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
    vcpu.set_sregs(&sregs)?;

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
            data: SYSCALL_TRAMPOLINE_ADDRESS,
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
    memory.write(GDT_ADDRESS, &bytes)?;
    write_exception_tables(memory)?;
    memory.zero(TSS_ADDRESS, 0x68)?;
    write_u64(memory, TSS_ADDRESS + 4, EXCEPTION_STACK_TOP)?;
    memory.write(TSS_ADDRESS + 0x66, &0x68_u16.to_le_bytes())?;
    memory.zero(EXCEPTION_STACK_BOTTOM, PAGE_SIZE as usize)
}

fn write_exception_tables(memory: &mut GuestMemory) -> Result<()> {
    memory.zero(IDT_ADDRESS, PAGE_SIZE as usize)?;
    memory.zero(EXCEPTION_STUB_ADDRESS, PAGE_SIZE as usize)?;

    for vector in 0..EXCEPTION_VECTOR_COUNT {
        let handler = EXCEPTION_STUB_ADDRESS + vector as u64 * EXCEPTION_STUB_STRIDE;
        let gate = idt_gate(handler);
        memory.write(IDT_ADDRESS + (vector * IDT_ENTRY_SIZE) as u64, &gate)?;
        let stub = exception_stub(vector as u8);
        memory.write(handler, &stub)?;
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

fn exception_stub(vector: u8) -> Vec<u8> {
    let mut code = Vec::with_capacity(EXCEPTION_STUB_STRIDE as usize);
    code.push(0xb8);
    code.extend_from_slice(&u32::from(vector).to_le_bytes());
    if exception_pushes_error_code(vector) {
        code.extend_from_slice(&[0x48, 0x8b, 0x5c, 0x24, 0x08]);
    } else {
        code.extend_from_slice(&[0x48, 0x8b, 0x1c, 0x24]);
    }
    code.push(0xf4);
    code
}

fn exception_pushes_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

pub(crate) fn exception_from_halt(
    rip: u64,
    vector_register: u64,
    faulting_instruction_pointer: u64,
) -> Option<(u8, u64)> {
    let vector = u8::try_from(vector_register).ok()?;
    if usize::from(vector) >= EXCEPTION_VECTOR_COUNT {
        return None;
    }
    let stub_length = if exception_pushes_error_code(vector) {
        11
    } else {
        10
    };
    let expected_rip =
        EXCEPTION_STUB_ADDRESS + u64::from(vector) * EXCEPTION_STUB_STRIDE + stub_length;
    (rip == expected_rip).then_some((vector, faulting_instruction_pointer))
}

fn write_page_tables(memory: &mut GuestMemory) -> Result<()> {
    memory.zero(PML4_ADDRESS, PAGE_SIZE as usize)?;
    memory.zero(PDPT_ADDRESS, PAGE_SIZE as usize)?;
    memory.zero(PDE_ADDRESS, PAGE_SIZE as usize)?;

    write_u64(memory, PML4_ADDRESS, PDPT_ADDRESS | 0x7)?;
    write_u64(memory, PDPT_ADDRESS, PDE_ADDRESS | 0x7)?;

    let mapped_pages = memory.guest_end().div_ceil(LARGE_PAGE_SIZE);
    for index in 0..mapped_pages {
        let entry_address = PDE_ADDRESS + index * std::mem::size_of::<u64>() as u64;
        write_u64(memory, entry_address, (index * LARGE_PAGE_SIZE) | 0x87)?;
    }
    Ok(())
}

fn write_u64(memory: &mut GuestMemory, address: u64, value: u64) -> Result<()> {
    memory.write(address, &value.to_le_bytes())
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

fn tss_segment() -> kvm_segment {
    kvm_segment {
        base: TSS_ADDRESS,
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

fn syscall_trampoline(hypercall_instruction: [u8; 3]) -> Vec<u8> {
    let mut code = Vec::with_capacity(192);

    store_absolute(&mut code, 0x48, 0x04, 0);
    store_absolute(&mut code, 0x48, 0x3c, 1);
    store_absolute(&mut code, 0x48, 0x34, 2);
    store_absolute(&mut code, 0x48, 0x14, 3);
    store_absolute(&mut code, 0x4c, 0x14, 4);
    store_absolute(&mut code, 0x4c, 0x04, 5);
    store_absolute(&mut code, 0x4c, 0x0c, 6);
    store_absolute(&mut code, 0x48, 0x0c, RETURN_RIP_WORD);
    store_absolute(&mut code, 0x4c, 0x1c, RETURN_FLAGS_WORD);
    store_absolute(&mut code, 0x48, 0x1c, SAVED_RBX_WORD);

    code.extend_from_slice(&[0x48, 0xc7, 0xc0]);
    code.extend_from_slice(&(VMCALL_SYSCALL_TRANSPORT as u32).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xbb]);
    code.extend_from_slice(&SYSCALL_FRAME_ADDRESS.to_le_bytes());
    code.extend_from_slice(&[0x48, 0xc7, 0xc1, 1, 0, 0, 0]);
    code.extend_from_slice(&[0x31, 0xd2, 0x31, 0xf6]);
    code.extend_from_slice(&hypercall_instruction);

    load_absolute(&mut code, 0x48, 0x04, RESULT_WORD);
    load_absolute(&mut code, 0x48, 0x3c, 1);
    load_absolute(&mut code, 0x48, 0x34, 2);
    load_absolute(&mut code, 0x48, 0x14, 3);
    load_absolute(&mut code, 0x4c, 0x14, 4);
    load_absolute(&mut code, 0x4c, 0x04, 5);
    load_absolute(&mut code, 0x4c, 0x0c, 6);
    load_absolute(&mut code, 0x48, 0x0c, RETURN_RIP_WORD);
    load_absolute(&mut code, 0x4c, 0x1c, RETURN_FLAGS_WORD);
    load_absolute(&mut code, 0x48, 0x1c, SAVED_RBX_WORD);
    code.extend_from_slice(&[0x48, 0x0f, 0x07]);
    code
}

fn store_absolute(code: &mut Vec<u8>, rex: u8, register: u8, word: usize) {
    code.extend_from_slice(&[rex, 0x89, register, 0x25]);
    code.extend_from_slice(&frame_word_address(word).to_le_bytes());
}

fn load_absolute(code: &mut Vec<u8>, rex: u8, register: u8, word: usize) {
    code.extend_from_slice(&[rex, 0x8b, register, 0x25]);
    code.extend_from_slice(&frame_word_address(word).to_le_bytes());
}

fn frame_word_address(word: usize) -> u32 {
    u32::try_from(SYSCALL_FRAME_ADDRESS + (word * std::mem::size_of::<u64>()) as u64)
        .expect("syscall frame must fit in an absolute disp32 address")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trampoline_preserves_syscall_return_state() {
        let code = syscall_trampoline([0x0f, 0x01, 0xc1]);

        assert!(code.windows(3).any(|window| window == [0x0f, 0x01, 0xc1]));
        assert_eq!(&code[code.len() - 3..], &[0x48, 0x0f, 0x07]);
        assert!(code.len() < PAGE_SIZE as usize);
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
    fn exception_halt_identifies_fault_vector_and_original_rip() {
        let invalid_opcode_rip = EXCEPTION_STUB_ADDRESS + 6 * EXCEPTION_STUB_STRIDE + 10;
        assert_eq!(
            exception_from_halt(invalid_opcode_rip, 6, 0x20_0042),
            Some((6, 0x20_0042))
        );

        let page_fault_rip = EXCEPTION_STUB_ADDRESS + 14 * EXCEPTION_STUB_STRIDE + 11;
        assert_eq!(
            exception_from_halt(page_fault_rip, 14, 0x20_0080),
            Some((14, 0x20_0080))
        );
        assert_eq!(exception_from_halt(0x1234, 6, 0x20_0042), None);
    }
}
