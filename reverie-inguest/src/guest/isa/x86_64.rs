/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
#![cfg(target_arch = "x86_64")]

//! The x86-64 [`Isa`] implementation: the only x86-64 cfg site for
//! the guest runtime's architecture facts.

use core::arch::global_asm;
use std::io;

use super::InstructionCapabilities;
use super::InstructionResult;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use super::Isa;
use crate::guest::event::InstructionEventKind;
use crate::guest::event::InstructionSubscriptions;
use crate::guest::support::SignalInstallGuard;
use crate::guest::support::exit_now;
use crate::trap::frame::FrameError;
use crate::trap::frame::SavedState;
use crate::trap::frame::SignalFrame;
use crate::trap::raw_syscall6;

global_asm!(
    r#"
    .text
    # These instruction sites are reached only after the nested-hook path has
    # temporarily enabled native execution. Keeping them private to that path
    # guarantees they have never been patched when they are first executed.
    .p2align 4
    .global reverie_inguest_native_cpuid
    .hidden reverie_inguest_native_cpuid
    .type reverie_inguest_native_cpuid,@function
reverie_inguest_native_cpuid:
    push rbx
    mov r8, rdx
    mov eax, edi
    mov ecx, esi
    cpuid
    mov dword ptr [r8], eax
    mov dword ptr [r8 + 4], ebx
    mov dword ptr [r8 + 8], ecx
    mov dword ptr [r8 + 12], edx
    pop rbx
    ret
    .size reverie_inguest_native_cpuid, .-reverie_inguest_native_cpuid

    .p2align 4
    .global reverie_inguest_native_rdtsc
    .hidden reverie_inguest_native_rdtsc
    .type reverie_inguest_native_rdtsc,@function
reverie_inguest_native_rdtsc:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
    .size reverie_inguest_native_rdtsc, .-reverie_inguest_native_rdtsc

    .p2align 4
    .global reverie_inguest_native_rdtscp
    .hidden reverie_inguest_native_rdtscp
    .type reverie_inguest_native_rdtscp,@function
reverie_inguest_native_rdtscp:
    mov r8, rdi
    rdtscp
    mov dword ptr [r8], ecx
    shl rdx, 32
    or rax, rdx
    ret
    .size reverie_inguest_native_rdtscp, .-reverie_inguest_native_rdtscp
"#
);

unsafe extern "C" {
    fn reverie_inguest_native_cpuid(eax: u32, ecx: u32, result: *mut NativeCpuidResult);
    fn reverie_inguest_native_rdtsc() -> u64;
    fn reverie_inguest_native_rdtscp(aux: *mut u32) -> u64;
}

#[derive(Default)]
#[repr(C)]
struct NativeCpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

fn instruction_control_unavailable(control: &str, result: i64) -> io::Error {
    let error = io::Error::from_raw_os_error((-result) as i32);
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "{control} is unavailable: {}",
            crate::guest::support::describe_io_error(&error)
        ),
    )
}

static SAVE_BYTES: AtomicU32 = AtomicU32::new(512);
static SAVE_MASK: AtomicU64 = AtomicU64::new(0);
static PKRU_OFFSET: AtomicU32 = AtomicU32::new(0);
static CALLBACK_MXCSR: u32 = 0x1f80;

fn configure_save() -> Result<(), &'static str> {
    let features = core::arch::x86_64::__cpuid(1);
    if features.ecx & ((1 << 26) | (1 << 27)) == ((1 << 26) | (1 << 27)) {
        // XCR0 includes every enabled user component, including components
        // unknown to this runtime. Never silently discard a component here.
        let enabled = unsafe { core::arch::x86_64::_xgetbv(0) };
        let state = core::arch::x86_64::__cpuid_count(0xD, 0);
        let supported = u64::from(state.eax) | (u64::from(state.edx) << 32);
        let (mask, bytes) = save_configuration(enabled, supported, state.ebx)?;
        // Choose the PKRU-aware entry before returning from SIGSYS. It must
        // open runtime memory before reading any global or TLS storage.
        let features = core::arch::x86_64::__cpuid_count(7, 0);
        if mask & (1 << 9) != 0 && features.ecx & (1 << 4) != 0 {
            let component = core::arch::x86_64::__cpuid_count(0xD, 9);
            let offset = pkru_offset(component.ebx, component.eax, state.ebx)?;
            PKRU_OFFSET.store(offset, Ordering::Relaxed);
        }
        SAVE_BYTES.store(bytes, Ordering::Relaxed);
        SAVE_MASK.store(mask, Ordering::Relaxed);
    }
    Ok(())
}

fn save_configuration(
    enabled: u64,
    supported: u64,
    bytes: u32,
) -> Result<(u64, u32), &'static str> {
    let bytes = bytes.checked_add(63).ok_or("XSAVE size overflow")? & !63;
    if enabled == 0 || enabled & !supported != 0 || bytes < 576 || bytes > i32::MAX as u32 {
        return Err("unsupported XSAVE configuration");
    }
    Ok((enabled, bytes))
}

fn pkru_offset(offset: u32, size: u32, bytes: u32) -> Result<u32, &'static str> {
    if size != 8 || offset < 576 || offset.checked_add(size).is_none_or(|end| end > bytes) {
        return Err("unsupported PKRU XSAVE layout");
    }
    Ok(offset)
}

unsafe extern "C" {
    fn fallback_entry();
    static fallback_completion_syscall: u8;
    static fallback_completion_return: u8;
}

global_asm!(
    r#"
    .pushsection .text.reverie_inguest_fallback_entry,"ax",@progbits
    .p2align 4
    .global fallback_entry
    .hidden fallback_entry
    .type fallback_entry,@function
fallback_entry:
    // First genuine sigreturn supplied an owned, aligned stack and open PKRU.
    // The saved guest image retains DF and every FP component independently.
    cld
    fninit
    ldmxcsr [rip + {callback_mxcsr}]
    mov r12, rdi
    call {dispatch}
    call {generation}
    mov rsi, rax
    mov rdx, r12
    mov rdi, {cookie}
    mov eax, {getpid}
    .global fallback_completion_syscall
    .hidden fallback_completion_syscall
fallback_completion_syscall:
    syscall
    .global fallback_completion_return
    .hidden fallback_completion_return
fallback_completion_return:
    // A correct completion resumes the saved guest, never this continuation.
    ud2
    .size fallback_entry, .-fallback_entry
    .popsection
"#,
    dispatch = sym crate::guest::continuation::dispatch,
    generation = sym crate::guest::continuation::completion_generation,
    callback_mxcsr = sym CALLBACK_MXCSR,
    cookie = const super::COMPLETION_COOKIE,
    getpid = const libc::SYS_getpid,
);

/// The guest's general-purpose registers at a hooked or continued
/// instruction, saved by the trampoline or continuation that entered
/// the runtime. Its layout is fixed (176 bytes): it is the same block
/// LiteInst's trampolines (liteinst's `HookContext`) and the fallback
/// continuation save, and the runtime reads and writes it through a
/// pointer.
#[repr(C)]
#[derive(Debug, Default)]
pub struct RegisterContext {
    /// Address of the displaced (hooked or continued) instruction.
    pub instruction_pointer: u64,
    /// Application RSP at that instruction.
    pub stack_pointer: u64,
    /// Saved R15.
    pub r15: u64,
    /// Saved R14.
    pub r14: u64,
    /// Saved R13.
    pub r13: u64,
    /// Saved R12.
    pub r12: u64,
    /// Saved R11.
    pub r11: u64,
    /// Saved R10.
    pub r10: u64,
    /// Saved R9.
    pub r9: u64,
    /// Saved R8.
    pub r8: u64,
    /// Saved RDI.
    pub rdi: u64,
    /// Saved RSI.
    pub rsi: u64,
    /// Saved RBP.
    pub rbp: u64,
    /// Saved RBX.
    pub rbx: u64,
    /// Saved RDX.
    pub rdx: u64,
    /// Saved RCX.
    pub rcx: u64,
    /// Saved RAX.
    pub rax: u64,
    /// Saved RFLAGS.
    pub rflags: u64,
    /// The saver's descriptor of the saved extended (FPU/vector)
    /// state; opaque here and never written. All zeros means no saved
    /// state (the trampolines' "unavailable" descriptor), which is
    /// what [`Default`] gives.
    saved_extended_state: [u64; 4],
}

impl RegisterContext {
    /// Whether the context carries no saved extended state, as one
    /// built by the fallback continuation (or [`Default`]) does.
    pub fn extended_state_unavailable(&self) -> bool {
        self.saved_extended_state == [0; 4]
    }
}

const _: () = {
    assert!(core::mem::size_of::<RegisterContext>() == 176);
    assert!(core::mem::align_of::<RegisterContext>() == 8);
    assert!(core::mem::offset_of!(RegisterContext, r11) == 48);
    assert!(core::mem::offset_of!(RegisterContext, rflags) == 136);
};

/// The x86-64 instruction-set architecture marker.
#[derive(Clone, Copy, Debug, Default)]
pub struct X86_64;

impl Isa for X86_64 {
    type RegisterContext = RegisterContext;
    type SavedState = SavedState;
    type RestartSnapshot = (u64, u64, u64);

    const SYSCALL_LEN: u64 = 2;
    const SYSCALL_INSN: &'static [u8] = &[0x0f, 0x05];

    fn syscall_number(context: &RegisterContext) -> i64 {
        context.rax as i64
    }

    fn syscall_args(context: &RegisterContext) -> [u64; 6] {
        [
            context.rdi,
            context.rsi,
            context.rdx,
            context.r10,
            context.r8,
            context.r9,
        ]
    }

    fn finish_syscall(context: &mut RegisterContext, result: i64) {
        context.rax = result as u64;
        // The hardware `syscall` instruction leaves the return
        // address in RCX and RFLAGS in R11; a dispatched context
        // resumes with exactly those values.
        context.rcx = context
            .instruction_pointer
            .saturating_add(Self::SYSCALL_LEN);
        context.r11 = context.rflags;
    }

    fn instruction_pointer(context: &RegisterContext) -> u64 {
        context.instruction_pointer
    }

    fn set_instruction_pointer(context: &mut RegisterContext, value: u64) {
        context.instruction_pointer = value;
    }

    fn stack_pointer(context: &RegisterContext) -> u64 {
        context.stack_pointer
    }

    fn context_from_saved(saved: &SavedState, instruction: u64) -> RegisterContext {
        let r = &saved.registers;
        let context = RegisterContext {
            instruction_pointer: instruction,
            stack_pointer: r[libc::REG_RSP as usize] as u64,
            rax: r[libc::REG_RAX as usize] as u64,
            rbx: r[libc::REG_RBX as usize] as u64,
            rcx: r[libc::REG_RCX as usize] as u64,
            rdx: r[libc::REG_RDX as usize] as u64,
            rsi: r[libc::REG_RSI as usize] as u64,
            rdi: r[libc::REG_RDI as usize] as u64,
            rbp: r[libc::REG_RBP as usize] as u64,
            r8: r[libc::REG_R8 as usize] as u64,
            r9: r[libc::REG_R9 as usize] as u64,
            r10: r[libc::REG_R10 as usize] as u64,
            r11: r[libc::REG_R11 as usize] as u64,
            r12: r[libc::REG_R12 as usize] as u64,
            r13: r[libc::REG_R13 as usize] as u64,
            r14: r[libc::REG_R14 as usize] as u64,
            r15: r[libc::REG_R15 as usize] as u64,
            rflags: r[libc::REG_EFL as usize] as u64,
            ..RegisterContext::default()
        };
        debug_assert!(context.extended_state_unavailable());
        context
    }

    fn commit_context(
        saved: &mut SavedState,
        context: &RegisterContext,
        length: u64,
    ) -> Result<(), FrameError> {
        let r = &mut saved.registers;
        for (index, value) in [
            (libc::REG_R8, context.r8),
            (libc::REG_R9, context.r9),
            (libc::REG_R10, context.r10),
            (libc::REG_R11, context.r11),
            (libc::REG_R12, context.r12),
            (libc::REG_R13, context.r13),
            (libc::REG_R14, context.r14),
            (libc::REG_R15, context.r15),
            (libc::REG_RDI, context.rdi),
            (libc::REG_RSI, context.rsi),
            (libc::REG_RBP, context.rbp),
            (libc::REG_RBX, context.rbx),
            (libc::REG_RDX, context.rdx),
            (libc::REG_RAX, context.rax),
            (libc::REG_RCX, context.rcx),
            (libc::REG_RSP, context.stack_pointer),
            (libc::REG_EFL, context.rflags),
        ] {
            r[index as usize] = value as i64;
        }
        r[libc::REG_RIP as usize] = context
            .instruction_pointer
            .checked_add(length)
            .ok_or(FrameError)? as i64;
        Ok(())
    }

    fn restart_snapshot(context: &RegisterContext) -> (u64, u64, u64) {
        // The registers syscall dispatch writes (see finish_syscall):
        // the number/result and the two hardware clobbers.
        (context.rax, context.rcx, context.r11)
    }

    fn restore_restart_snapshot(context: &mut RegisterContext, snapshot: (u64, u64, u64)) {
        (context.rax, context.rcx, context.r11) = snapshot;
    }

    fn user_regs_from_context(context: &RegisterContext) -> libc::user_regs_struct {
        // SAFETY: user_regs_struct is plain integers; zero is valid.
        let mut regs = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
        regs.r15 = context.r15;
        regs.r14 = context.r14;
        regs.r13 = context.r13;
        regs.r12 = context.r12;
        regs.rbp = context.rbp;
        regs.rbx = context.rbx;
        regs.r11 = context.r11;
        regs.r10 = context.r10;
        regs.r9 = context.r9;
        regs.r8 = context.r8;
        regs.rax = context.rax;
        regs.rcx = context.rcx;
        regs.rdx = context.rdx;
        regs.rsi = context.rsi;
        regs.rdi = context.rdi;
        regs.orig_rax = context.rax;
        regs.rip = context.instruction_pointer;
        regs.rsp = context.stack_pointer;
        regs.eflags = context.rflags;
        regs
    }

    fn user_regs_from_event(
        number: i64,
        args: [u64; 6],
        instruction_pointer: u64,
    ) -> libc::user_regs_struct {
        // SAFETY: user_regs_struct is plain integers; zero is valid.
        let mut regs = unsafe { core::mem::zeroed::<libc::user_regs_struct>() };
        regs.rax = number as u64;
        regs.orig_rax = number as u64;
        regs.rdi = args[0];
        regs.rsi = args[1];
        regs.rdx = args[2];
        regs.r10 = args[3];
        regs.r8 = args[4];
        regs.r9 = args[5];
        regs.rip = instruction_pointer;
        regs
    }

    fn event_from_user_regs(regs: &libc::user_regs_struct) -> (i64, [u64; 6]) {
        (
            regs.rax as i64,
            [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9],
        )
    }

    fn apply_user_regs(context: &mut RegisterContext, regs: &libc::user_regs_struct) {
        context.r15 = regs.r15;
        context.r14 = regs.r14;
        context.r13 = regs.r13;
        context.r12 = regs.r12;
        context.rbp = regs.rbp;
        context.rbx = regs.rbx;
        context.r11 = regs.r11;
        context.r10 = regs.r10;
        context.r9 = regs.r9;
        context.r8 = regs.r8;
        context.rax = regs.rax;
        context.rcx = regs.rcx;
        context.rdx = regs.rdx;
        context.rsi = regs.rsi;
        context.rdi = regs.rdi;
        context.stack_pointer = regs.rsp;
        context.rflags = regs.eflags;
    }

    fn configure_saved_state() -> Result<(), &'static str> {
        configure_save()
    }

    fn saved_instruction_pointer(saved: &SavedState) -> u64 {
        saved.registers[libc::REG_RIP as usize] as u64
    }

    fn frame_pc(frame: &SignalFrame<'_>) -> u64 {
        frame.register(libc::REG_RIP as usize) as u64
    }

    fn prepare_frame_for_entry(
        frame: &mut SignalFrame<'_>,
        stack_top: usize,
        owner: usize,
        saved: &SavedState,
    ) -> Result<(), FrameError> {
        frame.set_register(libc::REG_RSP as usize, (stack_top & !15) as i64);
        frame.set_register(libc::REG_RDI as usize, owner as i64);
        // The ABI requires DF clear in ordinary Rust code; the saved guest
        // image retains its own flags independently of this callback frame.
        frame.set_register(
            libc::REG_EFL as usize,
            frame.register(libc::REG_EFL as usize) & !(1 << 10),
        );
        frame.set_pkru(saved.pkru().map(|_| 0))
    }

    fn fallback_entry() -> u64 {
        fallback_entry as *const () as u64
    }

    fn completion_syscall_address() -> u64 {
        core::ptr::addr_of!(fallback_completion_syscall) as usize as u64
    }

    fn completion_return_address() -> u64 {
        core::ptr::addr_of!(fallback_completion_return) as usize as u64
    }

    fn validate_completion_frame(frame: &SignalFrame<'_>, generation: u64, owner: usize) -> bool {
        let instruction = Self::completion_syscall_address() as usize;
        instruction.checked_add(Self::SYSCALL_LEN as usize)
            == Some(Self::completion_return_address() as usize)
            && unsafe {
                core::slice::from_raw_parts(instruction as *const u8, Self::SYSCALL_INSN.len())
            } == Self::SYSCALL_INSN
            && frame.register(libc::REG_RAX as usize) == libc::SYS_getpid
            && frame.register(libc::REG_RDI as usize) as u64 == super::COMPLETION_COOKIE
            && frame.register(libc::REG_RSI as usize) as u64 == generation
            && frame.register(libc::REG_RDX as usize) as usize == owner
    }

    fn fault_stack_pointer(context: &libc::ucontext_t) -> u64 {
        context.uc_mcontext.gregs[libc::REG_RSP as usize] as u64
    }

    fn instruction_capabilities() -> InstructionCapabilities {
        InstructionCapabilities {
            cpuid: true,
            rdtsc: true,
        }
    }

    fn admit_instruction_subscriptions(subscriptions: InstructionSubscriptions) -> io::Result<()> {
        if !subscriptions.cpuid && !subscriptions.rdtsc {
            return Ok(());
        }

        // The exact setter probes temporarily change this thread's
        // instruction controls. Keep inherited asynchronous handlers
        // from running application CPUID/RDTSC during that bounded
        // window, and restore the caller's exact signal mask on
        // every return path.
        #[cfg(feature = "exec-private-init")]
        let all_signals = if crate::guest::exec_private::active() {
            !(1_u64 << (libc::SIGSYS - 1))
        } else {
            u64::MAX
        };
        #[cfg(not(feature = "exec-private-init"))]
        let all_signals = u64::MAX;
        let mut previous_mask = 0;
        let masked = unsafe {
            raw_syscall6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_SETMASK as u64,
                    (&raw const all_signals) as u64,
                    (&raw mut previous_mask) as u64,
                    core::mem::size_of::<u64>() as u64,
                    0,
                    0,
                ],
            )
        };
        if masked != 0 {
            return Err(io::Error::from_raw_os_error((-masked) as i32));
        }
        let _signal_mask = SignalInstallGuard::restoring(previous_mask);

        if subscriptions.cpuid {
            const ARCH_GET_CPUID: u64 = 0x1011;
            const ARCH_SET_CPUID: u64 = 0x1012;
            let previous =
                unsafe { raw_syscall6(libc::SYS_arch_prctl, [ARCH_GET_CPUID, 0, 0, 0, 0, 0]) };
            if previous < 0 {
                return Err(instruction_control_unavailable("CPUID faulting", previous));
            }
            let result =
                unsafe { raw_syscall6(libc::SYS_arch_prctl, [ARCH_SET_CPUID, 0, 0, 0, 0, 0]) };
            if result != 0 {
                return Err(instruction_control_unavailable("CPUID faulting", result));
            }
            let restored = unsafe {
                raw_syscall6(
                    libc::SYS_arch_prctl,
                    [ARCH_SET_CPUID, previous as u64, 0, 0, 0, 0],
                )
            };
            if restored != 0 {
                unsafe { exit_now(126) };
            }
        }
        if subscriptions.rdtsc {
            let mut previous = 0;
            let result = unsafe {
                raw_syscall6(
                    libc::SYS_prctl,
                    [
                        libc::PR_GET_TSC as u64,
                        (&raw mut previous) as u64,
                        0,
                        0,
                        0,
                        0,
                    ],
                )
            };
            if result != 0 {
                return Err(instruction_control_unavailable("TSC faulting", result));
            }
            let result = unsafe {
                raw_syscall6(
                    libc::SYS_prctl,
                    [
                        libc::PR_SET_TSC as u64,
                        libc::PR_TSC_SIGSEGV as u64,
                        0,
                        0,
                        0,
                        0,
                    ],
                )
            };
            if result != 0 {
                return Err(instruction_control_unavailable("TSC faulting", result));
            }
            let restored = unsafe {
                raw_syscall6(
                    libc::SYS_prctl,
                    [libc::PR_SET_TSC as u64, previous as u64, 0, 0, 0, 0],
                )
            };
            if restored != 0 {
                unsafe { exit_now(126) };
            }
        }
        Ok(())
    }

    fn decode_instruction(bytes: &[u8]) -> Option<(InstructionEventKind, &'static [u8])> {
        match bytes {
            [0x0f, 0xa2, ..] => Some((InstructionEventKind::Cpuid, &[0x0f, 0xa2])),
            [0x0f, 0x31, ..] => Some((InstructionEventKind::Rdtsc, &[0x0f, 0x31])),
            [0x0f, 0x01, 0xf9, ..] => Some((InstructionEventKind::Rdtscp, &[0x0f, 0x01, 0xf9])),
            _ => None,
        }
    }

    fn enable_instruction_faulting(subscriptions: InstructionSubscriptions) -> io::Result<()> {
        if subscriptions.cpuid {
            const ARCH_SET_CPUID: u64 = 0x1012;
            let result =
                unsafe { raw_syscall6(libc::SYS_arch_prctl, [ARCH_SET_CPUID, 0, 0, 0, 0, 0]) };
            if result != 0 {
                return Err(io::Error::from_raw_os_error((-result) as i32));
            }
        }
        if subscriptions.rdtsc {
            let result = unsafe {
                raw_syscall6(
                    libc::SYS_prctl,
                    [
                        libc::PR_SET_TSC as u64,
                        libc::PR_TSC_SIGSEGV as u64,
                        0,
                        0,
                        0,
                        0,
                    ],
                )
            };
            if result != 0 {
                return Err(io::Error::from_raw_os_error((-result) as i32));
            }
        }
        Ok(())
    }

    unsafe fn set_instruction_native(kind: InstructionEventKind, enabled: bool) -> io::Result<()> {
        let result = match kind {
            InstructionEventKind::Cpuid => unsafe {
                const ARCH_SET_CPUID: u64 = 0x1012;
                raw_syscall6(
                    libc::SYS_arch_prctl,
                    [ARCH_SET_CPUID, u64::from(enabled), 0, 0, 0, 0],
                )
            },
            InstructionEventKind::Rdtsc | InstructionEventKind::Rdtscp => unsafe {
                raw_syscall6(
                    libc::SYS_prctl,
                    [
                        libc::PR_SET_TSC as u64,
                        if enabled {
                            libc::PR_TSC_ENABLE as u64
                        } else {
                            libc::PR_TSC_SIGSEGV as u64
                        },
                        0,
                        0,
                        0,
                        0,
                    ],
                )
            },
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error((-result) as i32))
        }
    }

    unsafe fn execute_native_instruction(
        kind: InstructionEventKind,
        context: &mut RegisterContext,
    ) {
        match kind {
            InstructionEventKind::Cpuid => {
                let mut result = NativeCpuidResult::default();
                unsafe {
                    reverie_inguest_native_cpuid(
                        context.rax as u32,
                        context.rcx as u32,
                        &mut result,
                    )
                };
                context.rax = u64::from(result.eax);
                context.rbx = u64::from(result.ebx);
                context.rcx = u64::from(result.ecx);
                context.rdx = u64::from(result.edx);
            }
            InstructionEventKind::Rdtsc => {
                let value = unsafe { reverie_inguest_native_rdtsc() };
                context.rax = value as u32 as u64;
                context.rdx = value >> 32;
            }
            InstructionEventKind::Rdtscp => {
                let mut aux = 0;
                let value = unsafe { reverie_inguest_native_rdtscp(&mut aux) };
                context.rax = value as u32 as u64;
                context.rdx = value >> 32;
                context.rcx = u64::from(aux);
            }
        }
    }

    unsafe fn execute_native_fault_instruction(
        kind: InstructionEventKind,
        context: &mut libc::ucontext_t,
        instruction_len: usize,
    ) {
        let registers = &mut context.uc_mcontext.gregs;
        match kind {
            InstructionEventKind::Cpuid => {
                let mut result = NativeCpuidResult::default();
                unsafe {
                    reverie_inguest_native_cpuid(
                        registers[libc::REG_RAX as usize] as u32,
                        registers[libc::REG_RCX as usize] as u32,
                        &mut result,
                    )
                };
                registers[libc::REG_RAX as usize] = i64::from(result.eax);
                registers[libc::REG_RBX as usize] = i64::from(result.ebx);
                registers[libc::REG_RCX as usize] = i64::from(result.ecx);
                registers[libc::REG_RDX as usize] = i64::from(result.edx);
            }
            InstructionEventKind::Rdtsc => {
                let value = unsafe { reverie_inguest_native_rdtsc() };
                registers[libc::REG_RAX as usize] = i64::from(value as u32);
                registers[libc::REG_RDX as usize] = (value >> 32) as i64;
            }
            InstructionEventKind::Rdtscp => {
                let mut aux = 0;
                let value = unsafe { reverie_inguest_native_rdtscp(&mut aux) };
                registers[libc::REG_RAX as usize] = i64::from(value as u32);
                registers[libc::REG_RDX as usize] = (value >> 32) as i64;
                registers[libc::REG_RCX as usize] = i64::from(aux);
            }
        }
        registers[libc::REG_RIP as usize] =
            registers[libc::REG_RIP as usize].saturating_add(instruction_len as i64);
    }

    fn fault_instruction_pointer(context: &libc::ucontext_t) -> u64 {
        context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64
    }

    fn set_fault_instruction_pointer(context: &mut libc::ucontext_t, value: u64) {
        context.uc_mcontext.gregs[libc::REG_RIP as usize] = value as i64;
    }

    fn set_frame_resume(frame: &mut SignalFrame<'_>, entry: u64) {
        frame.set_register(libc::REG_RIP as usize, entry as i64);
    }

    fn cpuid_inputs(context: &RegisterContext) -> (u32, u32) {
        (context.rax as u32, context.rcx as u32)
    }

    fn apply_instruction_result(
        context: &mut RegisterContext,
        _kind: InstructionEventKind,
        result: InstructionResult,
    ) {
        match result {
            InstructionResult::Cpuid { eax, ebx, ecx, edx } => {
                context.rax = u64::from(eax);
                context.rbx = u64::from(ebx);
                context.rcx = u64::from(ecx);
                context.rdx = u64::from(edx);
            }
            InstructionResult::Tsc { value, aux } => {
                context.rax = value as u32 as u64;
                context.rdx = value.checked_shr(32).unwrap_or(0);
                if let Some(aux) = aux {
                    context.rcx = u64::from(aux);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesized_context_preserves_registers_and_has_no_extended_state() {
        let mut saved = SavedState::new().unwrap();
        for (index, register) in saved.registers.iter_mut().enumerate() {
            *register = 0x1000 + index as i64;
        }

        let context = X86_64::context_from_saved(&saved, 0xfeed_face_cafe_beef);
        assert_eq!(context.instruction_pointer, 0xfeed_face_cafe_beef);
        for (index, actual) in [
            (libc::REG_RSP, context.stack_pointer),
            (libc::REG_RAX, context.rax),
            (libc::REG_RBX, context.rbx),
            (libc::REG_RCX, context.rcx),
            (libc::REG_RDX, context.rdx),
            (libc::REG_RSI, context.rsi),
            (libc::REG_RDI, context.rdi),
            (libc::REG_RBP, context.rbp),
            (libc::REG_R8, context.r8),
            (libc::REG_R9, context.r9),
            (libc::REG_R10, context.r10),
            (libc::REG_R11, context.r11),
            (libc::REG_R12, context.r12),
            (libc::REG_R13, context.r13),
            (libc::REG_R14, context.r14),
            (libc::REG_R15, context.r15),
            (libc::REG_EFL, context.rflags),
        ] {
            assert_eq!(actual, saved.registers[index as usize] as u64);
        }
        assert!(context.extended_state_unavailable());
    }

    #[test]
    fn every_enabled_user_component_is_saved_without_a_fixed_mask() {
        // Include MPX, AMX, and a future high component bit: CPU-provided
        // layout and XCR0, rather than an instruction-set list, own the mask.
        let enabled = 0x2ff | (3 << 17) | (1 << 40);
        assert_eq!(
            save_configuration(enabled, enabled, 11_009),
            Ok((enabled, 11_072))
        );
        assert!(save_configuration(enabled, 0x2e7, 11_009).is_err());
        assert!(save_configuration(0, 0, 576).is_err());
        assert!(save_configuration(3, 3, 512).is_err());
        assert!(save_configuration(3, 3, u32::MAX).is_err());
    }

    #[test]
    fn pkru_layout_must_fit_the_standard_save_area() {
        assert_eq!(pkru_offset(2688, 8, 2696), Ok(2688));
        assert!(pkru_offset(2688, 8, 2695).is_err());
        assert!(pkru_offset(512, 8, 2696).is_err());
        assert!(pkru_offset(2688, 4, 2696).is_err());
        assert!(pkru_offset(u32::MAX - 3, 8, u32::MAX).is_err());
    }
}
