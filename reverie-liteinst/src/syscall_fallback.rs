/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::arch::global_asm;
use core::cell::Cell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io;
use std::sync::OnceLock;

use liteinst2::trampoline::HookContext;
use liteinst2::trampoline::SavedExtendedStateDescriptor;
use reverie_preload::trap::frame::FrameError;
use reverie_preload::trap::frame::SavedState;
use reverie_preload::trap::frame::SignalFrame;
use reverie_preload::trap::raw_syscall6;

static SAVE_BYTES: AtomicU32 = AtomicU32::new(512);
static SAVE_MASK: AtomicU64 = AtomicU64::new(0);
static PKRU_OFFSET: AtomicU32 = AtomicU32::new(0);
static SAVE_CONFIG: OnceLock<Result<(), &'static str>> = OnceLock::new();
static CALLBACK_MXCSR: u32 = 0x1f80;

const _: () = {
    assert!(core::mem::size_of::<HookContext>() == 176);
    assert!(core::mem::offset_of!(HookContext, r11) == 48);
    assert!(core::mem::offset_of!(HookContext, rflags) == 136);
};

thread_local! {
    static READY: Cell<bool> = const { Cell::new(false) };
    static OWNER: Cell<*mut Continuation> = const { Cell::new(core::ptr::null_mut()) };
    static PENDING: Cell<Option<Pending>> = const { Cell::new(None) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pending {
    instruction: u64,
}

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

const CALLBACK_STACK_BYTES: usize = 8 * 1024 * 1024;
const COMPLETION_COOKIE: u64 = 0x4c49_4641_4c4c_424b;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Idle,
    Captured,
    Running,
    ReadyToReturn,
}

struct CallbackStack {
    mapping: *mut libc::c_void,
    bytes: usize,
    top: usize,
}

impl CallbackStack {
    fn new() -> io::Result<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::other("invalid page size"));
        }
        let page = page as usize;
        let bytes = CALLBACK_STACK_BYTES
            .checked_add(
                page.checked_mul(2)
                    .ok_or_else(|| io::Error::other("stack size overflow"))?,
            )
            .ok_or_else(|| io::Error::other("stack size overflow"))?;
        let mapping = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                bytes,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // mmap supplied a range of `bytes`; compute the usable end without
        // unchecked pointer-sized arithmetic before publishing any owner.
        let top = (mapping as usize).checked_add(bytes - page);
        let stack = Self {
            mapping,
            bytes,
            top: top.unwrap_or(0),
        };
        if top.is_none() {
            return Err(io::Error::other("stack address overflow"));
        }
        if unsafe {
            libc::mprotect(
                mapping.cast::<u8>().add(page).cast(),
                CALLBACK_STACK_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(stack)
    }
}

impl Drop for CallbackStack {
    fn drop(&mut self) {
        // Only unpublished preparation owns a destructor. Published owners
        // are retained through process teardown, never freed on this stack.
        unsafe { libc::munmap(self.mapping, self.bytes) };
    }
}

struct Continuation {
    stack: CallbackStack,
    saved: SavedState,
    context: HookContext,
    owner_tid: i64,
    generation: u64,
    phase: Phase,
    entries: u64,
    callbacks: u64,
    completions: u64,
}

fn current_tid() -> i64 {
    unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) }
}

pub(crate) fn initialize() -> io::Result<()> {
    SAVE_CONFIG
        .get_or_init(configure_save)
        .as_ref()
        .map_err(|error| io::Error::other(*error))?;
    if PENDING.get().is_some() {
        return Err(io::Error::other("a syscall continuation is still active"));
    }
    if OWNER.get().is_null() {
        let saved = SavedState::new()?;
        let stack = CallbackStack::new()?;
        let owner = Box::new(Continuation {
            stack,
            saved,
            // A fallback-created context has no trampoline-owned saved-state
            // image. Default makes that unavailable descriptor explicit.
            context: HookContext::default(),
            owner_tid: current_tid(),
            generation: 0,
            phase: Phase::Idle,
            entries: 0,
            callbacks: 0,
            completions: 0,
        });
        OWNER.set(Box::into_raw(owner));
    }
    READY.set(true);
    Ok(())
}

/// Reserve the existing single activation without overwriting a pending one.
/// Kept separate from frame capture so its reentry contract remains testable.
pub(crate) fn prepare(instruction: u64) -> Option<u64> {
    PENDING.with(|pending| {
        if !READY.get() || pending.get().is_some() {
            return None;
        }
        pending.set(Some(Pending { instruction }));
        Some(fallback_entry as *const () as u64)
    })
}

pub(crate) fn prepare_signal(
    instruction: u64,
    frame: &mut SignalFrame<'_>,
) -> Result<Option<u64>, FrameError> {
    let Some(entry) = prepare(instruction) else {
        return Ok(None);
    };
    let pointer = OWNER.get();
    if pointer.is_null() {
        return Err(FrameError);
    }
    let owner = unsafe { &mut *pointer };
    if owner.phase != Phase::Idle || owner.owner_tid != current_tid() {
        return Err(FrameError);
    }
    owner.generation = owner.generation.checked_add(1).ok_or(FrameError)?;
    frame.capture(&mut owner.saved)?;
    let resume = instruction.checked_add(2).ok_or(FrameError)?;
    if frame.register(libc::REG_RIP as usize) as u64 != resume {
        return Err(FrameError);
    }
    owner.context = context_from_image(&owner.saved, instruction);
    owner.phase = Phase::Captured;
    frame.set_register(libc::REG_RSP as usize, (owner.stack.top & !15) as i64);
    frame.set_register(libc::REG_RDI as usize, pointer as i64);
    frame.set_register(
        libc::REG_EFL as usize,
        frame.register(libc::REG_EFL as usize) & !(1 << 10),
    );
    frame.set_pkru(owner.saved.pkru().map(|_| 0))?;
    owner.entries += 1;
    Ok(Some(entry))
}

fn context_from_image(saved: &SavedState, instruction: u64) -> HookContext {
    let r = &saved.registers;
    let mut context = HookContext::default();
    context.instruction_pointer = instruction;
    context.stack_pointer = r[libc::REG_RSP as usize] as u64;
    context.rax = r[libc::REG_RAX as usize] as u64;
    context.rbx = r[libc::REG_RBX as usize] as u64;
    context.rcx = r[libc::REG_RCX as usize] as u64;
    context.rdx = r[libc::REG_RDX as usize] as u64;
    context.rsi = r[libc::REG_RSI as usize] as u64;
    context.rdi = r[libc::REG_RDI as usize] as u64;
    context.rbp = r[libc::REG_RBP as usize] as u64;
    context.r8 = r[libc::REG_R8 as usize] as u64;
    context.r9 = r[libc::REG_R9 as usize] as u64;
    context.r10 = r[libc::REG_R10 as usize] as u64;
    context.r11 = r[libc::REG_R11 as usize] as u64;
    context.r12 = r[libc::REG_R12 as usize] as u64;
    context.r13 = r[libc::REG_R13 as usize] as u64;
    context.r14 = r[libc::REG_R14 as usize] as u64;
    context.r15 = r[libc::REG_R15 as usize] as u64;
    context.rflags = r[libc::REG_EFL as usize] as u64;
    debug_assert_eq!(
        context.saved_extended_state(),
        SavedExtendedStateDescriptor::UNAVAILABLE
    );
    context
}

fn commit_context(owner: &mut Continuation) -> Result<(), FrameError> {
    let c = &owner.context;
    let r = &mut owner.saved.registers;
    for (index, value) in [
        (libc::REG_R8, c.r8),
        (libc::REG_R9, c.r9),
        (libc::REG_R10, c.r10),
        (libc::REG_R11, c.r11),
        (libc::REG_R12, c.r12),
        (libc::REG_R13, c.r13),
        (libc::REG_R14, c.r14),
        (libc::REG_R15, c.r15),
        (libc::REG_RDI, c.rdi),
        (libc::REG_RSI, c.rsi),
        (libc::REG_RBP, c.rbp),
        (libc::REG_RBX, c.rbx),
        (libc::REG_RDX, c.rdx),
        (libc::REG_RAX, c.rax),
        (libc::REG_RCX, c.rcx),
        (libc::REG_RSP, c.stack_pointer),
        (libc::REG_EFL, c.rflags),
    ] {
        r[index as usize] = value as i64;
    }
    r[libc::REG_RIP as usize] = c.instruction_pointer.checked_add(2).ok_or(FrameError)? as i64;
    Ok(())
}

/// The current handler prefix has already opened runtime permissions before
/// any memory access. Nested operations retain their own interrupted image.
pub(crate) fn enable_nested_runtime_access() {}

/// A raw fork copies the active image and ordinary stack. Rebind only after
/// the real child result, in ordinary context, before child callbacks/return.
pub(crate) fn rebind_fork_child() {
    let pointer = OWNER.get();
    if !pointer.is_null() {
        unsafe {
            (*pointer).owner_tid = current_tid();
            // The entry/callback happened in the parent. The child inherits
            // its active image but physically receives only its completion.
            (*pointer).entries = 0;
            (*pointer).callbacks = 0;
            (*pointer).completions = 0;
        }
    }
}

fn fatal() -> ! {
    unsafe { raw_syscall6(libc::SYS_exit_group, [123, 0, 0, 0, 0, 0]) };
    loop {
        core::hint::spin_loop()
    }
}

unsafe extern "C" fn dispatch(pointer: *mut Continuation) {
    if pointer.is_null() || pointer != OWNER.get() || PENDING.get().is_none() {
        fatal()
    }
    // No reference to the full owner is held across Tool dispatch: child fork
    // completion and nested signals may access separate owner fields.
    if unsafe { (*pointer).phase != Phase::Captured || (*pointer).owner_tid != current_tid() } {
        fatal()
    }
    unsafe {
        (*pointer).phase = Phase::Running;
        (*pointer).callbacks += 1;
    }
    let errno = unsafe { libc::__errno_location() };
    let saved_errno = unsafe { *errno };
    let mut pkru = unsafe { (*pointer).saved.pkru() };
    unsafe {
        crate::runtime::dispatch_fallback_context(
            core::ptr::addr_of_mut!((*pointer).context),
            &mut pkru,
        );
        *errno = saved_errno;
    }
    let owner = unsafe { &mut *pointer };
    if owner.owner_tid != current_tid()
        || owner.saved.set_pkru(pkru).is_err()
        || commit_context(owner).is_err()
    {
        fatal()
    }
    owner.phase = Phase::ReadyToReturn;
}

/// Completion is intercepted before ordinary syscall/site classification.
/// A genuine frame may reuse the same alt-stack address as the consumed first
/// frame; address inequality is not evidence of freshness.
pub(crate) fn complete(frame: &mut SignalFrame<'_>) -> Result<bool, FrameError> {
    let resume = core::ptr::addr_of!(fallback_completion_return) as usize as u64;
    if frame.register(libc::REG_RIP as usize) as u64 != resume {
        return Ok(false);
    }
    let pointer = OWNER.get();
    if pointer.is_null() {
        return Err(FrameError);
    }
    let owner = unsafe { &mut *pointer };
    let instruction = core::ptr::addr_of!(fallback_completion_syscall) as usize;
    if instruction.checked_add(2) != Some(resume as usize)
        || unsafe { core::slice::from_raw_parts(instruction as *const u8, 2) } != [0x0f, 0x05]
        || owner.phase != Phase::ReadyToReturn
        || owner.owner_tid != current_tid()
        || PENDING.get().is_none()
        || frame.register(libc::REG_RAX as usize) != libc::SYS_getpid
        || frame.register(libc::REG_RDI as usize) as u64 != COMPLETION_COOKIE
        || frame.register(libc::REG_RSI as usize) as u64 != owner.generation
        || frame.register(libc::REG_RDX as usize) as usize != pointer as usize
    {
        return Err(FrameError);
    }
    frame.restore(&owner.saved)?;
    owner.completions += 1;
    owner.phase = Phase::Idle;
    PENDING.set(None);
    Ok(true)
}

/// Diagnostic observations for the current thread's owned continuation.
/// Selectors 0/1/2 are actual fallback entry, reached ordinary callback, and
/// prepared genuine completion frame. They are not a kernel-stop census.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_owned_fallback_observation(selector: u32) -> u64 {
    let pointer = OWNER.get();
    if pointer.is_null() {
        return 0;
    }
    unsafe {
        match selector {
            0 => (*pointer).entries,
            1 => (*pointer).callbacks,
            2 => (*pointer).completions,
            _ => 0,
        }
    }
}

/// Check a fixture's actual callback local address against owned stack bounds.
#[unsafe(no_mangle)]
pub extern "C" fn reverie_liteinst_on_owned_fallback_stack(address: usize) -> bool {
    let pointer = OWNER.get();
    if pointer.is_null() {
        return false;
    }
    unsafe {
        let top = (*pointer).stack.top;
        address >= top - CALLBACK_STACK_BYTES && address < top
    }
}

unsafe extern "C" fn completion_generation() -> u64 {
    let pointer = OWNER.get();
    if pointer.is_null() || unsafe { (*pointer).phase != Phase::ReadyToReturn } {
        fatal()
    }
    unsafe { (*pointer).generation }
}

unsafe extern "C" {
    fn fallback_entry();
    static fallback_completion_syscall: u8;
    static fallback_completion_return: u8;
}

global_asm!(
    r#"
    .text
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
"#,
    dispatch = sym dispatch,
    generation = sym completion_generation,
    callback_mxcsr = sym CALLBACK_MXCSR,
    cookie = const COMPLETION_COOKIE,
    getpid = const libc::SYS_getpid,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthesized_context_preserves_registers_and_has_no_extended_state() {
        let mut saved = SavedState::new().unwrap();
        for (index, register) in saved.registers.iter_mut().enumerate() {
            *register = 0x1000 + index as i64;
        }

        let context = context_from_image(&saved, 0xfeed_face_cafe_beef);
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
        assert_eq!(
            context.saved_extended_state(),
            SavedExtendedStateDescriptor::UNAVAILABLE
        );
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

    #[test]
    fn pending_continuation_refuses_reentry_without_overwriting() {
        initialize().unwrap();
        assert!(prepare(0x1000).is_some());
        assert!(prepare(0x2000).is_none());
        assert_eq!(
            PENDING.get(),
            Some(Pending {
                instruction: 0x1000
            })
        );
        assert!(initialize().is_err());
        PENDING.set(None);
        assert!(prepare(0x3000).is_some());
        assert_eq!(
            PENDING.get(),
            Some(Pending {
                instruction: 0x3000
            })
        );
        PENDING.set(None);
    }
}
