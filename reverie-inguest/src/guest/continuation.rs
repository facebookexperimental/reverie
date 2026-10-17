/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The in-guest fallback continuation. A trapped syscall (`SIGSYS`), or a
//! faulting CPUID, RDTSC or RDTSCP (`SIGSEGV`), is captured from its signal
//! frame, and the first `sigreturn` resumes on this thread's owned stack in
//! ordinary context, where the backend runs it through the Tool (see
//! [`ContinuationHandlers`]). A completion `syscall` then restores the
//! captured guest image with the Tool's results. This is the path every call
//! takes when nothing is patched.

use core::arch::global_asm;
use core::cell::Cell;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io;
use std::sync::OnceLock;

use super::context::RegisterContext;
use super::event::InstructionEventKind;
use super::tool_region::StackBacking;
use super::tool_region::StackLease;
use crate::trap::frame::FrameError;
use crate::trap::frame::SavedState;
use crate::trap::frame::SignalFrame;
use crate::trap::raw_syscall6;

static SAVE_BYTES: AtomicU32 = AtomicU32::new(512);
static SAVE_MASK: AtomicU64 = AtomicU64::new(0);
static PKRU_OFFSET: AtomicU32 = AtomicU32::new(0);
static SAVE_CONFIG: OnceLock<Result<(), &'static str>> = OnceLock::new();
static CALLBACK_MXCSR: u32 = 0x1f80;

static HANDLERS: OnceLock<ContinuationHandlers> = OnceLock::new();

/// The backend functions the continuation runs a captured call through, in
/// ordinary context on the continuation's own stack. Registered once per
/// process with [`register_handlers`].
#[derive(Clone, Copy)]
pub struct ContinuationHandlers {
    /// Runs a continued syscall whose registers are in the context. The PKRU
    /// value is the guest's interrupted one; the handler may change it.
    pub syscall: unsafe fn(context: *mut RegisterContext, pkru: &mut Option<u32>),
    /// Runs a continued CPUID, RDTSC or RDTSCP whose registers are in the
    /// context.
    pub instruction: unsafe fn(context: *mut RegisterContext, kind: InstructionEventKind),
}

thread_local! {
    static READY: Cell<bool> = const { Cell::new(false) };
    static OWNER: Cell<*mut Continuation> = const { Cell::new(core::ptr::null_mut()) };
    static PENDING: Cell<Option<Pending>> = const { Cell::new(None) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pending {
    instruction: u64,
    kind: PendingKind,
}

/// What the single per-thread continuation emulates after sigreturn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingKind {
    /// A trapped `syscall` whose `SIGSYS` frame resumes after the instruction.
    Syscall,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(liteinst-late-code-cpuid): Review instruction emulation through the continuation.
    /// A faulting CPUID/RDTSC/RDTSCP with no patchable site, whose kernel
    /// `SIGSEGV` frame still points at the instruction itself.
    Instruction(InstructionEventKind),
}

impl PendingKind {
    /// Bytes from the instruction's address to its saved resume address.
    fn frame_offset(self) -> u64 {
        match self {
            Self::Syscall => 2,
            Self::Instruction(_) => 0,
        }
    }

    /// Bytes the committed guest context advances past the instruction.
    fn length(self) -> u64 {
        match self {
            Self::Syscall => 2,
            Self::Instruction(kind) => kind.encoded_len(),
        }
    }
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
    region: Option<StackLease>,
}

impl CallbackStack {
    fn new(backing: StackBacking) -> io::Result<Self> {
        if let StackBacking::ToolRegion(region) = backing {
            let lease = region.stack(CALLBACK_STACK_BYTES)?;
            return Ok(Self {
                mapping: core::ptr::null_mut(),
                bytes: 0,
                top: lease.top(),
                region: Some(lease),
            });
        }
        let page = usize::try_from(crate::guest::support::page_size()?)
            .map_err(|_| io::Error::other("invalid page size"))?;
        let bytes = CALLBACK_STACK_BYTES
            .checked_add(
                page.checked_mul(2)
                    .ok_or_else(|| io::Error::other("stack size overflow"))?,
            )
            .ok_or_else(|| io::Error::other("stack size overflow"))?;
        // Raw syscalls, not libc's interposable wrappers: this runs inside
        // the guest, where the program or a preloaded library may define them.
        let mapping = crate::guest::support::raw_result(unsafe {
            raw_syscall6(
                libc::SYS_mmap,
                [
                    0,
                    bytes as u64,
                    libc::PROT_NONE as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK) as u64,
                    u64::MAX,
                    0,
                ],
            )
        })? as *mut libc::c_void;
        // mmap supplied a range of `bytes`; compute the usable end without
        // unchecked pointer-sized arithmetic before publishing any owner.
        let top = (mapping as usize).checked_add(bytes - page);
        let stack = Self {
            mapping,
            bytes,
            top: top.unwrap_or(0),
            region: None,
        };
        if top.is_none() {
            return Err(io::Error::other("stack address overflow"));
        }
        crate::guest::support::raw_zero_result(unsafe {
            raw_syscall6(
                libc::SYS_mprotect,
                [
                    mapping as u64 + page as u64,
                    CALLBACK_STACK_BYTES as u64,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    0,
                    0,
                    0,
                ],
            )
        })?;
        Ok(stack)
    }
}

impl Drop for CallbackStack {
    fn drop(&mut self) {
        if self.region.is_some() {
            // The unique unpublished lease performs protection reset/discard.
            // Published owners are retained and never reach this destructor.
            return;
        }
        // Only unpublished preparation owns a destructor. Published owners
        // are retained through process teardown, never freed on this stack.
        unsafe {
            raw_syscall6(
                libc::SYS_munmap,
                [self.mapping as u64, self.bytes as u64, 0, 0, 0, 0],
            )
        };
    }
}

/// Kernel-frame observation bound to one actual running fallback. This does
/// not grant exec authorization or supply watched-birth/target proof.
#[cfg(feature = "exec-native-injection")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeExecResumeReceipt {
    owner: usize,
    tid: i64,
    generation: u64,
    mask: u64,
    number: i64,
    args: [u64; 6],
    instruction: u64,
    pkru: Option<u32>,
}

#[cfg(feature = "exec-native-injection")]
impl NativeExecResumeReceipt {
    /// Exact guest uc_sigmask captured before the first genuine rt_sigreturn.
    pub fn signal_mask(&self) -> u64 {
        self.mask
    }
    /// Actual continuation generation, not a ticket capability.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn recheck(&self, event: &super::event::SyscallEvent) -> bool {
        native_exec_resume_receipt(event).as_ref() == Some(self)
    }
}

/// Observe only the actual running syscall continuation and captured resume
/// mask. No whole-owner/context reference is formed: the Tool already owns a
/// mutable borrow of the disjoint context field for this callback.
#[cfg(feature = "exec-native-injection")]
pub fn native_exec_resume_receipt(
    event: &super::event::SyscallEvent,
) -> Option<NativeExecResumeReceipt> {
    if !matches!(event.dispatch, super::event::SyscallDispatch::Fallback) {
        return None;
    }
    let pointer = OWNER.get();
    if pointer.is_null() {
        return None;
    }
    let pending = PENDING.get()?;
    // Retained storage, exclusively owned by this thread; disjoint fields.
    let receipt = unsafe { (&raw const (*pointer).native_exec_resume).read() }?;
    let phase = unsafe { (&raw const (*pointer).phase).read() };
    let tid = unsafe { (&raw const (*pointer).owner_tid).read() };
    let generation = unsafe { (&raw const (*pointer).generation).read() };
    if phase != Phase::Running
        || tid != current_tid()
        || receipt.tid != tid
        || receipt.owner != pointer as usize
        || receipt.generation != generation
        || pending.kind != PendingKind::Syscall
        || pending.instruction != receipt.instruction
        || event.context != unsafe { (&raw const (*pointer).context) as usize }
        || event.number != receipt.number
        || event.args != receipt.args
        || event.instruction_pointer != receipt.instruction
        || event.guest_pkru != receipt.pkru
    {
        return None;
    }
    Some(receipt)
}

struct Continuation {
    stack: CallbackStack,
    saved: SavedState,
    context: RegisterContext,
    owner_tid: i64,
    generation: u64,
    #[cfg(feature = "exec-native-injection")]
    native_exec_resume: Option<NativeExecResumeReceipt>,
    phase: Phase,
    entries: u64,
    callbacks: u64,
    completions: u64,
}

fn current_tid() -> i64 {
    unsafe { raw_syscall6(libc::SYS_gettid, [0; 6]) }
}

/// Records the backend's handlers for every thread of this process. Fails if
/// handlers are already registered.
///
/// # Safety
///
/// Each handler must be sound to call on the guest thread whose call was
/// captured, in ordinary context on the continuation's stack, with `context`
/// pointing to that thread's continuation register block: valid for reads and
/// writes and used by nothing else for the call. A handler must not free that
/// block or keep the pointer after it returns. The syscall handler's `pkru` is
/// the guest's interrupted PKRU value, which it may change.
pub unsafe fn register_handlers(handlers: ContinuationHandlers) -> io::Result<()> {
    HANDLERS.set(handlers).map_err(|_| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "continuation handlers are already registered",
        )
    })
}

/// Register one runtime's handlers once, then prepare each calling thread.
///
/// The caller retains its registration cache. Another runtime's cache still
/// encounters the existing process-wide registry's `AlreadyExists` refusal.
/// Only registration is cached: pending-call and backing checks run on every
/// invocation, and an initialization failure does not poison registration.
///
/// # Safety
/// The requirements of [`register_handlers`] apply. `registration` must always
/// identify the same process-lifetime handler pair; a successful cache must
/// never be reused for a different pair or a different runtime owner. Call in
/// ordinary initialization context before this thread can enter a continuation.
pub unsafe fn initialize_registered(
    registration: &OnceLock<Result<(), io::ErrorKind>>,
    handlers: ContinuationHandlers,
    backing: StackBacking,
) -> io::Result<()> {
    let result = registration.get_or_init(|| {
        // SAFETY: the caller binds this cache permanently to these handlers.
        unsafe { register_handlers(handlers) }.map_err(|error| error.kind())
    });
    if let Err(kind) = result {
        return Err(io::Error::new(
            *kind,
            "the in-guest continuation's handlers are registered by another backend",
        ));
    }
    initialize_with_stack_backing(backing)
}

/// Prepares this thread's continuation (its owned stack and saved-state
/// buffer). Call after [`register_handlers`] and before the first trap can
/// reach [`prepare_signal`] or [`prepare_instruction_signal`]; fails if no
/// handlers are registered or while a captured call is still pending.
pub fn initialize() -> io::Result<()> {
    initialize_with_stack_backing(StackBacking::Legacy)
}

/// Prepare the existing continuation using explicitly selected stack storage.
/// Generic callers of [`initialize`] retain their previous anonymous backing.
/// Repeated preparation must select the same backing; a live stack is never
/// replaced. Like [`initialize`], this is ordinary setup, not a handler API.
pub fn initialize_with_stack_backing(backing: StackBacking) -> io::Result<()> {
    if HANDLERS.get().is_none() {
        return Err(io::Error::other("no continuation handlers are registered"));
    }
    SAVE_CONFIG
        .get_or_init(configure_save)
        .as_ref()
        .map_err(|error| io::Error::other(*error))?;
    if PENDING.get().is_some() {
        return Err(io::Error::other("a syscall continuation is still active"));
    }
    if OWNER.get().is_null() {
        let saved = SavedState::new()?;
        let stack = CallbackStack::new(backing)?;
        let owner = Box::new(Continuation {
            stack,
            saved,
            // A fallback-created context has no trampoline-owned saved-state
            // image. Default makes that unavailable descriptor explicit.
            context: RegisterContext::default(),
            owner_tid: current_tid(),
            generation: 0,
            #[cfg(feature = "exec-native-injection")]
            native_exec_resume: None,
            phase: Phase::Idle,
            entries: 0,
            callbacks: 0,
            completions: 0,
        });
        OWNER.set(Box::into_raw(owner));
    } else {
        // The current thread exclusively owns the retained continuation. Only
        // inspect its backing; never reset a live COW-inherited stack/image.
        let region = unsafe { &(*OWNER.get()).stack.region };
        let same = match (region.as_ref(), backing) {
            (None, StackBacking::Legacy) => true,
            (Some(lease), StackBacking::ToolRegion(owner)) => lease.belongs_to(owner),
            _ => false,
        };
        if !same {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
    }
    READY.set(true);
    Ok(())
}

/// Reserve the activation for a trapped syscall; see [`prepare_pending`].
#[cfg(test)]
pub(crate) fn prepare(instruction: u64) -> Option<u64> {
    prepare_pending(Pending {
        instruction,
        kind: PendingKind::Syscall,
    })
}

/// Reserve the existing single activation without overwriting a pending one.
/// Kept separate from frame capture so its reentry contract remains testable.
fn prepare_pending(request: Pending) -> Option<u64> {
    PENDING.with(|pending| {
        if !READY.get() || pending.get().is_some() {
            return None;
        }
        pending.set(Some(request));
        Some(fallback_entry as *const () as u64)
    })
}

/// Capture a trapped `syscall`'s `SIGSYS` frame for ordinary-context dispatch.
///
/// # Safety
///
/// `frame` must be the frame of the `SIGSYS` the kernel delivered on this
/// thread for the `syscall` instruction at `instruction`, and the caller must
/// be that signal's handler.
/// On `Ok(Some(entry))` the continuation is reserved and the frame's stack,
/// first argument, flags and PKRU are set for it: the caller must make the
/// handler return to `entry` (by setting the frame's RIP, or by deferring the
/// event to it) and must not resume the guest from this frame any other way.
/// On `Ok(None)` nothing was reserved or changed. On `Err` the frame may be
/// partly changed and the caller must end the process.
pub unsafe fn prepare_signal(
    instruction: u64,
    frame: &mut SignalFrame<'_>,
) -> Result<Option<u64>, FrameError> {
    prepare_signal_for(
        Pending {
            instruction,
            kind: PendingKind::Syscall,
        },
        frame,
    )
}

/// Capture a faulting instruction's kernel `SIGSEGV` frame so the Tool
/// emulates it in ordinary context, exactly like an unpatched syscall. The
/// frame's saved RIP must be the instruction itself; the committed context
/// resumes after its `kind.encoded_len()` bytes.
///
/// # Safety
///
/// `frame` must be the frame of the `SIGSEGV` the kernel delivered on this
/// thread for the faulting `kind` instruction at `instruction`, and the
/// caller must be that signal's handler.
/// On `Ok(Some(entry))` the continuation is reserved and the frame's stack,
/// first argument, flags and PKRU are set for it: the caller must make the
/// handler return to `entry` (by setting the frame's RIP, or by deferring the
/// event to it) and must not resume the guest from this frame any other way.
/// On `Ok(None)` nothing was reserved or changed. On `Err` the frame may be
/// partly changed and the caller must end the process.
pub unsafe fn prepare_instruction_signal(
    instruction: u64,
    kind: InstructionEventKind,
    frame: &mut SignalFrame<'_>,
) -> Result<Option<u64>, FrameError> {
    prepare_signal_for(
        Pending {
            instruction,
            kind: PendingKind::Instruction(kind),
        },
        frame,
    )
}

fn prepare_signal_for(
    request: Pending,
    frame: &mut SignalFrame<'_>,
) -> Result<Option<u64>, FrameError> {
    let instruction = request.instruction;
    let Some(entry) = prepare_pending(request) else {
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
    // Signal phase 1: the frame invariant, before this call can commit a
    // delivery (the process ends on a mismatch).
    if super::sigalrm::handled() {
        super::sigalrm::check_entry_frame(frame.signal_mask(), frame.signal_stack());
    }
    owner.generation = owner.generation.checked_add(1).ok_or(FrameError)?;
    frame.capture(&mut owner.saved)?;
    let resume = instruction
        .checked_add(request.kind.frame_offset())
        .ok_or(FrameError)?;
    if frame.register(libc::REG_RIP as usize) as u64 != resume {
        return Err(FrameError);
    }
    owner.context = context_from_image(&owner.saved, instruction);
    #[cfg(feature = "exec-native-injection")]
    {
        // SavedState has no mask. Only the kernel uc_sigmask is the desired
        // guest resume mask, before the first genuine rt_sigreturn.
        owner.native_exec_resume =
            (request.kind == PendingKind::Syscall).then_some(NativeExecResumeReceipt {
                owner: pointer as usize,
                tid: owner.owner_tid,
                generation: owner.generation,
                mask: frame.signal_mask(),
                number: owner.context.rax as i64,
                args: [
                    owner.context.rdi,
                    owner.context.rsi,
                    owner.context.rdx,
                    owner.context.r10,
                    owner.context.r8,
                    owner.context.r9,
                ],
                instruction,
                pkru: owner.saved.pkru(),
            });
    }
    owner.phase = Phase::Captured;
    frame.set_register(libc::REG_RSP as usize, (owner.stack.top & !15) as i64);
    frame.set_register(libc::REG_RDI as usize, pointer as i64);
    frame.set_register(
        libc::REG_EFL as usize,
        frame.register(libc::REG_EFL as usize) & !(1 << 10),
    );
    frame.set_pkru(owner.saved.pkru().map(|_| 0))?;
    owner.entries += 1;
    #[cfg(feature = "exec-private-init")]
    super::exec_private::callback_prepared();
    Ok(Some(entry))
}

fn context_from_image(saved: &SavedState, instruction: u64) -> RegisterContext {
    let r = &saved.registers;
    let mut context = RegisterContext::default();
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
    debug_assert!(context.extended_state_unavailable());
    context
}

fn commit_context(owner: &mut Continuation, length: u64) -> Result<(), FrameError> {
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
    r[libc::REG_RIP as usize] = c
        .instruction_pointer
        .checked_add(length)
        .ok_or(FrameError)? as i64;
    Ok(())
}

/// The current handler prefix has already opened runtime permissions before
/// any memory access. Nested operations retain their own interrupted image.
pub fn enable_nested_runtime_access() {}

/// A raw fork copies the active image and ordinary stack. Rebind only after
/// the real child result, in ordinary context, before child callbacks/return.
pub fn rebind_fork_child() {
    let pointer = OWNER.get();
    if !pointer.is_null() {
        unsafe {
            (*pointer).owner_tid = current_tid();
            #[cfg(feature = "exec-native-injection")]
            {
                (*pointer).native_exec_resume = None;
            }
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
    let Some(pending) = PENDING.get() else {
        fatal()
    };
    let Some(handlers) = HANDLERS.get() else {
        fatal()
    };
    if pointer.is_null() || pointer != OWNER.get() {
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
    // The registers the syscall dispatch writes, for a syscall that is to
    // start again (signal phase 1's delivery at syscall entry).
    let entry = unsafe {
        (
            (*pointer).context.rax,
            (*pointer).context.rcx,
            (*pointer).context.r11,
        )
    };
    unsafe {
        let context = core::ptr::addr_of_mut!((*pointer).context);
        match pending.kind {
            PendingKind::Syscall => (handlers.syscall)(context, &mut pkru),
            // An instruction has no permission effect: the guest's interrupted
            // PKRU is restored unchanged by completion.
            PendingKind::Instruction(kind) => (handlers.instruction)(context, kind),
        }
        *errno = saved_errno;
    }
    let owner = unsafe { &mut *pointer };
    let mut length = pending.kind.length();
    if super::sigalrm::take_entry_delivery() {
        // The syscall did not run: resume at its `syscall` instruction with
        // its number and the guest's registers, so it runs from the start
        // after the delivered handler returns. Only a syscall can ask.
        //
        // A stated limitation: rcx and r11 are the values the SIGSYS frame
        // holds, which the hardware `syscall` instruction already wrote (the
        // return address and rflags) before it trapped; their values just
        // before the instruction are gone. So the handler's ucontext shows
        // those two as the instruction left them, where Linux, delivering at
        // the previous handler's rt_sigreturn, would show whatever the guest
        // had there. Only a handler that reads rcx or r11 from its ucontext
        // can see it; this is the I4 addendum's stated difference (guest
        // instructions between that return and this syscall run before the
        // handler here), extended to the `syscall` instruction itself.
        if !matches!(pending.kind, PendingKind::Syscall) {
            fatal()
        }
        (owner.context.rax, owner.context.rcx, owner.context.r11) = entry;
        length = 0;
    }
    if owner.owner_tid != current_tid()
        || owner.saved.set_pkru(pkru).is_err()
        || commit_context(owner, length).is_err()
    {
        fatal()
    }
    owner.phase = Phase::ReadyToReturn;
}

/// Completion is intercepted before ordinary syscall/site classification.
/// A genuine frame may reuse the same alt-stack address as the consumed first
/// frame; address inequality is not evidence of freshness.
pub fn complete(frame: &mut SignalFrame<'_>) -> Result<bool, FrameError> {
    let resume = core::ptr::addr_of!(fallback_completion_return) as usize as u64;
    if frame.register(libc::REG_RIP as usize) as u64 != resume {
        return Ok(false);
    }
    let pointer = OWNER.get();
    if pointer.is_null() {
        return Err(FrameError);
    }
    // Validate through raw field reads: while a handler runs it may hold a
    // reference into the owner's context, so no reference to the whole owner
    // is formed until this is known to be the owner's completion (phase
    // ReadyToReturn, which the dispatch sets only after the handler returned).
    let phase = unsafe { core::ptr::addr_of!((*pointer).phase).read() };
    let owner_tid = unsafe { core::ptr::addr_of!((*pointer).owner_tid).read() };
    let generation = unsafe { core::ptr::addr_of!((*pointer).generation).read() };
    let instruction = core::ptr::addr_of!(fallback_completion_syscall) as usize;
    if instruction.checked_add(2) != Some(resume as usize)
        || unsafe { core::slice::from_raw_parts(instruction as *const u8, 2) } != [0x0f, 0x05]
        || phase != Phase::ReadyToReturn
        || owner_tid != current_tid()
        || PENDING.get().is_none()
        || frame.register(libc::REG_RAX as usize) != libc::SYS_getpid
        || frame.register(libc::REG_RDI as usize) as u64 != COMPLETION_COOKIE
        || frame.register(libc::REG_RSI as usize) as u64 != generation
        || frame.register(libc::REG_RDX as usize) as usize != pointer as usize
    {
        return Err(FrameError);
    }
    let owner = unsafe { &mut *pointer };
    frame.restore(&owner.saved)?;
    // Signal phase 1: a prepared SIGALRM delivery opens its window here, so
    // the queued instance arrives as this frame returns, before any guest
    // instruction.
    if let Some(window) = super::sigalrm::take_window() {
        frame.set_signal_mask(window);
    }
    owner.completions += 1;
    owner.phase = Phase::Idle;
    PENDING.set(None);
    #[cfg(feature = "exec-private-init")]
    super::exec_private::guest_completed();
    Ok(true)
}

/// Diagnostic observations for the current thread's owned continuation.
/// Selectors 0/1/2 are actual fallback entry, reached ordinary callback, and
/// prepared genuine completion frame. They are not a kernel-stop census.
pub fn owned_observation(selector: u32) -> u64 {
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
pub fn on_owned_stack(address: usize) -> bool {
    let pointer = OWNER.get();
    if pointer.is_null() {
        return false;
    }
    unsafe {
        let top = (*pointer).stack.top;
        address >= top - CALLBACK_STACK_BYTES && address < top
    }
}

/// Read the already prepared stack, without preparing or entering a callback.
/// This diagnostic is distinct from evidence that execution reached the stack.
#[cfg(feature = "allocator-fixture")]
#[doc(hidden)]
pub fn fixture_stack_descriptor() -> Option<(usize, usize, u32)> {
    let pointer = OWNER.get();
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the current thread owns this retained continuation. This query
    // reads only its immutable stack bounds and current owner identity.
    let (top, tid) = unsafe { ((*pointer).stack.top, (*pointer).owner_tid) };
    Some((top - CALLBACK_STACK_BYTES, top, tid as u32))
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

#[cfg(feature = "exec-private-init")]
pub(crate) fn is_completion_address(address: u64) -> bool {
    address == core::ptr::addr_of!(fallback_completion_return) as usize as u64
}

/// Test-only violations against an already captured genuine running event.
/// No receipt or mask is fabricated; each owner mutation is restored exactly.
#[cfg(all(test, feature = "exec-native-injection"))]
pub(crate) fn native_exec_test_binding_controls(event: &super::event::SyscallEvent) {
    use super::event::SyscallDispatch;
    let receipt = native_exec_resume_receipt(event).expect("genuine running receipt");
    for index in 0..6 {
        let mut changed = *event;
        changed.args[index] ^= 1;
        assert!(
            native_exec_resume_receipt(&changed).is_none(),
            "argument {index}"
        );
    }
    for index in 0..6 {
        let mut changed = *event;
        match index {
            0 => changed.number ^= 1,
            1 => changed.context ^= 8,
            2 => changed.instruction_pointer ^= 1,
            3 => changed.dispatch = SyscallDispatch::Trap,
            4 => changed.dispatch = SyscallDispatch::InstalledHook,
            5 => changed.guest_pkru = changed.guest_pkru.map(|v| v ^ 1).or(Some(1)),
            _ => unreachable!(),
        }
        assert!(native_exec_resume_receipt(&changed).is_none());
    }
    let pointer = OWNER.get();
    unsafe {
        let generation = (&raw const (*pointer).generation).read();
        (&raw mut (*pointer).generation).write(generation.checked_add(1).unwrap());
        assert!(!receipt.recheck(event));
        (&raw mut (*pointer).generation).write(generation);
        let phase = (&raw const (*pointer).phase).read();
        for other in [Phase::Idle, Phase::Captured, Phase::ReadyToReturn] {
            (&raw mut (*pointer).phase).write(other);
            assert!(native_exec_resume_receipt(event).is_none());
        }
        (&raw mut (*pointer).phase).write(phase);
        let tid = (&raw const (*pointer).owner_tid).read();
        (&raw mut (*pointer).owner_tid).write(tid.checked_add(1).unwrap());
        assert!(native_exec_resume_receipt(event).is_none());
        (&raw mut (*pointer).owner_tid).write(tid);
    }
    let pending = PENDING.get();
    PENDING.set(None);
    assert!(native_exec_resume_receipt(event).is_none());
    PENDING.set(Some(Pending {
        instruction: event.instruction_pointer,
        kind: PendingKind::Instruction(InstructionEventKind::Cpuid),
    }));
    assert!(native_exec_resume_receipt(event).is_none());
    PENDING.set(Some(Pending {
        instruction: event.instruction_pointer ^ 1,
        kind: PendingKind::Syscall,
    }));
    assert!(native_exec_resume_receipt(event).is_none());
    PENDING.set(pending);
    assert_eq!(native_exec_resume_receipt(event), Some(receipt));
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

    unsafe fn no_syscall(_: *mut RegisterContext, _: &mut Option<u32>) {
        unreachable!("these tests never run a continuation");
    }

    unsafe fn no_instruction(_: *mut RegisterContext, _: InstructionEventKind) {
        unreachable!("these tests never run a continuation");
    }

    const HANDLERS_FOR_TESTS: ContinuationHandlers = ContinuationHandlers {
        syscall: no_syscall,
        instruction: no_instruction,
    };

    #[test]
    fn registration_cache_keeps_one_owner_and_per_thread_initialization() {
        const CHILD: &str = "REVERIE_CONTINUATION_REGISTRATION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // A fresh process isolates the real, never-reset handler registry
            // from tests which deliberately share their first registration.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "guest::continuation::tests::registration_cache_keeps_one_owner_and_per_thread_initialization",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("registration ownership checked")
            );
            return;
        }

        let owner = OnceLock::new();
        let initialize_owner = || unsafe {
            // SAFETY: this cache always denotes the same inert test handlers;
            // these tests prepare storage but never execute a continuation.
            initialize_registered(&owner, HANDLERS_FOR_TESTS, StackBacking::Legacy)
        };
        initialize_owner().unwrap();
        let first_stack = OWNER.get() as usize;
        assert_ne!(first_stack, 0);
        initialize_owner().unwrap();
        assert_eq!(OWNER.get() as usize, first_stack);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(OWNER.get().is_null());
                    initialize_owner().unwrap();
                    assert!(READY.get());
                    assert_ne!(OWNER.get() as usize, 0);
                    assert_ne!(OWNER.get() as usize, first_stack);
                })
                .join()
                .unwrap();
        });
        assert!(prepare(0x1000).is_some());
        assert_eq!(
            initialize_owner().unwrap_err().to_string(),
            "a syscall continuation is still active"
        );
        assert_eq!(PENDING.get().unwrap().instruction, 0x1000);
        PENDING.set(None);
        initialize_owner().unwrap();

        let other_owner = OnceLock::new();
        for _ in 0..2 {
            // Even the same callback addresses cannot replace the first
            // runtime's ownership using a different registration cache.
            let error = unsafe {
                initialize_registered(&other_owner, HANDLERS_FOR_TESTS, StackBacking::Legacy)
            }
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            assert_eq!(
                error.to_string(),
                "the in-guest continuation's handlers are registered by another backend"
            );
        }
        println!("registration ownership checked");
    }

    #[test]
    fn pending_continuation_refuses_reentry_without_overwriting() {
        // Tests in this process share the registration; the first wins.
        // SAFETY: these handlers are never called (see above).
        let _ = unsafe { register_handlers(HANDLERS_FOR_TESTS) };
        initialize().unwrap();
        assert!(prepare(0x1000).is_some());
        assert!(prepare(0x2000).is_none());
        assert_eq!(
            PENDING.get(),
            Some(Pending {
                instruction: 0x1000,
                kind: PendingKind::Syscall,
            })
        );
        assert!(initialize().is_err());
        PENDING.set(None);
        assert!(prepare(0x3000).is_some());
        assert_eq!(
            PENDING.get(),
            Some(Pending {
                instruction: 0x3000,
                kind: PendingKind::Syscall,
            })
        );
        PENDING.set(None);
    }

    #[test]
    fn instruction_continuations_resume_after_their_own_encoding() {
        // A SIGSYS frame already points after the 2-byte syscall; a SIGSEGV
        // instruction fault points at the instruction itself.
        assert_eq!(PendingKind::Syscall.frame_offset(), 2);
        assert_eq!(PendingKind::Syscall.length(), 2);
        for (kind, length) in [
            (InstructionEventKind::Cpuid, 2),
            (InstructionEventKind::Rdtsc, 2),
            (InstructionEventKind::Rdtscp, 3),
        ] {
            assert_eq!(PendingKind::Instruction(kind).frame_offset(), 0);
            assert_eq!(PendingKind::Instruction(kind).length(), length);
        }

        let mut owner = Continuation {
            stack: CallbackStack::new(StackBacking::Legacy).unwrap(),
            saved: SavedState::new().unwrap(),
            context: RegisterContext::default(),
            owner_tid: current_tid(),
            generation: 0,
            #[cfg(feature = "exec-native-injection")]
            native_exec_resume: None,
            phase: Phase::Idle,
            entries: 0,
            callbacks: 0,
            completions: 0,
        };
        owner.context.instruction_pointer = 0x7000;
        commit_context(&mut owner, 3).unwrap();
        assert_eq!(owner.saved.registers[libc::REG_RIP as usize], 0x7003);
        owner.context.instruction_pointer = u64::MAX - 1;
        assert!(commit_context(&mut owner, 3).is_err());
    }
}
