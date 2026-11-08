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

use core::cell::Cell;
use std::io;
use std::sync::OnceLock;

use super::context::RegisterContext;
use super::event::InstructionEventKind;
use super::isa::Isa;
use super::isa::NativeIsa;
use super::tool_region::StackBacking;
use super::tool_region::StackLease;
use crate::trap::frame::FrameError;
use crate::trap::frame::SavedState;
use crate::trap::frame::SignalFrame;
use crate::trap::raw_syscall6;

static SAVE_CONFIG: OnceLock<Result<(), &'static str>> = OnceLock::new();

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
    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    static MAPPED_CALLBACK: Cell<Option<MappedCallbackStamp>> = const { Cell::new(None) };
}

/// The one outlined access site for the OWNER cell (see
/// `tool_callback_active_cell` in super::support).
#[inline(never)]
pub(crate) fn owner_cell() -> *mut core::cell::Cell<*mut Continuation> {
    OWNER.with(|cell| cell as *const core::cell::Cell<*mut Continuation> as *mut _)
}

/// The one outlined access site for the PENDING cell. The address is
/// type-erased so the retained-accessor table in super::support does
/// not name the private Pending type.
#[inline(never)]
pub(crate) fn pending_cell() -> *mut core::ffi::c_void {
    PENDING.with(|cell| cell as *const core::cell::Cell<Option<Pending>> as *mut core::ffi::c_void)
}

fn owner_get() -> *mut Continuation {
    // SAFETY: this thread's own cell, used only on this thread.
    unsafe { (*owner_cell()).get() }
}

fn owner_set(value: *mut Continuation) {
    // SAFETY: this thread's own cell, used only on this thread.
    unsafe { (*owner_cell()).set(value) }
}

fn pending_get() -> Option<Pending> {
    // SAFETY: this thread's own cell, used only on this thread.
    unsafe { (*pending_cell().cast::<core::cell::Cell<Option<Pending>>>()).get() }
}

fn pending_set(value: Option<Pending>) {
    // SAFETY: this thread's own cell, used only on this thread.
    unsafe { (*pending_cell().cast::<core::cell::Cell<Option<Pending>>>()).set(value) }
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
            Self::Syscall => NativeIsa::SYSCALL_LEN,
            Self::Instruction(_) => 0,
        }
    }

    /// Bytes the committed guest context advances past the instruction.
    fn length(self) -> u64 {
        match self {
            Self::Syscall => NativeIsa::SYSCALL_LEN,
            Self::Instruction(kind) => kind.encoded_len(),
        }
    }
}

const CALLBACK_STACK_BYTES: usize = 8 * 1024 * 1024;

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
    let pointer = owner_get();
    if pointer.is_null() {
        return None;
    }
    let pending = pending_get()?;
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

pub(crate) struct Continuation {
    stack: CallbackStack,
    saved: SavedState,
    context: RegisterContext,
    owner_tid: i64,
    generation: u64,
    // Authentic outer kernel mask, captured before the first sigreturn. SavedState
    // intentionally has no mask; instruction callbacks need this fact too.
    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    mapped_signal_mask: u64,
    #[cfg(feature = "exec-native-injection")]
    native_exec_resume: Option<NativeExecResumeReceipt>,
    /// While the runtime delivers signals itself (`runtime_mask`): the
    /// guest's mask, from the trap frame, which the completion installs; the
    /// calls on the blocked set act on it meanwhile. Unused otherwise.
    guest_mask: u64,
    phase: Phase,
    entries: u64,
    callbacks: u64,
    completions: u64,
}

// Scoped borrow of the existing Running continuation, not a transferable
// permission/owner. Only the actual installed Tool dispatch boundary sets it.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
#[derive(Clone, Copy, Eq, PartialEq)]
struct MappedCallbackStamp {
    owner: usize,
    generation: u64,
    host: usize,
}

#[cfg(all(
    feature = "loader-private-runtime",
    target_env = "musl",
    feature = "coordinator-rpc"
))]
pub(super) struct MappedCallbackScope {
    stamp: MappedCallbackStamp,
    _thread: core::marker::PhantomData<*mut ()>,
}

#[cfg(all(
    feature = "loader-private-runtime",
    target_env = "musl",
    feature = "coordinator-rpc"
))]
impl Drop for MappedCallbackScope {
    fn drop(&mut self) {
        if MAPPED_CALLBACK.get() != Some(self.stamp) {
            fatal();
        }
        MAPPED_CALLBACK.set(None);
    }
}

// Used by both the real entry and nested frame validator. No reference to the
// full Continuation or its mutably borrowed RegisterContext crosses Tool code.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
fn mapped_running_owner(pointer: *mut Continuation) -> Option<u64> {
    if pointer.is_null() || pending_get().is_none() {
        return None;
    }
    // SAFETY: OWNER is this thread's retained continuation; these disjoint
    // fields are not the live mutable Tool RegisterContext.
    unsafe {
        let generation = (&raw const (*pointer).generation).read();
        let tid = (&raw const (*pointer).owner_tid).read();
        if (&raw const (*pointer).phase).read() != Phase::Running
            || generation == 0
            || tid != current_tid()
            || super::exec_private::callback_native_tid().map(i64::from) != Some(tid)
        {
            return None;
        }
        Some(generation)
    }
}

// Private unsafe API: actual installed Tool caller, never a numeric callback
// token. Legacy/unmapped callers retain their previous behavior. The bounded
// first implementation refuses patched-hook contexts not owned by Running.
#[cfg(all(
    feature = "loader-private-runtime",
    target_env = "musl",
    feature = "coordinator-rpc"
))]
pub(super) unsafe fn enter_mapped_callback(
    context: *mut RegisterContext,
    host: usize,
) -> Option<MappedCallbackScope> {
    if !super::exec_private::mapped_callback_origin() {
        return None;
    }
    let pointer = owner_get();
    let Some(generation) = mapped_running_owner(pointer) else {
        fatal()
    };
    // SAFETY: genuine retained OWNER, raw address comparison forms no alias.
    if host == 0
        || context != unsafe { &raw mut (*pointer).context }
        || MAPPED_CALLBACK.get().is_some()
    {
        fatal();
    }
    let stamp = MappedCallbackStamp {
        owner: pointer as usize,
        generation,
        host,
    };
    MAPPED_CALLBACK.set(Some(stamp));
    Some(MappedCallbackScope {
        stamp,
        _thread: core::marker::PhantomData,
    })
}

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(super) struct MappedCallbackFacts {
    pub(super) host: usize,
    pub(super) mask: u64,
}

#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
fn same_mapped_scope(stamp: MappedCallbackStamp, owner: usize, generation: u64) -> bool {
    stamp.owner != 0
        && stamp.host != 0
        && stamp.generation != 0
        && stamp.owner == owner
        && stamp.generation == generation
}

// Actual saved Tool RSP must belong to the Running continuation's lease in the
// one published region. An active ToolCallbackGuard alone is insufficient.
#[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
pub(super) fn mapped_callback_facts(
    saved_rsp: usize,
    region: &'static super::tool_region::ToolRegion,
) -> Option<MappedCallbackFacts> {
    let stamp = MAPPED_CALLBACK.get()?;
    let pointer = owner_get();
    let generation = mapped_running_owner(pointer)?;
    if !same_mapped_scope(stamp, pointer as usize, generation) {
        return None;
    }
    // SAFETY: disjoint immutable stack metadata and saved mask; no context
    // reference is formed while Tool holds its unique mutable register block.
    unsafe {
        let lease = (&*(&raw const (*pointer).stack)).region.as_ref()?;
        if !lease.belongs_to(region) || saved_rsp < lease.base() || saved_rsp >= lease.top() {
            return None;
        }
        Some(MappedCallbackFacts {
            host: stamp.host,
            mask: (&raw const (*pointer).mapped_signal_mask).read(),
        })
    }
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
        .get_or_init(NativeIsa::configure_saved_state)
        .as_ref()
        .map_err(|error| io::Error::other(*error))?;
    if pending_get().is_some() {
        return Err(io::Error::other("a syscall continuation is still active"));
    }
    if owner_get().is_null() {
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
            #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
            mapped_signal_mask: 0,
            #[cfg(feature = "exec-native-injection")]
            native_exec_resume: None,
            guest_mask: 0,
            phase: Phase::Idle,
            entries: 0,
            callbacks: 0,
            completions: 0,
        });
        owner_set(Box::into_raw(owner));
    } else {
        // The current thread exclusively owns the retained continuation. Only
        // inspect its backing; never reset a live COW-inherited stack/image.
        let region = unsafe { &(*owner_get()).stack.region };
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
    if !READY.get() || pending_get().is_some() {
        return None;
    }
    pending_set(Some(request));
    Some(NativeIsa::fallback_entry())
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
/// handler return to `entry` (by setting the frame's resume address, or by deferring the
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
/// handler return to `entry` (by setting the frame's resume address, or by deferring the
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
    let pointer = owner_get();
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
    if NativeIsa::frame_pc(frame) != resume {
        return Err(FrameError);
    }
    owner.context = context_from_image(&owner.saved, instruction);
    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    {
        owner.mapped_signal_mask = frame.signal_mask();
    }
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
                number: NativeIsa::syscall_number(&owner.context),
                args: NativeIsa::syscall_args(&owner.context),
                instruction,
                pkru: owner.saved.pkru(),
            });
    }
    if super::runtime_mask::delivers_signals() {
        // The guest's mask is kept for the completion, and the continuation
        // is entered under the runtime mask, which the SIGSYS and SIGSEGV
        // actions already installed for this handler (`runtime_mask`).
        owner.guest_mask = frame.signal_mask();
        frame.set_signal_mask(super::runtime_mask::runtime_mask());
    }
    owner.phase = Phase::Captured;
    NativeIsa::prepare_frame_for_entry(frame, owner.stack.top, pointer as usize, &owner.saved)?;
    owner.entries += 1;
    #[cfg(feature = "exec-private-init")]
    super::exec_private::callback_prepared();
    Ok(Some(entry))
}

fn context_from_image(saved: &SavedState, instruction: u64) -> RegisterContext {
    NativeIsa::context_from_saved(saved, instruction)
}

fn commit_context(owner: &mut Continuation, length: u64) -> Result<(), FrameError> {
    NativeIsa::commit_context(&mut owner.saved, &owner.context, length)
}

/// While the runtime delivers signals itself (`runtime_mask`), the guest mask
/// this thread's running continuation saved from its trap frame and its
/// completion installs; `None` with no callback running on this thread, or
/// with the gate off.
pub fn saved_guest_mask() -> Option<u64> {
    let pointer = running_owner()?;
    // Raw field read: the running callback may hold a reference into the
    // owner's context, a disjoint field.
    Some(unsafe { core::ptr::addr_of!((*pointer).guest_mask).read() })
}

/// Replaces the mask [`saved_guest_mask`] reports, which the completion then
/// installs. Returns false, changing nothing, where it reports `None`.
pub fn set_saved_guest_mask(mask: u64) -> bool {
    let Some(pointer) = running_owner() else {
        return false;
    };
    unsafe { core::ptr::addr_of_mut!((*pointer).guest_mask).write(mask) };
    true
}

/// This thread's continuation while a callback runs on it, under the gate.
fn running_owner() -> Option<*mut Continuation> {
    if !super::runtime_mask::delivers_signals() {
        return None;
    }
    let pointer = owner_get();
    if pointer.is_null()
        || unsafe { core::ptr::addr_of!((*pointer).phase).read() } != Phase::Running
    {
        return None;
    }
    Some(pointer)
}

/// The current handler prefix has already opened runtime permissions before
/// any memory access. Nested operations retain their own interrupted image.
pub fn enable_nested_runtime_access() {}

/// A raw fork copies the active image and ordinary stack. Rebind only after
/// the real child result, in ordinary context, before child callbacks/return.
///
/// The saved guest mask is kept: Linux's child starts with its parent's
/// blocked set (`copy_process` copies `blocked`), and the child's completion
/// installs it. Under the gate the cached thread and process ids are the
/// child's from here on.
pub fn rebind_fork_child() {
    if super::runtime_mask::delivers_signals() {
        super::runtime_mask::rebind_identity();
    }
    let pointer = owner_get();
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

pub(crate) unsafe extern "C" fn dispatch(pointer: *mut Continuation) {
    let Some(pending) = pending_get() else {
        fatal()
    };
    let Some(handlers) = HANDLERS.get() else {
        fatal()
    };
    if pointer.is_null() || pointer != owner_get() {
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
    let entry = unsafe { NativeIsa::restart_snapshot(&(*pointer).context) };
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
        NativeIsa::restore_restart_snapshot(&mut owner.context, entry);
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
    let resume = NativeIsa::completion_return_address();
    if NativeIsa::frame_pc(frame) != resume {
        return Ok(false);
    }
    let pointer = owner_get();
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
    if phase != Phase::ReadyToReturn
        || owner_tid != current_tid()
        || pending_get().is_none()
        || !NativeIsa::validate_completion_frame(frame, generation, pointer as usize)
    {
        return Err(FrameError);
    }
    let owner = unsafe { &mut *pointer };
    frame.restore(&owner.saved)?;
    if super::runtime_mask::delivers_signals() {
        // The guest's own mask, saved at the trap and changed only by the
        // calls on the blocked set; the kernel delivers what it lets in as
        // this frame returns, before any guest instruction.
        frame.set_signal_mask(owner.guest_mask);
    }
    // Signal phase 1: a prepared SIGALRM delivery opens its window here, so
    // the queued instance arrives as this frame returns, before any guest
    // instruction.
    if let Some(window) = super::sigalrm::take_window() {
        frame.set_signal_mask(window);
    }
    owner.completions += 1;
    owner.phase = Phase::Idle;
    pending_set(None);
    #[cfg(feature = "exec-private-init")]
    super::exec_private::guest_completed();
    Ok(true)
}

/// Diagnostic observations for the current thread's owned continuation.
/// Selectors 0/1/2 are actual fallback entry, reached ordinary callback, and
/// prepared genuine completion frame. They are not a kernel-stop census.
pub fn owned_observation(selector: u32) -> u64 {
    let pointer = owner_get();
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
    let pointer = owner_get();
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
    let pointer = owner_get();
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the current thread owns this retained continuation. This query
    // reads only its immutable stack bounds and current owner identity.
    let (top, tid) = unsafe { ((*pointer).stack.top, (*pointer).owner_tid) };
    Some((top - CALLBACK_STACK_BYTES, top, tid as u32))
}

pub(crate) unsafe extern "C" fn completion_generation() -> u64 {
    let pointer = owner_get();
    if pointer.is_null() || unsafe { (*pointer).phase != Phase::ReadyToReturn } {
        fatal()
    }
    unsafe { (*pointer).generation }
}

#[cfg(feature = "exec-private-init")]
pub(crate) fn is_completion_address(address: u64) -> bool {
    address == NativeIsa::completion_return_address()
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
    let pointer = owner_get();
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
    let pending = pending_get();
    pending_set(None);
    assert!(native_exec_resume_receipt(event).is_none());
    pending_set(Some(Pending {
        instruction: event.instruction_pointer,
        kind: PendingKind::Instruction(InstructionEventKind::Cpuid),
    }));
    assert!(native_exec_resume_receipt(event).is_none());
    pending_set(Some(Pending {
        instruction: event.instruction_pointer ^ 1,
        kind: PendingKind::Syscall,
    }));
    assert!(native_exec_resume_receipt(event).is_none());
    pending_set(pending);
    assert_eq!(native_exec_resume_receipt(event), Some(receipt));
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let first_stack = owner_get() as usize;
        assert_ne!(first_stack, 0);
        initialize_owner().unwrap();
        assert_eq!(owner_get() as usize, first_stack);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    assert!(owner_get().is_null());
                    initialize_owner().unwrap();
                    assert!(READY.get());
                    assert_ne!(owner_get() as usize, 0);
                    assert_ne!(owner_get() as usize, first_stack);
                })
                .join()
                .unwrap();
        });
        assert!(prepare(0x1000).is_some());
        assert_eq!(
            initialize_owner().unwrap_err().to_string(),
            "a syscall continuation is still active"
        );
        assert_eq!(pending_get().unwrap().instruction, 0x1000);
        pending_set(None);
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
            pending_get(),
            Some(Pending {
                instruction: 0x1000,
                kind: PendingKind::Syscall,
            })
        );
        assert!(initialize().is_err());
        pending_set(None);
        assert!(prepare(0x3000).is_some());
        assert_eq!(
            pending_get(),
            Some(Pending {
                instruction: 0x3000,
                kind: PendingKind::Syscall,
            })
        );
        pending_set(None);
    }

    #[test]
    fn instruction_continuations_resume_after_their_own_encoding() {
        // A SIGSYS frame already points after the 2-byte syscall; a SIGSEGV
        // instruction fault points at the instruction itself.
        assert_eq!(PendingKind::Syscall.frame_offset(), NativeIsa::SYSCALL_LEN);
        assert_eq!(PendingKind::Syscall.length(), NativeIsa::SYSCALL_LEN);
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
            #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
            mapped_signal_mask: 0,
            #[cfg(feature = "exec-native-injection")]
            native_exec_resume: None,
            guest_mask: 0,
            phase: Phase::Idle,
            entries: 0,
            callbacks: 0,
            completions: 0,
        };
        owner.context.instruction_pointer = 0x7000;
        commit_context(&mut owner, 3).unwrap();
        assert_eq!(NativeIsa::saved_instruction_pointer(&owner.saved), 0x7003);
        owner.context.instruction_pointer = u64::MAX - 1;
        assert!(commit_context(&mut owner, 3).is_err());
    }

    #[cfg(all(feature = "loader-private-runtime", target_env = "musl"))]
    #[test]
    fn mapped_callback_scope_requires_exact_live_owner_generation_and_host() {
        let stamp = MappedCallbackStamp {
            owner: 0x1000,
            generation: 7,
            host: 0x2000,
        };
        assert!(same_mapped_scope(stamp, 0x1000, 7));
        assert!(!same_mapped_scope(stamp, 0x1000, 8));
        assert!(!same_mapped_scope(stamp, 0x3000, 7));
        assert!(!same_mapped_scope(
            MappedCallbackStamp { host: 0, ..stamp },
            0x1000,
            7
        ));
        assert!(!same_mapped_scope(
            MappedCallbackStamp {
                generation: 0,
                ..stamp
            },
            0x1000,
            0
        ));
    }
}
