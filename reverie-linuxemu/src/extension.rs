/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Optional LinuxEmu extension seams.
//!
//! The core executor owns syscall routing, task lifecycle, and the
//! synthetic `/proc` carriers. An extension registers only syscall
//! numbers the core does not answer and synthetic `/proc/self` paths
//! the core does not serve. It receives the narrow [`ExtensionCtx`]
//! facade and its own per-task slot; it never names
//! [`LoadedStaticElf`], a scheduler, a
//! clock, or host state.
//!
//! Hermit's composition installs the empty table, so every seam below
//! is an absent-extension no-op there: dispatch reaches the same
//! ENOSYS default and synthetic `/proc` content is byte-identical.
//! There is deliberately no signal adjuster registry in this slice;
//! that seam is deferred with the rseq design that first needs it.

use std::any::Any;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use crate::GuestMemory;
use crate::elf::LoadedStaticElf;
use crate::elf::STACK_LIMIT;
use crate::elf::TASK_COMM_LEN;
use crate::provider_memory::GuestMemoryAccess;
use crate::provider_memory::ProviderMemory;

/// The slot an extension's per-task state occupies in registration
/// order. Only the builder mints one.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExtensionSlotId(usize);

impl ExtensionSlotId {
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

/// How the task an extension slot is cloned for was created. The kind
/// is flag-shaped from the first API because state such as rseq
/// follows `CLONE_VM`: a thread clone inherits it and a vfork child
/// resets it, which a fork/thread boolean pair cannot express.
///
/// `kind()` names the three creation shapes LinuxEmu admits.
/// [`ExtensionClone::flags`] is authoritative for combinations
/// outside them -- a VM-only process clone, which the staged paths
/// refuse -- should a direct API caller ever supply one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtensionCloneKind {
    /// `fork`, or a process `clone`/`clone3` without `CLONE_VFORK`.
    ProcessFork,
    /// A `CLONE_THREAD` clone (`CLONE_VM` without `CLONE_VFORK`).
    Thread,
    /// `vfork`, or a process clone with `CLONE_VM | CLONE_VFORK`.
    Vfork,
}

/// The validated clone that created a task, as an extension's
/// [`ExtensionState::on_clone`] sees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionClone {
    kind: ExtensionCloneKind,
    flags: u64,
}

impl ExtensionClone {
    pub(crate) const fn process_fork(flags: u64) -> Self {
        Self {
            kind: ExtensionCloneKind::ProcessFork,
            flags,
        }
    }

    pub(crate) const fn thread(flags: u64) -> Self {
        Self {
            kind: ExtensionCloneKind::Thread,
            flags,
        }
    }

    pub(crate) const fn vfork(flags: u64) -> Self {
        Self {
            kind: ExtensionCloneKind::Vfork,
            flags,
        }
    }

    /// The clone for a process creation with validated `flags`:
    /// `CLONE_VFORK` decides the kind, so a VM-only process clone is
    /// a `ProcessFork` whose `flags()` still carries the VM bit.
    pub(crate) fn for_process(flags: u64) -> Self {
        if flags & libc::CLONE_VFORK as u64 != 0 {
            Self::vfork(flags)
        } else {
            Self::process_fork(flags)
        }
    }

    /// Which kind of clone created the child task.
    pub const fn kind(self) -> ExtensionCloneKind {
        self.kind
    }

    /// The clone flags LinuxEmu validated for this creation. A plain
    /// `fork` carries 0 and `vfork` carries `CLONE_VM | CLONE_VFORK`.
    pub const fn flags(self) -> u64 {
        self.flags
    }
}

/// Per-task state owned by one extension.
///
/// A slot is per-task by construction: the table gives a handler only
/// its own task's slot, and there is no API by which one task can read
/// another task's slot. Exec drops every slot and recreates it from
/// the factory, so there is no exec hook to keep stale state alive;
/// a failed exec never reaches the state replacement, so the slots
/// it would have dropped are the identical objects.
///
/// `Sync` is required because an executor is shared by reference
/// across the backend's futures; it does not widen access, since a
/// slot is still only handed mutably to its own task's handler.
///
/// Task-owned state obligation: factories and `on_clone` must
/// return state owned by that one task, with no mutable interior
/// shared across slots -- no shared `Arc<Mutex<...>>`, statics, or
/// parent/child aliases of mutable buffers. Thread clones run in
/// parallel, so shared mutable interior would let tasks observe
/// each other at host-chosen times and break determinism, and the
/// core would faithfully transport it. The type system cannot
/// prove this for an arbitrary factory, so compositions are
/// reviewed against this obligation (Slice 4's rseq state is the
/// first real consumer).
pub trait ExtensionState: Any + Debug + Send + Sync {
    /// The child's slot for `clone`, derived from this (the parent's)
    /// slot. Infallible, as the factories are: task creation has no
    /// extension failure channel in this slice.
    fn on_clone(&self, clone: ExtensionClone) -> Box<dyn ExtensionState>;

    /// This state as [`Any`], for the owning extension's downcasts.
    fn as_any(&self) -> &dyn Any;

    /// This state as [`Any`], mutably.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Creates one task's slot at load and after a successful exec.
pub type ExtensionStateFactory = fn() -> Box<dyn ExtensionState>;

/// Answers one syscall the core dispatch does not. The return value
/// is the raw Linux result: a value, or a negative errno.
pub type ExtensionSyscallHandler = fn(&mut ExtensionCtx<'_>) -> i64;

/// Renders one claimed synthetic `/proc/self` path from the core's
/// facts snapshot, or declines it with `None`.
pub type ExtensionProcRender = fn(&dyn ExtensionState, &ProcFacts) -> Option<Vec<u8>>;

/// Why an extension registration was refused. Precedence is fixed --
/// Tool/Detcore, then the core arm or core proc claim, then an
/// extension -- so a number Detcore decides on every backend can
/// never be an extension's.
#[derive(Debug, thiserror::Error)]
pub enum ExtensionRegistrationError {
    #[error("LinuxEmu extension slot {slot} was not registered with this builder")]
    UnknownSlot { slot: usize },
    #[error("duplicate LinuxEmu extension syscall handler for {number}")]
    DuplicateSyscall { number: u64 },
    #[error("LinuxEmu extension syscall {number} is decided by the Tool on every backend")]
    ToolDecidedSyscall { number: u64 },
    #[error("duplicate LinuxEmu extension proc claim for {path:?}")]
    DuplicateProcClaim { path: &'static [u8] },
    #[error("LinuxEmu extension proc claim {path:?} is not a /proc/self path")]
    InvalidProcPath { path: &'static [u8] },
}

#[derive(Debug)]
struct Extension {
    name: &'static str,
    factory: ExtensionStateFactory,
}

/// The immutable extension composition of one run, built once by
/// [`ExtensionTableBuilder`] and carried by every task's state.
#[derive(Debug, Default)]
pub struct ExtensionTable {
    extensions: Vec<Extension>,
    syscalls: BTreeMap<u64, (ExtensionSlotId, ExtensionSyscallHandler)>,
    proc_claims: BTreeMap<&'static [u8], (ExtensionSlotId, ExtensionProcRender)>,
}

impl ExtensionTable {
    /// The table with no extensions: Hermit's composition.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether no extension, syscall handler, or proc claim is
    /// registered.
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty() && self.syscalls.is_empty() && self.proc_claims.is_empty()
    }

    /// The registered extension names, in slot order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.extensions.iter().map(|extension| extension.name)
    }

    pub(crate) fn new_slots(&self) -> Box<[Option<Box<dyn ExtensionState>>]> {
        self.extensions
            .iter()
            .map(|extension| Some((extension.factory)()))
            .collect()
    }

    pub(crate) fn clone_slots(
        &self,
        parent: &[Option<Box<dyn ExtensionState>>],
        clone: ExtensionClone,
    ) -> Box<[Option<Box<dyn ExtensionState>>]> {
        parent
            .iter()
            .map(|slot| slot.as_ref().map(|state| state.on_clone(clone)))
            .collect()
    }

    pub(crate) fn syscall(
        &self,
        number: u64,
    ) -> Option<(ExtensionSlotId, ExtensionSyscallHandler)> {
        self.syscalls.get(&number).copied()
    }

    pub(crate) fn proc_claim(&self, path: &[u8]) -> Option<(ExtensionSlotId, ExtensionProcRender)> {
        self.proc_claims.get(path).copied()
    }
}

/// Builds an [`ExtensionTable`], refusing registrations that would
/// break the fixed precedence or name the same surface twice.
#[derive(Debug, Default)]
pub struct ExtensionTableBuilder {
    extensions: Vec<Extension>,
    syscalls: BTreeMap<u64, (ExtensionSlotId, ExtensionSyscallHandler)>,
    proc_claims: BTreeMap<&'static [u8], (ExtensionSlotId, ExtensionProcRender)>,
}

impl ExtensionTableBuilder {
    /// Registers one extension and returns the slot its per-task
    /// state will occupy.
    pub fn register_extension(
        &mut self,
        name: &'static str,
        factory: ExtensionStateFactory,
    ) -> ExtensionSlotId {
        let slot = ExtensionSlotId(self.extensions.len());
        self.extensions.push(Extension { name, factory });
        slot
    }

    fn check_slot(&self, slot: ExtensionSlotId) -> Result<(), ExtensionRegistrationError> {
        if slot.get() < self.extensions.len() {
            Ok(())
        } else {
            Err(ExtensionRegistrationError::UnknownSlot { slot: slot.get() })
        }
    }

    /// Registers `handler` for syscall `number`, answered only when
    /// the core dispatch has no arm for it.
    pub fn register_syscall(
        &mut self,
        slot: ExtensionSlotId,
        number: u64,
        handler: ExtensionSyscallHandler,
    ) -> Result<(), ExtensionRegistrationError> {
        self.check_slot(slot)?;
        if crate::executor::is_tool_decided_syscall(number) {
            return Err(ExtensionRegistrationError::ToolDecidedSyscall { number });
        }
        if self.syscalls.contains_key(&number) {
            return Err(ExtensionRegistrationError::DuplicateSyscall { number });
        }
        self.syscalls.insert(number, (slot, handler));
        Ok(())
    }

    /// Registers `render` for the normalized synthetic proc `path`,
    /// served only when the core serves no content for it.
    pub fn register_proc_claim(
        &mut self,
        slot: ExtensionSlotId,
        path: &'static [u8],
        render: ExtensionProcRender,
    ) -> Result<(), ExtensionRegistrationError> {
        self.check_slot(slot)?;
        if !path.starts_with(b"/proc/self/") || path.contains(&0) {
            return Err(ExtensionRegistrationError::InvalidProcPath { path });
        }
        if self.proc_claims.contains_key(path) {
            return Err(ExtensionRegistrationError::DuplicateProcClaim { path });
        }
        self.proc_claims.insert(path, (slot, render));
        Ok(())
    }

    /// The immutable table these registrations compose.
    pub fn build(self) -> ExtensionTable {
        ExtensionTable {
            extensions: self.extensions,
            syscalls: self.syscalls,
            proc_claims: self.proc_claims,
        }
    }
}

/// The narrow facade an extension syscall handler runs against: the
/// request, this task's identity, checked guest-memory copies (the
/// same `copy_from_user`/`copy_to_user` rules the core arms use),
/// and its own slot. Nothing else: no raw task state, no host file
/// system or syscalls, no time, no randomness, and no scheduler.
pub struct ExtensionCtx<'a> {
    number: u64,
    args: [u64; 6],
    pid: i32,
    tid: i32,
    memory: ProviderMemory<'a>,
    state: &'a mut dyn ExtensionState,
}

impl<'a> ExtensionCtx<'a> {
    pub(crate) fn new(
        memory: &'a GuestMemory,
        state: &'a mut LoadedStaticElf,
        slot: ExtensionSlotId,
        number: u64,
        args: [u64; 6],
    ) -> Option<Self> {
        let pid = state.pid;
        let tid = state.tid;
        let slot = state.extensions.get_mut(slot.get())?.as_deref_mut()?;
        Some(Self {
            number,
            args,
            pid,
            tid,
            memory: ProviderMemory(memory),
            state: slot,
        })
    }

    /// The syscall number being answered.
    pub const fn number(&self) -> u64 {
        self.number
    }

    /// The syscall's six argument words.
    pub const fn args(&self) -> [u64; 6] {
        self.args
    }

    /// The calling task's thread-group id (`getpid`).
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    /// The calling task's thread-group id; an alias of [`Self::pid`]
    /// under the name proc facts use.
    pub const fn tgid(&self) -> i32 {
        self.pid
    }

    /// The calling thread's id (`gettid`).
    pub const fn tid(&self) -> i32 {
        self.tid
    }

    /// This task's own extension slot.
    pub fn state(&self) -> &dyn ExtensionState {
        self.state
    }

    /// This task's own extension slot, mutably.
    pub fn state_mut(&mut self) -> &mut dyn ExtensionState {
        self.state
    }

    /// This task's slot as the owning extension's concrete state.
    pub fn state_as<T: ExtensionState>(&self) -> Option<&T> {
        self.state.as_any().downcast_ref()
    }

    /// This task's slot as the owning extension's concrete state,
    /// mutably.
    pub fn state_as_mut<T: ExtensionState>(&mut self) -> Option<&mut T> {
        self.state.as_any_mut().downcast_mut()
    }

    /// `copy_from_user`, all or nothing.
    pub fn read_exact(&self, address: u64, destination: &mut [u8]) -> crate::Result<()> {
        self.memory.read_exact(address, destination)
    }

    /// `copy_from_user` of the longest readable prefix.
    pub fn copy_from_user_prefix(
        &self,
        address: u64,
        destination: &mut [u8],
    ) -> crate::Result<usize> {
        self.memory.copy_from_user_prefix(address, destination)
    }

    /// Stores all of `source` if every byte is mapped user memory.
    pub fn write_exact(&self, address: u64, source: &[u8]) -> crate::Result<()> {
        self.memory.write_exact(address, source)
    }

    /// Linux `copy_to_user`: the writable prefix stays stored even
    /// when the whole copy faults.
    pub fn copy_to_user(&self, address: u64, source: &[u8]) -> crate::Result<()> {
        self.memory.copy_to_user(address, source)
    }

    /// [`Self::copy_to_user`], returning the stored prefix length.
    pub fn copy_to_user_prefix(&self, address: u64, source: &[u8]) -> crate::Result<usize> {
        self.memory.copy_to_user_prefix(address, source)
    }

    /// Linux `put_user` of a 32-bit value.
    pub fn put_user_i32(&self, address: u64, value: i32) -> crate::Result<()> {
        self.memory.put_user_i32(address, value)
    }

    /// Linux `put_user` of a 64-bit value.
    pub fn put_user_u64(&self, address: u64, value: u64) -> crate::Result<()> {
        self.memory.put_user_u64(address, value)
    }
}

/// One memory mapping in a [`ProcFacts`] snapshot, as
/// `/proc/<pid>/maps` reports it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcMapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub name: Option<String>,
}

/// The core-owned facts an extension proc claim renders from. The
/// core builds the snapshot and owns the seq/carrier machinery; the
/// claim returns content bytes or declines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcFacts {
    pub pid: i32,
    pub ppid: i32,
    pub tgid: i32,
    /// The calling thread's `comm`, without its terminating NUL.
    pub comm: Vec<u8>,
    /// The thread-group leader's `comm`, without its terminating NUL.
    pub leader_name: Vec<u8>,
    pub umask: libc::mode_t,
    pub maps: Vec<ProcMapEntry>,
}

fn comm_bytes(name: &[u8; TASK_COMM_LEN]) -> Vec<u8> {
    let length = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(TASK_COMM_LEN);
    name[..length].to_vec()
}

impl ProcFacts {
    pub(crate) fn of_state(state: &LoadedStaticElf) -> Self {
        let leader_name = {
            let name = state
                .thread_group_leader_name
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            comm_bytes(&name)
        };
        Self {
            pid: state.pid,
            ppid: state.guest_parent_pid(),
            tgid: state.pid,
            comm: comm_bytes(&state.thread_name),
            leader_name,
            umask: state.fs_context.umask,
            maps: vec![ProcMapEntry {
                start: crate::memory::USER_ADDRESS_END - STACK_LIMIT,
                end: crate::memory::USER_STACK_TOP,
                perms: "rw-p".to_owned(),
                offset: 0,
                dev_major: 0,
                dev_minor: 0,
                inode: 0,
                name: Some("[stack]".to_owned()),
            }],
        }
    }
}

impl LoadedStaticElf {
    /// Installs `table` as this task's extension composition and
    /// creates its slots from the factories. Composition installs a
    /// table on the loaded state before handing it to a backend, or
    /// through a backend setter on its loaded image where the backend
    /// owns the loading.
    pub fn install_extension_table(&mut self, table: Arc<ExtensionTable>) {
        let slots = table.new_slots();
        self.extension_table = table;
        self.extensions = slots;
    }

    /// This task's extension composition.
    pub fn extension_table(&self) -> &Arc<ExtensionTable> {
        &self.extension_table
    }

    pub(crate) fn clone_extension_slots(
        &self,
        clone: ExtensionClone,
    ) -> Box<[Option<Box<dyn ExtensionState>>]> {
        self.extension_table.clone_slots(&self.extensions, clone)
    }

    /// The extension content for a normalized synthetic proc path
    /// the core does not serve, if a claim renders it.
    pub(crate) fn extension_proc_content(&self, normalized_path: &[u8]) -> Option<Vec<u8>> {
        let table = self.extension_table.clone();
        let (slot, render) = table.proc_claim(normalized_path)?;
        let state = self.extensions.get(slot.get())?.as_deref()?;
        render(state, &ProcFacts::of_state(self))
    }
}

/// Answers `number` from `state`'s extension table, or `None` when
/// no extension registered it. Called only from the core dispatch's
/// default arm, so a core arm always wins over an extension.
pub(crate) fn execute_extension_syscall(
    memory: &GuestMemory,
    state: &mut LoadedStaticElf,
    number: u64,
    args: &[u64; 6],
) -> Option<i64> {
    if state.extension_table.is_empty() {
        return None;
    }
    let table = state.extension_table.clone();
    let (slot, handler) = table.syscall(number)?;
    let mut ctx = ExtensionCtx::new(memory, state, slot, number, *args)?;
    Some(handler(&mut ctx))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::executor::native_loaded_state;

    const TEST_SYSCALL: u64 = 9999;

    #[derive(Debug)]
    struct TestState {
        value: i64,
        cloned_as: Option<(ExtensionCloneKind, u64)>,
    }

    impl ExtensionState for TestState {
        fn on_clone(&self, clone: ExtensionClone) -> Box<dyn ExtensionState> {
            Box::new(Self {
                value: self.value,
                cloned_as: Some((clone.kind(), clone.flags())),
            })
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
    }

    fn test_factory() -> Box<dyn ExtensionState> {
        Box::new(TestState {
            value: 7,
            cloned_as: None,
        })
    }

    fn test_handler(ctx: &mut ExtensionCtx<'_>) -> i64 {
        let add = ctx.args()[0] as i64;
        let state = ctx
            .state_as_mut::<TestState>()
            .expect("handler runs with its own slot");
        state.value += add;
        state.value
    }

    fn test_render(state: &dyn ExtensionState, facts: &ProcFacts) -> Option<Vec<u8>> {
        let state = state.as_any().downcast_ref::<TestState>()?;
        Some(
            format!(
                "{}:{}:{}\n",
                facts.pid,
                String::from_utf8_lossy(&facts.comm),
                state.value
            )
            .into_bytes(),
        )
    }

    fn test_table() -> Arc<ExtensionTable> {
        let mut builder = ExtensionTableBuilder::default();
        let slot = builder.register_extension("test", test_factory);
        builder
            .register_syscall(slot, TEST_SYSCALL, test_handler)
            .expect("test syscall registers");
        builder
            .register_proc_claim(slot, b"/proc/self/test-extension", test_render)
            .expect("test proc claim registers");
        Arc::new(builder.build())
    }

    fn slot_value(state: &LoadedStaticElf) -> i64 {
        state.extensions[0]
            .as_deref()
            .expect("slot is populated")
            .as_any()
            .downcast_ref::<TestState>()
            .expect("slot holds the test state")
            .value
    }

    fn set_slot_value(state: &mut LoadedStaticElf, value: i64) {
        state.extensions[0]
            .as_deref_mut()
            .expect("slot is populated")
            .as_any_mut()
            .downcast_mut::<TestState>()
            .expect("slot holds the test state")
            .value = value;
    }

    #[test]
    fn registration_refusals_are_named() {
        let mut builder = ExtensionTableBuilder::default();
        let slot = builder.register_extension("test", test_factory);
        builder
            .register_syscall(slot, TEST_SYSCALL, test_handler)
            .expect("first registration succeeds");
        assert!(matches!(
            builder.register_syscall(slot, TEST_SYSCALL, test_handler),
            Err(ExtensionRegistrationError::DuplicateSyscall { number }) if number == TEST_SYSCALL
        ));
        assert!(matches!(
            builder.register_syscall(slot, libc::SYS_getuid as u64, test_handler),
            Err(ExtensionRegistrationError::ToolDecidedSyscall { .. })
        ));
        assert!(matches!(
            builder.register_syscall(ExtensionSlotId(99), TEST_SYSCALL + 1, test_handler),
            Err(ExtensionRegistrationError::UnknownSlot { slot: 99 })
        ));
        builder
            .register_proc_claim(slot, b"/proc/self/test-extension", test_render)
            .expect("first claim succeeds");
        assert!(matches!(
            builder.register_proc_claim(slot, b"/proc/self/test-extension", test_render),
            Err(ExtensionRegistrationError::DuplicateProcClaim { .. })
        ));
        assert!(matches!(
            builder.register_proc_claim(slot, b"/etc/passwd", test_render),
            Err(ExtensionRegistrationError::InvalidProcPath { .. })
        ));
    }

    #[test]
    fn empty_table_has_no_slots_or_answers() {
        let state = native_loaded_state(Path::new("/"));
        assert!(state.extension_table.is_empty(), "default table is empty");
        assert!(state.extensions.is_empty(), "empty table makes no slots");
        assert_eq!(
            state.extension_proc_content(b"/proc/self/test-extension"),
            None
        );
    }

    #[test]
    fn dispatch_and_proc_claim_use_the_owning_slot() {
        let mut state = native_loaded_state(Path::new("/"));
        state.install_extension_table(test_table());
        let memory = GuestMemory::new(0, 4096).expect("test guest memory");
        assert_eq!(
            execute_extension_syscall(&memory, &mut state, TEST_SYSCALL, &[5, 0, 0, 0, 0, 0]),
            Some(12),
            "factory value 7 plus the first argument"
        );
        assert_eq!(
            execute_extension_syscall(&memory, &mut state, TEST_SYSCALL, &[5, 0, 0, 0, 0, 0]),
            Some(17),
            "the slot persists across calls of one task"
        );
        assert_eq!(
            execute_extension_syscall(&memory, &mut state, TEST_SYSCALL + 1, &[0; 6]),
            None,
            "an unregistered number stays the core default's"
        );
        assert_eq!(
            state.extension_proc_content(b"/proc/self/test-extension"),
            Some(b"1:test:17\n".to_vec()),
            "the claim renders core facts with its own slot"
        );
        assert_eq!(state.extension_proc_content(b"/proc/self/other"), None);
    }

    #[test]
    fn clone_slots_carry_kind_and_flags_and_stay_per_task() {
        let table = test_table();
        let parent = table.new_slots();
        for clone in [
            ExtensionClone::process_fork(0),
            ExtensionClone::thread(libc::CLONE_VM as u64 | libc::CLONE_THREAD as u64),
            ExtensionClone::vfork(libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64),
        ] {
            let mut child = table.clone_slots(&parent, clone);
            let child_state = child[0]
                .as_deref_mut()
                .expect("child slot is populated")
                .as_any_mut()
                .downcast_mut::<TestState>()
                .expect("child slot holds the test state");
            assert_eq!(child_state.cloned_as, Some((clone.kind(), clone.flags())));
            child_state.value = 99;
        }
        let parent_state = parent[0]
            .as_deref()
            .expect("parent slot is populated")
            .as_any()
            .downcast_ref::<TestState>()
            .expect("parent slot holds the test state");
        assert_eq!(
            parent_state.value, 7,
            "child slots never alias the parent's"
        );
    }

    #[test]
    fn factory_produces_independent_slots_per_task() {
        // The task-owned-state obligation, witnessed for a conforming
        // factory: two tasks' slots from one factory share nothing.
        let table = test_table();
        let mut first = table.new_slots();
        let second = table.new_slots();
        first[0]
            .as_deref_mut()
            .expect("first slot is populated")
            .as_any_mut()
            .downcast_mut::<TestState>()
            .expect("first slot holds the test state")
            .value = 99;
        let second_value = second[0]
            .as_deref()
            .expect("second slot is populated")
            .as_any()
            .downcast_ref::<TestState>()
            .expect("second slot holds the test state")
            .value;
        assert_eq!(second_value, 7, "one task's slot never aliases another's");
    }

    #[test]
    fn process_clone_kind_comes_from_the_vfork_flag() {
        let vm = libc::CLONE_VM as u64;
        let vfork = vm | libc::CLONE_VFORK as u64;
        assert_eq!(
            ExtensionClone::for_process(0).kind(),
            ExtensionCloneKind::ProcessFork
        );
        assert_eq!(
            ExtensionClone::for_process(vfork).kind(),
            ExtensionCloneKind::Vfork
        );
        // A VM-only process clone is not a vfork; the raw flags
        // remain authoritative for the combination.
        let vm_only = ExtensionClone::for_process(vm);
        assert_eq!(vm_only.kind(), ExtensionCloneKind::ProcessFork);
        assert_eq!(vm_only.flags(), vm);
    }

    #[test]
    fn fork_clones_slots_and_exec_recreates_them() {
        let mut parent = native_loaded_state(Path::new("/"));
        parent.install_extension_table(test_table());
        set_slot_value(&mut parent, 33);

        let mut child = parent
            .try_clone_for_fork(2)
            .expect("fork clone of the test state");
        assert_eq!(slot_value(&child), 33, "fork derives the child slot");
        set_slot_value(&mut child, 44);
        assert_eq!(slot_value(&parent), 33, "the forked slot is independent");

        // A failed exec never replaces the state, so the parent slot
        // above is still the identical object; a successful one drops
        // it and recreates from the factory under the carried table.
        let mut replacement = native_loaded_state(Path::new("/"));
        replacement.inherit_process_state(parent);
        assert_eq!(slot_value(&replacement), 7, "exec recreates slots");
        assert_eq!(
            replacement.extension_table.names().collect::<Vec<_>>(),
            ["test"],
            "exec carries the composition"
        );
    }
}
