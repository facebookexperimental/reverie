/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! DynamoRIO backend prototype for in-process Reverie tools.
//!
//! The native client performs hot-path instruction rewriting while this crate
//! adapts DynamoRIO events to Reverie's shared [`reverie::Tool`] and
//! [`reverie::Guest`] contracts.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod counter;
mod launcher;
pub mod sync_rpc;
#[cfg(feature = "prototype-runtime")]
mod tools;

use std::collections::HashSet;
use std::ffi::c_void;
use std::future::Future;
use std::path::Path;
use std::pin::pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

// TODO-HUMAN-REVIEW(PR-134): Review the native bootstrap failure ABI export.
pub use launcher::CLIENT_THREAD_START_FAILURE_EXIT_CODE;
pub use launcher::DbiRunner;
use reverie::Backtrace;
use reverie::Error;
use reverie::ExitStatus;
use reverie::Frame;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Never;
use reverie::Pid;
use reverie::Stack;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::FcntlCmd;
use reverie::syscalls::PathPtr;
use reverie::syscalls::ReadAddr;
use reverie::syscalls::Syscall;
#[cfg(any(feature = "prototype-runtime", test))]
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_memory::LocalMemory;
use reverie_memory::MemoryAccess;
use serde::Deserialize;
use serde::Serialize;

/// Native callback used to issue a syscall with DynamoRIO bookkeeping.
pub type SyscallInvoker = unsafe extern "C" fn(usize, i64, *const u64) -> i64;

/// Native callback used to translate DynamoRIO's machine context.
pub type RegisterReader = unsafe extern "C" fn(usize, *mut libc::user_regs_struct) -> i32;

/// Native callback used to overwrite DynamoRIO's machine context. The write
/// counterpart to [`RegisterReader`]; returns nonzero on success.
pub type RegisterWriter = unsafe extern "C" fn(usize, *const libc::user_regs_struct) -> i32;

/// Native callback used to copy application memory with DynamoRIO fault handling.
pub type MemoryReader = unsafe extern "C" fn(usize, *mut u8, usize) -> i32;

// TODO-HUMAN-REVIEW(PR-66): Confirm the external runtime callback ABI.
/// Native callback used to emit runtime diagnostics without re-entering guest I/O.
pub type RuntimeEmitter = unsafe extern "C" fn(*const u8, usize);

// TODO-HUMAN-REVIEW(PR-66): Confirm the external runtime callback ABI.
/// Native callback that yields a DBI client thread at a DynamoRIO-safe point.
pub type RuntimeIdler = unsafe extern "C" fn();

// TODO-HUMAN-REVIEW(PR-66): Confirm the C-compatible callback layout.
/// Callbacks supplied to an external Tool runtime on its background client thread.
#[repr(C)]
pub struct DbiRuntimeCallbacks {
    /// Emits already-formatted runtime output through DynamoRIO.
    pub emit: RuntimeEmitter,
    /// Yields while an async runtime future remains pending.
    pub idle: RuntimeIdler,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-84): Review the persistent fail-closed client policy ABI.
    /// Nonzero when the persistent client policy requires unsupported syscalls to fail closed.
    pub panic_on_unsupported_syscalls: i32,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-84): Review the private report descriptor ABI.
    /// DynamoRIO-owned descriptor for aggregate unsupported-syscall records.
    pub unsupported_report_fd: i32,
    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-162): Review the additive stdout emit callback ABI.
    /// Re-entrancy-safe emitter for real stdout, used by tools that suppress and
    /// later re-emit guest stdout bytes (e.g. `chunky_print`). Added at the end
    /// of the struct so the existing field layout matches the C
    /// `runtime_callbacks_t`.
    pub emit_stdout: RuntimeEmitter,
}

/// Result of dispatching a syscall through an external DBI Tool.
// TODO-HUMAN-REVIEW(PR-154): Review the deferred native lifecycle syscall API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbiSyscallOutcome {
    /// Suppress the original syscall and install this return value.
    Suppress(i64),
    /// Execute this syscall through DynamoRIO after the Rust callback returns.
    ExecuteOriginal(Syscall),
}

/// In-process guest state passed to a Reverie tool handler.
pub struct DbiGuest<'a, T>
where
    T: Tool,
{
    context: usize,
    tid: Pid,
    pid: Pid,
    ppid: Option<Pid>,
    branch_count: u64,
    thread_state: &'a mut T::ThreadState,
    global_state: &'a T::GlobalState,
    config: &'a <T::GlobalState as GlobalTool>::Config,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
    tail_inject_result: Arc<TailInjectResult>,
}

impl<'a, T> DbiGuest<'a, T>
where
    T: Tool,
{
    /// Creates a DBI guest adapter for an external Reverie tool runtime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: usize,
        tid: Pid,
        pid: Pid,
        ppid: Option<Pid>,
        branch_count: u64,
        thread_state: &'a mut T::ThreadState,
        global_state: &'a T::GlobalState,
        config: &'a <T::GlobalState as GlobalTool>::Config,
        invoke_syscall: SyscallInvoker,
        read_registers: RegisterReader,
        write_registers: RegisterWriter,
    ) -> Self {
        Self {
            context,
            tid,
            pid,
            ppid,
            branch_count,
            thread_state,
            global_state,
            config,
            invoke_syscall,
            read_registers,
            write_registers,
            tail_inject_result: Arc::new(TailInjectResult::default()),
        }
    }
}

struct DbiGlobal<'a, T>
where
    T: Tool,
{
    tid: Pid,
    global_state: &'a T::GlobalState,
    config: &'a <T::GlobalState as GlobalTool>::Config,
}

#[reverie::tool]
impl<T> GlobalRPC<T::GlobalState> for DbiGlobal<'_, T>
where
    T: Tool,
{
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(#121): Review cross-process GlobalState RPC routing.
        // When a coordinator socket is configured, route the RPC to the single
        // shared GlobalState hosted out-of-process; otherwise fall back to the
        // in-process (per-process) global state.
        if crate::sync_rpc::is_active() {
            crate::sync_rpc::send_rpc(self.tid, message)
        } else {
            self.global_state.receive_rpc(self.tid, message).await
        }
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.config
    }
}

#[reverie::tool]
impl<T> GlobalRPC<T::GlobalState> for DbiGuest<'_, T>
where
    T: Tool,
{
    async fn send_rpc(
        &self,
        message: <T::GlobalState as GlobalTool>::Request,
    ) -> <T::GlobalState as GlobalTool>::Response {
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(#121): Review cross-process GlobalState RPC routing.
        // See `DbiGlobal::send_rpc`: prefer the cross-process coordinator when
        // one is configured, so fork/exec children share one GlobalState.
        if crate::sync_rpc::is_active() {
            crate::sync_rpc::send_rpc(self.tid, message)
        } else {
            self.global_state.receive_rpc(self.tid, message).await
        }
    }

    fn config(&self) -> &<T::GlobalState as GlobalTool>::Config {
        self.config
    }
}

#[reverie::tool]
impl<T> Guest<T> for DbiGuest<'_, T>
where
    T: Tool,
{
    type Memory = LocalMemory;
    type Stack = DbiStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-ratchet11): Review the DBI in-tree parent surface.
    fn ppid(&self) -> Option<Pid> {
        // The real in-tree parent pid, or `None` for the root of the traced
        // tree, matching `pid()`/`tid()` reporting real host ids. The native
        // client already tracks the process tree across `clone`/`fork` (it
        // follows children with `-follow_children`) and supplies this value at
        // thread initialization via `current_ppid`; the tree root reports `None`
        // because its real parent is the out-of-tree launcher. This also makes
        // the `is_root_process` default (`ppid().is_none()`) correct for forked
        // children, which previously always looked like roots.
        self.ppid
    }

    fn memory(&self) -> Self::Memory {
        LocalMemory::new()
    }

    fn thread_state_mut(&mut self) -> &mut T::ThreadState {
        self.thread_state
    }

    fn thread_state(&self) -> &T::ThreadState {
        self.thread_state
    }

    async fn regs(&mut self) -> libc::user_regs_struct {
        let mut regs = unsafe { std::mem::zeroed() };
        let read = unsafe { (self.read_registers)(self.context, &mut regs) };
        assert_ne!(read, 0, "DynamoRIO failed to translate the guest registers");
        regs
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-167): Review the DBI guest register-write path.
    async fn set_regs(&mut self, regs: libc::user_regs_struct) -> Result<(), Error> {
        // The write counterpart to `regs()`: hand the tool-supplied register
        // file to the native `dr_set_mcontext` callback. DynamoRIO applies the
        // modified integer context when the guest resumes from this syscall
        // stop; the instruction pointer is not written (DynamoRIO ignores it
        // outside kernel-transfer events), matching `set_regs`'s contract of
        // controlling the register file at a stop rather than redirecting flow.
        let wrote = unsafe { (self.write_registers)(self.context, &regs) };
        if wrote == 0 {
            return Err(Errno::EIO.into());
        }
        Ok(())
    }

    async fn stack(&mut self) -> Self::Stack {
        DbiStack::new()
    }

    async fn daemonize(&mut self) {}

    async fn inject<S: SyscallInfo>(&mut self, syscall: S) -> Result<i64, Errno> {
        let (number, args) = syscall.into_parts();
        let args = [
            args.arg0 as u64,
            args.arg1 as u64,
            args.arg2 as u64,
            args.arg3 as u64,
            args.arg4 as u64,
            args.arg5 as u64,
        ];
        let result =
            unsafe { (self.invoke_syscall)(self.context, number.id() as i64, args.as_ptr()) };
        Errno::from_ret(result as usize).map(|value| value as i64)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-154): Review exact syscall deferral for DBI tail injection.
    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        // A tail injection never resumes the handler, so execute it only after
        // this future and every Rust state borrow have been dropped. Besides
        // preserving DynamoRIO lifecycle bookkeeping, this keeps blocking calls
        // such as futex out of `dr_invoke_syscall_as_app`.
        let (number, args) = syscall.into_parts();
        self.tail_inject_result
            .set_execute_original(Syscall::from_raw(number, args));
        std::future::pending().await
    }

    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        // A working timer needs a retired-conditional-branch threshold trap
        // installed in the native DynamoRIO client; the branch counter is
        // currently only sampled at syscall boundaries, never armed.
        // TODO-STUB(#31): arm an RCB threshold in the native client and
        // dispatch `Tool::handle_timer_event`.
        Err(Errno::ENOSYS.into())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        // Precise timers additionally require single-stepping to the exact
        // instruction, which the native client does not implement.
        // TODO-STUB(#31): add RCB + single-step delivery in the native client.
        Err(Errno::ENOSYS.into())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        // Coarse: this is the retired-conditional-branch count sampled by the
        // native client at the most recent syscall entry, not a continuously
        // updated clock. Adequate for ordering at syscall boundaries only.
        // TODO-STUB(#31): expose a continuously updated RCB read from the
        // native client for sub-syscall resolution.
        Ok(self.branch_count)
    }

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-ratchet16): Review the DBI in-process guest backtrace.
    fn backtrace(&mut self) -> Option<Backtrace> {
        // The DBI Tool runs *in-process*, in the guest's own address space, so a
        // backtrace needs no remote unwinder (unlike ptrace, which unwinds the
        // tracee over `/proc/pid/mem` with libunwind): the guest stack is
        // directly readable here. Seed the walk with the guest's translated
        // register file — the same `dr_get_mcontext` source `regs()` uses — and
        // follow the x86-64 saved-frame-pointer chain. Every stack read goes
        // through `process_vm_readv` on our own process so a truncated or wild
        // frame pointer ends the trace instead of raising SIGSEGV, which in a DBI
        // handler would abort the entire DynamoRIO process. This requires frame
        // pointers in the guest (`-fno-omit-frame-pointer`); full DWARF-CFI
        // unwinding (as reverie-ptrace gets from libunwind) would be a strictly
        // larger, separate increment.
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let read = unsafe { (self.read_registers)(self.context, &mut regs) };
        if read == 0 {
            return None;
        }

        let mut frames = Vec::new();
        // Frame 0 is the current instruction pointer.
        frames.push(Frame {
            ip: regs.rip,
            is_signal: false,
        });

        // Walk the saved-frame-pointer chain: on x86-64 with frame pointers,
        // `[rbp]` holds the caller's saved `rbp` and `[rbp + 8]` holds the return
        // address into the caller.
        let mut fp = regs.rbp;
        // Bound the depth so a corrupt or self-referential chain can never spin;
        // real stacks are far shallower than this.
        const MAX_FRAMES: usize = 256;
        while frames.len() < MAX_FRAMES {
            // A null or unaligned frame pointer is not a valid frame base.
            if fp == 0 || !fp.is_multiple_of(std::mem::align_of::<u64>() as u64) {
                break;
            }
            let Some(saved_fp) = read_guest_word(fp) else {
                break;
            };
            let Some(return_addr) = read_guest_word(fp.wrapping_add(8)) else {
                break;
            };
            if return_addr == 0 {
                break;
            }
            frames.push(Frame {
                ip: return_addr,
                is_signal: false,
            });
            // The chain must strictly ascend: the stack grows down, so each
            // caller frame sits at a higher address. A non-increasing link is a
            // cycle or garbage, so stop rather than loop or wander.
            if saved_fp <= fp {
                break;
            }
            fp = saved_fp;
        }

        Some(Backtrace::new(self.tid(), frames))
    }
}

/// Reads one 64-bit word at `addr` from the current process using
/// `process_vm_readv`, which reports an out-of-bounds address as a short/failed
/// read rather than raising `SIGSEGV`. Used by the DBI [`Guest::backtrace`]
/// frame-pointer walk so a bad guest frame pointer ends the trace safely instead
/// of aborting the whole DynamoRIO process.
fn read_guest_word(addr: u64) -> Option<u64> {
    let mut value: u64 = 0;
    let local = libc::iovec {
        iov_base: (&mut value as *mut u64).cast::<libc::c_void>(),
        iov_len: std::mem::size_of::<u64>(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: std::mem::size_of::<u64>(),
    };
    // Reading our own address space is always permitted; `getpid()` names it.
    let n = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    if n == std::mem::size_of::<u64>() as isize {
        Some(value)
    } else {
        None
    }
}

/// Capacity, in bytes, of the in-process scratch arena handed out by
/// [`DbiGuest::stack`]. The ptrace backend uses a comparably small window on
/// the tracee's real stack; a page is generous for argument marshalling.
const DBI_STACK_CAPACITY: usize = 4096;

/// In-process guest scratch stack for the DynamoRIO backend.
///
/// The ptrace backend's `GuestStack` allocates on the tracee's real stack and
/// defers writes until `commit`, because the tracer lives in a different
/// address space. The DynamoRIO backend instead shares the guest's address
/// space, so allocations are written immediately into a heap-backed arena and
/// their addresses are valid for injected syscalls as soon as they are made.
/// `commit` transfers ownership of the arena to the returned guard, which keeps
/// the memory alive until it is dropped (mirroring how a `StackGuard` bounds the
/// lifetime of the allocations).
pub struct DbiStack {
    arena: Box<[u8]>,
    offset: usize,
}

impl DbiStack {
    fn new() -> Self {
        Self {
            arena: vec![0u8; DBI_STACK_CAPACITY].into_boxed_slice(),
            offset: 0,
        }
    }

    fn allocate<'stack, T>(&mut self, value: T) -> AddrMut<'stack, T> {
        let size = core::mem::size_of::<T>();
        let align = core::mem::align_of::<T>();
        let base = self.arena.as_ptr() as usize;
        // Align the absolute address (not just the offset) so `T` reads/writes
        // are always aligned regardless of the arena's base alignment.
        let start = align_up(base + self.offset, align) - base;
        let end = start + size;
        assert!(
            end <= self.arena.len(),
            "DBI guest stack overflow: need {end} bytes, capacity {}",
            self.arena.len()
        );
        // In-process: write directly. The pointer is stable across the later
        // move of `arena` into the guard, so the returned address stays valid.
        let ptr = unsafe { self.arena.as_mut_ptr().add(start) } as *mut T;
        unsafe { ptr.write(value) };
        self.offset = end;
        AddrMut::from_raw(ptr as usize).expect("DBI guest stack produced a null scratch pointer")
    }
}

/// Guard that keeps a committed [`DbiStack`] arena alive. Dropping it releases
/// the scratch memory, at which point any addresses handed out become invalid.
pub struct DbiStackGuard {
    _arena: Box<[u8]>,
}

impl Drop for DbiStackGuard {
    fn drop(&mut self) {}
}

impl Stack for DbiStack {
    type StackGuard = DbiStackGuard;

    fn size(&self) -> usize {
        self.offset
    }

    fn capacity(&self) -> usize {
        self.arena.len()
    }

    fn push<'stack, T>(&mut self, value: T) -> Addr<'stack, T> {
        self.allocate(value).into()
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        let value: T = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
        self.allocate(value)
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Ok(DbiStackGuard { _arena: self.arena })
    }
}

/// Rounds `value` up to the next multiple of `align` (a power of two).
fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TailInjectAction {
    ExecuteOriginal(Syscall),
}

#[derive(Debug, Default)]
struct TailInjectResult {
    action: Mutex<Option<TailInjectAction>>,
}

impl TailInjectResult {
    fn clear(&self) {
        *self
            .action
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn set_execute_original(&self, syscall: Syscall) {
        *self
            .action
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(TailInjectAction::ExecuteOriginal(syscall));
    }

    fn take(&self) -> Option<TailInjectAction> {
        self.action
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    fn is_ready(&self) -> bool {
        self.action
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some()
    }
}

/// Per-thread state used by the prototype tool.
#[repr(C)]
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrototypeCounters {
    /// Branches observed by inline DynamoRIO instrumentation.
    pub branches: u64,
    /// Syscall entry events observed by DynamoRIO.
    pub observed_syscalls: u64,
    /// Syscalls executed through [`Guest::inject`] and suppressed at entry.
    pub rewritten_syscalls: u64,
}

/// Tool used by the standalone prototype client.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrototypeTool;

#[reverie::tool]
impl Tool for PrototypeTool {
    type GlobalState = ();
    type ThreadState = PrototypeCounters;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.thread_state_mut().rewritten_syscalls += 1;
        match syscall {
            Syscall::Uname(call) => {
                let result = guest.inject(call).await?;
                if result == 0
                    && let Some(buffer) = call.buf()
                {
                    // Overwrite every host-derived field, not just `release`, so
                    // `nodename` (hostname) and `version` (kernel build string)
                    // cannot leak host- or run-specific values.
                    let mut value = guest.memory().read_value(buffer)?;
                    set_c_string(&mut value.sysname, b"Linux");
                    set_c_string(&mut value.nodename, b"hermit");
                    set_c_string(&mut value.release, b"5.2.0");
                    set_c_string(&mut value.version, b"#1 SMP hermit-deterministic");
                    set_c_string(&mut value.machine, b"x86_64");
                    set_c_string(&mut value.domainname, b"(none)");
                    guest.memory().write_value(buffer, &value)?;
                }
                Ok(result)
            }
            Syscall::Bind(call) => {
                rewrite_bind_port(guest, call)?;
                Ok(guest.inject(call).await?)
            }
            Syscall::Open(call) => handle_open(guest, call.path(), call).await,
            Syscall::Openat(call) => handle_open(guest, call.path(), call).await,
            Syscall::Read(call) if is_random_fd(call.fd()) => {
                write_deterministic_random(guest, call.buf(), call.len())
            }
            Syscall::Pread64(call) if is_random_fd(call.fd()) => {
                write_deterministic_random(guest, call.buf(), call.len())
            }
            Syscall::Readv(call) if is_random_fd(call.fd()) => {
                deterministic_random_readv(guest, call.iov(), call.len())
            }
            Syscall::Preadv(call) if is_random_fd(call.fd()) => {
                deterministic_random_readv(guest, call.iov(), call.iov_len())
            }
            Syscall::Preadv2(call) if is_random_fd(call.fd()) => {
                deterministic_random_readv(guest, call.iov(), call.iov_len() as usize)
            }
            Syscall::Dup(call) => {
                let result = guest.inject(call).await?;
                track_duplicated_fd(call.oldfd(), result);
                Ok(result)
            }
            Syscall::Dup2(call) => {
                let (oldfd, newfd) = (call.oldfd(), call.newfd());
                let result = guest.inject(call).await?;
                track_replacing_fd(oldfd, newfd, result);
                Ok(result)
            }
            Syscall::Dup3(call) => {
                let (oldfd, newfd) = (call.oldfd(), call.newfd());
                let result = guest.inject(call).await?;
                track_replacing_fd(oldfd, newfd, result);
                Ok(result)
            }
            Syscall::Fcntl(call) => {
                let oldfd = call.fd();
                let duplicating = matches!(
                    call.cmd(),
                    FcntlCmd::F_DUPFD(_) | FcntlCmd::F_DUPFD_CLOEXEC(_)
                );
                let result = guest.inject(call).await?;
                if duplicating {
                    track_duplicated_fd(oldfd, result);
                }
                Ok(result)
            }
            Syscall::Close(call) => {
                let result = guest.inject(call).await?;
                if result == 0 {
                    random_fds().remove(&call.fd());
                }
                Ok(result)
            }
            Syscall::Getrandom(call) => deterministic_getrandom(guest, call),
            Syscall::Getrusage(call) => {
                let result = guest.inject(call).await?;
                if result == 0
                    && let Some(usage) = call.usage()
                {
                    guest
                        .memory()
                        .write_value(usage, &unsafe { std::mem::zeroed::<libc::rusage>() })?;
                }
                Ok(result)
            }
            Syscall::Sysinfo(call) => deterministic_sysinfo(guest, call),
            syscall => Ok(guest.inject(syscall).await?),
        }
    }
}

const RNG_SEED_ENV: &str = "HERMIT_DBI_RNG_SEED";

static RANDOM_FDS: LazyLock<Mutex<HashSet<i32>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Global count of 64-bit random words dispensed so far. The deterministic RNG
/// stream is a pure function of `(seed, word position)`, so it does not depend
/// on guest memory layout and is reproducible across hosts.
static RANDOM_WORDS: AtomicU64 = AtomicU64::new(0);

fn random_fds() -> std::sync::MutexGuard<'static, HashSet<i32>> {
    RANDOM_FDS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn is_random_fd(fd: i32) -> bool {
    random_fds().contains(&fd)
}

/// Records that `new_fd` (the return value of `dup`/`fcntl(F_DUPFD*)`) aliases
/// `old_fd`, so reads through the duplicate stay deterministic.
fn track_duplicated_fd(old_fd: i32, new_fd: i64) {
    if new_fd >= 0 && is_random_fd(old_fd) {
        random_fds().insert(new_fd as i32);
    }
}

/// Records the effect of `dup2`/`dup3`, where `new_fd` becomes a copy of
/// `old_fd`, dropping any previous random association on the target descriptor.
fn track_replacing_fd(old_fd: i32, new_fd: i32, result: i64) {
    if result < 0 {
        return;
    }
    let mut fds = random_fds();
    if fds.contains(&old_fd) {
        fds.insert(result as i32);
    } else {
        fds.remove(&new_fd);
    }
}

fn deterministic_proc_content(path: &Path) -> Option<Vec<u8>> {
    match path.to_str()? {
        "/proc/cpuinfo" => Some(b"processor\t: 0\ncpu MHz\t\t: 0.000\n".to_vec()),
        "/proc/self/maps" => {
            Some(b"00400000-00401000 r--p 00000000 00:00 0 [reverie-dbi]\n".to_vec())
        }
        "/proc/self/stat" => {
            let mut contents = String::from("1 (hermit-dbi) R");
            for _ in 0..49 {
                contents.push_str(" 0");
            }
            contents.push('\n');
            Some(contents.into_bytes())
        }
        "/proc/self/status" => Some(
            b"Name:\thermit-dbi\nPid:\t1\nvoluntary_ctxt_switches:\t0\nnonvoluntary_ctxt_switches:\t0\n"
                .to_vec(),
        ),
        _ => None,
    }
}

fn create_memfd(contents: &[u8]) -> Result<i64, Error> {
    let name = b"reverie-dbi-proc\0";
    let fd = Errno::result(unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr() as *const libc::c_char,
            libc::MFD_CLOEXEC,
        )
    })? as i32;
    let written = Errno::result(unsafe {
        libc::write(fd, contents.as_ptr() as *const c_void, contents.len())
    });
    if written != Ok(contents.len() as isize)
        || Errno::result(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }).is_err()
    {
        unsafe { libc::close(fd) };
        return Err(Errno::EIO.into());
    }
    Ok(fd as i64)
}

async fn handle_open<'a, G, S>(
    guest: &mut G,
    path: Option<PathPtr<'a>>,
    call: S,
) -> Result<i64, Error>
where
    G: Guest<PrototypeTool>,
    S: SyscallInfo,
{
    let Some(path) = path else {
        return Ok(guest.inject(call).await?);
    };
    let path = path.read(&guest.memory())?;
    if let Some(contents) = deterministic_proc_content(&path) {
        return create_memfd(&contents);
    }

    let result = guest.inject(call).await?;
    if result >= 0 && matches!(path.to_str(), Some("/dev/random" | "/dev/urandom")) {
        random_fds().insert(result as i32);
    }
    Ok(result)
}

fn configured_rng_seed() -> u64 {
    std::env::var(RNG_SEED_ENV)
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(0)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

/// Fills `bytes` from a reproducible stream indexed by `position` (the absolute
/// 64-bit word offset of the first chunk). The stream depends only on the seed
/// and the word position, never on the destination address, so it is stable
/// across memory layouts and hosts. Bytes are emitted little-endian for
/// host-independence.
fn deterministic_random_bytes(seed: u64, position: u64, bytes: &mut [u8]) {
    for (index, chunk) in bytes.chunks_mut(8).enumerate() {
        let word = position.wrapping_add(index as u64);
        let value = splitmix64(seed ^ splitmix64(word));
        chunk.copy_from_slice(&value.to_le_bytes()[..chunk.len()]);
    }
}

/// Reserves `count` consecutive 64-bit words from the global stream and returns
/// the first word's absolute position.
fn reserve_random_words(count: u64) -> u64 {
    RANDOM_WORDS.fetch_add(count, Ordering::SeqCst)
}

fn write_deterministic_random<G: Guest<PrototypeTool>>(
    guest: &mut G,
    buffer: Option<AddrMut<'_, u8>>,
    length: usize,
) -> Result<i64, Error> {
    if length == 0 {
        return Ok(0);
    }
    let buffer = buffer.ok_or(Errno::EFAULT)?;
    let words = length.div_ceil(8) as u64;
    let position = reserve_random_words(words);
    let mut bytes = vec![0; length];
    deterministic_random_bytes(configured_rng_seed(), position, &mut bytes);
    guest.memory().write_exact(buffer, &bytes)?;
    Ok(length as i64)
}

/// Fills each `iovec` of a `readv`/`preadv` from a random descriptor with the
/// deterministic stream, returning the total number of bytes written.
fn deterministic_random_readv<G: Guest<PrototypeTool>>(
    guest: &mut G,
    iov: Option<Addr<'_, libc::iovec>>,
    iov_count: usize,
) -> Result<i64, Error> {
    let iov = iov.ok_or(Errno::EFAULT)?;
    // Match the kernel's IOV_MAX cap rather than trusting an arbitrary count.
    const IOV_MAX: usize = 1024;
    if iov_count > IOV_MAX {
        return Err(Errno::EINVAL.into());
    }
    let mut vectors = vec![unsafe { std::mem::zeroed::<libc::iovec>() }; iov_count];
    guest.memory().read_values(iov, &mut vectors)?;
    let mut total: usize = 0;
    for vector in &vectors {
        if vector.iov_len == 0 {
            continue;
        }
        let base = AddrMut::<u8>::from_raw(vector.iov_base as usize).ok_or(Errno::EFAULT)?;
        let written = write_deterministic_random(guest, Some(base), vector.iov_len)?;
        total = total.saturating_add(written as usize);
    }
    Ok(total as i64)
}

fn deterministic_getrandom<G: Guest<PrototypeTool>>(
    guest: &mut G,
    call: reverie::syscalls::Getrandom,
) -> Result<i64, Error> {
    // GRND_INSECURE is a valid kernel flag; accept it alongside the others.
    let allowed = (libc::GRND_NONBLOCK | libc::GRND_RANDOM | libc::GRND_INSECURE) as usize;
    if call.flags() & !allowed != 0 {
        return Err(Errno::EINVAL.into());
    }
    write_deterministic_random(guest, call.buf(), call.buflen())
}

fn deterministic_sysinfo<G: Guest<PrototypeTool>>(
    guest: &mut G,
    call: reverie::syscalls::Sysinfo,
) -> Result<i64, Error> {
    let destination = call.info().ok_or(Errno::EFAULT)?;
    let mut info = unsafe { std::mem::zeroed::<libc::sysinfo>() };
    info.uptime = 1;
    info.loads = [0; 3];
    info.totalram = 1024 * 1024 * 1024;
    info.freeram = 512 * 1024 * 1024;
    info.procs = 1;
    info.mem_unit = 1;
    guest.memory().write_value(destination, &info)?;
    Ok(0)
}

#[cfg(any(feature = "prototype-runtime", test))]
fn should_rewrite_syscall(sysnum: i64) -> bool {
    [
        libc::SYS_write,
        libc::SYS_uname,
        libc::SYS_bind,
        libc::SYS_open,
        libc::SYS_openat,
        // AUTONOMOUS-BOT-IMPLEMENTED
        // TODO-HUMAN-REVIEW(#60)
        libc::SYS_creat,
        libc::SYS_stat,
        libc::SYS_fstat,
        libc::SYS_lstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_read,
        libc::SYS_lseek,
        libc::SYS_access,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_pread64,
        libc::SYS_readv,
        libc::SYS_preadv,
        libc::SYS_preadv2,
        libc::SYS_dup,
        libc::SYS_dup2,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_close,
        libc::SYS_getrandom,
        libc::SYS_getrusage,
        libc::SYS_sysinfo,
    ]
    .contains(&sysnum)
}

fn set_c_string(destination: &mut [libc::c_char], value: &[u8]) {
    destination.fill(0);
    for (destination, source) in destination.iter_mut().zip(value) {
        *destination = *source as libc::c_char;
    }
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(32768);

fn deterministic_port(next: &AtomicU16, requested: u16) -> u16 {
    if requested == 0 {
        next.fetch_add(1, Ordering::SeqCst)
    } else {
        next.fetch_max(requested.saturating_add(1), Ordering::SeqCst);
        requested
    }
}

fn rewrite_bind_port<G: Guest<PrototypeTool>>(
    guest: &mut G,
    call: reverie::syscalls::Bind,
) -> Result<(), Error> {
    let Some(address) = call.umyaddr() else {
        return Ok(());
    };
    let family = guest.memory().read_value(address.cast::<u16>())?;
    match family as i32 {
        libc::AF_INET => {
            let address = address.cast::<libc::sockaddr_in>();
            let mut value = guest.memory().read_value(address)?;
            let port = deterministic_port(&NEXT_PORT, u16::from_be(value.sin_port));
            value.sin_port = port.to_be();
            guest.memory().write_value(address, &value)?;
        }
        libc::AF_INET6 => {
            let address = address.cast::<libc::sockaddr_in6>();
            let mut value = guest.memory().read_value(address)?;
            let port = deterministic_port(&NEXT_PORT, u16::from_be(value.sin6_port));
            value.sin6_port = port.to_be();
            guest.memory().write_value(address, &value)?;
        }
        _ => {}
    }
    Ok(())
}

/// Drives an async tool handler on the calling guest thread, returning `Some`
/// when it resolves and `None` when it suspends via [`Guest::tail_inject`].
///
/// The DynamoRIO client invokes each handler synchronously on the guest thread
/// that made the syscall, but Reverie handlers are `async` and may suspend for
/// two distinct reasons that this driver must tell apart:
///
/// 1. A genuine cross-thread wait, such as Detcore awaiting its global
///    scheduler. The driver cooperatively re-polls until the scheduler makes
///    the future ready. It deliberately avoids Rust thread-local park APIs,
///    which are unavailable on DynamoRIO application threads.
///
/// 2. [`Guest::tail_inject`], which performs the syscall, stores its result in
///    the guest-owned [`TailInjectResult`], and then suspends forever. The
///    driver returns `None` as soon as that result appears so the caller can
///    install it and drop the suspended future.
///
/// Handlers that complete on the first poll return `Some` immediately.
fn run_ready<F: Future>(future: F, tail_result: &TailInjectResult) -> Option<F::Output> {
    let mut future = pin!(future);
    // Park this thread while the handler is Pending instead of busy-spinning at
    // 100% CPU. A `Wake` that unparks the current thread resumes a genuinely
    // async handler (e.g. one resumed by a cross-thread wake) promptly, and a
    // short park timeout re-checks `tail_result` defensively in case a wake is
    // ever missed. A diverging handler installs its tail-inject result during
    // the poll that returns Pending, so the `tail_result.is_ready()` arm is
    // reached before any parking. With the synchronous RPC client, RPC handlers
    // now resolve on the first poll and never reach the parking path at all.
    let waker = Waker::from(Arc::new(ThreadUnparkWaker(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return Some(value),
            Poll::Pending if tail_result.is_ready() => return None,
            Poll::Pending => std::thread::park_timeout(std::time::Duration::from_millis(1)),
        }
    }
}

/// A [`Wake`] implementation that unparks a specific thread, so a `Pending`
/// handler future in [`run_ready`] is re-polled promptly when woken rather than
/// via a busy spin.
struct ThreadUnparkWaker(std::thread::Thread);

impl std::task::Wake for ThreadUnparkWaker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Drives an external tool's thread-start lifecycle hook on a DBI guest.
#[allow(clippy::too_many_arguments)]
pub fn run_tool_thread_start<T: Tool>(
    tool: &T,
    context: usize,
    tid: Pid,
    pid: Pid,
    branch_count: u64,
    thread_state: &mut T::ThreadState,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
) -> Result<(), Error> {
    let mut guest = DbiGuest::new(
        context,
        tid,
        pid,
        current_ppid(),
        branch_count,
        thread_state,
        global_state,
        config,
        invoke_syscall,
        read_registers,
        write_registers,
    );
    let tail_result = Arc::clone(&guest.tail_inject_result);
    run_ready(tool.handle_thread_start(&mut guest), &tail_result)
        .expect("thread-start handler unexpectedly tail-injected")
}

/// Drives an external tool's post-exec lifecycle hook on a DBI guest.
#[allow(clippy::too_many_arguments)]
pub fn run_tool_post_exec<T: Tool>(
    tool: &T,
    context: usize,
    tid: Pid,
    pid: Pid,
    branch_count: u64,
    thread_state: &mut T::ThreadState,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
) -> Result<(), Errno> {
    let mut guest = DbiGuest::new(
        context,
        tid,
        pid,
        current_ppid(),
        branch_count,
        thread_state,
        global_state,
        config,
        invoke_syscall,
        read_registers,
        write_registers,
    );
    let tail_result = Arc::clone(&guest.tail_inject_result);
    run_ready(tool.handle_post_exec(&mut guest), &tail_result)
        .expect("post-exec handler unexpectedly tail-injected")
}

/// Drives an external tool's thread-exit lifecycle hook.
pub fn run_tool_thread_exit<T: Tool>(
    tool: &T,
    tid: Pid,
    thread_state: T::ThreadState,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    exit_status: ExitStatus,
) -> Result<(), Error> {
    let global = DbiGlobal::<T> {
        tid,
        global_state,
        config,
    };
    let tail_result = TailInjectResult::default();
    run_ready(
        tool.on_exit_thread(tid, &global, thread_state, exit_status),
        &tail_result,
    )
    .expect("thread-exit handler unexpectedly tail-injected")
}

/// Drives one syscall through an external Reverie tool over [`DbiGuest`].
#[allow(clippy::too_many_arguments)]
pub fn run_tool_syscall<T: Tool>(
    tool: &T,
    context: usize,
    tid: Pid,
    pid: Pid,
    branch_count: u64,
    thread_state: &mut T::ThreadState,
    global_state: &T::GlobalState,
    config: &<T::GlobalState as GlobalTool>::Config,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
) -> Result<DbiSyscallOutcome, Error> {
    let mut guest = DbiGuest::new(
        context,
        tid,
        pid,
        current_ppid(),
        branch_count,
        thread_state,
        global_state,
        config,
        invoke_syscall,
        read_registers,
        write_registers,
    );
    let tail_result = Arc::clone(&guest.tail_inject_result);
    tail_result.clear();
    match run_ready(tool.handle_syscall_event(&mut guest, syscall), &tail_result) {
        Some(result) => result.map(DbiSyscallOutcome::Suppress),
        None => match tail_result
            .take()
            .expect("tool handler suspended without a tail-inject result")
        {
            TailInjectAction::ExecuteOriginal(syscall) => {
                Ok(DbiSyscallOutcome::ExecuteOriginal(syscall))
            }
        },
    }
}

/// Returns the Cargo-vendored DynamoRIO launcher built for this crate.
pub fn bundled_drrun_path() -> &'static Path {
    Path::new(env!("REVERIE_DBI_DYNAMORIO_DRRUN"))
}

/// Returns the Cargo-vendored DynamoRIO CMake package directory.
pub fn bundled_dynamorio_cmake_dir() -> &'static Path {
    Path::new(env!("REVERIE_DBI_DYNAMORIO_CMAKE"))
}

/// Returns the source directory for the native DynamoRIO client.
pub fn native_client_source_dir() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/native"))
}
/// Sentinel stored in [`PROCESS_PPID`] meaning "no in-tree parent" — this
/// process is the root of the traced tree, so [`Guest::ppid`] reports `None`.
const PPID_NONE: i32 = -1;

/// The current process's real in-tree parent pid, supplied once by the native
/// client during thread initialization (see `in_tree_parent_pid` in
/// `native/client.c`), or [`PPID_NONE`] for the tree root. It is a per-process
/// constant — every thread of the process shares one parent — so it is written
/// idempotently by each `reverie_dbi_runtime_thread_init` and read with relaxed
/// ordering. It starts at [`PPID_NONE`] so a guest constructed before native
/// initialization (or in a build without the native runtime) preserves the
/// previous behaviour of reporting no parent rather than a bogus pid.
static PROCESS_PPID: AtomicI32 = AtomicI32::new(PPID_NONE);

/// The in-tree parent pid recorded for this process, or `None` for the tree
/// root. Threaded into every [`DbiGuest`] so `Guest::ppid` (and the
/// `is_root_process` default built on it) reflect the real process tree that the
/// native client follows across `clone`/`fork`.
fn current_ppid() -> Option<Pid> {
    match PROCESS_PPID.load(Ordering::Relaxed) {
        raw if raw > 0 => Some(Pid::from_raw(raw)),
        _ => None,
    }
}

#[cfg(feature = "prototype-runtime")]
static PROTOTYPE_TOOL: PrototypeTool = PrototypeTool;
#[cfg(feature = "prototype-runtime")]
static GLOBAL_STATE: () = ();
#[cfg(feature = "prototype-runtime")]
static CONFIG: () = ();
#[cfg(feature = "prototype-runtime")]
static TOTAL_BRANCHES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "prototype-runtime")]
static TOTAL_SYSCALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "prototype-runtime")]
static TOTAL_REWRITTEN: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "prototype-runtime")]
static IMAGE_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Begins a new DynamoRIO application image and returns its generation.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub extern "C" fn reverie_dbi_runtime_image_init() -> u64 {
    IMAGE_GENERATION.fetch_add(1, Ordering::SeqCst) + 1
}

/// Initializes the prototype state for the current application thread.
///
/// # Safety
///
/// `counters` must point to aligned, writable storage for one counter value and
/// the callback pointers must be valid for the lifetime of the application.
// TODO-HUMAN-REVIEW(PR-131): Review the expanded native thread initialization ABI.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn reverie_dbi_runtime_thread_init(
    counters: *mut PrototypeCounters,
    _context: *mut c_void,
    _tid: i32,
    _pid: i32,
    in_tree_ppid: i32,
    _branches: u64,
    _defer_runtime: i32,
    _invoke_syscall: SyscallInvoker,
    _read_registers: RegisterReader,
    _write_registers: RegisterWriter,
) -> i32 {
    // Record this process's real in-tree parent (or `PPID_NONE` for the tree
    // root) so every `DbiGuest` built afterwards reports it through
    // `Guest::ppid`. A per-process constant; each thread writes the same value.
    PROCESS_PPID.store(in_tree_ppid, Ordering::Relaxed);
    unsafe { counters.write(PrototypeCounters::default()) };
    0
}

/// Observes a natively created child thread in the prototype runtime.
///
/// # Safety
///
/// `counters` must name initialized per-thread storage and the callback pointers
/// must be valid for the lifetime of the application.
// TODO-HUMAN-REVIEW(PR-131): Review the native child-registration ABI.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn reverie_dbi_runtime_thread_created(
    _counters: *mut PrototypeCounters,
    _context: *mut c_void,
    _parent_tid: i32,
    _pid: i32,
    _branches: u64,
    _child_tid: i32,
    _child_tid_addr: u64,
    _flags: u64,
    _invoke_syscall: SyscallInvoker,
    _read_registers: RegisterReader,
    _write_registers: RegisterWriter,
) -> i32 {
    0
}

/// Releases prototype state for an exiting application thread.
///
/// # Safety
///
/// `counters` must be the pointer previously passed to thread initialization.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_thread_exit(_counters: *mut PrototypeCounters) {}

/// Restores prototype state after an exec syscall returns with an error.
///
/// # Safety
///
/// `counters` must be the pointer initialized for the current application thread.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_exec_failed(
    _counters: *mut PrototypeCounters,
    _pid: i32,
) {
}

/// Applies copied-child syscall policy for the built-in prototype runtime.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub extern "C" fn reverie_dbi_runtime_copied_syscall(_sysnum: i64) -> i32 {
    0
}

// TODO-HUMAN-REVIEW(PR-154): Review the deferred lifecycle syscall callback ABI.
unsafe fn write_deferred_syscall(syscall: Syscall, number: *mut i64, args: *mut u64) {
    let (sysno, syscall_args) = syscall.into_parts();
    unsafe { number.write(sysno.id() as i64) };
    let values = [
        syscall_args.arg0 as u64,
        syscall_args.arg1 as u64,
        syscall_args.arg2 as u64,
        syscall_args.arg3 as u64,
        syscall_args.arg4 as u64,
        syscall_args.arg5 as u64,
    ];
    unsafe { std::slice::from_raw_parts_mut(args, values.len()) }.copy_from_slice(&values);
}

/// Handles a DynamoRIO pre-syscall event.
///
/// Returning one asks the native client to suppress the original syscall and
/// install `result`; returning two asks it to execute `deferred_sysnum` with
/// `deferred_args` after the Rust callback returns. Returning zero leaves the
/// syscall unchanged. A negative return terminates the isolated runtime with an
/// enforcement failure.
///
/// # Safety
///
/// The context and callback pointers must remain valid for the call. `counters`,
/// `result`, and `deferred_sysnum` must be writable; `args` and `deferred_args`
/// must each address six syscall arguments.
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_pre_syscall(
    context: *mut c_void,
    counters: *mut PrototypeCounters,
    tid: i32,
    pid: i32,
    _image_generation: u64,
    sysnum: i64,
    args: *const u64,
    branches: u64,
    result: *mut i64,
    deferred_sysnum: *mut i64,
    deferred_args: *mut u64,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
    _read_memory: MemoryReader,
    emit: tools::Emitter,
) -> i32 {
    // NB: `catch_unwind` cannot actually contain a panic here — unwinding out of
    // a handler aborts under the DynamoRIO client (see `Guest::tail_inject`). It
    // is retained only so the same code path is exercised off-DR (unit tests).
    // Handlers therefore must not panic; divergence (tail_inject) suspends
    // instead, which this driver handles explicitly below.
    let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let counters = unsafe { &mut *counters };
        counters.branches = branches;
        counters.observed_syscalls += 1;
        TOTAL_BRANCHES.store(branches, Ordering::Relaxed);
        TOTAL_SYSCALLS.fetch_add(1, Ordering::Relaxed);
        tools::set_emitter(emit);

        let raw_args = unsafe { std::slice::from_raw_parts(args, 6) };

        // If an env-selected observation tool (syscall counter / strace) is
        // active, it handles every syscall via the standard `Tool` trait and
        // supersedes the built-in determinism policy.
        if let Some(outcome) = tools::run_active_tool(
            context as usize,
            tid,
            pid,
            sysnum,
            raw_args,
            branches,
            invoke_syscall,
            read_registers,
            write_registers,
        ) {
            return match outcome {
                DbiSyscallOutcome::Suppress(value) => {
                    unsafe { result.write(value) };
                    TOTAL_REWRITTEN.fetch_add(1, Ordering::Relaxed);
                    1
                }
                DbiSyscallOutcome::ExecuteOriginal(syscall) => {
                    unsafe { write_deferred_syscall(syscall, deferred_sysnum, deferred_args) };
                    2
                }
            };
        }

        if !should_rewrite_syscall(sysnum) {
            return 0;
        }

        let syscall = Syscall::from_raw(
            Sysno::from(sysnum as i32),
            SyscallArgs::new(
                raw_args[0] as usize,
                raw_args[1] as usize,
                raw_args[2] as usize,
                raw_args[3] as usize,
                raw_args[4] as usize,
                raw_args[5] as usize,
            ),
        );
        let mut guest = DbiGuest::new(
            context as usize,
            Pid::from_raw(tid),
            Pid::from_raw(pid),
            current_ppid(),
            branches,
            counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke_syscall,
            read_registers,
            write_registers,
        );
        // Clear any stale tail-inject result before polling; `tail_inject`
        // records a fresh one just before it suspends.
        let tail_result = Arc::clone(&guest.tail_inject_result);
        tail_result.clear();
        let value = match run_ready(
            PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall),
            &tail_result,
        ) {
            Some(Ok(value)) => value,
            Some(Err(Error::Errno(errno))) => -(errno.into_raw() as i64),
            Some(Err(_)) => -(Errno::EIO.into_raw() as i64),
            None => match tail_result.take() {
                Some(TailInjectAction::ExecuteOriginal(syscall)) => {
                    unsafe { write_deferred_syscall(syscall, deferred_sysnum, deferred_args) };
                    return 2;
                }
                None => return 0,
            },
        };
        unsafe { result.write(value) };
        TOTAL_REWRITTEN.fetch_add(1, Ordering::Relaxed);
        1
    }));

    // `catch_unwind` cannot actually catch under DR; a genuine panic aborts
    // before reaching here. An error means "leave the syscall unchanged".
    handled.unwrap_or_default()
}

/// Initializes the built-in prototype runtime on a native client thread.
///
/// The `argument` is a `*const DbiRuntimeCallbacks` (the native
/// `runtime_callbacks_t`). The only field consumed here is `emit_stdout`, a
/// re-entrancy-safe DynamoRIO stdout emitter recorded so tools that suppress and
/// re-emit guest stdout (e.g. `chunky_print`) can flush buffered bytes. This
/// runs on the background client thread before any flush boundary, so the
/// emitter is installed well ahead of the first `exit`/epoch flush.
///
/// # Safety
///
/// `argument` must point to a valid `DbiRuntimeCallbacks` for the call.
// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-162): Review the stdout-emitter init delivery.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_background_init(argument: *mut c_void) {
    if !argument.is_null() {
        let callbacks = unsafe { &*(argument as *const DbiRuntimeCallbacks) };
        tools::set_stdout_emitter(callbacks.emit_stdout);
    }
}

// TODO-HUMAN-REVIEW(PR-66): Confirm process-exit callback ownership semantics.
/// Handles process exit for the built-in synchronous prototype runtime.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub extern "C" fn reverie_dbi_runtime_process_exit() {}

/// Reports whether the built-in prototype runtime is ready for callbacks.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub extern "C" fn reverie_dbi_runtime_ready(_image_generation: u64) -> i32 {
    1
}

/// Returns the name of the built-in DBI runtime for native summary evidence.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub extern "C" fn reverie_dbi_runtime_name() -> *const libc::c_char {
    c"PrototypeTool".as_ptr()
}

/// Returns process-wide prototype counters accumulated at syscall boundaries.
///
/// # Safety
///
/// Each output pointer must be aligned and writable for one `u64`.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_totals(
    branches: *mut u64,
    syscalls: *mut u64,
    rewritten: *mut u64,
    memory_hash: *mut u64,
) {
    unsafe {
        branches.write(TOTAL_BRANCHES.load(Ordering::Relaxed));
        syscalls.write(TOTAL_SYSCALLS.load(Ordering::Relaxed));
        rewritten.write(TOTAL_REWRITTEN.load(Ordering::Relaxed));
        memory_hash.write(0);
    }
    // NB: the syscall-counter tool prints its histogram from the guest's own
    // exit_group syscall (see `tools`), not here — this callback runs on the
    // DynamoRIO client's tiny stack, which overflows while formatting.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes tests that mutate the process-global `RANDOM_FDS` set.
    static RANDOM_FD_TEST_LOCK: Mutex<()> = Mutex::new(());

    unsafe extern "C" fn invoke(_context: usize, sysnum: i64, args: *const u64) -> i64 {
        assert_eq!(sysnum, libc::SYS_write);
        unsafe { *args.add(2) as i64 }
    }

    struct ExpectedInvocation {
        sysnum: i64,
        args: [u64; 6],
        result: i64,
    }

    unsafe extern "C" fn invoke_expected(context: usize, sysnum: i64, args: *const u64) -> i64 {
        let expected = unsafe { &*(context as *const ExpectedInvocation) };
        let actual_args = unsafe { std::slice::from_raw_parts(args, 6) };
        assert_eq!(sysnum, expected.sysnum);
        assert_eq!(actual_args, expected.args);
        expected.result
    }

    unsafe extern "C" fn invoke_uname(_context: usize, sysnum: i64, args: *const u64) -> i64 {
        assert_eq!(sysnum, libc::SYS_uname);
        unsafe { libc::uname(*args as *mut libc::utsname) as i64 }
    }

    unsafe extern "C" fn read_regs(_context: usize, regs: *mut libc::user_regs_struct) -> i32 {
        unsafe { (*regs).rip = 0x1234 };
        1
    }

    /// A register-reader mock for the backtrace walk: seeds `rip` with a fixed
    /// sentinel and `rbp` with the frame-base address passed as `context`, so a
    /// test can point the walk at a hand-built frame chain in its own memory.
    unsafe extern "C" fn read_regs_with_rbp(
        context: usize,
        regs: *mut libc::user_regs_struct,
    ) -> i32 {
        unsafe {
            *regs = std::mem::zeroed();
            (*regs).rip = 0xabc0;
            (*regs).rbp = context as u64;
        }
        1
    }

    /// A register-reader mock that reports the register file is unavailable, so
    /// `backtrace` must give up and return `None`.
    unsafe extern "C" fn read_regs_unavailable(
        _context: usize,
        _regs: *mut libc::user_regs_struct,
    ) -> i32 {
        0
    }

    /// A register-writer mock that succeeds without recording anything, for
    /// tests that build a guest but never exercise `set_regs`.
    unsafe extern "C" fn write_regs_noop(
        _context: usize,
        _regs: *const libc::user_regs_struct,
    ) -> i32 {
        1
    }

    /// A register-writer mock that records the exact register file handed to it
    /// into the `Option<user_regs_struct>` addressed by `context`.
    unsafe extern "C" fn write_regs_capture(
        context: usize,
        regs: *const libc::user_regs_struct,
    ) -> i32 {
        let slot = unsafe { &mut *(context as *mut Option<libc::user_regs_struct>) };
        *slot = Some(unsafe { *regs });
        1
    }

    /// A register-writer mock that reports failure, so the guest surfaces the
    /// backend error path.
    unsafe extern "C" fn write_regs_fail(
        _context: usize,
        _regs: *const libc::user_regs_struct,
    ) -> i32 {
        0
    }

    /// A suspending handler (one that returns `Poll::Pending` until another
    /// thread completes it) must resume rather than panic. This mirrors
    /// Detcore's `send_rpc` awaiting the global scheduler: the handler parks
    /// until the scheduler, running on another thread, grants this thread its
    /// turn and wakes it. Under the old single-poll `run_ready` this panicked.
    #[test]
    fn run_ready_resumes_a_cross_thread_woken_future() {
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::task::Waker;
        use std::time::Duration;

        struct Shared {
            ready: bool,
            waker: Option<Waker>,
        }

        let shared = Arc::new(Mutex::new(Shared {
            ready: false,
            waker: None,
        }));
        let completer = Arc::clone(&shared);

        // Another thread completes the future after the handler has parked,
        // then wakes the stored waker (as the scheduler would).
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(25));
            let mut state = completer.lock().unwrap();
            state.ready = true;
            if let Some(waker) = state.waker.take() {
                waker.wake();
            }
        });

        let future = std::future::poll_fn(move |cx| {
            let mut state = shared.lock().unwrap();
            if state.ready {
                Poll::Ready(1234)
            } else {
                state.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        });

        // A cross-thread completion is observed by the TLS-free cooperative
        // poll loop and returned as `Some`.
        let tail_result = TailInjectResult::default();
        assert_eq!(run_ready(future, &tail_result), Some(1234));
        handle.join().unwrap();
    }

    #[test]
    fn prototype_tool_uses_shared_guest_contract() {
        let mut counters = PrototypeCounters::default();
        let syscall = Syscall::from_raw(Sysno::write, SyscallArgs::new(1, 0x1000, 7, 0, 0, 0));
        let mut guest = DbiGuest::new(
            0,
            Pid::from_raw(10),
            Pid::from_raw(10),
            None,
            99,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs,
            write_regs_noop,
        );

        let tail_result = Arc::clone(&guest.tail_inject_result);
        assert_eq!(
            run_ready(
                PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall),
                &tail_result,
            )
            .unwrap()
            .unwrap(),
            7
        );
        assert_eq!(guest.thread_state().rewritten_syscalls, 1);
        assert_eq!(guest.read_clock().unwrap(), 99);
        let tail_result = Arc::clone(&guest.tail_inject_result);
        assert_eq!(run_ready(guest.regs(), &tail_result).unwrap().rip, 0x1234);
    }

    #[test]
    fn core_file_io_syscalls_dispatch_through_guest() {
        let cases = [
            (libc::SYS_open, [0, 11, 12, 13, 14, 15]),
            (libc::SYS_openat, [20, 0, 22, 23, 24, 25]),
            (libc::SYS_creat, [30, 31, 32, 33, 34, 35]),
            (libc::SYS_read, [50, 51, 52, 53, 54, 55]),
            (libc::SYS_write, [60, 61, 62, 63, 64, 65]),
            (libc::SYS_close, [70, 71, 72, 73, 74, 75]),
            (libc::SYS_stat, [80, 81, 82, 83, 84, 85]),
            (libc::SYS_fstat, [90, 91, 92, 93, 94, 95]),
            (libc::SYS_lstat, [100, 101, 102, 103, 104, 105]),
            (libc::SYS_newfstatat, [110, 111, 112, 113, 114, 115]),
            (libc::SYS_statx, [120, 121, 122, 123, 124, 125]),
            (libc::SYS_lseek, [130, 131, 132, 133, 134, 135]),
            (libc::SYS_access, [140, 141, 142, 143, 144, 145]),
            (libc::SYS_faccessat, [150, 151, 152, 153, 154, 155]),
            (libc::SYS_faccessat2, [160, 161, 162, 163, 164, 165]),
        ];
        let mut counters = PrototypeCounters::default();

        for (index, (sysnum, raw_args)) in cases.into_iter().enumerate() {
            assert!(should_rewrite_syscall(sysnum));
            let result = if index + 1 == cases.len() {
                -(Errno::EACCES.into_raw() as i64)
            } else {
                sysnum
            };
            let expected = ExpectedInvocation {
                sysnum,
                args: raw_args.map(|arg| arg as u64),
                result,
            };
            let syscall = Syscall::from_raw(
                Sysno::from(sysnum as i32),
                SyscallArgs::new(
                    raw_args[0],
                    raw_args[1],
                    raw_args[2],
                    raw_args[3],
                    raw_args[4],
                    raw_args[5],
                ),
            );
            let mut guest = DbiGuest::new(
                (&expected as *const ExpectedInvocation) as usize,
                Pid::from_raw(10),
                Pid::from_raw(10),
                None,
                99,
                &mut counters,
                &GLOBAL_STATE,
                &CONFIG,
                invoke_expected,
                read_regs,
                write_regs_noop,
            );
            let tail_result = Arc::clone(&guest.tail_inject_result);
            let outcome = run_ready(
                PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall),
                &tail_result,
            )
            .unwrap();
            if result < 0 {
                assert!(matches!(outcome, Err(Error::Errno(Errno::EACCES))));
            } else {
                assert_eq!(outcome.unwrap(), result);
            }
        }

        assert_eq!(counters.rewritten_syscalls, cases.len() as u64);
    }

    #[test]
    fn prototype_tool_virtualizes_uname_release() {
        let mut counters = PrototypeCounters::default();
        let mut utsname = unsafe { std::mem::zeroed::<libc::utsname>() };
        let syscall = Syscall::from_raw(
            Sysno::uname,
            SyscallArgs::new((&mut utsname as *mut libc::utsname) as usize, 0, 0, 0, 0, 0),
        );
        let mut guest = DbiGuest::new(
            0,
            Pid::from_raw(10),
            Pid::from_raw(10),
            None,
            99,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke_uname,
            read_regs,
            write_regs_noop,
        );

        let tail_result = Arc::clone(&guest.tail_inject_result);
        assert_eq!(
            run_ready(
                PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall),
                &tail_result,
            )
            .unwrap()
            .unwrap(),
            0
        );
        let field = |bytes: &[libc::c_char]| {
            unsafe { std::ffi::CStr::from_ptr(bytes.as_ptr()) }
                .to_bytes()
                .to_vec()
        };
        assert_eq!(field(&utsname.release), b"5.2.0");
        // Host-derived fields must be pinned too, not left as the real values.
        assert_eq!(field(&utsname.sysname), b"Linux");
        assert_eq!(field(&utsname.nodename), b"hermit");
        assert_eq!(field(&utsname.machine), b"x86_64");
        assert_eq!(field(&utsname.version), b"#1 SMP hermit-deterministic");
    }

    #[test]
    fn procfs_snapshots_cover_volatile_files() {
        for path in [
            "/proc/cpuinfo",
            "/proc/self/maps",
            "/proc/self/stat",
            "/proc/self/status",
        ] {
            assert!(
                !deterministic_proc_content(Path::new(path))
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(deterministic_proc_content(Path::new("/proc/self/cmdline")).is_none());
    }

    #[test]
    fn deterministic_random_streams_are_reproducible_and_distinct() {
        let mut expected = [0; 24];
        deterministic_random_bytes(17, 0, &mut expected);

        let mut repeated = [0; 24];
        deterministic_random_bytes(17, 0, &mut repeated);
        assert_eq!(repeated, expected);

        // Different seed or stream position must change the output; the
        // destination address is no longer an input at all.
        for (seed, position) in [(18, 0), (17, 1), (17, 3)] {
            let mut changed = [0; 24];
            deterministic_random_bytes(seed, position, &mut changed);
            assert_ne!(changed, expected);
        }
    }

    #[test]
    fn deterministic_random_stream_positions_do_not_collide() {
        // Chunk `index` at position `p` must equal a single fresh chunk at
        // absolute position `p + index`: the stream is a flat, unique sequence.
        let mut two_words = [0u8; 16];
        deterministic_random_bytes(5, 10, &mut two_words);

        let mut first = [0u8; 8];
        deterministic_random_bytes(5, 10, &mut first);
        let mut second = [0u8; 8];
        deterministic_random_bytes(5, 11, &mut second);

        assert_eq!(&two_words[..8], &first);
        assert_eq!(&two_words[8..], &second);
        assert_ne!(first, second);
    }

    #[test]
    fn duplicated_descriptors_inherit_random_tracking() {
        let _guard = RANDOM_FD_TEST_LOCK.lock().unwrap();
        random_fds().clear();
        random_fds().insert(7);

        // dup(7) -> 9 keeps determinism; fcntl(F_DUPFD) path uses the same hook.
        track_duplicated_fd(7, 9);
        assert!(is_random_fd(9));
        // A failed dup must not register anything.
        track_duplicated_fd(7, -1);
        assert!(!is_random_fd(-1));
        // dup2 of a non-random fd over a tracked target clears it.
        track_replacing_fd(3, 9, 9);
        assert!(!is_random_fd(9));
        // dup2 of a random fd registers the target.
        track_replacing_fd(7, 4, 4);
        assert!(is_random_fd(4));

        random_fds().clear();
    }

    #[test]
    fn rewrite_filter_covers_deterministic_policies() {
        for syscall in [
            libc::SYS_open,
            libc::SYS_openat,
            libc::SYS_read,
            libc::SYS_pread64,
            libc::SYS_readv,
            libc::SYS_preadv,
            libc::SYS_preadv2,
            libc::SYS_dup,
            libc::SYS_dup2,
            libc::SYS_dup3,
            libc::SYS_fcntl,
            libc::SYS_close,
            libc::SYS_getrandom,
            libc::SYS_getrusage,
            libc::SYS_sysinfo,
        ] {
            assert!(should_rewrite_syscall(syscall));
        }
        assert!(!should_rewrite_syscall(libc::SYS_prlimit64));
    }

    #[test]
    fn dbi_stack_allocations_are_valid_in_process_and_aligned() {
        let mut stack = DbiStack::new();
        assert_eq!(stack.size(), 0);
        assert_eq!(stack.capacity(), DBI_STACK_CAPACITY);

        // A one-byte allocation followed by a u64 must not misalign the u64.
        let flag = stack.push(0x99u8);
        let word = stack.push(0x1122_3344_5566_7788u64);
        assert_eq!(word.as_raw() % core::mem::align_of::<u64>(), 0);

        // `reserve` hands out zeroed, writable scratch.
        let slot = stack.reserve::<u32>();
        assert_eq!(unsafe { (slot.as_raw() as *const u32).read() }, 0);
        unsafe { (slot.as_raw() as *mut u32).write(0xdead_beef) };

        assert!(stack.size() >= 1 + 8 + 4);

        // Addresses stay valid after `commit` moves the arena into the guard.
        let guard = stack.commit().unwrap();
        unsafe {
            assert_eq!((flag.as_raw() as *const u8).read(), 0x99);
            assert_eq!((word.as_raw() as *const u64).read(), 0x1122_3344_5566_7788);
            assert_eq!((slot.as_raw() as *const u32).read(), 0xdead_beef);
        }
        drop(guard);
    }

    #[test]
    fn tail_inject_defers_exact_syscall_and_suspends() {
        let mut counters = PrototypeCounters::default();
        let syscall = Syscall::from_raw(Sysno::write, SyscallArgs::new(1, 0x1000, 7, 0, 0, 0));
        let mut guest: DbiGuest<'_, PrototypeTool> = DbiGuest::new(
            0,
            Pid::from_raw(10),
            Pid::from_raw(10),
            None,
            0,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs,
            write_regs_noop,
        );

        // `tail_inject` records the exact syscall for native execution after
        // Rust state is released, then suspends forever.
        let tail_result = Arc::clone(&guest.tail_inject_result);
        tail_result.clear();
        let polled = run_ready(guest.tail_inject(syscall), &tail_result);
        assert!(polled.is_none(), "tail_inject must suspend, not resolve");
        assert_eq!(
            tail_result.take(),
            Some(TailInjectAction::ExecuteOriginal(syscall))
        );

        let exit = Syscall::from_raw(Sysno::exit_group, SyscallArgs::new(42, 0, 0, 0, 0, 0));
        tail_result.clear();
        let polled = run_ready(guest.tail_inject(exit), &tail_result);
        assert!(polled.is_none(), "exit tail-inject must suspend");
        assert_eq!(
            tail_result.take(),
            Some(TailInjectAction::ExecuteOriginal(exit)),
            "exit must run only after Rust callback borrows are released"
        );
        let mut deferred_number = -1;
        let mut deferred_args = [0; 6];
        unsafe { write_deferred_syscall(exit, &mut deferred_number, deferred_args.as_mut_ptr()) };
        assert_eq!(deferred_number, Sysno::exit_group.id() as i64);
        assert_eq!(deferred_args, [42, 0, 0, 0, 0, 0]);

        for number in [
            Sysno::fork,
            Sysno::vfork,
            Sysno::clone,
            Sysno::clone3,
            Sysno::execve,
            Sysno::execveat,
        ] {
            let lifecycle = Syscall::from_raw(number, SyscallArgs::new(0, 0, 0, 0, 0, 0));
            tail_result.clear();
            let polled = run_ready(guest.tail_inject(lifecycle), &tail_result);
            assert!(polled.is_none(), "{number:?} tail-inject must suspend");
            assert_eq!(
                tail_result.take(),
                Some(TailInjectAction::ExecuteOriginal(lifecycle)),
                "{number:?} must use DynamoRIO's original lifecycle path"
            );
        }
    }

    #[test]
    fn set_regs_forwards_exact_register_file_to_native_writer() {
        let mut counters = PrototypeCounters::default();
        let mut captured: Option<libc::user_regs_struct> = None;
        let context = &mut captured as *mut Option<libc::user_regs_struct> as usize;
        let mut guest: DbiGuest<'_, PrototypeTool> = DbiGuest::new(
            context,
            Pid::from_raw(10),
            Pid::from_raw(10),
            None,
            0,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs,
            write_regs_capture,
        );

        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        regs.r15 = 0xDEAD_BEEF_CAFE_F00D;
        regs.rdi = 0x1111_2222_3333_4444;
        regs.rip = 0x5555_6666_7777_8888;
        let tail_result = TailInjectResult::default();
        let outcome = run_ready(guest.set_regs(regs), &tail_result)
            .expect("set_regs must resolve without suspending");
        assert!(outcome.is_ok(), "successful writer must yield Ok");

        let written = captured.expect("native writer must have been invoked");
        assert_eq!(written.r15, 0xDEAD_BEEF_CAFE_F00D);
        assert_eq!(written.rdi, 0x1111_2222_3333_4444);
        assert_eq!(written.rip, 0x5555_6666_7777_8888);
    }

    #[test]
    fn set_regs_surfaces_writer_failure_as_errno() {
        let mut counters = PrototypeCounters::default();
        let mut guest: DbiGuest<'_, PrototypeTool> = DbiGuest::new(
            0,
            Pid::from_raw(10),
            Pid::from_raw(10),
            None,
            0,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs,
            write_regs_fail,
        );

        let regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let tail_result = TailInjectResult::default();
        let outcome = run_ready(guest.set_regs(regs), &tail_result)
            .expect("set_regs must resolve without suspending");
        assert!(
            matches!(outcome, Err(Error::Errno(Errno::EIO))),
            "a failing native writer must surface EIO, got {outcome:?}"
        );
    }

    #[test]
    fn ppid_reflects_constructed_parent_and_root_status() {
        let mut counters = PrototypeCounters::default();
        // A forked child has a real in-tree parent, so it is not a root and its
        // `is_root_process` (built on `ppid`) must be false.
        let child: DbiGuest<'_, PrototypeTool> = DbiGuest::new(
            0,
            Pid::from_raw(20),
            Pid::from_raw(20),
            Some(Pid::from_raw(10)),
            0,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs,
            write_regs_noop,
        );
        assert_eq!(child.ppid(), Some(Pid::from_raw(10)));
        assert!(!child.is_root_process());
        drop(child);

        // The tree root has no in-tree parent (`ppid == None`), so
        // `is_root_process` holds.
        let root: DbiGuest<'_, PrototypeTool> = DbiGuest::new(
            0,
            Pid::from_raw(10),
            Pid::from_raw(10),
            None,
            0,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs,
            write_regs_noop,
        );
        assert_eq!(root.ppid(), None);
        assert!(root.is_root_process());
    }

    #[test]
    fn backtrace_walks_the_guest_frame_pointer_chain() {
        // Build two stacked frames in this test's own memory. `backtrace` reads
        // them through `process_vm_readv`, exactly as it reads the guest stack
        // in-process, so a hand-built chain here exercises the real walk. On
        // x86-64, `[fp]` is the caller's saved frame pointer and `[fp + 8]` is
        // the return address into the caller.
        let mut stack = [0u64; 4];
        let frame1_fp = (&stack[2] as *const u64) as u64;
        stack[0] = frame1_fp; // frame 0: saved rbp -> frame 1 (a higher address)
        stack[1] = 0x1111; //    frame 0: return address into its caller
        stack[2] = 0; //         frame 1: saved rbp -> null, terminating the walk
        stack[3] = 0x2222; //    frame 1: return address into its caller
        let frame0_fp = (&stack[0] as *const u64) as u64;

        let mut counters = PrototypeCounters::default();
        let mut guest: DbiGuest<'_, PrototypeTool> = DbiGuest::new(
            frame0_fp as usize,
            Pid::from_raw(7),
            Pid::from_raw(7),
            None,
            0,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs_with_rbp,
            write_regs_noop,
        );

        let backtrace = guest
            .backtrace()
            .expect("a seeded walk must produce a backtrace");
        let ips: Vec<u64> = backtrace.iter().map(|frame| frame.ip).collect();
        // rip (0xabc0) plus the return address of each walked frame, in order.
        assert_eq!(ips, vec![0xabc0, 0x1111, 0x2222]);
    }

    #[test]
    fn backtrace_returns_none_when_registers_are_unavailable() {
        let mut counters = PrototypeCounters::default();
        let mut guest: DbiGuest<'_, PrototypeTool> = DbiGuest::new(
            0,
            Pid::from_raw(7),
            Pid::from_raw(7),
            None,
            0,
            &mut counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke,
            read_regs_unavailable,
            write_regs_noop,
        );
        assert!(
            guest.backtrace().is_none(),
            "backtrace must be None when the register file cannot be read"
        );
    }

    #[test]
    fn thread_init_records_process_ppid_for_current_ppid() {
        // This is the only test that touches the process-global `PROCESS_PPID`
        // (no other test calls `reverie_dbi_runtime_thread_init` or
        // `current_ppid`), so the store/load pairs below are not racy under
        // parallel test execution.
        let mut counters = PrototypeCounters::default();

        // A positive in-tree parent pid surfaces as a real parent.
        let init = unsafe {
            reverie_dbi_runtime_thread_init(
                &mut counters,
                std::ptr::null_mut(),
                20,
                20,
                10,
                0,
                0,
                invoke,
                read_regs,
                write_regs_noop,
            )
        };
        assert_eq!(init, 0);
        assert_eq!(current_ppid(), Some(Pid::from_raw(10)));

        // The root sentinel (`PPID_NONE`) surfaces as no parent.
        let init = unsafe {
            reverie_dbi_runtime_thread_init(
                &mut counters,
                std::ptr::null_mut(),
                10,
                10,
                PPID_NONE,
                0,
                0,
                invoke,
                read_regs,
                write_regs_noop,
            )
        };
        assert_eq!(init, 0);
        assert_eq!(current_ppid(), None);
    }

    #[test]
    fn align_up_rounds_to_power_of_two() {
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 8), 8);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 8), 16);
        assert_eq!(align_up(13, 1), 13);
    }

    #[test]
    fn deterministic_ports_advance_past_explicit_bindings() {
        let next = AtomicU16::new(32768);

        assert_eq!(deterministic_port(&next, 0), 32768);
        assert_eq!(deterministic_port(&next, 32769), 32769);
        assert_eq!(deterministic_port(&next, 0), 32770);
        assert_eq!(deterministic_port(&next, 1200), 1200);
        assert_eq!(deterministic_port(&next, 0), 32771);
    }
}
