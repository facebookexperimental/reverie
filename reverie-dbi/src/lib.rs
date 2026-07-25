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

mod launcher;
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
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

pub use launcher::DbiRunner;
use reverie::Error;
use reverie::ExitStatus;
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
}

/// Result of dispatching a syscall through an external DBI Tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbiSyscallOutcome {
    /// Suppress the original syscall and install this return value.
    Suppress(i64),
    /// Let DynamoRIO execute the original syscall after the Rust callback returns.
    AllowOriginal,
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
        self.global_state.receive_rpc(self.tid, message).await
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
        self.global_state.receive_rpc(self.tid, message).await
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

    fn ppid(&self) -> Option<Pid> {
        // The DynamoRIO backend currently instruments a single process, whose
        // main thread is the root of the traced tree, so `None` is correct for
        // it (see `is_root_process`). Reporting a real in-tree parent for
        // forked children requires the native client to track the process tree
        // across `clone`/`fork`, which it does not yet surface.
        // TODO-STUB(#31): track the process tree so children report their
        // in-tree parent instead of always `None`.
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

    async fn tail_inject<S: SyscallInfo>(&mut self, syscall: S) -> Never {
        // An exiting application thread can invoke DynamoRIO's thread-exit
        // callback reentrantly from `dr_invoke_syscall_as_app`. Defer those two
        // syscalls until this Rust callback and all state borrows have returned.
        let (number, args) = syscall.into_parts();
        if matches!(number, Sysno::exit | Sysno::exit_group) {
            self.tail_inject_result.set_allow_original();
            std::future::pending().await
        }

        let syscall = Syscall::from_raw(number, args);
        let value = match self.inject(syscall).await {
            Ok(value) => value,
            Err(errno) => -(errno.into_raw() as i64),
        };
        self.tail_inject_result.set_result(value);
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
    Return(i64),
    AllowOriginal,
}

#[derive(Debug, Default)]
struct TailInjectResult {
    action: AtomicU8,
    value: AtomicI64,
}

impl TailInjectResult {
    fn clear(&self) {
        self.action.store(0, Ordering::SeqCst);
    }

    fn set_result(&self, value: i64) {
        self.value.store(value, Ordering::SeqCst);
        self.action.store(1, Ordering::SeqCst);
    }

    fn set_allow_original(&self) {
        self.action.store(2, Ordering::SeqCst);
    }

    fn take(&self) -> Option<TailInjectAction> {
        match self.action.swap(0, Ordering::SeqCst) {
            0 => None,
            1 => Some(TailInjectAction::Return(self.value.load(Ordering::SeqCst))),
            2 => Some(TailInjectAction::AllowOriginal),
            value => panic!("invalid tail-inject action {value}"),
        }
    }

    fn is_ready(&self) -> bool {
        self.action.load(Ordering::SeqCst) != 0
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
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return Some(value),
            Poll::Pending if tail_result.is_ready() => return None,
            Poll::Pending => std::hint::spin_loop(),
        }
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
) -> Result<(), Error> {
    let mut guest = DbiGuest::new(
        context,
        tid,
        pid,
        None,
        branch_count,
        thread_state,
        global_state,
        config,
        invoke_syscall,
        read_registers,
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
) -> Result<(), Errno> {
    let mut guest = DbiGuest::new(
        context,
        tid,
        pid,
        None,
        branch_count,
        thread_state,
        global_state,
        config,
        invoke_syscall,
        read_registers,
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
) -> Result<DbiSyscallOutcome, Error> {
    let mut guest = DbiGuest::new(
        context,
        tid,
        pid,
        None,
        branch_count,
        thread_state,
        global_state,
        config,
        invoke_syscall,
        read_registers,
    );
    let tail_result = Arc::clone(&guest.tail_inject_result);
    tail_result.clear();
    match run_ready(tool.handle_syscall_event(&mut guest, syscall), &tail_result) {
        Some(result) => result.map(DbiSyscallOutcome::Suppress),
        None => match tail_result
            .take()
            .expect("tool handler suspended without a tail-inject result")
        {
            TailInjectAction::Return(value) => Errno::from_ret(value as usize)
                .map(|value| DbiSyscallOutcome::Suppress(value as i64))
                .map_err(Error::from),
            TailInjectAction::AllowOriginal => Ok(DbiSyscallOutcome::AllowOriginal),
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
/// `counters` must point to aligned, writable storage for one counter value.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_thread_init(counters: *mut PrototypeCounters) {
    unsafe { counters.write(PrototypeCounters::default()) };
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

/// Handles a DynamoRIO pre-syscall event.
///
/// Returning one asks the native client to suppress the original syscall and
/// install `result`; returning zero leaves the syscall unchanged.
///
/// # Safety
///
/// The context and callback pointers must remain valid for the call. `counters`
/// and `result` must be writable, and `args` must address six syscall arguments.
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
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
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
        if let Some(value) = tools::run_active_tool(
            context as usize,
            tid,
            pid,
            sysnum,
            raw_args,
            branches,
            invoke_syscall,
            read_registers,
        ) {
            unsafe { result.write(value) };
            TOTAL_REWRITTEN.fetch_add(1, Ordering::Relaxed);
            return true;
        }

        if !should_rewrite_syscall(sysnum) {
            return false;
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
            None,
            branches,
            counters,
            &GLOBAL_STATE,
            &CONFIG,
            invoke_syscall,
            read_registers,
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
                Some(TailInjectAction::Return(value)) => value,
                Some(TailInjectAction::AllowOriginal) | None => return false,
            },
        };
        unsafe { result.write(value) };
        TOTAL_REWRITTEN.fetch_add(1, Ordering::Relaxed);
        true
    }));

    match handled {
        Ok(true) => 1,
        // `catch_unwind` cannot actually catch under DR; a genuine panic aborts
        // before reaching here. `Ok(false)` means "leave the syscall unchanged".
        Ok(false) | Err(_) => 0,
    }
}

/// Initializes the built-in prototype runtime on a native client thread.
#[cfg(feature = "prototype-runtime")]
#[unsafe(no_mangle)]
pub extern "C" fn reverie_dbi_runtime_background_init(_argument: *mut c_void) {}

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
    fn tail_inject_records_result_and_suspends() {
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
        );

        // `tail_inject` performs the syscall, records its result, then suspends
        // forever, so the driver returns `None`.
        let tail_result = Arc::clone(&guest.tail_inject_result);
        tail_result.clear();
        let polled = run_ready(guest.tail_inject(syscall), &tail_result);
        assert!(polled.is_none(), "tail_inject must suspend, not resolve");
        // The injected `write` returns its length argument (see `invoke`).
        assert_eq!(tail_result.take(), Some(TailInjectAction::Return(7)));

        let exit = Syscall::from_raw(Sysno::exit_group, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        tail_result.clear();
        let polled = run_ready(guest.tail_inject(exit), &tail_result);
        assert!(polled.is_none(), "exit tail-inject must suspend");
        assert_eq!(
            tail_result.take(),
            Some(TailInjectAction::AllowOriginal),
            "exit must run only after Rust callback borrows are released"
        );
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
