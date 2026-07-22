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

use std::collections::HashSet;
use std::ffi::c_void;
use std::future::Future;
use std::path::Path;
use std::pin::pin;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

pub use launcher::DbiRunner;
use reverie::Error;
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
}

impl<'a, T> DbiGuest<'a, T>
where
    T: Tool,
{
    #[allow(clippy::too_many_arguments)]
    fn new(
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
        }
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
    type Stack = UnsupportedStack;

    fn tid(&self) -> Pid {
        self.tid
    }

    fn pid(&self) -> Pid {
        self.pid
    }

    fn ppid(&self) -> Option<Pid> {
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
        UnsupportedStack
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

    async fn tail_inject<S: SyscallInfo>(&mut self, _syscall: S) -> Never {
        panic!("tail injection is not implemented by the DynamoRIO prototype")
    }

    fn set_timer(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(Errno::ENOSYS.into())
    }

    fn set_timer_precise(&mut self, _sched: TimerSchedule) -> Result<(), Error> {
        Err(Errno::ENOSYS.into())
    }

    fn read_clock(&mut self) -> Result<u64, Error> {
        Ok(self.branch_count)
    }
}

/// Placeholder stack implementation for the initial backend prototype.
pub struct UnsupportedStack;

/// Guard returned by [`UnsupportedStack`].
pub struct UnsupportedStackGuard;

impl Drop for UnsupportedStackGuard {
    fn drop(&mut self) {}
}

impl Stack for UnsupportedStack {
    type StackGuard = UnsupportedStackGuard;

    fn size(&self) -> usize {
        0
    }

    fn capacity(&self) -> usize {
        0
    }

    fn push<'stack, T>(&mut self, _value: T) -> Addr<'stack, T> {
        panic!("guest stack allocation is not implemented by the DynamoRIO prototype")
    }

    fn reserve<'stack, T>(&mut self) -> AddrMut<'stack, T> {
        panic!("guest stack allocation is not implemented by the DynamoRIO prototype")
    }

    fn commit(self) -> Result<Self::StackGuard, Errno> {
        Err(Errno::ENOSYS)
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

fn should_rewrite_syscall(sysnum: i64) -> bool {
    [
        libc::SYS_write,
        libc::SYS_uname,
        libc::SYS_bind,
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

fn run_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("the prototype tool handler must not suspend"),
    }
}

static PROTOTYPE_TOOL: PrototypeTool = PrototypeTool;
static GLOBAL_STATE: () = ();
static CONFIG: () = ();
static TOTAL_BRANCHES: AtomicU64 = AtomicU64::new(0);
static TOTAL_SYSCALLS: AtomicU64 = AtomicU64::new(0);
static TOTAL_REWRITTEN: AtomicU64 = AtomicU64::new(0);

/// Initializes the prototype state for the current application thread.
///
/// # Safety
///
/// `counters` must point to aligned, writable storage for one counter value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_thread_init(counters: *mut PrototypeCounters) {
    unsafe { counters.write(PrototypeCounters::default()) };
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_pre_syscall(
    context: *mut c_void,
    counters: *mut PrototypeCounters,
    tid: i32,
    pid: i32,
    sysnum: i64,
    args: *const u64,
    branches: u64,
    result: *mut i64,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> i32 {
    let handled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let counters = unsafe { &mut *counters };
        counters.branches = branches;
        counters.observed_syscalls += 1;
        TOTAL_BRANCHES.store(branches, Ordering::Relaxed);
        TOTAL_SYSCALLS.fetch_add(1, Ordering::Relaxed);

        if !should_rewrite_syscall(sysnum) {
            return false;
        }

        let raw_args = unsafe { std::slice::from_raw_parts(args, 6) };
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
        let value = match run_ready(PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall)) {
            Ok(value) => value,
            Err(Error::Errno(errno)) => -(errno.into_raw() as i64),
            Err(_) => -(Errno::EIO.into_raw() as i64),
        };
        unsafe { result.write(value) };
        TOTAL_REWRITTEN.fetch_add(1, Ordering::Relaxed);
        true
    }));

    match handled {
        Ok(true) => 1,
        Ok(false) | Err(_) => 0,
    }
}

/// Returns process-wide prototype counters accumulated at syscall boundaries.
///
/// # Safety
///
/// Each output pointer must be aligned and writable for one `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn reverie_dbi_runtime_totals(
    branches: *mut u64,
    syscalls: *mut u64,
    rewritten: *mut u64,
) {
    unsafe {
        branches.write(TOTAL_BRANCHES.load(Ordering::Relaxed));
        syscalls.write(TOTAL_SYSCALLS.load(Ordering::Relaxed));
        rewritten.write(TOTAL_REWRITTEN.load(Ordering::Relaxed));
    }
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

    unsafe extern "C" fn invoke_uname(_context: usize, sysnum: i64, args: *const u64) -> i64 {
        assert_eq!(sysnum, libc::SYS_uname);
        unsafe { libc::uname(*args as *mut libc::utsname) as i64 }
    }

    unsafe extern "C" fn read_regs(_context: usize, regs: *mut libc::user_regs_struct) -> i32 {
        unsafe { (*regs).rip = 0x1234 };
        1
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

        assert_eq!(
            run_ready(PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall)).unwrap(),
            7
        );
        assert_eq!(guest.thread_state().rewritten_syscalls, 1);
        assert_eq!(guest.read_clock().unwrap(), 99);
        assert_eq!(run_ready(guest.regs()).rip, 0x1234);
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

        assert_eq!(
            run_ready(PROTOTYPE_TOOL.handle_syscall_event(&mut guest, syscall)).unwrap(),
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
    fn deterministic_ports_advance_past_explicit_bindings() {
        let next = AtomicU16::new(32768);

        assert_eq!(deterministic_port(&next, 0), 32768);
        assert_eq!(deterministic_port(&next, 32769), 32769);
        assert_eq!(deterministic_port(&next, 0), 32770);
        assert_eq!(deterministic_port(&next, 1200), 1200);
        assert_eq!(deterministic_port(&next, 0), 32771);
    }
}
