/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Simple observation tools built on the standard Reverie [`Tool`] trait, used
//! to validate that the DynamoRIO [`crate::DbiGuest`] implements enough of the
//! [`reverie::Guest`] contract for real tools to run — before attempting
//! anything as complex as Detcore.
//!
//! The tools mirror the noop, counter1, counter2, and strace examples, plus a
//! syscall histogram, adapted to the DBI backend's
//! constraints (documented in the crate's interface audit):
//!
//!  * [`SyscallCounterTool`] — counts every syscall by number and prints a
//!    histogram at exit. The upstream example uses a `GlobalState` RPC counter;
//!    the DBI backend hardwires the global state to `()`, so this uses a
//!    process-global map instead.
//!  * [`StraceTool`] — logs every syscall's name and decoded arguments, then
//!    tail-injects it without holding Rust state across a blocking call.
//!  * [`Counter2Tool`] — drives `tail_inject`, preserves available per-thread
//!    state across syscalls, and reports process-wide admission counts after its
//!    exit hook. In-flight thread state may be discarded by `exit_group`.
//!  * [`NoopTool`] and [`Counter1Tool`] exercise passthrough and GlobalState RPC.
//!
//! They are selected at run time via environment variables and dispatched by the
//! native client through [`run_active_tool`]. Output is written through a
//! DynamoRIO emit callback rather than `eprintln!`/fd 2, because the guest may
//! close its stderr before exit and app-level writes re-enter the syscall path.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::Condvar;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::Displayable;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

use crate::DbiSyscallOutcome;
use crate::RegisterReader;
use crate::SyscallInvoker;
use crate::counter::RecordSyscall;
use crate::counter::SyscallCounterGlobal;

/// Native callback that emits a pre-formatted buffer via DynamoRIO's own I/O.
pub type Emitter = unsafe extern "C" fn(*const u8, usize);

const SYSCALL_HISTOGRAM_ENV: &str = "HERMIT_DBI_SYSCALL_HISTOGRAM";
const STRACE_ENV: &str = "HERMIT_DBI_STRACE";
const NOOP_ENV: &str = "HERMIT_DBI_NOOP";
const TEST_REWRITE_EXIT_ENV: &str = "HERMIT_DBI_TEST_REWRITE_EXIT";
const COUNTER1_ENV: &str = "HERMIT_DBI_COUNTER1";
const COUNTER2_ENV: &str = "HERMIT_DBI_COUNTER2";
const CHUNKY_PRINT_ENV: &str = "HERMIT_DBI_CHUNKY_PRINT";

fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| {
        !value.is_empty() && value != OsStr::new("0") && value != OsStr::new("false")
    })
}

static HISTOGRAM_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(SYSCALL_HISTOGRAM_ENV));
static STRACE_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(STRACE_ENV));
static NOOP_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(NOOP_ENV));
static TEST_REWRITE_EXIT_ENABLED: LazyLock<bool> =
    LazyLock::new(|| env_flag(TEST_REWRITE_EXIT_ENV));
static COUNTER1_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER1_ENV));
static COUNTER2_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER2_ENV));
static CHUNKY_PRINT_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(CHUNKY_PRINT_ENV));

/// Per-syscall-number invocation counts, keyed by raw syscall number.
static SYSCALL_HISTOGRAM: LazyLock<Mutex<BTreeMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The DynamoRIO emit callback (a C function pointer stored as a `usize`),
/// installed on the first syscall event. Emits to the diagnostic file (stderr).
static EMITTER: AtomicUsize = AtomicUsize::new(0);

/// The DynamoRIO **stdout** emit callback, installed once at background init via
/// [`set_stdout_emitter`]. Distinct from [`EMITTER`] (stderr) so a tool can
/// re-emit suppressed guest stdout bytes to the real stdout. Zero until set.
static STDOUT_EMITTER: AtomicUsize = AtomicUsize::new(0);

/// Records the emit callback so the tools can produce output.
pub fn set_emitter(emit: Emitter) {
    EMITTER.store(emit as usize, Ordering::Relaxed);
}

/// Records the stdout emit callback (see [`STDOUT_EMITTER`]). Called once from
/// the native background-init path, before any flush boundary.
pub fn set_stdout_emitter(emit: Emitter) {
    STDOUT_EMITTER.store(emit as usize, Ordering::Relaxed);
}

/// Emits raw bytes (no trailing newline) through a stored emit callback.
/// Returns `false` when no emitter is installed.
fn emit_raw(slot: &AtomicUsize, bytes: &[u8]) -> bool {
    let raw = slot.load(Ordering::Relaxed);
    if raw == 0 {
        return false;
    }
    let emit: Emitter = unsafe { std::mem::transmute::<usize, Emitter>(raw) };
    unsafe { emit(bytes.as_ptr(), bytes.len()) };
    true
}

/// Writes one line of tool output through the DynamoRIO emit callback. Using
/// DynamoRIO I/O (not `eprintln!`) avoids two hazards: the guest closing its own
/// stderr before exit, and app-level `write(2)`s re-entering the syscall hook.
fn emit_line(line: &str) {
    let raw = EMITTER.load(Ordering::Relaxed);
    if raw == 0 {
        return;
    }
    let emit: Emitter = unsafe { std::mem::transmute::<usize, Emitter>(raw) };
    let mut bytes = line.as_bytes().to_vec();
    bytes.push(b'\n');
    unsafe { emit(bytes.as_ptr(), bytes.len()) };
}

fn record_syscall(number: Sysno) {
    *SYSCALL_HISTOGRAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(number.id())
        .or_insert(0) += 1;
}

/// Prints the by-number syscall histogram, sorted by syscall number.
fn print_syscall_histogram() {
    let histogram = SYSCALL_HISTOGRAM
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let total: u64 = histogram.values().sum();
    emit_line(&format!(
        "reverie-dbi: syscall histogram ({total} calls, {} distinct)",
        histogram.len()
    ));
    for (number, count) in histogram.iter() {
        emit_line(&format!(
            "  {:>6}  {:<24} {count}",
            number,
            Sysno::from(*number).name()
        ));
    }
}

/// Counts every syscall by number and prints a histogram at process exit.
///
/// The DBI backend hardwires the global state to `()`, so unlike the upstream
/// `counter1` example (which routes counts through a `GlobalState` RPC), the
/// histogram lives in a process-global map. `guest.tail_inject` passes the
/// syscall through while preserving DynamoRIO's native lifecycle boundaries.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallCounterTool;

#[reverie::tool]
impl Tool for SyscallCounterTool {
    type GlobalState = ();
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-154): Review lifecycle-safe histogram tail injection.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let number = syscall.number();
        record_syscall(number);
        // Print before injecting exit/exit_group, whose injected call won't
        // return to us.
        if matches!(number, Sysno::exit | Sysno::exit_group) {
            print_syscall_histogram();
        }
        guest.tail_inject(syscall).await
    }
}

/// Counts every syscall by number into a **shared, cross-process** histogram.
///
/// Unlike [`SyscallCounterTool`] (whose histogram is process-local, so fork
/// children are counted separately), this tool routes each syscall through
/// [`reverie::Guest::send_rpc`] to the single [`SyscallCounterGlobal`] owned by
/// the coordinator process — over a Unix-domain socket (see [`crate::sync_rpc`])
/// when one is configured. The coordinator prints the aggregate at run end, so
/// this handler produces no per-process output.
#[derive(Clone, Copy, Debug, Default)]
pub struct SharedSyscallCounterTool;

#[reverie::tool]
impl Tool for SharedSyscallCounterTool {
    type GlobalState = SyscallCounterGlobal;
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-154): Review lifecycle-safe shared-counter tail injection.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let number = syscall.number();
        // Record into the shared histogram before injecting; `exit`/`exit_group`
        // never return to us, but the count is already committed above.
        let _ = guest.send_rpc(RecordSyscall(number.id())).await;
        guest.tail_inject(syscall).await
    }
}

/// Logs every syscall's name and decoded arguments.
///
/// Mirrors `strace_minimal`: the non-returning tail injection is logged as `= ?`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StraceTool;

#[reverie::tool]
impl Tool for StraceTool {
    type GlobalState = ();
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-154): Review nonblocking native deferral in DBI strace.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        // If both tools are enabled, keep the histogram populated too.
        if *HISTOGRAM_ENABLED {
            record_syscall(syscall.number());
        }
        let prefix = format!(
            "[dbi strace pid {}] {}",
            guest.tid(),
            syscall.display(&guest.memory())
        );
        emit_line(&format!("{prefix} = ?"));
        if matches!(syscall.number(), Sysno::exit | Sysno::exit_group) && *HISTOGRAM_ENABLED {
            print_syscall_histogram();
        }
        guest.tail_inject(syscall).await
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#123): Review the DBI noop/counter1 example-tool ports.
/// The reverie `noop` example, adapted to DBI: a tool that observes every
/// syscall but changes nothing, passing each straight through to the kernel.
/// Exercises the minimal `Guest::tail_inject` path — the floor of DBI Tool
/// support.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopTool;

#[reverie::tool]
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-154): Review lifecycle-safe noop tail injection.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.tail_inject(syscall).await
    }
}

/// Regression tool that replaces `getpid` with `exit_group(42)` to prove that a
/// deferred lifecycle syscall preserves the Tool-supplied number and arguments.
#[derive(Clone, Copy, Debug, Default)]
struct RewriteExitTool;

#[reverie::tool]
impl Tool for RewriteExitTool {
    type GlobalState = ();
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-154): Review deferred lifecycle syscall replacement.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            // AUTONOMOUS-BOT-IMPLEMENTED
            Sysno::getpid => {
                let exit =
                    Syscall::from_raw(Sysno::exit_group, SyscallArgs::new(42, 0, 0, 0, 0, 0));
                guest.tail_inject(exit).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

/// RPC request for [`Counter1Global`]: either record one syscall or read the
/// running total back. Mirrors `reverie-examples/counter1`'s `IncrMsg`, but adds
/// a `Report` so the tool can retrieve the count to print at guest exit (the DBI
/// observation harness has no post-run hook to read the global like the ptrace
/// example's `tracer.wait()` does).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Counter1Request {
    /// Record one syscall (by raw number).
    Incr(i32),
    /// Return the running total without modifying it.
    Report,
}

/// A syscall counter that routes through `GlobalRPC::send_rpc`, exactly like the
/// `counter1` example — proving the DBI `Guest`'s RPC surface works, not just
/// direct syscall injection.
#[derive(Debug, Default)]
pub struct Counter1Global {
    count: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for Counter1Global {
    type Request = Counter1Request;
    type Response = u64;
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, request: Counter1Request) -> u64 {
        match request {
            Counter1Request::Incr(_number) => {
                self.count.fetch_add(1, Ordering::SeqCst);
                0
            }
            Counter1Request::Report => self.count.load(Ordering::SeqCst),
        }
    }
}

/// The `counter1` example tool, adapted to DBI: count every syscall via
/// `send_rpc`, and at guest exit read the total back (again via `send_rpc`) and
/// print it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Counter1Tool;

#[reverie::tool]
impl Tool for Counter1Tool {
    type GlobalState = Counter1Global;
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-154): Review lifecycle-safe counter1 tail injection.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let number = syscall.number();
        let _ = guest.send_rpc(Counter1Request::Incr(number.id())).await;
        if matches!(number, Sysno::exit | Sysno::exit_group) {
            let total = guest.send_rpc(Counter1Request::Report).await;
            emit_line(&format!(
                "reverie-dbi: counter1 total system calls: {total}"
            ));
        }
        guest.tail_inject(syscall).await
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-150): Review the DBI counter2 Tool port and lifecycle accounting.
#[derive(Debug, Default)]
struct Counter2Totals {
    total_syscalls: u64,
    exited_processes: u64,
    exited_threads: u64,
}

#[derive(Debug, Default)]
pub struct Counter2Global {
    totals: Mutex<Counter2Totals>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counter2Request {
    syscalls: u64,
    threads: u64,
}

#[reverie::global_tool]
impl GlobalTool for Counter2Global {
    type Request = Counter2Request;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, request: Counter2Request) {
        let mut totals = self
            .totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        totals.total_syscalls += request.syscalls;
        totals.exited_threads += request.threads;
        totals.exited_processes += 1;
    }
}

impl Counter2Global {
    fn snapshot(&self) -> (u64, u64, u64) {
        let totals = self
            .totals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (
            totals.total_syscalls,
            totals.exited_processes,
            totals.exited_threads,
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Counter2Tool {
    process_syscalls: Arc<AtomicU64>,
    observed_threads: Arc<AtomicU64>,
}

impl Counter2Tool {
    fn observe_syscall(&self) {
        self.process_syscalls.fetch_add(1, Ordering::SeqCst);
    }
}

#[reverie::tool]
impl Tool for Counter2Tool {
    type GlobalState = Counter2Global;
    type ThreadState = u64;
    fn init_thread_state(&self, _child: Tid, _parent: Option<(Tid, &u64)>) -> u64 {
        self.observed_threads.fetch_add(1, Ordering::SeqCst);
        0
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        guest.tail_inject(syscall).await
    }

    async fn on_exit_process<G: reverie::GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        global_state: &G,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        let _ = global_state
            .send_rpc(Counter2Request {
                syscalls: self.process_syscalls.load(Ordering::SeqCst),
                threads: self.observed_threads.load(Ordering::SeqCst),
            })
            .await;
        Ok(())
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-162): Review the DBI chunky_print port and stdout re-emit path.
/// Number of system calls (per thread) that define one epoch. Mirrors the
/// upstream `chunky_print` example.
const CHUNKY_EPOCH: u64 = 10;

/// Which real stream a suppressed guest write should be re-emitted to.
#[derive(PartialEq, Debug, Eq, Clone, Copy, Serialize, Deserialize)]
pub enum ChunkyWhich {
    Stdout,
    Stderr,
}

/// RPC to [`ChunkyPrintGlobal`]. Mirrors the upstream example's `Msg`.
#[derive(PartialEq, Debug, Eq, Clone, Serialize, Deserialize)]
pub enum ChunkyMsg {
    /// Buffer a suppressed write for later re-emission.
    Print(ChunkyWhich, Vec<u8>),
    /// Advance the per-thread logical clock and flush at an epoch boundary.
    Tick,
    /// Flush all buffered output immediately (used at process exit).
    Flush,
}

#[derive(Debug, Default)]
struct ChunkyInner {
    /// Per-thread logical time, keyed by raw tid.
    times: BTreeMap<i32, u64>,
    /// Per-thread buffered writes awaiting a flush, keyed by raw tid.
    printbuf: BTreeMap<i32, Vec<(ChunkyWhich, Vec<u8>)>>,
    epoch_num: u64,
}

impl ChunkyInner {
    /// Flushes when every observed thread has advanced past the epoch length.
    fn check_epoch(&mut self) {
        if !self.times.is_empty() && self.times.values().all(|t| *t > CHUNKY_EPOCH) {
            self.flush_messages();
            self.times.values_mut().for_each(|t| *t -= CHUNKY_EPOCH);
            self.epoch_num += 1;
        }
    }

    /// Re-emits all buffered bytes to their real stream and clears the buffers.
    /// Stdout bytes route through the dedicated stdout emitter; stderr bytes
    /// through the diagnostic (stderr) emitter. Both use DynamoRIO's own I/O, so
    /// re-emission does not re-enter the syscall interception path.
    fn flush_messages(&mut self) {
        for buffered in self.printbuf.values_mut() {
            for (which, bytes) in buffered.iter() {
                match which {
                    ChunkyWhich::Stdout => {
                        emit_raw(&STDOUT_EMITTER, bytes);
                    }
                    ChunkyWhich::Stderr => {
                        emit_raw(&EMITTER, bytes);
                    }
                }
            }
            buffered.clear();
        }
    }
}

/// The `chunky_print` example's [`GlobalTool`], adapted to DBI. Buffers
/// suppressed guest stdout/stderr writes and re-emits them at epoch/exit flush
/// boundaries. Served in-process through [`CHUNKY_PRINT_GLOBAL`] (like
/// [`COUNTER1_GLOBAL`]); `send_rpc` from the tool dispatches to `receive_rpc`
/// here.
#[derive(Debug, Default)]
pub struct ChunkyPrintGlobal(Mutex<ChunkyInner>);

#[reverie::global_tool]
impl GlobalTool for ChunkyPrintGlobal {
    type Request = ChunkyMsg;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, from: Tid, message: ChunkyMsg) {
        let mut inner = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match message {
            ChunkyMsg::Print(which, bytes) => {
                inner
                    .printbuf
                    .entry(from.as_raw())
                    .or_default()
                    .push((which, bytes));
            }
            ChunkyMsg::Tick => {
                *inner.times.entry(from.as_raw()).or_insert(0) += 1;
                inner.check_epoch();
            }
            ChunkyMsg::Flush => inner.flush_messages(),
        }
    }
}

/// Tracks whether fd 1/2 have been redirected (`dup2`/`dup3` onto them). Once a
/// stream is redirected we let its writes through unchanged, matching the
/// upstream example. The DBI tool is rebuilt per syscall, so these flags live
/// process-globally rather than in the tool instance.
static CHUNKY_STDOUT_REDIRECTED: AtomicBool = AtomicBool::new(false);
static CHUNKY_STDERR_REDIRECTED: AtomicBool = AtomicBool::new(false);

/// The `chunky_print` example [`Tool`], adapted to DBI: suppress guest writes to
/// fd 1/2, buffer the bytes in the [`ChunkyPrintGlobal`], and flush (re-emit) at
/// epoch boundaries and at `exit`/`exit_group`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChunkyPrintTool;

#[reverie::tool]
impl Tool for ChunkyPrintTool {
    type GlobalState = ChunkyPrintGlobal;
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-162): Review lifecycle-safe chunky_print suppression + flush.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let _ = guest.send_rpc(ChunkyMsg::Tick).await;
        match syscall {
            Syscall::Dup2(dup) => {
                match dup.newfd() {
                    1 => CHUNKY_STDOUT_REDIRECTED.store(true, Ordering::SeqCst),
                    2 => CHUNKY_STDERR_REDIRECTED.store(true, Ordering::SeqCst),
                    _ => {}
                }
                guest.tail_inject(syscall).await
            }
            Syscall::Dup3(dup) => {
                match dup.newfd() {
                    1 => CHUNKY_STDOUT_REDIRECTED.store(true, Ordering::SeqCst),
                    2 => CHUNKY_STDERR_REDIRECTED.store(true, Ordering::SeqCst),
                    _ => {}
                }
                guest.tail_inject(syscall).await
            }
            Syscall::Write(write) => {
                let fd = write.fd();
                let which = match fd {
                    1 if !CHUNKY_STDOUT_REDIRECTED.load(Ordering::SeqCst) => ChunkyWhich::Stdout,
                    2 if !CHUNKY_STDERR_REDIRECTED.load(Ordering::SeqCst) => ChunkyWhich::Stderr,
                    // Redirected fd 1/2, or any other fd: pass through unchanged.
                    // `tail_inject` diverges (`Never`), so it coerces here.
                    _ => guest.tail_inject(syscall).await,
                };
                let len = write.len();
                let buf = match write.buf() {
                    Some(addr) => read_guest_bytes(guest, addr, len)?,
                    // No buffer pointer (len 0 or NULL): nothing to re-emit; just
                    // suppress with the byte count the guest expects.
                    None => Vec::new(),
                };
                let _ = guest.send_rpc(ChunkyMsg::Print(which, buf)).await;
                emit_line(&format!(
                    "reverie-dbi: chunky_print suppressed write of {len} bytes to fd {fd}"
                ));
                // Suppress the original write; report the full length as written.
                Ok(len as i64)
            }
            _ => {
                if matches!(syscall.number(), Sysno::exit | Sysno::exit_group) {
                    // Flush before injecting the terminating call, which never
                    // returns to this handler.
                    let _ = guest.send_rpc(ChunkyMsg::Flush).await;
                    emit_line("reverie-dbi: chunky_print flushed buffered output at exit");
                }
                guest.tail_inject(syscall).await
            }
        }
    }
}

/// Reads `len` bytes of guest memory at `addr`. The DBI client is in-process
/// with the guest, so [`Guest::memory`] reads its own address space directly.
fn read_guest_bytes<G: Guest<ChunkyPrintTool>>(
    guest: &G,
    addr: Addr<u8>,
    len: usize,
) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; len];
    guest.memory().read_exact(addr, &mut buf)?;
    Ok(buf)
}

/// The observation tool selected by the environment, if any.
enum ActiveTool {
    Strace,
    Counter,
    SharedCounter,
    Noop,
    RewriteExit,
    Counter1,
    Counter2,
    ChunkyPrint,
}

fn active_tool() -> Option<ActiveTool> {
    if *TEST_REWRITE_EXIT_ENABLED {
        Some(ActiveTool::RewriteExit)
    } else if *STRACE_ENABLED {
        Some(ActiveTool::Strace)
    } else if *HISTOGRAM_ENABLED {
        // When a coordinator socket is configured, count into the single shared
        // cross-process GlobalState; otherwise fall back to the process-local
        // histogram.
        if crate::sync_rpc::is_active() {
            Some(ActiveTool::SharedCounter)
        } else {
            Some(ActiveTool::Counter)
        }
    } else if *COUNTER2_ENABLED {
        Some(ActiveTool::Counter2)
    } else if *COUNTER1_ENABLED {
        Some(ActiveTool::Counter1)
    } else if *CHUNKY_PRINT_ENABLED {
        Some(ActiveTool::ChunkyPrint)
    } else if *NOOP_ENABLED {
        Some(ActiveTool::Noop)
    } else {
        None
    }
}

/// Polls a handler future that is expected to resolve without suspending. The
/// observation tools only call synchronous `Guest` methods, so this never spins.
fn run_ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("observation tool handler must not suspend"),
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-154): Review nonblocking Counter2 state leases and exit gate.
#[derive(Default)]
struct Counter2Registry {
    process_exiting: bool,
    exit_ready: bool,
    tool: Option<Arc<Counter2Tool>>,
    thread_states: BTreeMap<i32, Arc<Mutex<Option<u64>>>>,
}

#[derive(Default)]
struct Counter2Host {
    registry: Mutex<Counter2Registry>,
    exit_ready: Condvar,
    global_state: Counter2Global,
}

impl Counter2Host {
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &self,
        context: usize,
        tid: Pid,
        pid: Pid,
        branches: u64,
        syscall: Syscall,
        exit_code: i32,
        invoke_syscall: SyscallInvoker,
        read_registers: RegisterReader,
    ) -> Result<(DbiSyscallOutcome, bool), Error> {
        let number = syscall.number();
        let (tool, state_slot, new_thread, mut thread_state) = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if registry.process_exiting {
                if number == Sysno::exit_group {
                    while !registry.exit_ready {
                        registry = self
                            .exit_ready
                            .wait(registry)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                    }
                }
                return Ok((DbiSyscallOutcome::ExecuteOriginal(syscall), false));
            }
            if number == Sysno::exit_group {
                registry.process_exiting = true;
            }

            let tool = Arc::clone(
                registry
                    .tool
                    .get_or_insert_with(|| Arc::new(Counter2Tool::new(pid, &()))),
            );
            let new_thread = !registry.thread_states.contains_key(&tid.as_raw());
            if new_thread {
                let state = tool.init_thread_state(tid, None);
                registry
                    .thread_states
                    .insert(tid.as_raw(), Arc::new(Mutex::new(Some(state))));
            }
            let state_slot = Arc::clone(
                registry
                    .thread_states
                    .get(&tid.as_raw())
                    .expect("DBI Counter2 thread state disappeared"),
            );
            let thread_state = {
                let mut stored = state_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                stored
                    .take()
                    .expect("DBI Counter2 thread state is already leased")
            };
            tool.observe_syscall();
            (tool, state_slot, new_thread, thread_state)
        };

        if new_thread {
            crate::run_tool_thread_start(
                tool.as_ref(),
                context,
                tid,
                pid,
                branches,
                &mut thread_state,
                &self.global_state,
                &(),
                invoke_syscall,
                read_registers,
            )?;
        }

        let outcome = crate::run_tool_syscall(
            tool.as_ref(),
            context,
            tid,
            pid,
            branches,
            &mut thread_state,
            &self.global_state,
            &(),
            syscall,
            invoke_syscall,
            read_registers,
        );

        if !is_exit_syscall(number) {
            let registry = self
                .registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !registry.process_exiting {
                let mut stored = state_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                debug_assert!(stored.is_none());
                *stored = Some(thread_state);
            }
            return outcome.map(|outcome| (outcome, false));
        }

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if number == Sysno::exit_group {
                    self.finish_exit_group();
                }
                return Err(error);
            }
        };
        let status = ExitStatus::Exited(exit_code & 0xff);
        if number == Sysno::exit_group {
            let (states, process_tool) = {
                let mut registry = self
                    .registry
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let states = std::mem::take(&mut registry.thread_states);
                let process_tool = registry
                    .tool
                    .take()
                    .expect("DBI Counter2 Tool disappeared before process exit");
                (states, process_tool)
            };

            crate::run_tool_thread_exit(
                tool.as_ref(),
                tid,
                thread_state,
                &self.global_state,
                &(),
                status,
            )?;
            for (raw_tid, state_slot) in states {
                if raw_tid == tid.as_raw() {
                    continue;
                }
                let state = state_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .take();
                if let Some(state) = state {
                    crate::run_tool_thread_exit(
                        tool.as_ref(),
                        Pid::from_raw(raw_tid),
                        state,
                        &self.global_state,
                        &(),
                        status,
                    )?;
                }
            }

            let global = crate::DbiGlobal::<Counter2Tool> {
                tid,
                global_state: &self.global_state,
                config: &(),
            };
            run_ready(
                process_tool
                    .as_ref()
                    .clone()
                    .on_exit_process(pid, &global, status),
            )?;
            return Ok((outcome, true));
        }

        let (process_exited, process_tool) = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.thread_states.remove(&tid.as_raw());
            let process_exited = tid == pid && registry.thread_states.is_empty();
            if process_exited {
                registry.process_exiting = true;
            }
            let process_tool = process_exited.then(|| {
                registry
                    .tool
                    .take()
                    .expect("DBI Counter2 Tool disappeared before process exit")
            });
            (process_exited, process_tool)
        };
        crate::run_tool_thread_exit(
            tool.as_ref(),
            tid,
            thread_state,
            &self.global_state,
            &(),
            status,
        )?;
        if let Some(process_tool) = process_tool {
            let global = crate::DbiGlobal::<Counter2Tool> {
                tid,
                global_state: &self.global_state,
                config: &(),
            };
            run_ready(
                process_tool
                    .as_ref()
                    .clone()
                    .on_exit_process(pid, &global, status),
            )?;
        }
        Ok((outcome, process_exited))
    }

    fn finish_exit_group(&self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.process_exiting && !registry.exit_ready {
            registry.exit_ready = true;
            self.exit_ready.notify_all();
        }
    }
}

// TODO-HUMAN-REVIEW(PR-150): Review DBI exit lifecycle classification.
fn is_exit_syscall(number: Sysno) -> bool {
    // AUTONOMOUS-BOT-IMPLEMENTED
    matches!(number, Sysno::exit | Sysno::exit_group)
}

/// Runs the environment-selected observation tool for one syscall, if any is
/// active. The outcome either suppresses the original syscall with a result or
/// lets DynamoRIO execute it after the Rust handler has released its borrows.
#[allow(clippy::too_many_arguments)]
// TODO-HUMAN-REVIEW(PR-150): Review the suspension-aware observation Tool outcome API.
pub(crate) fn run_active_tool(
    context: usize,
    tid: i32,
    pid: i32,
    sysnum: i64,
    raw_args: &[u64],
    branches: u64,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> Option<DbiSyscallOutcome> {
    let tool = active_tool()?;
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
    let result = match tool {
        ActiveTool::Strace => dispatch(
            &StraceTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        ),
        ActiveTool::Counter => dispatch(
            &SyscallCounterTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        ),
        ActiveTool::SharedCounter => dispatch_shared(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        ),
        ActiveTool::Noop => dispatch(
            &NoopTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        ),
        ActiveTool::RewriteExit => dispatch(
            &RewriteExitTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        ),
        ActiveTool::Counter1 => dispatch_counter1(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        ),
        ActiveTool::Counter2 => dispatch_counter2(
            context,
            tid,
            pid,
            branches,
            syscall,
            raw_args[0] as i32,
            invoke_syscall,
            read_registers,
        ),
        ActiveTool::ChunkyPrint => dispatch_chunky_print(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        ),
    };
    Some(match result {
        Ok(outcome) => outcome,
        Err(Error::Errno(errno)) => DbiSyscallOutcome::Suppress(-(errno.into_raw() as i64)),
        Err(_) => DbiSyscallOutcome::Suppress(-(reverie::syscalls::Errno::EIO.into_raw() as i64)),
    })
}

/// Builds a [`DbiGuest`] specialized for `tool` and runs its syscall handler.
/// Each tool type gets its own guest monomorphization; both tools here carry no
/// thread or global state, so a local unit backs each.
#[allow(clippy::too_many_arguments)]
fn dispatch<T>(
    tool: &T,
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> Result<DbiSyscallOutcome, Error>
where
    T: Tool<GlobalState = (), ThreadState = ()>,
{
    let mut thread_state = ();
    crate::run_tool_syscall(
        tool,
        context,
        Pid::from_raw(tid),
        Pid::from_raw(pid),
        branches,
        &mut thread_state,
        &(),
        &(),
        syscall,
        invoke_syscall,
        read_registers,
    )
}

/// The process-global `counter1` state. It must persist across syscalls (each
/// `run_active_tool` call builds a fresh `DbiGuest`), so it lives here rather
/// than in a per-call local. `send_rpc` on `DbiGuest` dispatches to this
/// instance's `receive_rpc` in-process.
static COUNTER1_GLOBAL: LazyLock<Counter1Global> = LazyLock::new(Counter1Global::default);

/// Runs one syscall through [`SharedSyscallCounterTool`], whose non-`()`
/// [`SyscallCounterGlobal`] is served out-of-process. `send_rpc` routes to the
/// coordinator socket, so the local `global` below is a never-touched
/// placeholder required only by the [`DbiGuest`] constructor.
#[allow(clippy::too_many_arguments)]
fn dispatch_shared(
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> Result<DbiSyscallOutcome, Error> {
    let global = SyscallCounterGlobal::default();
    let config = ();
    let mut thread_state = ();
    crate::run_tool_syscall(
        &SharedSyscallCounterTool,
        context,
        Pid::from_raw(tid),
        Pid::from_raw(pid),
        branches,
        &mut thread_state,
        &global,
        &config,
        syscall,
        invoke_syscall,
        read_registers,
    )
}

/// Runs one syscall through [`Counter1Tool`], whose non-`()` [`Counter1Global`]
/// is the shared [`COUNTER1_GLOBAL`] so the count accumulates across the run.
#[allow(clippy::too_many_arguments)]
fn dispatch_counter1(
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> Result<DbiSyscallOutcome, Error> {
    let mut thread_state = ();
    crate::run_tool_syscall(
        &Counter1Tool,
        context,
        Pid::from_raw(tid),
        Pid::from_raw(pid),
        branches,
        &mut thread_state,
        // `&*` forces `LazyLock<Counter1Global>` to deref to `&Counter1Global`.
        &*COUNTER1_GLOBAL,
        &(),
        syscall,
        invoke_syscall,
        read_registers,
    )
}

/// The process-global `chunky_print` state, persisting the per-thread print
/// buffers across syscalls. Like [`COUNTER1_GLOBAL`], `send_rpc` on the DBI
/// guest dispatches to this instance's `receive_rpc` in-process.
static CHUNKY_PRINT_GLOBAL: LazyLock<ChunkyPrintGlobal> = LazyLock::new(ChunkyPrintGlobal::default);

/// Runs one syscall through [`ChunkyPrintTool`], whose [`ChunkyPrintGlobal`] is
/// the shared [`CHUNKY_PRINT_GLOBAL`] so buffered output accumulates across the
/// run and flushes at epoch/exit boundaries.
#[allow(clippy::too_many_arguments)]
fn dispatch_chunky_print(
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> Result<DbiSyscallOutcome, Error> {
    let mut thread_state = ();
    crate::run_tool_syscall(
        &ChunkyPrintTool,
        context,
        Pid::from_raw(tid),
        Pid::from_raw(pid),
        branches,
        &mut thread_state,
        &*CHUNKY_PRINT_GLOBAL,
        &(),
        syscall,
        invoke_syscall,
        read_registers,
    )
}

static COUNTER2_HOST: LazyLock<Counter2Host> = LazyLock::new(Counter2Host::default);

#[allow(clippy::too_many_arguments)]
fn dispatch_counter2(
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    exit_code: i32,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> Result<DbiSyscallOutcome, Error> {
    let (outcome, process_exited) = COUNTER2_HOST.dispatch(
        context,
        Pid::from_raw(tid),
        Pid::from_raw(pid),
        branches,
        syscall,
        exit_code,
        invoke_syscall,
        read_registers,
    )?;
    if process_exited {
        let (syscalls, processes, threads) = COUNTER2_HOST.global_state.snapshot();
        emit_line(&format!(
            "reverie-dbi: counter2 total system calls: {syscalls}, from {processes} processes, {threads} thread(s)"
        ));
        COUNTER2_HOST.finish_exit_group();
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn fake_invoke(_context: usize, _number: i64, _args: *const u64) -> i64 {
        0
    }

    unsafe extern "C" fn fake_read_registers(
        _context: usize,
        _registers: *mut libc::user_regs_struct,
    ) -> i32 {
        1
    }

    fn syscall(number: Sysno, arg0: usize) -> Syscall {
        Syscall::from_raw(number, SyscallArgs::new(arg0, 0, 0, 0, 0, 0))
    }

    #[test]
    fn counter2_host_persists_thread_state_and_runs_exit_lifecycle() {
        let host = Counter2Host::default();
        let tid = Pid::from_raw(3);
        let worker_tid = Pid::from_raw(4);
        for _ in 0..2 {
            let (outcome, exited) = host
                .dispatch(
                    0,
                    tid,
                    tid,
                    0,
                    syscall(Sysno::getpid, 0),
                    0,
                    fake_invoke,
                    fake_read_registers,
                )
                .unwrap();
            assert_eq!(
                outcome,
                DbiSyscallOutcome::ExecuteOriginal(syscall(Sysno::getpid, 0))
            );
            assert!(!exited);
        }

        let (outcome, exited) = host
            .dispatch(
                0,
                worker_tid,
                tid,
                0,
                syscall(Sysno::gettid, 0),
                0,
                fake_invoke,
                fake_read_registers,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DbiSyscallOutcome::ExecuteOriginal(syscall(Sysno::gettid, 0))
        );
        assert!(!exited);

        let (outcome, exited) = host
            .dispatch(
                0,
                worker_tid,
                tid,
                0,
                syscall(Sysno::exit, 0),
                0,
                fake_invoke,
                fake_read_registers,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DbiSyscallOutcome::ExecuteOriginal(syscall(Sysno::exit, 0))
        );
        assert!(!exited);

        let (outcome, exited) = host
            .dispatch(
                0,
                tid,
                tid,
                0,
                syscall(Sysno::exit_group, 7),
                7,
                fake_invoke,
                fake_read_registers,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DbiSyscallOutcome::ExecuteOriginal(syscall(Sysno::exit_group, 7))
        );
        assert!(exited);
        assert_eq!(host.global_state.snapshot(), (5, 1, 2));
    }
}
