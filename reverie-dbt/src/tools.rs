/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Simple observation tools built on the standard Reverie [`Tool`] trait, used
//! to validate that the DynamoRIO [`crate::DbtGuest`] implements enough of the
//! [`reverie::Guest`] contract for real tools to run — before attempting
//! anything as complex as Detcore.
//!
//! The tools mirror the noop, counter1, counter2, and strace examples, plus a
//! syscall histogram, adapted to the DBT backend's
//! constraints (documented in the crate's interface audit):
//!
//!  * [`SyscallCounterTool`] — counts every syscall by number and prints a
//!    histogram at exit. The upstream example uses a `GlobalState` RPC counter;
//!    the DBT backend hardwires the global state to `()`, so this uses a
//!    process-global map instead.
//!  * [`StraceTool`] — logs every syscall's name and decoded arguments, then
//!    tail-injects it without holding Rust state across a blocking call.
//!  * [`Counter2Tool`] — drives `tail_inject`, preserves available per-thread
//!    state across syscalls, and reports process-wide admission counts after its
//!    exit hook. In-flight thread state may be discarded by `exit_group`.
//!  * [`NoopTool`] and [`Counter1Tool`] exercise passthrough and GlobalState RPC.
//!  * [`ChromeTraceTool`] accumulates a per-thread syscall timeline in its
//!    [`GlobalState`](ChromeTraceGlobal) and emits it as Chrome trace JSON at
//!    exit. It records at syscall entry via `tail_inject` (never `inject`s), so
//!    its per-syscall durations are inter-entry approximations, not true return
//!    times — an intentional L0 fidelity limit.
//!  * [`ChaosTool`] is the first execution-*perturbing* DBT tool: it truncates
//!    `read`/`recvfrom` to one byte and optionally injects `EINTR`, driving each
//!    intervened syscall through `inject` to observe its real result. Its
//!    `ERESTARTSYS`→`EINTR` substitution is the one behavioral difference from
//!    the upstream example (DBT's suppress model has no kernel syscall restart).
//!
//! They are selected at run time via environment variables and dispatched by the
//! native client through [`run_active_tool`]. Output is written through a
//! DynamoRIO emit callback rather than `eprintln!`/fd 2, because the guest may
//! close its stderr before exit and app-level writes re-enter the syscall path.

#[path = "../../reverie-examples/counter1_tool.rs"]
mod counter1_exact;
#[path = "../../reverie-examples/counter2_tool.rs"]
mod counter2_exact;

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
use std::time::SystemTime;

use counter1_exact::CounterGlobal as ExactCounter1Global;
use counter1_exact::CounterLocal as ExactCounter1Tool;
use counter2_exact::CounterGlobal as ExactCounter2Global;
use counter2_exact::CounterLocal as ExactCounter2Tool;
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

use crate::DbtSyscallOutcome;
use crate::MemoryReader;
use crate::RegisterReader;
use crate::RegisterWriter;
use crate::SyscallInvoker;
use crate::counter::RecordSyscall;
use crate::counter::SyscallCounterGlobal;

/// Native callback that emits a pre-formatted buffer via DynamoRIO's own I/O.
pub type Emitter = unsafe extern "C" fn(*const u8, usize);

const SYSCALL_HISTOGRAM_ENV: &str = "HERMIT_DBT_SYSCALL_HISTOGRAM";
const STRACE_ENV: &str = "HERMIT_DBT_STRACE";
const NOOP_ENV: &str = "HERMIT_DBT_NOOP";
const TEST_REWRITE_EXIT_ENV: &str = "HERMIT_DBT_TEST_REWRITE_EXIT";
const TEST_SET_REG_ENV: &str = "HERMIT_DBT_TEST_SET_REG";
const TEST_PPID_ENV: &str = "HERMIT_DBT_TEST_PPID";
const TEST_BACKTRACE_ENV: &str = "HERMIT_DBT_TEST_BACKTRACE";
const COUNTER1_ENV: &str = "HERMIT_DBT_COUNTER1";
const COUNTER2_ENV: &str = "HERMIT_DBT_COUNTER2";
const CHUNKY_PRINT_ENV: &str = "HERMIT_DBT_CHUNKY_PRINT";
const CHROME_TRACE_ENV: &str = "HERMIT_DBT_CHROME_TRACE";
const CHAOS_ENV: &str = "HERMIT_DBT_CHAOS";
const CHAOS_SKIP_ENV: &str = "HERMIT_DBT_CHAOS_SKIP";
const CHAOS_NO_READ_ENV: &str = "HERMIT_DBT_CHAOS_NO_READ";
const CHAOS_NO_RECV_ENV: &str = "HERMIT_DBT_CHAOS_NO_RECV";
const CHAOS_INTERRUPT_ENV: &str = "HERMIT_DBT_CHAOS_INTERRUPT";
const COUNTER1_EXACT_ENV: &str = "HERMIT_DBT_COUNTER1_EXACT";
const COUNTER2_EXACT_ENV: &str = "HERMIT_DBT_COUNTER2_EXACT";

fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| {
        !value.is_empty() && value != OsStr::new("0") && value != OsStr::new("false")
    })
}

/// Parses an unsigned integer environment variable, defaulting to 0 when unset
/// or unparseable.
fn env_u64(name: &str) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0)
}

static HISTOGRAM_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(SYSCALL_HISTOGRAM_ENV));
static STRACE_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(STRACE_ENV));
static NOOP_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(NOOP_ENV));
static TEST_REWRITE_EXIT_ENABLED: LazyLock<bool> =
    LazyLock::new(|| env_flag(TEST_REWRITE_EXIT_ENV));
static TEST_SET_REG_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(TEST_SET_REG_ENV));
static TEST_PPID_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(TEST_PPID_ENV));
static TEST_BACKTRACE_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(TEST_BACKTRACE_ENV));
static COUNTER1_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER1_ENV));
static COUNTER2_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER2_ENV));
static CHUNKY_PRINT_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(CHUNKY_PRINT_ENV));
static CHROME_TRACE_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(CHROME_TRACE_ENV));
static CHAOS_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(CHAOS_ENV));

/// The `chaos` intervention configuration, resolved once from the environment.
///
/// Mirrors the `chaos` example's `ChaosOpts`, but sourced from environment
/// variables (the DBT backend selects and configures tools by env, not by a
/// CLI). `no_interrupt` defaults to `true` — DBT's suppress model cannot request
/// the kernel syscall restart that the ptrace example's `ERESTARTSYS` relies on,
/// so error injection surfaces `EINTR` directly and is opt-in via
/// [`CHAOS_INTERRUPT_ENV`]. Read/recv truncation is the safe default.
static CHAOS_CONFIG: LazyLock<ChaosOpts> = LazyLock::new(|| ChaosOpts {
    skip: env_u64(CHAOS_SKIP_ENV),
    no_read: env_flag(CHAOS_NO_READ_ENV),
    no_recv: env_flag(CHAOS_NO_RECV_ENV),
    no_interrupt: !env_flag(CHAOS_INTERRUPT_ENV),
});

/// Process-global syscall counter for [`ChaosTool`]'s `skip` window. Each
/// syscall event builds a fresh `DbtGuest`, so this must persist across calls.
static CHAOS_COUNT: AtomicU64 = AtomicU64::new(0);

/// Per-thread "already interrupted once" flags for [`ChaosTool`], keyed by raw
/// tid. The DBT tool hardwires `ThreadState` to `()`, so the example's
/// `bool` thread state lives here (the [`ChunkyPrintTool`]/[`ChromeTraceTool`]
/// process-global-by-tid pattern).
static CHAOS_INTERRUPTED: LazyLock<Mutex<BTreeMap<i32, bool>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn chaos_take_interrupted(tid: i32) -> bool {
    *CHAOS_INTERRUPTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(tid)
        .or_insert(false)
}

fn chaos_set_interrupted(tid: i32, value: bool) {
    CHAOS_INTERRUPTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .insert(tid, value);
}

/// Process-global epoch for [`ChromeTraceTool`] timestamps. Captured once, on
/// first access, so every recorded event is expressed as microseconds since a
/// single origin (mirrors the upstream `chrome_trace` example's `GlobalState`
/// epoch). `SystemTime::now` here is served by the vDSO, so it issues no real
/// syscall that could re-enter the DBT interception path.
static CHROME_EPOCH: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);

/// Microseconds elapsed from [`CHROME_EPOCH`] to now, saturating at zero if the
/// clock appears to move backwards (never panics — a panic in a DBT handler
/// aborts the process).
fn chrome_now_us() -> u64 {
    SystemTime::now()
        .duration_since(*CHROME_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}
static COUNTER1_EXACT_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER1_EXACT_ENV));
static COUNTER1_EXACT_TOOL: LazyLock<ExactCounter1Tool> = LazyLock::new(ExactCounter1Tool::default);
static COUNTER1_EXACT_GLOBAL: LazyLock<ExactCounter1Global> =
    LazyLock::new(ExactCounter1Global::default);
static COUNTER2_EXACT_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER2_EXACT_ENV));
static COUNTER2_EXACT_TOOL: LazyLock<ExactCounter2Tool> = LazyLock::new(|| {
    <ExactCounter2Tool as Tool>::new(reverie::Pid::from_raw(unsafe { libc::getpid() }), &())
});
static COUNTER2_EXACT_GLOBAL: LazyLock<ExactCounter2Global> =
    LazyLock::new(ExactCounter2Global::default);

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

/// Whether the exact backend-neutral counter1 tool is selected.
pub(crate) fn counter1_exact_enabled() -> bool {
    *COUNTER1_EXACT_ENABLED
}

/// Exact counter1 process-local tool instance.
pub(crate) fn counter1_exact_tool() -> &'static ExactCounter1Tool {
    &COUNTER1_EXACT_TOOL
}

/// Exact counter1 process-tree global state.
pub(crate) fn counter1_exact_global() -> &'static ExactCounter1Global {
    &COUNTER1_EXACT_GLOBAL
}

/// Emits the exact counter1 global summary through DynamoRIO.
pub(crate) fn emit_counter1_exact_summary() {
    emit_line(&format!(
        "counter1-global syscalls={}",
        COUNTER1_EXACT_GLOBAL.total()
    ));
}

/// Whether the exact backend-neutral counter2 tool is selected.
pub(crate) fn counter2_exact_enabled() -> bool {
    *COUNTER2_EXACT_ENABLED
}

/// Exact counter2 process-local tool instance.
pub(crate) fn counter2_exact_tool() -> &'static ExactCounter2Tool {
    &COUNTER2_EXACT_TOOL
}

/// Exact counter2 process-local global state.
pub(crate) fn counter2_exact_global() -> &'static ExactCounter2Global {
    &COUNTER2_EXACT_GLOBAL
}

/// Emits the exact counter2 process-local summary through DynamoRIO.
pub(crate) fn emit_counter2_exact_summary() {
    let (syscalls, threads) = COUNTER2_EXACT_TOOL.process_totals();
    emit_line(&format!(
        " [counter2 exact] Process-local system calls: {syscalls}, exited threads: {threads}"
    ));
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
        "reverie-dbt: syscall histogram ({total} calls, {} distinct)",
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
/// The DBT backend hardwires the global state to `()`, so unlike the upstream
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

    // TODO-HUMAN-REVIEW(PR-154): Review nonblocking native deferral in DBT strace.
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
            "[dbt strace pid {}] {}",
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
// TODO-HUMAN-REVIEW(#123): Review the DBT noop/counter1 example-tool ports.
/// The reverie `noop` example, adapted to DBT: a tool that observes every
/// syscall but changes nothing, passing each straight through to the kernel.
/// Exercises the minimal `Guest::tail_inject` path — the floor of DBT Tool
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

/// The sentinel value [`SetRegTool`] writes into the guest's `r15` to prove that
/// `Guest::set_regs` reaches the application register file (see the
/// `set_reg_probe` fixture, which loads a different value and reads it back).
const SET_REG_SENTINEL: u64 = 0xDEAD_BEEF_CAFE_F00D;

/// Regression tool that exercises the DBT `Guest::set_regs` path: on the guest's
/// `getpid`, overwrite the callee-saved `r15` register with [`SET_REG_SENTINEL`]
/// via `set_regs`, then suppress the syscall. Because `r15` is preserved across
/// the syscall boundary, a correct `set_regs` implementation lets the guest read
/// the sentinel back after the call returns. This is the first DBT tool to write
/// the guest register file rather than only read it.
#[derive(Clone, Copy, Debug, Default)]
struct SetRegTool;

#[reverie::tool]
impl Tool for SetRegTool {
    type GlobalState = ();
    type ThreadState = ();

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-167): Review the DBT set_regs regression tool.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::getpid => {
                let mut regs = guest.regs().await;
                regs.r15 = SET_REG_SENTINEL;
                guest.set_regs(regs).await?;
                // Suppress getpid with a fixed value; the guest observes the
                // rewritten r15 after resuming, not this return value.
                Ok(4321)
            }
            _ => guest.tail_inject(syscall).await,
        }
    }
}

/// Regression tool that exercises the DBT `Guest::ppid` path (and the
/// `is_root_process` default built on it). On the guest's `getpid`, it emits one
/// line reporting the tool-observed real `pid`, the `Guest::ppid` result, and
/// `is_root_process`, then lets the syscall run normally. The DBT Tool runtime
/// runs only in the root of the traced tree — copied/forked children are served
/// by the native-only identity/policy path (`emulate_identity_getter` /
/// `reverie_dbt_runtime_copied_syscall`) and never dispatch a Rust `Tool` — so
/// the emitted line is `PPID_ROOT`, where `ppid` must be `None`. The real
/// in-tree parent case (a positive `current_ppid`, so `ppid == Some(parent)` and
/// `is_root_process() == false`) is covered by the crate's unit tests, which
/// drive `current_ppid`/`Guest::ppid` with a positive parent pid directly.
#[derive(Clone, Copy, Debug, Default)]
struct PpidTool;

#[reverie::tool]
impl Tool for PpidTool {
    type GlobalState = ();
    type ThreadState = ();

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-ratchet11): Review the DBT ppid regression tool.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            let pid = guest.pid().as_raw();
            let ppid = guest.ppid();
            let is_root = guest.is_root_process();
            // The root observes no in-tree parent; a forked child observes its
            // real parent (the root) and is not itself a root.
            let (kind, ok) = if is_root {
                ("PPID_ROOT", ppid.is_none())
            } else {
                ("PPID_CHILD", ppid.is_some_and(|p| p.as_raw() > 0))
            };
            emit_line(&format!(
                "{kind} ok={} pid={} ppid={} root={}",
                ok as i32,
                pid,
                ppid.map_or(-1, |p| p.as_raw()),
                is_root as i32,
            ));
        }
        // Never suppress: let the guest observe its normal (virtualized) result.
        guest.tail_inject(syscall).await
    }
}

/// Regression tool that exercises the DBT `Guest::backtrace` path. On the
/// guest's `getpid`, it captures a stack trace and emits one line reporting
/// whether a backtrace was produced and how many frames it contains, then lets
/// the syscall run normally. Because the DBT Tool runs in-process in the guest's
/// own address space, `backtrace` walks the guest's real frame-pointer chain
/// (seeded from the guest register file), so a guest built with frame pointers
/// yields several frames (the syscall site plus its callers up to the entry
/// point). The fixture issues the `getpid` from a deliberately nested call chain
/// so a correct walk returns more than the single top frame.
#[derive(Clone, Copy, Debug, Default)]
struct BacktraceTool;

#[reverie::tool]
impl Tool for BacktraceTool {
    type GlobalState = ();
    type ThreadState = ();

    // AUTONOMOUS-BOT-IMPLEMENTED
    // TODO-HUMAN-REVIEW(PR-ratchet16): Review the DBT backtrace regression tool.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            let (ok, frames, top) = match guest.backtrace() {
                // A real in-process walk must recover at least the syscall site
                // plus a couple of the fixture's nested callers.
                Some(bt) => {
                    let count = bt.iter().count();
                    let top = bt.iter().next().map_or(0, |frame| frame.ip);
                    (count >= 3, count, top)
                }
                None => (false, 0, 0),
            };
            emit_line(&format!(
                "BACKTRACE ok={} frames={} top={:#x}",
                ok as i32, frames, top
            ));
        }
        // Never suppress: let the guest observe its normal (virtualized) result.
        guest.tail_inject(syscall).await
    }
}

/// RPC request for [`Counter1Global`]: either record one syscall or read the
/// running total back. Mirrors `reverie-examples/counter1`'s `IncrMsg`, but adds
/// a `Report` so the tool can retrieve the count to print at guest exit (the DBT
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
/// `counter1` example — proving the DBT `Guest`'s RPC surface works, not just
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

/// The `counter1` example tool, adapted to DBT: count every syscall via
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
                "reverie-dbt: counter1 total system calls: {total}"
            ));
        }
        guest.tail_inject(syscall).await
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-150): Review the DBT counter2 Tool port and lifecycle accounting.
#[derive(Debug, Default)]
struct Counter2Totals {
    total_syscalls: u64,
    exited_processes: u64,
    exited_threads: u64,
}

/// Coordinator-owned totals reported by DBT counter2 processes at exit.
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
    /// Returns aggregate `(syscalls, processes, threads)` totals.
    pub fn snapshot(&self) -> (u64, u64, u64) {
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

    fn report(&self) -> Counter2Request {
        Counter2Request {
            syscalls: self.process_syscalls.load(Ordering::SeqCst),
            threads: self.observed_threads.load(Ordering::SeqCst),
        }
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
        if crate::sync_rpc::is_active() {
            return Ok(());
        }
        let _ = global_state.send_rpc(self.report()).await;
        Ok(())
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-162): Review the DBT chunky_print port and stdout re-emit path.
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

/// The `chunky_print` example's [`GlobalTool`], adapted to DBT. Buffers
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
/// upstream example. The DBT tool is rebuilt per syscall, so these flags live
/// process-globally rather than in the tool instance.
static CHUNKY_STDOUT_REDIRECTED: AtomicBool = AtomicBool::new(false);
static CHUNKY_STDERR_REDIRECTED: AtomicBool = AtomicBool::new(false);

/// The `chunky_print` example [`Tool`], adapted to DBT: suppress guest writes to
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
                    "reverie-dbt: chunky_print suppressed write of {len} bytes to fd {fd}"
                ));
                // Suppress the original write; report the full length as written.
                Ok(len as i64)
            }
            _ => {
                if matches!(syscall.number(), Sysno::exit | Sysno::exit_group) {
                    // Flush before injecting the terminating call, which never
                    // returns to this handler.
                    let _ = guest.send_rpc(ChunkyMsg::Flush).await;
                    emit_line("reverie-dbt: chunky_print flushed buffered output at exit");
                }
                guest.tail_inject(syscall).await
            }
        }
    }
}

/// Reads `len` bytes of guest memory at `addr`. The DBT client is in-process
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

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-165): Review the DBT chrome_trace port and JSON emit path.
/// RPC to [`ChromeTraceGlobal`]. Mirrors the upstream `chrome_trace` example's
/// `ThreadExit`/`Event` messages, but sends one syscall observation at a time
/// (the DBT backend rebuilds the tool per syscall and hardwires `ThreadState`
/// to `()`, so per-thread accumulation lives in the process-global state keyed
/// by tid rather than in the tool's `ThreadState`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChromeMsg {
    /// One observed syscall entry: its start time (µs since [`CHROME_EPOCH`]),
    /// raw number, and pretty-printed form (inputs only).
    Syscall {
        tid: i32,
        pid: i32,
        at_us: u64,
        sysno: i32,
        pretty: String,
    },
    /// Finalize any in-flight per-thread event and emit the Chrome trace JSON.
    Flush,
}

/// A completed syscall event on one thread: `[start, start + dur)` in µs since
/// [`CHROME_EPOCH`]. The duration is approximated as the interval until the
/// thread's *next* observed syscall entry (or the flush time for the last one),
/// because the DBT tool records at syscall entry via `tail_inject` and never
/// resumes to observe the true return — an intentional L0 fidelity limit that
/// avoids injecting (and potentially blocking on) each syscall in-client.
#[derive(Clone, Debug)]
struct ChromeSyscall {
    start_us: u64,
    dur_us: u64,
    sysno: i32,
    pretty: String,
}

/// Per-thread accumulated timeline, keyed by raw tid in [`ChromeInner`].
#[derive(Clone, Debug, Default)]
struct ChromeThread {
    pid: i32,
    start_us: u64,
    end_us: u64,
    events: Vec<ChromeSyscall>,
    /// The most recent syscall entry whose end is not yet known (finalized when
    /// the next entry on this thread arrives, or at flush).
    pending: Option<(u64, i32, String)>,
}

impl ChromeThread {
    /// Closes out the pending syscall (if any) with an end time of `end_us`.
    fn settle_pending(&mut self, end_us: u64) {
        if let Some((start_us, sysno, pretty)) = self.pending.take() {
            self.events.push(ChromeSyscall {
                start_us,
                dur_us: end_us.saturating_sub(start_us),
                sysno,
                pretty,
            });
        }
    }
}

#[derive(Debug, Default)]
struct ChromeInner {
    /// Per-thread timelines, keyed by raw tid.
    threads: BTreeMap<i32, ChromeThread>,
    /// Whether the trace has already been emitted (guards against a second
    /// flush from a racing exit path).
    flushed: bool,
}

impl ChromeInner {
    fn record_syscall(&mut self, tid: i32, pid: i32, at_us: u64, sysno: i32, pretty: String) {
        let thread = self.threads.entry(tid).or_insert_with(|| ChromeThread {
            pid,
            start_us: at_us,
            end_us: at_us,
            events: Vec::new(),
            pending: None,
        });
        thread.pid = pid;
        thread.end_us = at_us;
        // The previous syscall on this thread ends where this one begins.
        thread.settle_pending(at_us);
        thread.pending = Some((at_us, sysno, pretty));
    }

    /// Finalizes every thread's pending syscall and emits the Chrome trace JSON
    /// (a single array of trace events) through the diagnostic emitter. Emitting
    /// via DynamoRIO's own I/O keeps the trace off the guest's stdout and avoids
    /// re-entering the syscall hook. Idempotent.
    fn flush(&mut self) {
        if self.flushed {
            return;
        }
        self.flushed = true;
        let mut events: Vec<serde_json::Value> = Vec::new();
        for (tid, thread) in self.threads.iter_mut() {
            thread.settle_pending(thread.end_us);
            events.push(serde_json::json!({
                "name": format!("TID {tid}"),
                "cat": "process",
                "ph": "B",
                "ts": thread.start_us,
                "pid": thread.pid,
                "tid": tid,
            }));
            for event in &thread.events {
                events.push(serde_json::json!({
                    "name": Sysno::from(event.sysno).name(),
                    "cat": "syscall",
                    "ph": "X",
                    "ts": event.start_us,
                    "dur": event.dur_us,
                    "pid": thread.pid,
                    "tid": tid,
                    "args": { "pretty": event.pretty, "sysno": event.sysno },
                }));
            }
            events.push(serde_json::json!({
                "name": format!("TID {tid}"),
                "cat": "process",
                "ph": "E",
                "ts": thread.end_us,
                "pid": thread.pid,
                "tid": tid,
            }));
        }
        let count = events.len();
        let threads = self.threads.len();
        let json = serde_json::to_string(&serde_json::Value::Array(events))
            .unwrap_or_else(|_| "[]".to_string());
        emit_line(&format!(
            "reverie-dbt: chrome_trace {count} trace events across {threads} thread(s)"
        ));
        // The full array on one line, prefixed so a consumer can extract it
        // (e.g. `sed 's/^reverie-dbt: chrome_trace_json=//'` into a .json file
        // loadable by chrome://tracing / perfetto).
        emit_line(&format!("reverie-dbt: chrome_trace_json={json}"));
    }
}

/// The `chrome_trace` example's [`GlobalTool`], adapted to DBT. Accumulates a
/// per-thread syscall timeline and emits it as Chrome trace JSON at exit. Served
/// in-process through [`CHROME_TRACE_GLOBAL`] (like [`COUNTER1_GLOBAL`]).
#[derive(Debug, Default)]
pub struct ChromeTraceGlobal(Mutex<ChromeInner>);

#[reverie::global_tool]
impl GlobalTool for ChromeTraceGlobal {
    type Request = ChromeMsg;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, message: ChromeMsg) {
        let mut inner = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match message {
            ChromeMsg::Syscall {
                tid,
                pid,
                at_us,
                sysno,
                pretty,
            } => inner.record_syscall(tid, pid, at_us, sysno, pretty),
            ChromeMsg::Flush => inner.flush(),
        }
    }
}

/// The `chrome_trace` example [`Tool`], adapted to DBT: record every syscall's
/// entry (timestamp + decoded inputs) into the per-thread timeline and, at
/// `exit`/`exit_group`, emit the whole trace as Chrome trace JSON. Unlike the
/// upstream tool it does not `inject` each syscall to measure the true return —
/// see [`ChromeSyscall`] for the resulting L0 fidelity limits.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChromeTraceTool;

#[reverie::tool]
impl Tool for ChromeTraceTool {
    type GlobalState = ChromeTraceGlobal;
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-165): Review lifecycle-safe chrome_trace recording + JSON emit.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let number = syscall.number();
        // Materialize the decoded syscall into an owned String *before* the
        // await: the `Display` borrows `guest.memory()`, which is not `Send`, so
        // it must not live across the `send_rpc` suspension point.
        let pretty = syscall.display(&guest.memory()).to_string();
        let tid = guest.tid().as_raw();
        let pid = guest.pid().as_raw();
        let at_us = chrome_now_us();
        let _ = guest
            .send_rpc(ChromeMsg::Syscall {
                tid,
                pid,
                at_us,
                sysno: number.id(),
                pretty,
            })
            .await;
        if matches!(number, Sysno::exit | Sysno::exit_group) {
            // Flush before injecting the terminating call, which never returns
            // to this handler.
            let _ = guest.send_rpc(ChromeMsg::Flush).await;
        }
        guest.tail_inject(syscall).await
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-166): Review the DBT chaos intervention port.
/// The `chaos` example's intervention knobs, adapted to the DBT backend.
///
/// Field meanings match `reverie-examples/chaos.rs`: `skip` passes the first N
/// syscalls through untouched (needed to clear the dynamic linker, which does
/// not retry short reads); `no_read`/`no_recv` disable read/recv truncation;
/// `no_interrupt` disables error injection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChaosOpts {
    skip: u64,
    no_read: bool,
    no_recv: bool,
    no_interrupt: bool,
}

impl Default for ChaosOpts {
    fn default() -> Self {
        // Truncation on, interruption off — see [`CHAOS_CONFIG`].
        Self {
            skip: 0,
            no_read: false,
            no_recv: false,
            no_interrupt: true,
        }
    }
}

/// The decision for a chaos-intercepted `read`, factored out so the branch
/// logic is unit-testable without a live `Guest`.
#[derive(Debug, PartialEq, Eq)]
enum ChaosRead {
    /// Inject an interruption without running the read. DBT's suppress model
    /// cannot request the kernel syscall restart the ptrace example triggers
    /// with `ERESTARTSYS`, so the guest sees `EINTR` directly and must retry.
    Interrupt,
    /// Run a read truncated to this many bytes and observe the result — the
    /// "pathological kernel returns one byte at a time" behavior.
    Truncate(usize),
    /// Run the read unmodified (only its result is observed).
    Unmodified,
}

/// Chooses the chaos action for a `read` of `len` bytes given the config and
/// whether this thread was already interrupted since its last completed read.
fn chaos_read_action(
    len: usize,
    no_read: bool,
    no_interrupt: bool,
    interrupted: bool,
) -> ChaosRead {
    if !no_interrupt && !interrupted {
        ChaosRead::Interrupt
    } else if !no_read {
        ChaosRead::Truncate(1.min(len))
    } else {
        ChaosRead::Unmodified
    }
}

/// The `chaos` example [`Tool`], adapted to DBT: the first **execution-
/// perturbing** DBT tool rather than a pure observer. It truncates `read`/
/// `recvfrom` to one byte (a pathological kernel), optionally injecting `EINTR`
/// first, and observes the real (identity-virtualized) result via
/// [`Guest::inject`]. Every other syscall is passed straight through with
/// `tail_inject`, keeping potentially-blocking calls off the
/// `dr_invoke_syscall_as_app` path.
#[derive(Clone, Copy, Debug, Default)]
pub struct ChaosTool;

#[reverie::tool]
impl Tool for ChaosTool {
    type GlobalState = ();
    type ThreadState = ();

    // TODO-HUMAN-REVIEW(PR-166): Review lifecycle-safe chaos truncation + injection.
    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let cfg = &*CHAOS_CONFIG;
        let count = CHAOS_COUNT.fetch_add(1, Ordering::SeqCst);
        let pid = guest.pid().as_raw();
        let tid = guest.tid().as_raw();

        // Pass the linker/startup window through untouched.
        if count < cfg.skip {
            emit_line(&format!(
                "chaos SKIPPED [pid {pid} n {count}] {}",
                syscall.display(&guest.memory())
            ));
            // `tail_inject` diverges; the `return` just exits this branch.
            #[allow(unreachable_code)]
            return guest.tail_inject(syscall).await;
        }

        // Decide the transformed syscall, or short-circuit with an injected
        // interruption / passthrough.
        let transformed = match syscall {
            Syscall::Read(read) => {
                match chaos_read_action(
                    read.len(),
                    cfg.no_read,
                    cfg.no_interrupt,
                    chaos_take_interrupted(tid),
                ) {
                    ChaosRead::Interrupt => {
                        chaos_set_interrupted(tid, true);
                        let err = reverie::syscalls::Errno::EINTR;
                        emit_line(&format!(
                            "chaos [pid {pid} n {count}] {} = {}",
                            syscall.display(&guest.memory()),
                            -err.into_raw() as i64
                        ));
                        return Err(err.into());
                    }
                    ChaosRead::Truncate(len) => Syscall::Read(read.with_len(len)),
                    ChaosRead::Unmodified => Syscall::Read(read),
                }
            }
            Syscall::Recvfrom(recv) if !cfg.no_recv => {
                Syscall::Recvfrom(recv.with_len(1.min(recv.len())))
            }
            other => {
                emit_line(&format!(
                    "chaos [pid {pid} n {count}] {}",
                    other.display(&guest.memory())
                ));
                #[allow(unreachable_code)]
                return guest.tail_inject(other).await;
            }
        };

        // A completed (truncated) read clears this thread's interrupt latch so
        // the next read is interrupted again, matching the example's alternation.
        chaos_set_interrupted(tid, false);
        let ret = guest.inject(transformed).await;
        emit_line(&format!(
            "chaos [pid {pid} n {count}] {} = {}",
            transformed.display_with_outputs(&guest.memory()),
            ret.unwrap_or_else(|errno| -errno.into_raw() as i64)
        ));
        Ok(ret?)
    }
}

/// The observation tool selected by the environment, if any.
enum ActiveTool {
    Strace,
    Counter,
    SharedCounter,
    Noop,
    RewriteExit,
    SetReg,
    Ppid,
    Backtrace,
    Counter1,
    Counter2,
    ChunkyPrint,
    ChromeTrace,
    Chaos,
}

fn active_tool() -> Option<ActiveTool> {
    if *TEST_REWRITE_EXIT_ENABLED {
        Some(ActiveTool::RewriteExit)
    } else if *TEST_SET_REG_ENABLED {
        Some(ActiveTool::SetReg)
    } else if *TEST_PPID_ENABLED {
        Some(ActiveTool::Ppid)
    } else if *TEST_BACKTRACE_ENABLED {
        Some(ActiveTool::Backtrace)
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
    } else if *CHROME_TRACE_ENABLED {
        Some(ActiveTool::ChromeTrace)
    } else if *CHAOS_ENABLED {
        Some(ActiveTool::Chaos)
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
        write_registers: RegisterWriter,
    ) -> Result<(DbtSyscallOutcome, Option<Counter2Request>), Error> {
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
                return Ok((DbtSyscallOutcome::ExecuteOriginal(syscall), None));
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
                    .expect("DBT Counter2 thread state disappeared"),
            );
            let thread_state = {
                let mut stored = state_slot
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                stored
                    .take()
                    .expect("DBT Counter2 thread state is already leased")
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
                write_registers,
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
            write_registers,
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
            return outcome.map(|outcome| (outcome, None));
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
                    .expect("DBT Counter2 Tool disappeared before process exit");
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

            let global = crate::DbtGlobal::<Counter2Tool> {
                tid,
                global_state: &self.global_state,
                config: &(),
                guest_rpc: None,
            };
            let report = process_tool.report();
            run_ready(
                process_tool
                    .as_ref()
                    .clone()
                    .on_exit_process(pid, &global, status),
            )?;
            return Ok((outcome, Some(report)));
        }

        let process_tool = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.thread_states.remove(&tid.as_raw());
            let process_exited = tid == pid && registry.thread_states.is_empty();
            if process_exited {
                registry.process_exiting = true;
            }
            process_exited.then(|| {
                registry
                    .tool
                    .take()
                    .expect("DBT Counter2 Tool disappeared before process exit")
            })
        };
        crate::run_tool_thread_exit(
            tool.as_ref(),
            tid,
            thread_state,
            &self.global_state,
            &(),
            status,
        )?;
        let report = process_tool.as_ref().map(|tool| tool.report());
        if let Some(process_tool) = process_tool {
            let global = crate::DbtGlobal::<Counter2Tool> {
                tid,
                global_state: &self.global_state,
                config: &(),
                guest_rpc: None,
            };
            run_ready(
                process_tool
                    .as_ref()
                    .clone()
                    .on_exit_process(pid, &global, status),
            )?;
        }
        Ok((outcome, report))
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

// TODO-HUMAN-REVIEW(PR-150): Review DBT exit lifecycle classification.
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
    write_registers: RegisterWriter,
    read_memory: MemoryReader,
) -> Option<DbtSyscallOutcome> {
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
            write_registers,
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
            write_registers,
        ),
        ActiveTool::SharedCounter => dispatch_shared(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
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
            write_registers,
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
            write_registers,
        ),
        ActiveTool::SetReg => dispatch(
            &SetRegTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
        ),
        ActiveTool::Ppid => dispatch(
            &PpidTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
        ),
        ActiveTool::Backtrace => dispatch_with_memory_reader(
            &BacktraceTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
            read_memory,
        ),
        ActiveTool::Counter1 => dispatch_counter1(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
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
            write_registers,
        ),
        ActiveTool::ChunkyPrint => dispatch_chunky_print(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
        ),
        ActiveTool::ChromeTrace => dispatch_chrome_trace(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
        ),
        // Chaos carries no global/thread state (its per-thread latch and skip
        // counter are process-global), so it uses the generic dispatch.
        ActiveTool::Chaos => dispatch(
            &ChaosTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
            write_registers,
        ),
    };
    Some(match result {
        Ok(outcome) => outcome,
        Err(Error::Errno(errno)) => DbtSyscallOutcome::Suppress(-(errno.into_raw() as i64)),
        Err(_) => DbtSyscallOutcome::Suppress(-(reverie::syscalls::Errno::EIO.into_raw() as i64)),
    })
}

#[allow(clippy::too_many_arguments)]
fn dispatch_with_memory_reader<T>(
    tool: &T,
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
    read_memory: MemoryReader,
) -> Result<DbtSyscallOutcome, Error>
where
    T: Tool<GlobalState = (), ThreadState = ()>,
{
    let mut thread_state = ();
    crate::run_tool_syscall_with_memory_reader(
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
        write_registers,
        read_memory,
    )
}

/// Builds a [`DbtGuest`] specialized for `tool` and runs its syscall handler.
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
    write_registers: RegisterWriter,
) -> Result<DbtSyscallOutcome, Error>
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
        write_registers,
    )
}

/// The process-global `counter1` state. It must persist across syscalls (each
/// `run_active_tool` call builds a fresh `DbtGuest`), so it lives here rather
/// than in a per-call local. `send_rpc` on `DbtGuest` dispatches to this
/// instance's `receive_rpc` in-process.
static COUNTER1_GLOBAL: LazyLock<Counter1Global> = LazyLock::new(Counter1Global::default);

/// Runs one syscall through [`SharedSyscallCounterTool`], whose non-`()`
/// [`SyscallCounterGlobal`] is served out-of-process. `send_rpc` routes to the
/// coordinator socket, so the local `global` below is a never-touched
/// placeholder required only by the [`DbtGuest`] constructor.
#[allow(clippy::too_many_arguments)]
fn dispatch_shared(
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
) -> Result<DbtSyscallOutcome, Error> {
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
        write_registers,
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
    write_registers: RegisterWriter,
) -> Result<DbtSyscallOutcome, Error> {
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
        write_registers,
    )
}

/// The process-global `chunky_print` state, persisting the per-thread print
/// buffers across syscalls. Like [`COUNTER1_GLOBAL`], `send_rpc` on the DBT
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
    write_registers: RegisterWriter,
) -> Result<DbtSyscallOutcome, Error> {
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
        write_registers,
    )
}

/// The process-global `chrome_trace` state, persisting the per-thread syscall
/// timelines across syscalls (each `run_active_tool` call builds a fresh
/// `DbtGuest`). Like [`COUNTER1_GLOBAL`], `send_rpc` on the DBT guest dispatches
/// to this instance's `receive_rpc` in-process.
static CHROME_TRACE_GLOBAL: LazyLock<ChromeTraceGlobal> = LazyLock::new(ChromeTraceGlobal::default);

/// Runs one syscall through [`ChromeTraceTool`], whose [`ChromeTraceGlobal`] is
/// the shared [`CHROME_TRACE_GLOBAL`] so the per-thread timeline accumulates
/// across the run and is emitted as Chrome trace JSON at `exit`/`exit_group`.
#[allow(clippy::too_many_arguments)]
fn dispatch_chrome_trace(
    context: usize,
    tid: i32,
    pid: i32,
    branches: u64,
    syscall: Syscall,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
    write_registers: RegisterWriter,
) -> Result<DbtSyscallOutcome, Error> {
    let mut thread_state = ();
    crate::run_tool_syscall(
        &ChromeTraceTool,
        context,
        Pid::from_raw(tid),
        Pid::from_raw(pid),
        branches,
        &mut thread_state,
        &*CHROME_TRACE_GLOBAL,
        &(),
        syscall,
        invoke_syscall,
        read_registers,
        write_registers,
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
    write_registers: RegisterWriter,
) -> Result<DbtSyscallOutcome, Error> {
    let (outcome, report) = COUNTER2_HOST.dispatch(
        context,
        Pid::from_raw(tid),
        Pid::from_raw(pid),
        branches,
        syscall,
        exit_code,
        invoke_syscall,
        read_registers,
        write_registers,
    )?;
    if let Some(report) = report {
        if crate::sync_rpc::is_active() {
            crate::sync_rpc::send_rpc_from_guest::<_, ()>(
                context,
                invoke_syscall,
                Pid::from_raw(tid),
                report,
            );
        } else {
            let (syscalls, processes, threads) = COUNTER2_HOST.global_state.snapshot();
            emit_line(&format!(
                "reverie-dbt: counter2 total system calls: {syscalls}, from {processes} processes, {threads} thread(s)"
            ));
            COUNTER2_HOST.finish_exit_group();
        }
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

    unsafe extern "C" fn fake_write_registers(
        _context: usize,
        _registers: *const libc::user_regs_struct,
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
                    fake_write_registers,
                )
                .unwrap();
            assert_eq!(
                outcome,
                DbtSyscallOutcome::ExecuteOriginal(syscall(Sysno::getpid, 0))
            );
            assert!(exited.is_none());
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
                fake_write_registers,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DbtSyscallOutcome::ExecuteOriginal(syscall(Sysno::gettid, 0))
        );
        assert!(exited.is_none());

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
                fake_write_registers,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DbtSyscallOutcome::ExecuteOriginal(syscall(Sysno::exit, 0))
        );
        assert!(exited.is_none());

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
                fake_write_registers,
            )
            .unwrap();
        assert_eq!(
            outcome,
            DbtSyscallOutcome::ExecuteOriginal(syscall(Sysno::exit_group, 7))
        );
        assert_eq!(
            exited,
            Some(Counter2Request {
                syscalls: 5,
                threads: 2
            })
        );
        assert_eq!(host.global_state.snapshot(), (5, 1, 2));
    }

    #[test]
    fn chrome_trace_settles_pending_and_computes_durations() {
        let mut inner = ChromeInner::default();
        // Three syscalls on one thread. Each entry closes out the prior one, so
        // getpid's duration is 150-100 and write's is 220-150.
        inner.record_syscall(3, 3, 100, Sysno::getpid.id(), "getpid()".to_string());
        inner.record_syscall(3, 3, 150, Sysno::write.id(), "write(1, ...)".to_string());
        inner.record_syscall(
            3,
            3,
            220,
            Sysno::exit_group.id(),
            "exit_group(0)".to_string(),
        );

        let thread = &inner.threads[&3];
        assert_eq!(thread.start_us, 100);
        assert_eq!(thread.end_us, 220);
        assert_eq!(
            thread.events.len(),
            2,
            "two settled, exit_group still pending"
        );
        assert_eq!(thread.events[0].dur_us, 50);
        assert_eq!(thread.events[1].dur_us, 70);

        inner.flush();
        assert!(inner.flushed);
        let thread = &inner.threads[&3];
        assert_eq!(
            thread.events.len(),
            3,
            "flush settles the pending exit_group"
        );
        assert_eq!(thread.events[2].sysno, Sysno::exit_group.id());
        assert_eq!(thread.events[2].dur_us, 0, "last event ends at thread end");

        // A second flush is a no-op (guards a racing exit path).
        inner.flush();
        assert_eq!(inner.threads[&3].events.len(), 3);
    }

    #[test]
    fn chrome_trace_tracks_multiple_threads_independently() {
        let mut inner = ChromeInner::default();
        inner.record_syscall(3, 3, 10, Sysno::getpid.id(), "getpid()".to_string());
        inner.record_syscall(4, 3, 20, Sysno::gettid.id(), "gettid()".to_string());
        inner.record_syscall(3, 3, 40, Sysno::write.id(), "write(1, ...)".to_string());
        inner.flush();

        // Both tids are tracked; the parent's getpid spans 10->40, the worker's
        // single gettid settles to a zero-length event at flush.
        assert_eq!(inner.threads.len(), 2);
        assert_eq!(inner.threads[&3].events.len(), 2);
        assert_eq!(inner.threads[&3].events[0].dur_us, 30);
        assert_eq!(inner.threads[&4].events.len(), 1);
        assert_eq!(inner.threads[&4].pid, 3);
    }

    #[test]
    fn chaos_read_alternates_interrupt_and_truncation() {
        // Default config: truncation on, interruption off (DBT-safe default).
        assert_eq!(
            chaos_read_action(4096, false, true, false),
            ChaosRead::Truncate(1)
        );
        assert_eq!(
            chaos_read_action(0, false, true, false),
            ChaosRead::Truncate(0)
        );

        // With interruption enabled, an un-interrupted thread is interrupted
        // first, then its next read is truncated.
        assert_eq!(
            chaos_read_action(4096, false, false, false),
            ChaosRead::Interrupt
        );
        assert_eq!(
            chaos_read_action(4096, false, false, true),
            ChaosRead::Truncate(1)
        );
    }

    #[test]
    fn chaos_read_respects_no_read_and_disabled_interrupt() {
        // no_read leaves the read unmodified (still observed, not truncated).
        assert_eq!(
            chaos_read_action(4096, true, true, false),
            ChaosRead::Unmodified
        );
        // no_read but interruption enabled still interrupts the first read.
        assert_eq!(
            chaos_read_action(4096, true, false, false),
            ChaosRead::Interrupt
        );
        // Both interventions off: pass the read through unmodified.
        assert_eq!(
            chaos_read_action(4096, true, true, true),
            ChaosRead::Unmodified
        );
    }

    #[test]
    fn chaos_default_config_truncates_without_interrupting() {
        let cfg = ChaosOpts::default();
        assert!(!cfg.no_read, "truncation on by default");
        assert!(cfg.no_interrupt, "interruption off by default (DBT-safe)");
        assert_eq!(cfg.skip, 0);
    }
}
