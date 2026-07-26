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
//!  * [`StraceTool`] — logs every syscall's name, decoded arguments and return
//!    value. Unlike `strace_minimal` (which uses `tail_inject` and can only
//!    print `= ?`), this uses [`reverie::Guest::inject`], so it recovers the
//!    real return value.
//!  * [`Counter2Tool`] — preserves per-thread counts across syscalls, drives
//!    `tail_inject`, and folds thread/process exit hooks into a global summary.
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
use std::sync::LazyLock;
use std::sync::Mutex;
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
use reverie::syscalls::Displayable;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use serde::Deserialize;
use serde::Serialize;

use crate::DbiGuest;
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
const COUNTER1_ENV: &str = "HERMIT_DBI_COUNTER1";
const COUNTER2_ENV: &str = "HERMIT_DBI_COUNTER2";

fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| {
        !value.is_empty() && value != OsStr::new("0") && value != OsStr::new("false")
    })
}

static HISTOGRAM_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(SYSCALL_HISTOGRAM_ENV));
static STRACE_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(STRACE_ENV));
static NOOP_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(NOOP_ENV));
static COUNTER1_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER1_ENV));
static COUNTER2_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(COUNTER2_ENV));

/// Per-syscall-number invocation counts, keyed by raw syscall number.
static SYSCALL_HISTOGRAM: LazyLock<Mutex<BTreeMap<i32, u64>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// The DynamoRIO emit callback (a C function pointer stored as a `usize`),
/// installed on the first syscall event.
static EMITTER: AtomicUsize = AtomicUsize::new(0);

/// Records the emit callback so the tools can produce output.
pub fn set_emitter(emit: Emitter) {
    EMITTER.store(emit as usize, Ordering::Relaxed);
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

/// True for syscalls that never return on success, so a tracer must log them
/// *before* injecting (the injected call will not come back).
fn never_returns(number: Sysno) -> bool {
    matches!(number, Sysno::exit | Sysno::exit_group | Sysno::execve)
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
/// histogram lives in a process-global map. `guest.inject` passes the syscall
/// through to the kernel, keeping the tool purely observational.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallCounterTool;

#[reverie::tool]
impl Tool for SyscallCounterTool {
    type GlobalState = ();
    type ThreadState = ();

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
        Ok(guest.inject(syscall).await?)
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

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let number = syscall.number();
        // Record into the shared histogram before injecting; `exit`/`exit_group`
        // never return to us, but the count is already committed above.
        let _ = guest.send_rpc(RecordSyscall(number.id())).await;
        Ok(guest.inject(syscall).await?)
    }
}

/// Logs every syscall's name, decoded arguments and return value.
///
/// Mirrors `strace_minimal`, but recovers the real return value via
/// `guest.inject` instead of printing `= ?`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StraceTool;

#[reverie::tool]
impl Tool for StraceTool {
    type GlobalState = ();
    type ThreadState = ();

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
        if never_returns(syscall.number()) {
            emit_line(&format!("{prefix} = ?"));
            if matches!(syscall.number(), Sysno::exit | Sysno::exit_group) && *HISTOGRAM_ENABLED {
                print_syscall_histogram();
            }
            return Ok(guest.inject(syscall).await?);
        }
        let result = guest.inject(syscall).await;
        match result {
            Ok(value) => emit_line(&format!("{prefix} = {value}")),
            Err(errno) => emit_line(&format!("{prefix} = -1 ({errno:?})")),
        }
        Ok(result?)
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#123): Review the DBI noop/counter1 example-tool ports.
/// The reverie `noop` example, adapted to DBI: a tool that observes every
/// syscall but changes nothing, passing each straight through to the kernel.
/// Exercises the minimal `Guest::inject` path — the floor of DBI Tool support.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopTool;

#[reverie::tool]
impl Tool for NoopTool {
    type GlobalState = ();
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
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
        Ok(guest.inject(syscall).await?)
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

#[derive(Debug, Default)]
pub struct Counter2Tool {
    process_syscalls: AtomicU64,
    exited_threads: AtomicU64,
}

#[reverie::tool]
impl Tool for Counter2Tool {
    type GlobalState = Counter2Global;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        *guest.thread_state_mut() += 1;
        guest.tail_inject(syscall).await
    }

    async fn on_exit_thread<G: reverie::GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Tid,
        _global_state: &G,
        thread_syscalls: u64,
        _exit_status: ExitStatus,
    ) -> Result<(), Error> {
        self.process_syscalls
            .fetch_add(thread_syscalls, Ordering::SeqCst);
        self.exited_threads.fetch_add(1, Ordering::SeqCst);
        Ok(())
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
                threads: self.exited_threads.load(Ordering::SeqCst),
            })
            .await;
        Ok(())
    }
}

/// The observation tool selected by the environment, if any.
enum ActiveTool {
    Strace,
    Counter,
    SharedCounter,
    Noop,
    Counter1,
    Counter2,
}

fn active_tool() -> Option<ActiveTool> {
    if *STRACE_ENABLED {
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

// TODO-HUMAN-REVIEW(PR-150): Review persistent DBI observation Tool state and exit lifecycle.
struct ObservationToolHost<T: Tool> {
    tool: Option<T>,
    global_state: T::GlobalState,
    config: <T::GlobalState as GlobalTool>::Config,
    thread_states: BTreeMap<i32, T::ThreadState>,
}

impl<T> Default for ObservationToolHost<T>
where
    T: Tool,
    T::GlobalState: Default,
    <T::GlobalState as GlobalTool>::Config: Default,
{
    fn default() -> Self {
        Self {
            tool: None,
            global_state: T::GlobalState::default(),
            config: <T::GlobalState as GlobalTool>::Config::default(),
            thread_states: BTreeMap::new(),
        }
    }
}

impl<T> ObservationToolHost<T>
where
    T: Tool,
    T::GlobalState: Default,
    <T::GlobalState as GlobalTool>::Config: Default,
{
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &mut self,
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
        if self.tool.is_none() {
            self.tool = Some(T::new(pid, &self.config));
        }

        if !self.thread_states.contains_key(&tid.as_raw()) {
            let state = self
                .tool
                .as_ref()
                .expect("DBI observation Tool disappeared")
                .init_thread_state(tid, None);
            self.thread_states.insert(tid.as_raw(), state);
            crate::run_tool_thread_start(
                self.tool
                    .as_ref()
                    .expect("DBI observation Tool disappeared"),
                context,
                tid,
                pid,
                branches,
                self.thread_states
                    .get_mut(&tid.as_raw())
                    .expect("DBI observation thread state disappeared"),
                &self.global_state,
                &self.config,
                invoke_syscall,
                read_registers,
            )?;
        }

        let outcome = crate::run_tool_syscall(
            self.tool
                .as_ref()
                .expect("DBI observation Tool disappeared"),
            context,
            tid,
            pid,
            branches,
            self.thread_states
                .get_mut(&tid.as_raw())
                .expect("DBI observation thread state disappeared"),
            &self.global_state,
            &self.config,
            syscall,
            invoke_syscall,
            read_registers,
        )?;

        if !is_exit_syscall(number) {
            return Ok((outcome, false));
        }

        let status = ExitStatus::Exited(exit_code & 0xff);
        let exit_group = number == Sysno::exit_group;
        let exiting_states = if exit_group {
            std::mem::take(&mut self.thread_states)
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            self.thread_states
                .remove(&tid.as_raw())
                .map(|state| vec![(tid.as_raw(), state)])
                .unwrap_or_default()
        };
        for (raw_tid, state) in exiting_states {
            crate::run_tool_thread_exit(
                self.tool
                    .as_ref()
                    .expect("DBI observation Tool disappeared"),
                Pid::from_raw(raw_tid),
                state,
                &self.global_state,
                &self.config,
                status,
            )?;
        }

        let process_exited = exit_group || (tid == pid && self.thread_states.is_empty());
        if process_exited {
            let tool = self
                .tool
                .take()
                .expect("DBI observation Tool disappeared before process exit");
            let global = crate::DbiGlobal::<T> {
                tid,
                global_state: &self.global_state,
                config: &self.config,
            };
            run_ready(tool.on_exit_process(pid, &global, status))?;
        }

        Ok((outcome, process_exited))
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
        )
        .map(DbiSyscallOutcome::Suppress),
        ActiveTool::Counter => dispatch(
            &SyscallCounterTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        )
        .map(DbiSyscallOutcome::Suppress),
        ActiveTool::SharedCounter => dispatch_shared(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        )
        .map(DbiSyscallOutcome::Suppress),
        ActiveTool::Noop => dispatch(
            &NoopTool,
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        )
        .map(DbiSyscallOutcome::Suppress),
        ActiveTool::Counter1 => dispatch_counter1(
            context,
            tid,
            pid,
            branches,
            syscall,
            invoke_syscall,
            read_registers,
        )
        .map(DbiSyscallOutcome::Suppress),
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
) -> Result<i64, Error>
where
    T: Tool<GlobalState = (), ThreadState = ()>,
{
    let mut thread_state = ();
    let mut guest = DbiGuest::new(
        context,
        reverie::Pid::from_raw(tid),
        reverie::Pid::from_raw(pid),
        None,
        branches,
        &mut thread_state,
        &(),
        &(),
        invoke_syscall,
        read_registers,
    );
    run_ready(tool.handle_syscall_event(&mut guest, syscall))
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
) -> Result<i64, Error> {
    let global = SyscallCounterGlobal::default();
    let config = ();
    let mut thread_state = ();
    let mut guest = DbiGuest::new(
        context,
        reverie::Pid::from_raw(tid),
        reverie::Pid::from_raw(pid),
        None,
        branches,
        &mut thread_state,
        &global,
        &config,
        invoke_syscall,
        read_registers,
    );
    run_ready(SharedSyscallCounterTool.handle_syscall_event(&mut guest, syscall))
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
) -> Result<i64, Error> {
    let mut thread_state = ();
    let mut guest = DbiGuest::new(
        context,
        reverie::Pid::from_raw(tid),
        reverie::Pid::from_raw(pid),
        None,
        branches,
        &mut thread_state,
        // `&*` forces `LazyLock<Counter1Global>` to deref to `&Counter1Global`.
        &*COUNTER1_GLOBAL,
        &(),
        invoke_syscall,
        read_registers,
    );
    run_ready(Counter1Tool.handle_syscall_event(&mut guest, syscall))
}

static COUNTER2_HOST: LazyLock<Mutex<ObservationToolHost<Counter2Tool>>> =
    LazyLock::new(|| Mutex::new(ObservationToolHost::default()));

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
    let mut host = COUNTER2_HOST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (outcome, process_exited) = host.dispatch(
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
        let (syscalls, processes, threads) = host.global_state.snapshot();
        emit_line(&format!(
            "reverie-dbi: counter2 total system calls: {syscalls}, from {processes} processes, {threads} thread(s)"
        ));
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
        let mut host = ObservationToolHost::<Counter2Tool>::default();
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
            assert_eq!(outcome, DbiSyscallOutcome::Suppress(0));
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
        assert_eq!(outcome, DbiSyscallOutcome::Suppress(0));
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
        assert_eq!(outcome, DbiSyscallOutcome::AllowOriginal);
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
        assert_eq!(outcome, DbiSyscallOutcome::AllowOriginal);
        assert!(exited);
        assert_eq!(host.global_state.snapshot(), (5, 1, 2));
    }
}
