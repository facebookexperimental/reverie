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
//! Two tools are provided, mirroring `reverie-examples/counter1.rs` and
//! `reverie-examples/strace_minimal.rs`, but adapted to the DBI backend's
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
//!
//! Both are selected at run time via environment variables and dispatched by the
//! native client through [`run_active_tool`]. Output is written through a
//! DynamoRIO emit callback rather than `eprintln!`/fd 2, because the guest may
//! close its stderr before exit and app-level writes re-enter the syscall path.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::future::Future;
use std::pin::pin;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use reverie::Error;
use reverie::Guest;
use reverie::Tool;
use reverie::syscalls::Displayable;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

use crate::DbiGuest;
use crate::RegisterReader;
use crate::SyscallInvoker;

/// Native callback that emits a pre-formatted buffer via DynamoRIO's own I/O.
pub type Emitter = unsafe extern "C" fn(*const u8, usize);

const SYSCALL_HISTOGRAM_ENV: &str = "HERMIT_DBI_SYSCALL_HISTOGRAM";
const STRACE_ENV: &str = "HERMIT_DBI_STRACE";

fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| {
        !value.is_empty() && value != OsStr::new("0") && value != OsStr::new("false")
    })
}

static HISTOGRAM_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(SYSCALL_HISTOGRAM_ENV));
static STRACE_ENABLED: LazyLock<bool> = LazyLock::new(|| env_flag(STRACE_ENV));

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

/// The observation tool selected by the environment, if any.
enum ActiveTool {
    Strace,
    Counter,
}

fn active_tool() -> Option<ActiveTool> {
    if *STRACE_ENABLED {
        Some(ActiveTool::Strace)
    } else if *HISTOGRAM_ENABLED {
        Some(ActiveTool::Counter)
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

/// Runs the environment-selected observation tool for one syscall, if any is
/// active. Returns `Some(result)` when a tool handled the syscall (the native
/// client should then suppress the original and install `result`); returns
/// `None` when no observation tool is active, so the caller falls back to its
/// default behaviour.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_active_tool(
    context: usize,
    tid: i32,
    pid: i32,
    sysnum: i64,
    raw_args: &[u64],
    branches: u64,
    invoke_syscall: SyscallInvoker,
    read_registers: RegisterReader,
) -> Option<i64> {
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
    };
    Some(match result {
        Ok(value) => value,
        Err(Error::Errno(errno)) => -(errno.into_raw() as i64),
        Err(_) => -(reverie::syscalls::Errno::EIO.into_raw() as i64),
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
