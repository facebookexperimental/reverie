/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Trap-only LiteInst with site patching on (P2b): every test runs one mode
//! of `tests/fixtures/trap_only_p2.c` under plain ptrace and under trap-only
//! with patching on, and requires the two runs to be equal: exit status, the
//! run-loop stop sequence, every Tool-visible event (with the registers the
//! Tool sees), the stop counts, and the guest's own report of its results,
//! registers and signal frames. Each test also checks that the trap-only run
//! really patched and hopped, so that equality is not vacuous.
//!
//! The fixture tags the calls it makes through its shared site with a magic
//! value in r9, which also tells the Tool how to handle the call and which
//! signals to send while the call is parked at its seccomp stop.

use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;

use reverie::TimerSchedule;
use serde::Deserialize;
use serde::Serialize;

use super::*;
use crate::liteinst_trap_only::DisabledReason;
use crate::liteinst_trap_only::RetiredReason;
use crate::liteinst_trap_only::SiteState;
use crate::liteinst_trap_only::SiteTable;
use crate::liteinst_trap_only::TableState;
use crate::task::step_count_for_test;
use crate::task::stepped_seccomp_count_for_test;

const TP_MAGIC: u64 = 0x7e57_0000_0000_0000;
const TP_MAGIC_MASK: u64 = 0xffff_0000_0000_0000;
const SHAPE_INJECT: u64 = 0;
const SHAPE_TAIL: u64 = 1;
const SHAPE_EMULATE: u64 = 2;
const SHAPE_PRIVATE: u64 = 3;
const SHAPE_TWO_INJECTS: u64 = 4;
const SHAPE_TWO_PRIVATE: u64 = 5;
const SEND_SIGUSR1: u64 = 0x100;
const SEND_SIGWINCH: u64 = 0x200;
const SEND_QUEUE: u64 = 0x400;
/// The tracer leaves SIGUSR1 pending for its final resume of the stop.
const SEND_RESUME: u64 = 0x800;
/// The Tool requests a precise timer of r8 (the fifth argument) branches.
const ARM_TIMER: u64 = 0x1000;
/// The Tool sends SIGSTOP to the calling thread while it is parked.
const SEND_SIGSTOP: u64 = 0x2000;
/// The Tool notifies the guest's parent again (SIGUSR2) when the kernel
/// restarts the call.
const NOTIFY_AGAIN: u64 = 0x4000;
/// Bits 32-36: a signal the parent sends when the Tool, at the call's seccomp
/// stop, notifies it; the Tool waits until the signal has arrived.
const TOOL_PARK_SHIFT: u32 = 32;
/// Bit 38: after the call's inject returned, the Tool notifies the parent,
/// waits until its SIGCONT has arrived, then queues SIGSTOP (SI_QUEUE, value 7)
/// to the thread.
const TOOL_AFTER_CONT: u64 = 0x40 << TOOL_PARK_SHIFT;
/// Bits 40-44: the same as the Tool's park signal, from the pre-syscall hook
/// (immediately before the call runs: plain ptrace's resume, trap-only's
/// masked hop), at its `Early` point unless `HOOK_LATE`.
const HOOK_PARK_SHIFT: u32 = 40;
/// Bit 45: the hook parks at its `Late` point.
const HOOK_LATE: u64 = 0x20 << HOOK_PARK_SHIFT;
/// Bit 46: at its `Early` point the hook sends SIGSTOP to the process (the
/// shared queue) and to the thread (its private queue).
const HOOK_SEND_STOPS: u64 = 0x40 << HOOK_PARK_SHIFT;
/// Bit 47: at its `Early` point the hook sends SIGKILL to the process and
/// returns at once; at its `Late` point it waits until the kill has taken
/// effect and stays parked.
const HOOK_KILL: u64 = 0x80 << HOOK_PARK_SHIFT;

/// The P2 Tool's configuration.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
struct P2Config {
    /// Resumes untagged syscalls through `tail_inject`; otherwise runs them
    /// through `inject` and records each return value.
    tail: bool,
    /// Leaves getuid unsubscribed, so the subscription is partial.
    partial: bool,
}

#[derive(Default)]
struct P2Log(Mutex<Vec<(Pid, String)>>);

#[reverie::global_tool]
impl GlobalTool for P2Log {
    type Config = P2Config;
    type Request = String;
    type Response = ();

    async fn receive_rpc(&self, from: Pid, event: String) {
        self.0.lock().unwrap().push((from, event));
    }
}

/// Single-step count of each tid when its thread started.
static STEP_BASE: Mutex<BTreeMap<i32, u64>> = Mutex::new(BTreeMap::new());
/// Stepped-seccomp count of each tid at its thread start or its latest
/// syscall entry, whichever is later.
static STEPPED_SEEN: Mutex<BTreeMap<i32, u64>> = Mutex::new(BTreeMap::new());
/// Prefixes the Tool's report of a syscall entry that a timer single-step
/// reached. `run_p2_options` moves these reports out of `tool_events` into
/// `stepped_entries`, so the backend comparisons see exactly the events they
/// saw before the reports existed.
const STEPPED_ENTRY_PREFIX: &str = "stepped-entry ";
/// The last tagged call (sequence number) each tid acted on, so that a call
/// the kernel restarts does not send its signals again.
static ACTED: Mutex<BTreeMap<i32, u64>> = Mutex::new(BTreeMap::new());
/// The restarted tagged calls (tid, sequence) the Tool notified the parent of.
static NOTIFIED: Mutex<std::collections::BTreeSet<(i32, u64)>> =
    Mutex::new(std::collections::BTreeSet::new());

fn steps(tid: Pid) -> u64 {
    let base = STEP_BASE
        .lock()
        .unwrap()
        .get(&tid.as_raw())
        .copied()
        .unwrap_or(0);
    step_count_for_test(tid) - base
}

/// Names an address: the fixture is linked -no-pie, so its own text is at
/// the same address in every run, as is the private page. Library and stack
/// addresses are not, and are only reported as `other`.
fn code(address: u64) -> String {
    let page = crate::cp::PRIVATE_PAGE_OFFSET as u64;
    if (0x40_0000..0x100_0000).contains(&address) {
        format!("{address:#x}")
    } else if (page..page + 0x1000).contains(&address) {
        format!("page+{:#x}", address - page)
    } else {
        "other".to_owned()
    }
}

/// Renders a register value that may hold a return value.
fn value(raw: u64, pid: Pid) -> String {
    let signed = raw as i64;
    if signed == i64::from(pid.as_raw()) {
        "<pid>".to_owned()
    } else if signed.unsigned_abs() >= 1 << 32 {
        "pointer".to_owned()
    } else {
        signed.to_string()
    }
}

fn send_queued(pid: Pid, tid: Pid, signal: i32, value: i32, thread: bool) {
    // A kernel siginfo: signo at 0, code at 8 (SI_QUEUE), pid at 16, uid at
    // 20 and the value at 24.
    let mut info = [0u8; 128];
    info[0..4].copy_from_slice(&signal.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_QUEUE.to_ne_bytes());
    info[16..20].copy_from_slice(&std::process::id().to_ne_bytes());
    info[20..24].copy_from_slice(&unsafe { libc::getuid() }.to_ne_bytes());
    info[24..28].copy_from_slice(&value.to_ne_bytes());
    let result = unsafe {
        if thread {
            libc::syscall(
                libc::SYS_rt_tgsigqueueinfo,
                pid.as_raw(),
                tid.as_raw(),
                signal,
                info.as_ptr(),
            )
        } else {
            libc::syscall(
                libc::SYS_rt_sigqueueinfo,
                pid.as_raw(),
                signal,
                info.as_ptr(),
            )
        }
    };
    assert_eq!(result, 0, "queue signal {signal}");
}

fn tgkill(pid: Pid, tid: Pid, signal: i32) {
    let result = unsafe { libc::syscall(libc::SYS_tgkill, pid.as_raw(), tid.as_raw(), signal) };
    assert_eq!(result, 0, "tgkill {signal}");
}

/// Sends the signals a tagged call asks for, while it is parked at its stop.
fn send_signals(pid: Pid, tid: Pid, action: u64) {
    if action & SEND_SIGUSR1 != 0 {
        tgkill(pid, tid, libc::SIGUSR1);
    }
    if action & SEND_SIGWINCH != 0 {
        tgkill(pid, tid, libc::SIGWINCH);
    }
    if action & SEND_SIGSTOP != 0 {
        tgkill(pid, tid, libc::SIGSTOP);
    }
    if action & SEND_QUEUE != 0 {
        // Standard signals only: the ptrace backend cannot handle a
        // real-time signal stop.
        send_queued(pid, tid, libc::SIGUSR1, 1, true);
        send_queued(pid, tid, libc::SIGUSR2, 2, false);
        send_queued(pid, tid, libc::SIGHUP, 3, false);
        tgkill(pid, tid, libc::SIGALRM);
        assert_eq!(unsafe { libc::kill(pid.as_raw(), libc::SIGURG) }, 0);
        // Coalesces with the pending SIGUSR1.
        send_queued(pid, tid, libc::SIGUSR1, 5, true);
    }
}

/// A field of `/proc/<tid>/status`, if the thread still exists.
fn proc_status_field(tid: Pid, field: &str) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .map(|value| value.trim().to_owned())
}

/// Notifies the (traced) parent of process `pid` with SIGUSR2.
fn notify_parent(pid: Pid) {
    let ppid: i32 = proc_status_field(pid, "PPid:")
        .expect("the parked guest exists")
        .parse()
        .expect("a PPid");
    let ppid = Pid::from_raw(ppid);
    tgkill(ppid, ppid, libc::SIGUSR2);
}

/// Whether a SIGKILL has arrived at thread `tid` and taken effect.
///
/// A pending SIGKILL is not enough: the killed thread leaves its ptrace stop
/// and, with PTRACE_O_TRACEEXIT, stops again at PTRACE_EVENT_EXIT (measured
/// on this host's kernel), with the entry registers. A ptrace request the
/// tracer makes in between fails with ESRCH, one made after it succeeds. The
/// kill has taken effect once the thread is a zombie or gone, or is in a
/// tracing stop again with its private SIGKILL dequeued (the process-wide
/// bit stays set until the process is reaped). A Tool handler or hook parked
/// on a SIGKILL does not return after this (see their callers): the exit then
/// races the handler inside the tracer, whatever this function observes.
///
/// Each field is a separate read of `/proc/<tid>/status`, so the reads are
/// ordered to be sound across the gaps: the process-wide bit first (the kill
/// has been sent; the kernel sets both bits under one lock), then the private
/// bit (clear now means dequeued, so the thread has left the stop it was in),
/// then the state (a tracing stop now must be the exit stop). Reading the
/// state first, as a single read of the file also does, can pair the old
/// stop's `t` with the dequeued bits of a thread that is still running to its
/// exit stop.
fn kill_took_effect(tid: Pid) -> bool {
    let state = proc_status_field(tid, "State:");
    if state
        .as_deref()
        .is_none_or(|state| state.starts_with('Z') || state.starts_with('X'))
    {
        return true;
    }
    let bit = 1u64 << (libc::SIGKILL - 1);
    let pending = |field: &str| {
        proc_status_field(tid, field)
            .and_then(|mask| u64::from_str_radix(&mask, 16).ok())
            .is_some_and(|mask| mask & bit != 0)
    };
    pending("ShdPnd:")
        && !pending("SigPnd:")
        && proc_status_field(tid, "State:").is_some_and(|state| {
            state.starts_with('t') || state.starts_with('Z') || state.starts_with('X')
        })
}

/// The private and shared pending signals of thread `tid`, from one read.
fn pending_masks(tid: Pid) -> (u64, u64) {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status"))
        .unwrap_or_else(|error| panic!("read the status of parked thread {tid}: {error}"));
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .unwrap_or_else(|| panic!("no {name} for {tid}"))
    };
    (field("SigPnd:"), field("ShdPnd:"))
}

/// Waits, without blocking the tracer's other tasks, until `arrived`.
async fn wait_until(what: &str, mut arrived: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !arrived() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Notifies the parent of the parked `tid` (of process `pid`), then waits,
/// without blocking the tracer's other tasks, until the signal the parent
/// sends in response has arrived: for SIGKILL, until it has taken effect;
/// for any other signal, until it is newly pending in either queue. The
/// parked thread dequeues nothing meanwhile, so a bit that becomes set is the
/// parent's signal; a test must not send one into a queue that already holds
/// it (it would coalesce, and never be seen to arrive).
async fn park_for(pid: Pid, tid: Pid, signal: i32) {
    let what = format!("signal {signal} did not arrive at parked thread {tid}");
    if signal == libc::SIGKILL {
        notify_parent(pid);
        return wait_until(&what, || kill_took_effect(tid)).await;
    }
    let bit = 1u64 << (signal - 1);
    let (private, shared) = pending_masks(tid);
    notify_parent(pid);
    wait_until(&what, || {
        let (now_private, now_shared) = pending_masks(tid);
        ((now_private & !private) | (now_shared & !shared)) & bit != 0
    })
    .await;
}

/// The pre-syscall hook: acts once on each call tagged with a hook action, at
/// the point the tag names (see `HOOK_PARK_SHIFT` and the flags after it).
fn park_hook() -> crate::task::PreSyscallForTest {
    type Fired = std::collections::BTreeSet<(i32, u64, crate::task::PreSyscallPoint)>;
    let fired = std::sync::Arc::new(Mutex::new(Fired::new()));
    std::sync::Arc::new(
        move |tid: Pid, regs: &libc::user_regs_struct, point: crate::task::PreSyscallPoint| {
            use crate::task::PreSyscallPoint::Early;
            use crate::task::PreSyscallPoint::Late;
            let signal = ((regs.r9 >> HOOK_PARK_SHIFT) & 0x1f) as i32;
            let park_point = if regs.r9 & HOOK_LATE != 0 {
                Late
            } else {
                Early
            };
            let sequence = (regs.r9 & !TP_MAGIC_MASK) >> 16;
            let tagged = regs.r9 & TP_MAGIC_MASK == TP_MAGIC
                && regs.r9 & (0xff << HOOK_PARK_SHIFT) != 0
                && fired
                    .lock()
                    .unwrap()
                    .insert((tid.as_raw(), sequence, point));
            // The P2 fixture parks only single-threaded children: pid == tid.
            let (send_stops, kill, wait_kill, park) = (
                tagged && point == Early && regs.r9 & HOOK_SEND_STOPS != 0,
                tagged && point == Early && regs.r9 & HOOK_KILL != 0,
                tagged && point == Late && regs.r9 & HOOK_KILL != 0,
                tagged && point == park_point && signal != 0,
            );
            if send_stops {
                // SAFETY: kill takes no pointers.
                assert_eq!(unsafe { libc::kill(tid.as_raw(), libc::SIGSTOP) }, 0);
                tgkill(tid, tid, libc::SIGSTOP);
            }
            if kill {
                // SAFETY: kill takes no pointers.
                assert_eq!(unsafe { libc::kill(tid.as_raw(), libc::SIGKILL) }, 0);
            }
            Box::pin(async move {
                if park {
                    park_for(tid, tid, signal).await;
                }
                if wait_kill || (park && signal == libc::SIGKILL) {
                    if !park {
                        let what = format!("the hook's SIGKILL did not take effect on {tid}");
                        wait_until(&what, || kill_took_effect(tid)).await;
                    }
                    // Stay parked, so that the exit always wins the race
                    // with the rest of the syscall (see the Tool's SIGKILL
                    // park).
                    std::future::pending::<()>().await;
                }
            })
        },
    )
}

fn errno_value(result: &Result<i64, Errno>) -> i64 {
    match result {
        Ok(value) => *value,
        Err(errno) => -i64::from(errno.into_raw()),
    }
}

/// Records every Tool-visible event with the registers the Tool sees, and
/// handles each tagged call the way its tag asks.
#[derive(Default)]
struct P2Tool;

#[reverie::tool]
impl Tool for P2Tool {
    type GlobalState = P2Log;
    type ThreadState = ();

    fn subscriptions(config: &P2Config) -> Subscription {
        let mut subscription = Subscription::all();
        if config.partial {
            subscription.disable_syscall(reverie::syscalls::Sysno::getuid);
        }
        subscription
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        let tid = guest.tid();
        STEP_BASE
            .lock()
            .unwrap()
            .insert(tid.as_raw(), step_count_for_test(tid));
        STEPPED_SEEN
            .lock()
            .unwrap()
            .insert(tid.as_raw(), stepped_seccomp_count_for_test(tid));
        let regs = guest.regs().await;
        guest
            .send_rpc(format!(
                "thread-start rip={} rax={} rcx={} r11={:#x}",
                code(regs.rip),
                value(regs.rax, guest.pid()),
                code(regs.rcx),
                regs.r11
            ))
            .await;
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        guest.send_rpc("post-exec".to_owned()).await;
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        let tid = guest.tid();
        let pid = guest.pid();
        let regs = guest.regs().await;
        let name = call.number();
        guest
            .send_rpc(format!(
                "entry {name} steps={} rcx=rip:{} r11=rflags:{} rip={} orig_rax={}",
                steps(tid),
                regs.rcx == regs.rip,
                regs.r11 == regs.eflags,
                code(regs.rip),
                regs.orig_rax as i64,
            ))
            .await;
        let stepped_seccomp = stepped_seccomp_count_for_test(tid);
        let stepped = STEPPED_SEEN
            .lock()
            .unwrap()
            .insert(tid.as_raw(), stepped_seccomp)
            .is_some_and(|seen| stepped_seccomp > seen);
        if stepped {
            guest
                .send_rpc(format!(
                    "{STEPPED_ENTRY_PREFIX}{name} rip={}",
                    code(regs.rip)
                ))
                .await;
        }
        let tagged = regs.r9 & TP_MAGIC_MASK == TP_MAGIC;
        let no_return = matches!(
            call,
            Syscall::Exit(_) | Syscall::ExitGroup(_) | Syscall::Execve(_) | Syscall::Execveat(_)
        );
        let shape = if no_return {
            SHAPE_TAIL
        } else if tagged {
            regs.r9 & 0xff
        } else if guest.config().tail {
            SHAPE_TAIL
        } else {
            SHAPE_INJECT
        };
        if tagged {
            let sequence = (regs.r9 & !TP_MAGIC_MASK) >> 16;
            guest
                .send_rpc(format!(
                    "tagged {name} rip={} orig_rax={} action={:#x}",
                    code(regs.rip),
                    regs.orig_rax as i64,
                    regs.r9 & 0xffff
                ))
                .await;
            let first = ACTED.lock().unwrap().insert(tid.as_raw(), sequence) != Some(sequence);
            if first {
                send_signals(pid, tid, regs.r9 & 0xff00);
                let park = ((regs.r9 >> TOOL_PARK_SHIFT) & 0x1f) as i32;
                if park != 0 {
                    park_for(pid, tid, park).await;
                }
                if park == libc::SIGKILL {
                    // The killed thread is at its PTRACE_EVENT_EXIT stop.
                    // The task's driver (`drive_ordinary`) selects, biased
                    // towards the exit, between that exit and the run loop
                    // holding this handler, so whether the rest of the
                    // handler and its final resume ever run depends only on
                    // whether the tracer's waiter has reported the exit stop
                    // by the time this future is polled again. Measured
                    // under both backends, in either direction: 1 of 60 and
                    // 3 of 70 runs of the P2 subset recorded that resume in
                    // one backend's run and not the other's. Stay parked, so
                    // the exit always wins, as it does in every other run.
                    return std::future::pending().await;
                }
            } else if regs.r9 & NOTIFY_AGAIN != 0
                && NOTIFIED.lock().unwrap().insert((tid.as_raw(), sequence))
            {
                notify_parent(pid);
            }
            if regs.r9 & ARM_TIMER != 0 {
                guest
                    .set_timer_precise(TimerSchedule::Rcbs(regs.r8))
                    .expect("arm the precise timer");
            }
        }
        match shape {
            SHAPE_TAIL => guest.tail_inject(call).await,
            SHAPE_EMULATE => {
                guest.send_rpc(format!("syscall {name} = 4242")).await;
                Ok(4242)
            }
            SHAPE_PRIVATE => {
                let result = guest.inject(reverie::syscalls::Getpid::new()).await;
                guest
                    .send_rpc(format!("syscall {name} = {}", errno_value(&result)))
                    .await;
                Ok(result?)
            }
            SHAPE_TWO_INJECTS => {
                let first = guest.inject(call).await;
                let second = guest.inject(reverie::syscalls::Getpid::new()).await;
                guest
                    .send_rpc(format!(
                        "syscall {name} = {} then getpid {}",
                        errno_value(&first),
                        errno_value(&second)
                    ))
                    .await;
                Ok(first?)
            }
            SHAPE_TWO_PRIVATE => {
                let first = guest.inject(reverie::syscalls::Getpid::new()).await;
                let second = guest.inject(reverie::syscalls::Getpid::new()).await;
                guest
                    .send_rpc(format!(
                        "syscall {name} = {} then {}",
                        errno_value(&first),
                        errno_value(&second)
                    ))
                    .await;
                Ok(second?)
            }
            _ => {
                assert_eq!(shape, SHAPE_INJECT, "unknown shape");
                let result = guest.inject(call).await;
                if tagged && regs.r9 & TOOL_AFTER_CONT != 0 {
                    park_for(pid, tid, libc::SIGCONT).await;
                    // Shaped like a re-raise (SI_QUEUE), with a value that
                    // is not a re-raise's tag.
                    send_queued(pid, tid, libc::SIGSTOP, 7, true);
                }
                let rendered = match result {
                    // The guest's parent is not traced, and differs per run.
                    Ok(value) if name == reverie::syscalls::Sysno::getppid && value > 0 => {
                        "<ppid>".to_owned()
                    }
                    _ => errno_value(&result).to_string(),
                };
                guest.send_rpc(format!("syscall {name} = {rendered}")).await;
                let after = guest.regs().await;
                guest
                    .send_rpc(format!(
                        "exit {name} rip={} rax={} rcx={} r11=rflags:{} steps={}",
                        code(after.rip),
                        value(after.rax, pid),
                        code(after.rcx),
                        after.r11 == after.eflags,
                        steps(tid)
                    ))
                    .await;
                Ok(result?)
            }
        }
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let regs = guest.regs().await;
        let clock = guest.read_clock().expect("read the timer clock");
        guest
            .send_rpc(format!(
                "timer rip={} clock={clock} rax={} steps={}",
                code(regs.rip),
                value(regs.rax, guest.pid()),
                steps(guest.tid())
            ))
            .await;
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: reverie::Signal,
    ) -> Result<Option<reverie::Signal>, Errno> {
        let regs = guest.regs().await;
        guest
            .send_rpc(format!(
                "signal {signal:?} rip={} rax={} orig_rax={} rcx={} steps={}",
                code(regs.rip),
                value(regs.rax, guest.pid()),
                regs.orig_rax as i64,
                code(regs.rcx),
                steps(guest.tid()),
            ))
            .await;
        if signal == reverie::Signal::SIGWINCH {
            // Suppressed: the interrupted call restarts.
            Ok(None)
        } else {
            Ok(Some(signal))
        }
    }
}

fn p2_guest() -> &'static std::path::Path {
    static GUEST: LazyLock<PathBuf> = LazyLock::new(|| {
        let source = crate::tracer::tests::fixture("trap_only_p2.c");
        let directory = std::env::current_exe()
            .expect("locate the test binary")
            .parent()
            .expect("the test binary has a directory")
            .to_path_buf();
        // Every test binary in this directory shares it, and another checkout
        // or commit may build into the same target: key the published name
        // by the source (FNV-1a, fixed width, so argv length never changes).
        let text = std::fs::read(&source).expect("read the trap-only P2 fixture source");
        let hash = text.iter().fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
        });
        let output = directory.join(format!("reverie-trap-only-p2-{hash:016x}"));
        let staging = directory.join(format!(
            "reverie-trap-only-p2-{hash:016x}.{}.tmp",
            std::process::id()
        ));
        // -no-pie: the fixture's text addresses are the same in every run, so
        // the two backends' reports and register observations compare.
        let status = std::process::Command::new("cc")
            .args(["-O0", "-g", "-Wall", "-no-pie", "-pthread"])
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .status()
            .expect("invoke cc for the trap-only P2 fixture");
        assert!(status.success(), "compile {}", source.display());
        // Write the text back before any guest maps it: T5 reads the site
        // page's smaps, where a page-cache page not yet written back counts
        // as dirty. btrfs flushes a file renamed over an existing one, but not
        // one published under a new name, so without this the first run after
        // a source change saw Shared_Dirty where the others see clean pages.
        std::fs::File::open(&staging)
            .and_then(|file| file.sync_all())
            .expect("write back the trap-only P2 fixture");
        std::fs::rename(&staging, &output).expect("publish the trap-only P2 fixture");
        output
    });
    GUEST.as_path()
}

#[derive(Debug)]
struct P2Run {
    status: ExitStatus,
    stops: BTreeMap<String, Vec<String>>,
    tool_events: BTreeMap<String, Vec<String>>,
    counts: PtraceBackendStatsSnapshot,
    /// The registers at every final resume of a Tool-visible syscall stop:
    /// rip, rax (the result, unless the Tool tail-injected) and orig_rax.
    resumes: BTreeMap<String, Vec<String>>,
    /// Trap-only only: run-loop stops the backend marked internal (the
    /// seccomp stop of an invisible allowed-class hop), removed from `stops`.
    internal_stops: BTreeMap<String, Vec<String>>,
    report: String,
    /// Trap-only only: the root address space's table at the end of the run.
    patched_sites: usize,
    table_state: Option<TableState>,
    site_state: Option<SiteState>,
    site: u64,
    /// Trap-only only: the site-table lifecycle decisions, in order.
    lifecycle: Vec<String>,
    /// Trap-only only: every table created after the root one, by how
    /// (`fork`, `share`, `exec`), as it was at the end of the run.
    tables: Vec<(String, SiteTable)>,
    /// Trap-only only: the root table at the end of the run.
    root_table: Option<SiteTable>,
    /// The Tool's `stepped-entry` reports, taken out of `tool_events`: each
    /// syscall entry that a timer single-step reached, in order.
    stepped_entries: BTreeMap<String, Vec<String>>,
    /// Every signal-delivery stop the run loop handled: the signal, its
    /// siginfo and where it took effect.
    signals: BTreeMap<String, Vec<String>>,
}

impl P2Run {
    fn all_events(&self) -> Vec<&String> {
        self.tool_events.values().flatten().collect()
    }

    fn count_events(&self, prefix: &str) -> usize {
        self.all_events()
            .iter()
            .filter(|event| event.starts_with(prefix))
            .count()
    }
}

/// Renames traced PIDs in a Tool event with the task names of the run: any
/// token that is, or ends in `=` followed by, a traced PID.
fn rename_event(names: &TaskNames, event: &str) -> String {
    let event = names.event(event);
    event
        .split(' ')
        .map(|token| match token.rsplit_once('=') {
            Some((key, number)) if !key.is_empty() => format!("{key}={}", names.value(number)),
            _ => names.value(token),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn run_p2(mode: &str, patching: Option<SitePatching>, tail: bool) -> P2Run {
    run_p2_with(mode, patching, tail, false)
        .await
        .unwrap_or_else(|error| {
            panic!("P2 fixture run {mode} {patching:?} tail={tail} failed: {error}")
        })
}

/// Test-only perturbations of a P2 run.
#[derive(Clone, Copy, Debug, Default)]
struct P2Options {
    tail: bool,
    partial: bool,
    skip_patch_write: bool,
    displace_hop_exit_rip: bool,
    forget_clone_flags: bool,
    flip_recorded_clone_vm: bool,
    flip_recorded_clone_vfork: bool,
    /// `TP_ORDER` in the guest's environment (see the fixture's
    /// `order_delay`).
    order: Option<&'static str>,
}

async fn run_p2_with(
    mode: &str,
    patching: Option<SitePatching>,
    tail: bool,
    skip_patch_write: bool,
) -> Result<P2Run, Error> {
    let hook = if skip_patch_write {
        P2Hook::SkipPatchWrite
    } else {
        P2Hook::None
    };
    run_p2_env(mode, patching, tail, hook, None).await
}

/// A test-only trap-only control for one run; ignored by a plain ptrace run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum P2Hook {
    None,
    /// `liteinst_trap_only_skip_patch_write_for_test`.
    SkipPatchWrite,
    /// `liteinst_trap_only_forget_clone_flags_for_test`.
    ForgetCloneFlags,
    /// `liteinst_trap_only_flip_recorded_clone_vm_for_test`.
    FlipRecordedCloneVm,
    /// `liteinst_trap_only_flip_recorded_clone_vfork_for_test`.
    FlipRecordedCloneVfork,
}

/// `run_p2_with`, with a test-only control and with `TP_ORDER` set in the
/// guest's environment (see the fixture's `order_delay`).
async fn run_p2_env(
    mode: &str,
    patching: Option<SitePatching>,
    tail: bool,
    hook: P2Hook,
    order: Option<&'static str>,
) -> Result<P2Run, Error> {
    let options = P2Options {
        tail,
        skip_patch_write: hook == P2Hook::SkipPatchWrite,
        forget_clone_flags: hook == P2Hook::ForgetCloneFlags,
        flip_recorded_clone_vm: hook == P2Hook::FlipRecordedCloneVm,
        flip_recorded_clone_vfork: hook == P2Hook::FlipRecordedCloneVfork,
        order,
        ..Default::default()
    };
    run_p2_options(mode, patching, options).await
}

async fn run_p2_options(
    mode: &str,
    patching: Option<SitePatching>,
    options: P2Options,
) -> Result<P2Run, Error> {
    let report_path = tempfile_path(&format!("trap-only-p2-{mode}"));
    let mut command = Command::new(p2_guest());
    command.arg(mode).arg(&report_path);
    if let Some(order) = options.order {
        command.env("TP_ORDER", order);
    }
    let resumes = std::sync::Arc::new(Mutex::new(Vec::new()));
    let mut builder = TracerBuilder::<P2Tool>::new(command)
        .config(P2Config {
            tail: options.tail,
            partial: options.partial,
        })
        .backend_stats(BackendStatsRequest::ENABLED)
        .final_resume_signal_for_test(resume_signal_hook(resumes.clone()))
        .pre_syscall_for_test(park_hook());
    if let Some(patching) = patching {
        builder = builder.liteinst_trap_only(patching);
        if options.skip_patch_write {
            builder = builder.liteinst_trap_only_skip_patch_write_for_test();
        }
        if options.forget_clone_flags {
            builder = builder.liteinst_trap_only_forget_clone_flags_for_test();
        }
        if options.flip_recorded_clone_vm {
            builder = builder.liteinst_trap_only_flip_recorded_clone_vm_for_test();
        }
        if options.flip_recorded_clone_vfork {
            builder = builder.liteinst_trap_only_flip_recorded_clone_vfork_for_test();
        }
        if options.displace_hop_exit_rip {
            builder = builder.liteinst_trap_only_displace_hop_exit_rip_for_test();
        }
    }
    let tracer = builder.spawn().await?;
    let stats = tracer.backend_stats().expect("stats were requested");
    let handle = tracer.liteinst_trap_only();
    let result = tokio::time::timeout(Duration::from_secs(60), finish_p2(tracer, &stats))
        .await
        .unwrap_or_else(|_| panic!("P2 fixture mode {mode} timed out"));
    let report = std::fs::read_to_string(&report_path).unwrap_or_default();
    let _ = std::fs::remove_file(&report_path);
    let (status, log) = result?;
    let site = report
        .lines()
        .next()
        .and_then(|line| line.split_once(" site=0x"))
        .and_then(|(_, hex)| u64::from_str_radix(hex, 16).ok())
        .unwrap_or_else(|| panic!("no site line in the report: {report}"));
    let stop_trace = stats.stop_trace();
    let names = TaskNames::new(Identity::Renamed, &stop_trace);
    let mut tool_events = BTreeMap::<String, Vec<String>>::new();
    let mut stepped_entries = BTreeMap::<String, Vec<String>>::new();
    for (pid, event) in std::mem::take(&mut *log.0.lock().unwrap()) {
        let event = rename_event(&names, &event);
        match event.strip_prefix(STEPPED_ENTRY_PREFIX) {
            Some(entry) => stepped_entries
                .entry(names.name(pid))
                .or_default()
                .push(entry.to_owned()),
            None => tool_events.entry(names.name(pid)).or_default().push(event),
        }
    }
    let mut resume_events = BTreeMap::<String, Vec<String>>::new();
    for (pid, event) in std::mem::take(&mut *resumes.lock().unwrap()) {
        resume_events
            .entry(names.name(pid))
            .or_default()
            .push(rename_event(&names, &event));
    }
    let mut signals = BTreeMap::<String, Vec<String>>::new();
    for (pid, event) in stats.signal_trace() {
        // The tracer's own traps: a kernel SIGSEGV (si_code SI_KERNEL) is its
        // rdtsc or cpuid trap, whose rax holds whatever the guest computed
        // last, and SIGSTKFLT is its timer's perf overflow, which lands
        // wherever the counter's skid left it (the timer event it leads to is
        // a compared Tool event). Their registers are not compared.
        let tracer_trap =
            event.starts_with("SIGSEGV signo=11 code=128 ") || event.starts_with("SIGSTKFLT ");
        let event = event
            .split(' ')
            .filter(|token| {
                !(tracer_trap && (token.starts_with("rax=") || token.starts_with("rip=")))
            })
            .map(|token| match token.strip_prefix("rip=0x") {
                Some(hex) => format!(
                    "rip={}",
                    code(u64::from_str_radix(hex, 16).expect("a hex rip"))
                ),
                // A signal the tracer (this process) sent.
                None if token == format!("pid={}", std::process::id()) => "pid=tracer".to_owned(),
                None => token.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ");
        signals
            .entry(names.name(pid))
            .or_default()
            .push(rename_event(&names, &event));
    }
    let mut stops = names.per_task(stop_trace);
    let mut internal_stops = BTreeMap::<String, Vec<String>>::new();
    for (task, events) in stops.iter_mut() {
        let internal: Vec<String> = events
            .iter()
            .filter_map(|event| event.strip_prefix(crate::stats::INTERNAL_STOP_PREFIX))
            .map(str::to_owned)
            .collect();
        if !internal.is_empty() {
            events.retain(|event| !event.starts_with(crate::stats::INTERNAL_STOP_PREFIX));
            internal_stops.insert(task.clone(), internal);
        }
    }
    Ok(P2Run {
        status,
        stops,
        tool_events,
        counts: reverie::BackendStatsSource::backend_stats(&stats),
        resumes: resume_events,
        internal_stops,
        report,
        patched_sites: handle.as_ref().map_or(0, |handle| handle.patched_sites()),
        table_state: handle.as_ref().map(|handle| handle.table_state()),
        site_state: handle.as_ref().and_then(|handle| handle.site_state(site)),
        site,
        lifecycle: handle
            .as_ref()
            .map(|handle| handle.hooks().log.lock().unwrap().clone())
            .unwrap_or_default(),
        tables: handle
            .as_ref()
            .map(|handle| {
                handle
                    .hooks()
                    .tables
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(label, table)| (label.clone(), table.lock().unwrap().clone()))
                    .collect()
            })
            .unwrap_or_default(),
        root_table: handle.as_ref().map(|handle| handle.root_table()),
        stepped_entries,
        signals,
    })
}

/// Waits for a P2 run like `Tracer::wait`, except that a run whose cleanup is
/// left pending is terminated, its root is killed, and the same cleanup is
/// resumed once; if it is still pending, every tracee of the run that this
/// process still traces is killed (and named on stderr) and the owner is
/// dropped, as the plain ptrace exec-owner tests do, rather than
/// quarantined. `Tracer::wait` (and
/// `quarantine`) take a process-wide quarantine permit that is never
/// released, so one failed run would refuse every later spawn in this test
/// binary and hide which test failed. The run still fails, with its original
/// cause.
async fn finish_p2(
    tracer: Tracer<P2Log>,
    stats: &crate::PtraceBackendStatsSource,
) -> Result<(ExitStatus, P2Log), Error> {
    let Some(termination) = tracer.termination_handle() else {
        return tracer.wait().await;
    };
    // SAFETY: pidfd_open takes no pointers; a failure leaves -1.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, tracer.guest_pid().as_raw(), 0) };
    // SAFETY: a non-negative result is a new descriptor owned here.
    let root = (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw as RawFd) });
    match tracer.wait_completion().await {
        ToolRunOutcome::Complete(completion) => completion
            .result
            .map(|status| (status, completion.global_state))
            .map_err(crate::PtraceRunFailure::into_legacy_error),
        ToolRunOutcome::CleanupPending(pending) => {
            let cause = pending.failure().to_string();
            termination.terminate(Error::Tool(anyhow::anyhow!("P2 rescue after: {cause}")));
            if let Some(root) = &root {
                // SAFETY: a valid pidfd, and a null siginfo.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        root.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
            }
            match tokio::time::timeout(Duration::from_secs(5), pending.resume_cleanup()).await {
                Ok(ToolRunOutcome::Complete(_)) => Err(Error::Tool(anyhow::anyhow!(
                    "{cause} (cleanup completed after the rescue)"
                ))),
                Ok(ToolRunOutcome::CleanupPending(pending)) => {
                    kill_remaining_tracees(stats);
                    drop(pending);
                    Err(Error::Tool(anyhow::anyhow!(
                        "{cause} (cleanup still pending after the rescue)"
                    )))
                }
                Ok(ToolRunOutcome::UnsupportedBackend(_)) => {
                    unreachable!("a pending ordinary cleanup resumes on the same backend")
                }
                Err(_) => Err(Error::Tool(anyhow::anyhow!(
                    "{cause} (cleanup rescue timed out)"
                ))),
            }
        }
        ToolRunOutcome::UnsupportedBackend(tracer) => tracer.wait().await,
    }
}

/// Kills, with SIGKILL, each thread group of a tracee in `stats`' stop trace
/// that a thread of this process still traces, and names each on stderr, so
/// that a run whose cleanup stayed pending leaves no tracee behind.
/// `TracerPid` is checked first, so a reused PID of an unrelated process is
/// not signalled.
fn kill_remaining_tracees(stats: &crate::PtraceBackendStatsSource) {
    let tids: std::collections::BTreeSet<i32> = stats
        .stop_trace()
        .into_iter()
        .map(|(pid, _)| pid.as_raw())
        .collect();
    for tid in tids {
        let Ok(status) = std::fs::read_to_string(format!("/proc/{tid}/status")) else {
            continue;
        };
        // The tracer is a thread (TracerPid is its TID) of this process.
        let tracer = status.lines().find_map(|line| {
            line.strip_prefix("TracerPid:")
                .and_then(|value| value.trim().parse::<i32>().ok())
        });
        let traced_here = tracer.is_some_and(|tracer| {
            tracer != 0 && std::path::Path::new(&format!("/proc/self/task/{tracer}")).exists()
        });
        if traced_here {
            // SAFETY: kill takes no pointers.
            let rc = unsafe { libc::kill(tid, libc::SIGKILL) };
            eprintln!("P2 rescue: killed remaining tracee {tid} (rc={rc})");
        }
    }
}

/// Records the registers at every final resume of a Tool-visible syscall
/// stop in `log`, and leaves SIGUSR1 pending for the final resume of each
/// `SEND_RESUME` call, once per call.
fn resume_signal_hook(
    log: std::sync::Arc<Mutex<Vec<(Pid, String)>>>,
) -> crate::task::FinalResumeSignalForTest {
    let fired = std::sync::Arc::new(Mutex::new(std::collections::BTreeSet::<(i32, u64)>::new()));
    std::sync::Arc::new(move |tid: Pid, regs: &libc::user_regs_struct| {
        // The guest's pid is the thread-group id, which the hook does not
        // see; a result equal to the tid is the common case (getpid in the
        // root thread) and is rendered as `<pid>` too.
        log.lock().unwrap().push((
            tid,
            format!(
                "resume rip={} rax={} orig_rax={} rcx={} r11=rflags:{}",
                code(regs.rip),
                value(regs.rax, tid),
                regs.orig_rax as i64,
                code(regs.rcx),
                // The raw flags depend on guest arithmetic on its own pid,
                // which differs per run.
                regs.r11 == regs.eflags
            ),
        ));
        if regs.r9 & TP_MAGIC_MASK != TP_MAGIC || regs.r9 & SEND_RESUME == 0 {
            return None;
        }
        let sequence = (regs.r9 & !TP_MAGIC_MASK) >> 16;
        fired
            .lock()
            .unwrap()
            .insert((tid.as_raw(), sequence))
            .then_some(nix::sys::signal::Signal::SIGUSR1)
    })
}

/// Describes where two per-task traces first differ.
fn first_divergence(
    trap_only: &BTreeMap<String, Vec<String>>,
    ptrace: &BTreeMap<String, Vec<String>>,
) -> String {
    let mut out = String::new();
    for task in ptrace.keys().chain(trap_only.keys()) {
        let (left, right) = (
            trap_only.get(task).cloned().unwrap_or_default(),
            ptrace.get(task).cloned().unwrap_or_default(),
        );
        if left == right {
            continue;
        }
        let index = left
            .iter()
            .zip(&right)
            .position(|(l, r)| l != r)
            .unwrap_or(left.len().min(right.len()));
        let from = index.saturating_sub(3);
        out += &format!(
            "{task}: first difference at {index} (lengths {} vs {})\n  trap-only: {:#?}\n  ptrace: {:#?}\n",
            left.len(),
            right.len(),
            &left[from..(index + 4).min(left.len())],
            &right[from..(index + 4).min(right.len())],
        );
        break;
    }
    out
}

fn assert_equal_runs(trap_only: &P2Run, ptrace: &P2Run) {
    assert_equal_runs_with_internal(trap_only, ptrace, &[]);
}

/// Like `assert_equal_runs`, except that the trap-only run also has exactly
/// the `internal` run-loop stops (all in `task#0`, in order): each is the
/// seccomp stop of an invisible allowed-class hop, and is counted as one
/// seccomp stop and one stop event that plain ptrace does not have.
fn assert_equal_runs_with_internal(trap_only: &P2Run, ptrace: &P2Run, internal: &[&str]) {
    assert_eq!(trap_only.status, ptrace.status, "exit status diverged");
    assert_eq!(trap_only.report, ptrace.report, "guest reports diverged");
    assert_equal_runs_except_report(trap_only, ptrace, internal);
}

/// Every comparison of `assert_equal_runs_with_internal` except the guest's
/// report, so that a mutation test can show the other comparisons catch a
/// defect on their own.
fn assert_equal_runs_except_report(trap_only: &P2Run, ptrace: &P2Run, internal: &[&str]) {
    assert_eq!(trap_only.status, ptrace.status, "exit status diverged");
    assert!(
        trap_only.tool_events == ptrace.tool_events,
        "Tool-visible events diverged: {}",
        first_divergence(&trap_only.tool_events, &ptrace.tool_events)
    );
    assert!(
        trap_only.resumes == ptrace.resumes,
        "final-resume registers diverged: {}",
        first_divergence(&trap_only.resumes, &ptrace.resumes)
    );
    assert!(
        trap_only.stops == ptrace.stops,
        "stop sequences diverged: {}",
        first_divergence(&trap_only.stops, &ptrace.stops)
    );
    assert!(
        trap_only.signals == ptrace.signals,
        "signal-delivery stops diverged: {}",
        first_divergence(&trap_only.signals, &ptrace.signals)
    );
    assert!(
        ptrace.internal_stops.is_empty(),
        "{:#?}",
        ptrace.internal_stops
    );
    let expected: BTreeMap<String, Vec<String>> = if internal.is_empty() {
        BTreeMap::new()
    } else {
        BTreeMap::from([(
            "task#0".to_owned(),
            internal.iter().map(|stop| (*stop).to_owned()).collect(),
        )])
    };
    assert_eq!(
        trap_only.internal_stops, expected,
        "internal (invisible) trap-only stops"
    );
    let extra = internal.len() as u64;
    let (t, p) = (&trap_only.counts, &ptrace.counts);
    assert_eq!(
        t.seccomp_stops(),
        p.seccomp_stops() + extra,
        "seccomp stops"
    );
    assert_eq!(t.stop_events(), p.stop_events() + extra, "stop events");
    assert_eq!(
        counts_except_seccomp(t),
        counts_except_seccomp(p),
        "stop counts diverged"
    );
    if extra == 0 {
        assert_eq!(trap_only.counts, ptrace.counts, "stop counts diverged");
    }
}

fn counts_except_seccomp(counts: &PtraceBackendStatsSnapshot) -> [u64; 8] {
    [
        counts.tracees_started(),
        counts.exited_tracees(),
        counts.signal_stops(),
        counts.exec_stops(),
        counts.fork_stops(),
        counts.vfork_stops(),
        counts.clone_stops(),
        counts.vfork_done_stops(),
    ]
}

/// The trap-only run patched the shared site, and its tagged calls reached
/// the Tool from the patched site.
fn assert_patched(trap_only: &P2Run, expected_site: SiteState) {
    assert_eq!(
        trap_only.site_state,
        Some(expected_site),
        "shared site {:#x} was not patched as expected",
        trap_only.site
    );
    assert!(trap_only.patched_sites > 0 || expected_site != SiteState::Live);
}

/// Runs `mode` under ptrace and under trap-only with patching on, in both
/// Tool configurations, and requires equal runs. Returns the four runs as
/// (ptrace inject, trap-only inject, ptrace tail, trap-only tail).
async fn compare_mode(mode: &str) -> [P2Run; 4] {
    let ptrace_inject = run_p2(mode, None, false).await;
    let trap_only_inject = run_p2(mode, Some(SitePatching::On), false).await;
    assert_equal_runs(&trap_only_inject, &ptrace_inject);
    let ptrace_tail = run_p2(mode, None, true).await;
    let trap_only_tail = run_p2(mode, Some(SitePatching::On), true).await;
    assert_equal_runs(&trap_only_tail, &ptrace_tail);
    for run in [&ptrace_inject, &ptrace_tail] {
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert!(run.report.ends_with("done\n"), "{}", run.report);
    }
    [ptrace_inject, trap_only_inject, ptrace_tail, trap_only_tail]
}

fn assert_report_has(run: &P2Run, lines: &[&str]) {
    for line in lines {
        assert!(
            run.report
                .lines()
                .any(|candidate| candidate.starts_with(line)),
            "report lacks a line starting {line:?}:\n{}",
            run.report
        );
    }
}

fn assert_events_have(run: &P2Run, events: &[&str]) {
    let all = run.all_events();
    for event in events {
        assert!(
            all.iter().any(|candidate| candidate.starts_with(event)),
            "no Tool event starting {event:?} in {all:#?}"
        );
    }
}

/// T1a: a signal sent while a patched getpid is parked is delivered after
/// getpid returned, at S+2, exactly as under ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t1a_signal_pending_at_a_patched_stop() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("sig_pending").await;
    assert_patched(&trap_only, SiteState::Live);
    assert_patched(&trap_only_tail, SiteState::Live);
    let s2 = format!("{:#x}", ptrace.site + 2);
    assert_report_has(
        &ptrace,
        &[
            "getpid returned pid=1",
            "sig_pending 0: sig=10 code=-6 value=-1 rip=tp_site_end rax=<pid> rcx=tp_site_end r11=0x246 ",
            "sig_pending_tail 0: sig=10 code=-6 value=-1 rip=tp_site_end rax=<pid> rcx=tp_site_end r11=0x246 ",
        ],
    );
    assert_events_have(
        &ptrace,
        &[&format!(
            "signal SIGUSR1 rip={s2} rax=<pid> orig_rax=39 rcx={s2} steps="
        )],
    );
}

/// T1c: queued thread- and process-directed signals are delivered in the
/// same order, with the same values, as under ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t1c_queued_signals_keep_order_and_values() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("rt_queue").await;
    assert_patched(&trap_only, SiteState::Live);
    assert_patched(&trap_only_tail, SiteState::Live);
    let queued = ptrace
        .report
        .lines()
        .filter(|line| line.starts_with("queue "))
        .count();
    assert_eq!(
        queued, 5,
        "five distinct signals delivered:\n{}",
        ptrace.report
    );
    assert!(
        ptrace.report.contains("sig=10 code=-1 value=1"),
        "{}",
        ptrace.report
    );
}

/// T1f: signals raised by the patched syscall itself are delivered at S+2
/// with the same registers as under ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t1f_self_raised_signals() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("self_raise").await;
    assert_patched(&trap_only, SiteState::Live);
    assert_patched(&trap_only_tail, SiteState::Live);
    assert_report_has(
        &ptrace,
        &[
            "kill 0: sig=10 code=0 value=-1 rip=tp_site_end rax=0 rcx=tp_site_end r11=0x246 ",
            "sigpipe 0: sig=13 code=0 value=-1 rip=tp_site_end rax=-32 rcx=tp_site_end r11=0x246 ",
            "unblock 0: sig=12 code=-6 value=-1 rip=tp_site_end rax=0 rcx=tp_site_end r11=0x246 ",
        ],
    );
}

/// T2: each Tool handler shape at a patched site single-steps exactly as
/// often as under ptrace, so SIGTRAP disposition, mask and trapno are equal.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t2_forced_sigtrap_profile_per_shape() {
    let [ptrace, trap_only, _, _] = compare_mode("sigtrap_profile").await;
    assert_patched(&trap_only, SiteState::Live);
    eprintln!("T2 ptrace report:\n{}", ptrace.report);
    // The guest-visible state after each shape, measured under ptrace (the
    // comparator already requires trap-only's report to be identical): a
    // shape that single-steps resets SIGTRAP to its default and unblocks it,
    // and the last trap the SIGUSR1 frame records is the step's debug trap
    // (1) instead of the syscall's (13).
    let mut guest_visible = Vec::new();
    for (shape, result, stepped) in [
        ("inject", "ppid", false),
        ("tail", "ppid", false),
        ("emulate", "4242", true),
        ("private", "pid", true),
        ("two-injects", "ppid", true),
        ("two-private", "pid", true),
    ] {
        let (disposition, blocked, trapno) = if stepped {
            ("dfl", 0, 1)
        } else {
            ("ign", 1, 13)
        };
        guest_visible.push(format!("{shape} getppid={result}"));
        guest_visible.push(format!("{shape} sigtrap={disposition} blocked={blocked}"));
        guest_visible.push(format!(
            "{shape} 0: sig=10 code=-6 value=-1 rip=other rax=0 rcx=other r11=0x246 \
             trapno={trapno} err=0"
        ));
    }
    for run in [&ptrace, &trap_only] {
        let lines: Vec<&str> = run
            .report
            .lines()
            .filter(|line| !line.starts_with("mode ") && *line != "done")
            .collect();
        assert_eq!(lines, guest_visible, "{}", run.report);
    }
    // Order of the fixture's shapes: tail, exact inject, emulate, private
    // inject, two injects, two private injects.
    let expected = [0, 0, 1, 2, 1, 3];
    let ptrace_steps = steps_per_shape(&ptrace);
    eprintln!("ptrace steps per shape: {ptrace_steps:?}");
    assert_eq!(ptrace_steps, expected, "ptrace step profile");
    assert_eq!(
        steps_per_shape(&trap_only),
        expected,
        "trap-only step profile"
    );
}

/// Steps taken by each tagged call: the cumulative count at the next
/// syscall entry minus the count at the call's entry.
fn steps_per_shape(run: &P2Run) -> Vec<u64> {
    let root = &run.tool_events["task#0"];
    let entry_steps = |event: &String| -> u64 {
        event
            .split_once(" steps=")
            .and_then(|(_, rest)| rest.split(' ').next())
            .and_then(|value| value.parse().ok())
            .unwrap()
    };
    let mut per_shape = Vec::new();
    for (index, event) in root.iter().enumerate() {
        if !event.starts_with("tagged getppid") {
            continue;
        }
        let before = entry_steps(&root[index - 1]);
        let after = root[index + 1..]
            .iter()
            .find(|event| event.starts_with("entry "))
            .map(entry_steps)
            .unwrap();
        per_shape.push(after - before);
    }
    per_shape
}

/// T3: interrupted and restarted calls at patched sites return the same
/// values, restart through the same stops (including restart_syscall) and
/// show the same frames as under ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t3_restart_matrix() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("restart").await;
    assert_patched(&trap_only, SiteState::Live);
    assert_patched(&trap_only_tail, SiteState::Live);
    assert_report_has(
        &ptrace,
        &[
            "nanosleep-suppressed ret=0 errno=0 rcx=tp_site_end r11=0x246",
            // The signal is pending when each sleep starts, so every
            // interrupted sleep (restarted or not) reports about the whole
            // request as its remaining time (the fixture's rem_class).
            "nanosleep-suppressed rem=whole",
            "nanosleep-handled rem=whole",
            "clock_nanosleep-suppressed rem=whole",
            "clock_nanosleep-handled rem=whole",
            "nanosleep-suppressed-tail rem=whole",
            "read-eintr ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "read-restart ret=1 errno=0 rcx=tp_site_end r11=0x246",
            "futex-restart ret=-11 errno=11 rcx=tp_site_end r11=0x246",
            "futex-eintr ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "ppoll ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "epoll_pwait ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "pause ret=-4 errno=4 rcx=tp_site_end r11=0x246",
        ],
    );
    assert!(
        ptrace.count_events("tagged restart_syscall") >= 3,
        "restart_syscall re-entries: {:#?}",
        ptrace.all_events()
    );
    assert!(
        ptrace
            .report
            .contains("read-restart 0: sig=10 code=-6 value=-1 rip=tp_site rax=0 "),
        "SA_RESTART frame shows rip == S:\n{}",
        ptrace.report
    );
}

/// T6a: fork, vfork, clone3 and a thread created through a patched site;
/// the thread restores the site and disables patching.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6a_fork_family_through_a_patched_site() {
    let ptrace = run_p2("fork_family", None, false).await;
    let trap_only = run_p2("fork_family", Some(SitePatching::On), false).await;
    let ptrace_tail = run_p2("fork_family", None, true).await;
    let trap_only_tail = run_p2("fork_family", Some(SitePatching::On), true).await;
    for (trap_only, ptrace) in [(&trap_only, &ptrace), (&trap_only_tail, &ptrace_tail)] {
        // The site bytes before the thread are the disclosed text residual:
        // patched under trap-only, original under ptrace.
        assert_report_has(ptrace, &["before thread site bytes 0f 05"]);
        assert_report_has(trap_only, &["before thread site bytes cd 80"]);
        let masked = P2Run {
            report: trap_only.report.replace(
                "before thread site bytes cd 80",
                "before thread site bytes 0f 05",
            ),
            ..clone_run(trap_only)
        };
        assert_equal_runs(&masked, ptrace);
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert_report_has(
            ptrace,
            &[
                "fork child rcx=tp_site_end r11=0x246",
                "fork child status exited=1 code=7",
                "vfork child status exited=1 code=7",
                "clone3 child status exited=1 code=7",
                "after thread site bytes 0f 05",
                "getpid after thread pid=1",
                "done",
            ],
        );
        assert_eq!(
            trap_only.table_state,
            Some(TableState::Disabled(DisabledReason::MultiTask))
        );
        assert_eq!(
            trap_only.site_state,
            Some(SiteState::Retired(RetiredReason::MultiTask))
        );
        assert_eq!(trap_only.patched_sites, 0);
    }
    assert_eq!(ptrace.counts.fork_stops() + ptrace.counts.clone_stops(), 0);
    assert_eq!(
        ptrace_tail.counts.fork_stops(),
        3,
        "fork, grandchild, clone3"
    );
    assert_eq!(ptrace_tail.counts.vfork_stops(), 1);
    assert_eq!(ptrace_tail.counts.clone_stops(), 1);
    // The tail vfork parent is still inside the call at its vfork-done stop,
    // where the run loop records its rax: the entry's -ENOSYS under ptrace.
    // The trap-only tail hop's new-child restore must leave it there, not
    // the child's id (the stop comparison above checks equality; this checks
    // that the compared stop exists and carries the value).
    for run in [&ptrace_tail, &trap_only_tail] {
        let vfork_done: Vec<&String> = run
            .stops
            .values()
            .flatten()
            .filter(|stop| stop.starts_with("VforkDone"))
            .collect();
        assert_eq!(vfork_done, ["VforkDone rax=-38"], "{:#?}", run.stops);
    }
}

fn clone_run(run: &P2Run) -> P2Run {
    P2Run {
        status: run.status,
        stops: run.stops.clone(),
        tool_events: run.tool_events.clone(),
        counts: run.counts.clone(),
        resumes: run.resumes.clone(),
        internal_stops: run.internal_stops.clone(),
        report: run.report.clone(),
        patched_sites: run.patched_sites,
        table_state: run.table_state,
        site_state: run.site_state,
        site: run.site,
        lifecycle: run.lifecycle.clone(),
        tables: run.tables.clone(),
        root_table: run.root_table.clone(),
        stepped_entries: run.stepped_entries.clone(),
        signals: run.signals.clone(),
    }
}

/// T7c: a real IA-32 `int 0x80` (not at a patched site) kills the process
/// with SIGSYS as plain ptrace's filter does, without any Tool event.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t7c_foreign_int_0x80_dies_of_sigsys() {
    let ptrace = run_p2("foreign_int80", None, false).await;
    let trap_only = run_p2("foreign_int80", Some(SitePatching::On), false).await;
    assert_eq!(trap_only.status, ptrace.status);
    assert_eq!(trap_only.report, ptrace.report);
    assert!(
        trap_only.tool_events == ptrace.tool_events,
        "{}",
        first_divergence(&trap_only.tool_events, &ptrace.tool_events)
    );
    assert!(
        ptrace
            .report
            .contains("child signaled=1 termsig=31 coredump="),
        "{}",
        ptrace.report
    );
    assert!(!ptrace.report.contains("int80 returned"));
    // The one difference: trap-only's filter reports the int 0x80 as a
    // seccomp stop, which plain ptrace's filter never does.
    let mut stops = trap_only.stops.clone();
    let mut removed = 0;
    for events in stops.values_mut() {
        if let Some(index) = events.iter().position(|event| event == "seccomp 20") {
            events.remove(index);
            removed += 1;
        }
    }
    assert_eq!(removed, 1, "{:#?}", trap_only.stops);
    assert_eq!(stops, ptrace.stops);
    let (t, p) = (&trap_only.counts, &ptrace.counts);
    assert_eq!(t.seccomp_stops(), p.seccomp_stops() + 1);
    assert_eq!(t.stop_events(), p.stop_events() + 1);
    assert_eq!(
        (
            t.tracees_started(),
            t.exited_tracees(),
            t.signal_stops(),
            t.exec_stops(),
            t.fork_stops(),
            t.vfork_stops(),
            t.clone_stops(),
            t.vfork_done_stops()
        ),
        (
            p.tracees_started(),
            p.exited_tracees(),
            p.signal_stops(),
            p.exec_stops(),
            p.fork_stops(),
            p.vfork_stops(),
            p.clone_stops(),
            p.vfork_done_stops()
        )
    );
    assert!(
        !trap_only
            .all_events()
            .iter()
            .any(|event| event.contains("SIGSYS")),
        "the Tool saw the SIGSYS"
    );
}

/// T7c with a precise timer past its target: the fixture's `late_timer`
/// child arms a timer far beyond any skid margin, blocks the timer's signal
/// so that no notification is ever handled, and runs well past the target.
/// A foreign `int 0x80` then ends the child under plain ptrace with no stop:
/// its filter kills the process. The event is still undecided when the
/// thread exits, so `Timer::settle_at_exit` records exactly one
/// skid-overshoot witness. Trap-only must leave the event to that same exit
/// rather than decide it at the `int 0x80` trap, a stop plain ptrace never
/// reports: it too records exactly one witness and, like plain ptrace, no
/// host-timed outcome, where deciding the event at the trap would count a
/// preempted overflow. The control, an ordinary getpid in the same place, is
/// a stop both backends report: it records exactly one witness under each,
/// at that stop, with one preempted overflow; it shows that the timer really
/// was due when the child reached its last instruction.
///
/// Neither count says WHERE the `int 0x80` witness was recorded, and a stop
/// can decide the event without counting a preempted overflow: retiring it
/// (`Timer::retire`) at the trap records the same one witness and cancels
/// the event, so the exit then records nothing. What tells the two apart is
/// whether the witness was overtaken with its notification queued. The
/// fixture blocks the timer's signal, so at every stop the notification is
/// queued and a stop that decides the event counts it as overtaken, as the
/// control's getpid stop does under each backend; the exit cannot read the
/// exited thread's pending signals and never counts it. So the `int 0x80`
/// mode must count no overtaken event under either backend.
///
/// The witness and overtaken counts are process-global and other tests in
/// this binary can write them, so the runs happen in a fresh exact-test
/// process, as in `tracer::tests::precise_timer_delivery_reaches_tool`.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t7c_foreign_int_0x80_past_a_timer_target_is_witnessed_at_exit() {
    const LATE_TIMER_CHILD: &str = "REVERIE_PTRACE_P2_LATE_TIMER_CHILD";
    if std::env::var_os(LATE_TIMER_CHILD).is_some() {
        compare_late_timer_witnesses().await;
        return;
    }
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let (_, module) = module_path!()
        .split_once("::")
        .expect("the module path names the crate");
    let output = std::process::Command::new(std::env::current_exe().expect("locate test binary"))
        .args([
            "--exact",
            &format!(
                "{module}::trap_only_p2_t7c_foreign_int_0x80_past_a_timer_target_is_witnessed_at_exit"
            ),
            "--nocapture",
            "--test-threads=1",
        ])
        .env(LATE_TIMER_CHILD, "1")
        .output()
        .expect("run the late-timer child test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "late-timer child test failed:\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The late-timer runs, in the exact-test child process that owns the
/// witness and overtaken counts: each mode under plain ptrace and under
/// trap-only, with the witnesses, the events overtaken with their
/// notification queued and the host-timed timer outcomes each run recorded.
/// Each mode records one witness under each backend: the `int 0x80` mode at
/// the thread's exit, which counts no overtaken event, the control at its
/// getpid stop, which counts one. The only host-timed outcome expected is
/// the control's: its getpid stop decides the event after the overflow was
/// due and its signal was never handled.
async fn compare_late_timer_witnesses() {
    let preempted = crate::timer::HostTimedTimerEvents {
        preempted_overflow: 1,
        ..Default::default()
    };
    for (mode, child_report, witnesses, overtaken, host_timed) in [
        (
            "late_timer_int80",
            "child signaled=1 termsig=31 exited=0 status=0",
            1,
            0,
            Default::default(),
        ),
        (
            "late_timer_getpid",
            "child signaled=0 termsig=0 exited=1 status=0",
            1,
            1,
            preempted,
        ),
    ] {
        let _ = reverie::take_skid_overshoot_count();
        let _ = crate::timer::take_host_timed_timer_events();
        let overtaken_before = crate::testing::precise_events_overtaken_with_notification_queued();
        let ptrace = run_p2(mode, None, false).await;
        let ptrace_witnesses = reverie::take_skid_overshoot_count();
        let ptrace_host_timed = crate::timer::take_host_timed_timer_events();
        let overtaken_after_ptrace =
            crate::testing::precise_events_overtaken_with_notification_queued();
        let trap_only = run_p2(mode, Some(SitePatching::On), false).await;
        let trap_only_witnesses = reverie::take_skid_overshoot_count();
        let trap_only_host_timed = crate::timer::take_host_timed_timer_events();
        let overtaken_after_trap_only =
            crate::testing::precise_events_overtaken_with_notification_queued();
        let ptrace_overtaken = overtaken_after_ptrace - overtaken_before;
        let trap_only_overtaken = overtaken_after_trap_only - overtaken_after_ptrace;
        assert_patched(&trap_only, SiteState::Live);
        assert!(
            ptrace.report.contains(child_report),
            "{mode}: {}",
            ptrace.report
        );
        assert!(
            !ptrace.report.contains("int80 returned"),
            "{mode}: {}",
            ptrace.report
        );
        assert_eq!(
            ptrace.report.contains("late timer getpid=1"),
            mode == "late_timer_getpid",
            "{mode}: {}",
            ptrace.report
        );
        assert_eq!(trap_only.status, ptrace.status, "{mode}");
        assert_eq!(trap_only.report, ptrace.report, "{mode}");
        assert!(
            trap_only.tool_events == ptrace.tool_events,
            "{mode}: {}",
            first_divergence(&trap_only.tool_events, &ptrace.tool_events)
        );
        for run in [&ptrace, &trap_only] {
            assert!(
                timer_events(run).is_empty(),
                "{mode}: {:#?}",
                run.tool_events
            );
        }
        assert_eq!(
            (ptrace_witnesses, trap_only_witnesses),
            (witnesses, witnesses),
            "{mode}: skid-overshoot witnesses (plain ptrace, trap-only)"
        );
        assert_eq!(
            (ptrace_overtaken, trap_only_overtaken),
            (overtaken, overtaken),
            "{mode}: events overtaken with their notification queued (plain ptrace, trap-only)"
        );
        assert_eq!(
            (ptrace_host_timed, trap_only_host_timed),
            (host_timed, host_timed),
            "{mode}: host-timed timer outcomes (plain ptrace, trap-only)"
        );
    }
}

/// T8: rcx and r11 after a patched site, in a signal frame and in a fork
/// child equal ptrace's, including with DF and AC set.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t8_rcx_r11_view() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("rcx_r11").await;
    assert_patched(&trap_only, SiteState::Live);
    assert_patched(&trap_only_tail, SiteState::Live);
    assert_report_has(
        &ptrace,
        &[
            "t8 0 pid=1 rcx=t8_site_end r11=0x293",
            "t8 3 pid=1 rcx=t8_site_end r11=0x293",
            "t8 df pid=1 rcx=t8_site_end r11=0x697",
            "t8 ac pid=1 rcx=t8_site_end r11=0x40246",
            "fork child rcx=tp_site_end r11=0x246",
        ],
    );
    assert!(
        ptrace.report.contains("read 0: sig=10") && ptrace.report.contains("rcx=tp_site_end r11="),
        "{}",
        ptrace.report
    );
}

/// A patch whose readback does not show `int 0x80` fails the run closed
/// with `TrapOnlyPatchReadback`.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_patch_readback_mismatch_fails_closed() {
    let error = run_p2_with("sig_pending", Some(SitePatching::On), false, true)
        .await
        .expect_err("a failed patch readback must end the run");
    let text = format!("{error:#} {error:?}");
    assert!(text.contains("TrapOnlyPatchReadback"), "{text}");
}

/// A signal left pending for the tracer's final resume of a patched stop is
/// handled as under ptrace. After an in-place inject or an emulation the
/// resume is from a syscall-exit stop, where the kernel sends it; after a
/// tail inject ptrace resumes the seccomp stop, where the kernel ignores it,
/// so the trap-only tail hop must drop it rather than pass it at its own
/// syscall-exit stop.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_resume_signal_matches_ptrace() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("resume_signal").await;
    assert_patched(&trap_only, SiteState::Live);
    assert_patched(&trap_only_tail, SiteState::Live);
    assert_report_has(
        &ptrace,
        &[
            "getpid returned pid=1",
            "resume_inject 0: sig=10 code=128 value=-1 rip=tp_site_end rax=<pid> ",
            "emulated getpid returned 4242",
            "resume_emulate 0: sig=10 code=0 value=-1 rip=tp_site_end rax=4242 ",
            "tail getpid returned pid=1",
        ],
    );
    assert!(
        !ptrace.report.contains("resume_tail 0:"),
        "ptrace drops a signal passed on resume from the seccomp stop:\n{}",
        ptrace.report
    );
}

/// Guest code that runs the private page's traced slot outside any hop fails
/// the run closed with `TrapOnlyStraySlotStop`.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_stray_slot_stop_fails_closed() {
    let error = run_p2_with("stray_slot", Some(SitePatching::On), false, false)
        .await
        .expect_err("a slot stop outside a hop must end the run");
    let text = format!("{error:#} {error:?}");
    assert!(text.contains("TrapOnlyStraySlotStop"), "{text}");
}

/// The tables of a trap-only run labelled `label`.
fn tables<'a>(run: &'a P2Run, label: &str) -> Vec<&'a SiteTable> {
    run.tables
        .iter()
        .filter(|(candidate, _)| candidate == label)
        .map(|(_, table)| table)
        .collect()
}

/// Requires a lifecycle decision starting with `prefix`, and returns the
/// largest number after `restored=` among those decisions, if any.
fn lifecycle_has(run: &P2Run, prefix: &str) -> Option<usize> {
    let events: Vec<_> = run
        .lifecycle
        .iter()
        .filter(|event| event.starts_with(prefix))
        .collect();
    assert!(
        !events.is_empty(),
        "no lifecycle event {prefix:?} in {:#?}",
        run.lifecycle
    );
    events
        .iter()
        .filter_map(|event| event.rsplit_once("restored="))
        .map(|(_, count)| count.parse().expect("a restored count"))
        .max()
}

/// Masks the host TID an untraced clone returns, which no traced task names,
/// wherever it appears: the Tool's return value, the rax of the exit event
/// and of the resume that follow it, and the sender pid of the SIGCHLD an
/// untraced fork child's death sends its parent. A tail-injected clone's
/// result never reaches the Tool, so there the child's pid is taken from
/// that SIGCHLD: a sender pid still numeric after renaming is one no traced
/// task has.
fn mask_untraced_tid(run: &P2Run) -> P2Run {
    let returned = run
        .tool_events
        .values()
        .flatten()
        .filter_map(|event| event.split_once("syscall clone = "))
        .map(|(_, tid)| tid.to_string());
    let sigchld_senders = run
        .signals
        .values()
        .flatten()
        .filter(|event| event.starts_with("SIGCHLD "))
        .flat_map(|event| event.split(' '))
        .filter_map(|token| token.strip_prefix("pid="))
        .map(str::to_string);
    let tids: Vec<String> = returned
        .chain(sigchld_senders)
        .filter(|tid| tid.parse::<i64>().is_ok_and(|tid| tid > 0))
        .collect();
    let mask = |events: &BTreeMap<String, Vec<String>>| {
        events
            .iter()
            .map(|(task, events)| {
                let events = events
                    .iter()
                    .map(|event| match event.split_once("syscall clone = ") {
                        Some((head, _)) => format!("{head}syscall clone = <untraced>"),
                        None => tids.iter().fold(event.clone(), |event, tid| {
                            event
                                .replace(&format!(" rax={tid} "), " rax=<untraced> ")
                                .replace(&format!(" pid={tid} "), " pid=<untraced> ")
                        }),
                    })
                    .collect();
                (task.clone(), events)
            })
            .collect()
    };
    P2Run {
        tool_events: mask(&run.tool_events),
        resumes: mask(&run.resumes),
        signals: mask(&run.signals),
        ..clone_run(run)
    }
}

/// T6b: an exec, by the leader or by a non-leader thread, gives the new image
/// a new empty table, which patches the image's own site from scratch; the
/// runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6b_exec_gets_an_empty_table() {
    for (mode, old_state) in [
        ("exec_leader", TableState::Patchable),
        (
            "exec_thread",
            TableState::Disabled(DisabledReason::MultiTask),
        ),
    ] {
        let [ptrace, trap_only, _, trap_only_tail] = compare_mode(mode).await;
        assert_report_has(
            &ptrace,
            &["mode exec_image site=", "exec image getpid ok", "done"],
        );
        for run in [&trap_only, &trap_only_tail] {
            lifecycle_has(run, "exec initial=false entries=0 state=Patchable");
            let exec = tables(run, "exec");
            assert_eq!(exec.len(), 1, "{mode}: one exec table");
            assert_eq!(exec[0].state(), TableState::Patchable, "{mode}");
            assert_eq!(
                exec[0].site_state(run.site),
                Some(SiteState::Live),
                "{mode}: the new image patched its site again"
            );
            // The old image's table is untouched by the exec.
            assert_eq!(run.table_state, Some(old_state), "{mode}");
        }
    }
}

/// T6c: JIT code is patched only while its page is `r-xp`; every mapping
/// change that reaches a patched site restores it first, so that the guest
/// reads its own bytes, and the runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6c_jit_code_and_mapping_changes() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("jit").await;
    assert_report_has(
        &ptrace,
        &[
            "jit a 2 pid=1",
            "jit fork child a bytes 0f 05",
            "jit fork child exited=1 code=0",
            "jit a after fork pid=1",
            "jit a after mprotect rw bytes 0f 05",
            "jit a2 2 ppid=1",
            "jit b2 2 tid=1",
            "jit d after mmap fixed bytes 00 00",
            "jit c after mremap bytes 0f 05",
            "jit c2 2 pid=1",
            "jit e 2 pid=1",
            "jit e bytes 0f 05",
            "after madvise site bytes 0f 05",
            "done",
        ],
    );
    let mapping = Some(SiteState::Retired(RetiredReason::Mapping));
    for run in [&trap_only, &trap_only_tail] {
        let root = run.root_table.as_ref().expect("a trap-only root table");
        assert_eq!(root.state(), TableState::Patchable);
        for (site, expected) in [
            // mprotect RW of patched code, then new code at another offset.
            (0x5000_0005, mapping),
            (0x5000_0007, Some(SiteState::Live)),
            // munmap; the same address is never patched again.
            (0x5001_0005, mapping),
            // mmap(MAP_FIXED) over patched code.
            (0x5005_0005, mapping),
            // mremap: the old address is restored before the move, and the
            // moved code patches at its new address.
            (0x5002_0005, mapping),
            (0x5003_0005, Some(SiteState::Live)),
            // A writable and executable page is never patched.
            (0x5004_0005, None),
            // madvise(MADV_DONTNEED) on the fixture's own text.
            (run.site, mapping),
        ] {
            assert_eq!(root.site_state(site), expected, "site {site:#x}");
        }
        // The fork child restored only its own copy.
        let fork = tables(run, "fork");
        assert_eq!(fork.len(), 1);
        assert_eq!(fork[0].site_state(0x5000_0005), mapping);
        assert!(lifecycle_has(run, "mapping munmap").unwrap() >= 1);
        assert!(lifecycle_has(run, "mapping mremap").unwrap() >= 1);
        assert!(lifecycle_has(run, "mapping madvise").unwrap() >= 1);
        assert!(lifecycle_has(run, "mapping mmap").unwrap() >= 1);
    }
}

/// T6c, continued: restoring a site puts back only the bytes that still
/// hold the patch, so a byte the guest stored over it through
/// `/proc/self/mem` survives; and an `mremap(MREMAP_FIXED)` onto a patched
/// page retires the site of the page it replaces. The runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6c_self_write_and_mremap_destination() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("jit_more").await;
    assert_report_has(
        &ptrace,
        &[
            "more a 2 pid=1",
            "more a after self write bytes 90 05",
            "more f 2 pid=1",
            "more f after mremap bytes 00 00",
            "more f2 2 tid=1",
            "done",
        ],
    );
    let mapping = Some(SiteState::Retired(RetiredReason::Mapping));
    for run in [&trap_only, &trap_only_tail] {
        let root = run.root_table.as_ref().expect("a trap-only root table");
        assert_eq!(root.state(), TableState::Patchable);
        for (site, expected) in [
            // Live when the guest stored over it (only a live site is
            // retired), then restored by the mprotect.
            (0x5100_0005, mapping),
            // The mremap destination's own site, and the moved code's site
            // at its new address.
            (0x5101_0005, mapping),
            (0x5101_0007, Some(SiteState::Live)),
            // The moved code never ran at its old address.
            (0x5102_0007, None),
        ] {
            assert_eq!(root.site_state(site), expected, "site {site:#x}");
        }
        assert!(lifecycle_has(run, "mapping mprotect").unwrap() >= 1);
        assert!(lifecycle_has(run, "mapping mremap").unwrap() >= 1);
    }
}

/// Whether this host's kernel lets a process pass `MADV_DONTNEED` for
/// itself to `process_madvise` (Linux 6.13 and later; older kernels accept
/// only the advice that newer ones allow for another address space, and
/// fail with EINVAL).
fn process_madvise_dontneed_on_self() -> bool {
    // SAFETY: an anonymous private page of our own, a pidfd for ourselves,
    // and an iovec that names only that page; all are released below.
    unsafe {
        let page = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert_ne!(page, libc::MAP_FAILED, "map a probe page");
        let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
        assert!(
            pidfd >= 0,
            "pidfd_open: {}",
            std::io::Error::last_os_error()
        );
        let iov = libc::iovec {
            iov_base: page,
            iov_len: 4096,
        };
        let result = libc::syscall(
            libc::SYS_process_madvise,
            pidfd,
            &iov as *const libc::iovec,
            1,
            libc::MADV_DONTNEED,
            0,
        );
        let error = std::io::Error::last_os_error();
        libc::close(pidfd as libc::c_int);
        libc::munmap(page, 4096);
        match result {
            4096 => true,
            -1 if error.raw_os_error() == Some(libc::EINVAL) => false,
            _ => panic!("process_madvise probe returned {result}: {error}"),
        }
    }
}

/// T6c: `process_madvise` restores every site of the caller's table before
/// it runs, since the tracer reads neither its iovec array nor which process
/// its pidfd names: here `MADV_DONTNEED` through a pidfd for the guest
/// itself, on the fixture's own patched text page, also restores the site of
/// a JIT page the call does not name. The call's result depends on the host
/// kernel (see `process_madvise_dontneed_on_self`); the restore does not.
/// The runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6c_process_madvise_restores_every_site() {
    let expected_call = if process_madvise_dontneed_on_self() {
        "process_madvise ret=4096 errno=0"
    } else {
        "process_madvise ret=-1 errno=22"
    };
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("process_madvise").await;
    assert_report_has(
        &ptrace,
        &[
            "pm jit 2 pid=1",
            expected_call,
            "after process_madvise site bytes 0f 05",
            "after process_madvise jit bytes 0f 05",
            "pm jit2 2 pid=1",
            "done",
        ],
    );
    let mapping = Some(SiteState::Retired(RetiredReason::Mapping));
    for run in [&trap_only, &trap_only_tail] {
        let root = run.root_table.as_ref().expect("a trap-only root table");
        assert_eq!(root.state(), TableState::Patchable);
        // The page the call names, and a JIT page it does not name.
        for site in [run.site, 0x5200_0005] {
            assert_eq!(root.site_state(site), mapping, "site {site:#x}");
        }
        assert!(
            lifecycle_has(run, "mapping process_madvise restored=").unwrap() >= 2,
            "the call restored both sites"
        );
    }
}

/// T6c: a site whose first call is `process_madvise` is not patched at that
/// call. Here the call is `MADV_DONTNEED`, through a pidfd for the guest
/// itself, on the page of the calling site (`tp_site`). Had the tracer
/// patched the site at that stop, the tail-injected call would have run
/// after the patch and dropped the page copy that holds it, leaving the site
/// live in the table over `0f 05`. In both Tool configurations: right after
/// the call the guest reads `0f 05` at the site on both backends, unmasked;
/// `warm()` then patches the site through getpid, and at the end of the run
/// the table holds it live while the guest's last read of it is `cd 80` (the
/// disclosed text residual, masked on that one line as in T6a). The table
/// holds the site live exactly when its bytes hold the patch. The call's
/// result depends on the host kernel (see
/// `process_madvise_dontneed_on_self`), and only a kernel that accepts it
/// can drop the page. The runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6c_process_madvise_first_call_leaves_its_site_unpatched() {
    let mode = "process_madvise_first";
    let expected_call = if process_madvise_dontneed_on_self() {
        "process_madvise first ret=4096"
    } else {
        "process_madvise first ret=-22"
    };
    for tail in [false, true] {
        let ptrace = run_p2(mode, None, tail).await;
        let trap_only = run_p2(mode, Some(SitePatching::On), tail).await;
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        assert_report_has(
            &ptrace,
            &[
                expected_call,
                "after process_madvise first site bytes 0f 05",
                "after warm site bytes 0f 05",
                "done",
            ],
        );
        assert_report_has(&trap_only, &["after warm site bytes cd 80"]);
        let masked = P2Run {
            report: trap_only
                .report
                .replace("after warm site bytes cd 80", "after warm site bytes 0f 05"),
            ..clone_run(&trap_only)
        };
        assert_equal_runs(&masked, &ptrace);
        let root = trap_only
            .root_table
            .as_ref()
            .expect("a trap-only root table");
        assert_eq!(root.state(), TableState::Patchable, "tail={tail}");
        assert_eq!(
            root.site_state(trap_only.site),
            Some(SiteState::Live),
            "tail={tail}: warm() patched the site"
        );
        assert!(trap_only.patched_sites >= 1, "tail={tail}: counts the site");
        lifecycle_has(&trap_only, "mapping process_madvise restored=");
    }
}

/// T6a, undecided: when a new-child stop has no recorded clone flags (a
/// Tool-injected clone; here the test makes the tracer drop them), every
/// site is restored in both tasks and they share the disabled table. The
/// runs equal ptrace, including the site bytes each copy reads.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6a_undecided_new_child_restores_both_tasks() {
    let run = |patching, tail| async move {
        run_p2_env(
            "fork_undecided",
            patching,
            tail,
            P2Hook::ForgetCloneFlags,
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("{patching:?} tail={tail} failed: {error}"))
    };
    for tail in [false, true] {
        let ptrace = run(None, tail).await;
        let trap_only = run(Some(SitePatching::On), tail).await;
        assert_equal_runs(&trap_only, &ptrace);
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert_report_has(
            &ptrace,
            &[
                "undecided fork child site bytes 0f 05",
                "undecided fork child exited=1 code=7",
                "undecided fork parent site bytes 0f 05",
                "done",
            ],
        );
        let restored = lifecycle_has(
            &trap_only,
            "new-child Fork undecided recorded=None restored=",
        );
        assert!(
            restored.unwrap() >= 1,
            "the undecided child restored the live site"
        );
        assert!(tables(&trap_only, "fork").is_empty());
        let shared = tables(&trap_only, "share");
        assert_eq!(shared.len(), 1, "the child shares the parent's table");
        assert_eq!(
            shared[0].state(),
            TableState::Disabled(DisabledReason::MultiTask)
        );
        assert_eq!(
            trap_only.table_state,
            Some(TableState::Disabled(DisabledReason::MultiTask))
        );
        assert_eq!(
            trap_only.site_state,
            Some(SiteState::Retired(RetiredReason::MultiTask))
        );
        assert_eq!(trap_only.patched_sites, 0);
    }
}

/// T6a, kcmp cross-check: when the clone flags recorded at the creating stop
/// disagree with `kcmp(KCMP_VM)` at the new-child stop (here the test flips
/// `CLONE_VM` in what the new-child stop sees), the stop takes the undecided
/// path in both directions.
/// - A real fork recorded as `CLONE_VM` (flags 0x100): the creating stop
///   acted on the real flags and left the site live, so the new-child stop
///   restores it in both copies of the address space, and both read the
///   original bytes; the two tasks share one disabled table. Believing the
///   recorded flags instead would fail the run with live sites in a shared
///   table.
/// - A real thread recorded without `CLONE_VM`: the creating stop already
///   restored every site, so nothing is left to restore, and the thread
///   still shares the parent's table instead of getting a copy of it.
///   Believing the recorded flags instead would give the thread a fork table.
///
/// The runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6a_clone_flags_disagreeing_with_kcmp_take_the_undecided_path() {
    let run = |mode, patching, tail| async move {
        run_p2_env(mode, patching, tail, P2Hook::FlipRecordedCloneVm, None)
            .await
            .unwrap_or_else(|error| panic!("{mode} {patching:?} tail={tail} failed: {error}"))
    };
    for tail in [false, true] {
        // A real fork, recorded as sharing the address space.
        let ptrace = run("fork_undecided", None, tail).await;
        let trap_only = run("fork_undecided", Some(SitePatching::On), tail).await;
        assert_equal_runs(&trap_only, &ptrace);
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert_report_has(
            &ptrace,
            &[
                "undecided fork child site bytes 0f 05",
                "undecided fork child exited=1 code=7",
                "undecided fork parent site bytes 0f 05",
                "done",
            ],
        );
        let restored = lifecycle_has(
            &trap_only,
            "new-child Fork undecided recorded=Some(100) restored=",
        );
        assert!(
            restored.unwrap() >= 1,
            "the mismatched fork restored the live site"
        );
        assert!(tables(&trap_only, "fork").is_empty());
        let shared = tables(&trap_only, "share");
        assert_eq!(shared.len(), 1, "the child shares the parent's table");
        assert_eq!(
            shared[0].state(),
            TableState::Disabled(DisabledReason::MultiTask)
        );
        assert_eq!(
            trap_only.table_state,
            Some(TableState::Disabled(DisabledReason::MultiTask))
        );
        assert_eq!(
            trap_only.site_state,
            Some(SiteState::Retired(RetiredReason::MultiTask))
        );
        assert_eq!(trap_only.patched_sites, 0);

        // A real thread, recorded as not sharing it.
        let ptrace = run("thread_mismatch", None, tail).await;
        let trap_only = run("thread_mismatch", Some(SitePatching::On), tail).await;
        assert_equal_runs(&trap_only, &ptrace);
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert_report_has(
            &ptrace,
            &[
                "mismatch thread ret=1",
                "mismatch thread parent site bytes 0f 05",
                "done",
            ],
        );
        let restored = lifecycle_has(&trap_only, "creating clone flags=0x250f00 restored=");
        assert!(
            restored.unwrap() >= 1,
            "the creating stop restored the live site"
        );
        assert_eq!(
            lifecycle_has(
                &trap_only,
                "new-child Clone undecided recorded=Some(250e00) restored=",
            ),
            Some(0),
            "the creating stop left nothing to restore"
        );
        assert!(tables(&trap_only, "fork").is_empty());
        let shared = tables(&trap_only, "share");
        assert_eq!(shared.len(), 1, "the thread shares the parent's table");
        assert_eq!(
            shared[0].state(),
            TableState::Disabled(DisabledReason::MultiTask)
        );
        assert_eq!(
            trap_only.table_state,
            Some(TableState::Disabled(DisabledReason::MultiTask))
        );
        assert_eq!(
            trap_only.site_state,
            Some(SiteState::Retired(RetiredReason::MultiTask))
        );
        assert_eq!(trap_only.patched_sites, 0);
    }
}

/// T6a, `CLONE_VFORK` cross-check: when the clone flags recorded at the
/// creating stop disagree with the kind of new-child stop that arrives
/// (here the test flips `CLONE_VFORK` in what the new-child stop sees; the
/// `CLONE_VM` half and kcmp agree), the stop takes the undecided path for
/// each kind of child.
/// - A real fork recorded as a vfork (flags 0x4000): the creating stop left
///   the site live, so the new-child stop restores it in both copies of the
///   address space, and both read the original bytes; the two tasks share
///   one disabled table. Believing the recorded flags instead would give the
///   child a fork table with a live site.
/// - A real vfork recorded without `CLONE_VFORK` (flags 0x100): the creating
///   stop left the site live, so the new-child stop restores it before the
///   child runs, and the child, which shares the address space, reads the
///   original bytes. Believing the recorded flags instead would fail the run
///   with live sites in a table shared by a second executor.
/// - A real thread recorded as a vfork: the creating stop already restored
///   every site, so nothing is left to restore, and the thread shares the
///   parent's disabled table.
///
/// The runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6a_clone_flags_disagreeing_with_the_vfork_stop_take_the_undecided_path() {
    let run = |mode, patching, tail| async move {
        run_p2_env(mode, patching, tail, P2Hook::FlipRecordedCloneVfork, None)
            .await
            .unwrap_or_else(|error| panic!("{mode} {patching:?} tail={tail} failed: {error}"))
    };
    let assert_one_disabled_shared_table = |run: &P2Run, what: &str| {
        assert!(tables(run, "fork").is_empty(), "{what}: no fork table");
        let shared = tables(run, "share");
        assert_eq!(
            shared.len(),
            1,
            "{what}: the child shares the parent's table"
        );
        assert_eq!(
            shared[0].state(),
            TableState::Disabled(DisabledReason::MultiTask),
            "{what}"
        );
        assert_eq!(
            run.table_state,
            Some(TableState::Disabled(DisabledReason::MultiTask)),
            "{what}"
        );
        assert_eq!(
            run.site_state,
            Some(SiteState::Retired(RetiredReason::MultiTask)),
            "{what}"
        );
        assert_eq!(run.patched_sites, 0, "{what}");
    };
    for tail in [false, true] {
        // A real fork, recorded as a vfork.
        let ptrace = run("fork_undecided", None, tail).await;
        let trap_only = run("fork_undecided", Some(SitePatching::On), tail).await;
        assert_equal_runs(&trap_only, &ptrace);
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert_report_has(
            &ptrace,
            &[
                "undecided fork child site bytes 0f 05",
                "undecided fork child exited=1 code=7",
                "undecided fork parent site bytes 0f 05",
                "done",
            ],
        );
        let restored = lifecycle_has(
            &trap_only,
            "new-child Fork undecided recorded=Some(4000) restored=",
        );
        assert!(
            restored.unwrap() >= 1,
            "the mismatched fork restored the live site"
        );
        assert_one_disabled_shared_table(&trap_only, "fork");

        // A real vfork, recorded without CLONE_VFORK.
        let ptrace = run("vfork_undecided", None, tail).await;
        let trap_only = run("vfork_undecided", Some(SitePatching::On), tail).await;
        assert_equal_runs(&trap_only, &ptrace);
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert_report_has(
            &ptrace,
            &[
                "undecided vfork child site bytes 0f 05",
                "undecided vfork child exited=1 code=7",
                "undecided vfork parent site bytes 0f 05",
                "done",
            ],
        );
        let restored = lifecycle_has(
            &trap_only,
            "new-child Vfork undecided recorded=Some(100) restored=",
        );
        assert!(
            restored.unwrap() >= 1,
            "the mismatched vfork restored the live site before the child ran"
        );
        assert_one_disabled_shared_table(&trap_only, "vfork");

        // A real thread, recorded as a vfork.
        let ptrace = run("thread_mismatch", None, tail).await;
        let trap_only = run("thread_mismatch", Some(SitePatching::On), tail).await;
        assert_equal_runs(&trap_only, &ptrace);
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert_report_has(
            &ptrace,
            &[
                "mismatch thread ret=1",
                "mismatch thread parent site bytes 0f 05",
                "done",
            ],
        );
        let restored = lifecycle_has(&trap_only, "creating clone flags=0x250f00 restored=");
        assert!(
            restored.unwrap() >= 1,
            "the creating stop restored the live site"
        );
        assert_eq!(
            lifecycle_has(
                &trap_only,
                "new-child Clone undecided recorded=Some(254f00) restored=",
            ),
            Some(0),
            "the creating stop left nothing to restore"
        );
        assert_one_disabled_shared_table(&trap_only, "thread");
    }
}

/// `restored_bytes` puts back only the bytes that still hold the patch.
#[test]
fn trap_only_p2_restore_keeps_the_guests_own_bytes() {
    use crate::liteinst_trap_only::PATCHED_BYTES;
    use crate::liteinst_trap_only::SYSCALL_BYTES;
    use crate::liteinst_trap_only::restored_bytes;
    let original = SYSCALL_BYTES;
    assert_eq!(restored_bytes(PATCHED_BYTES, original), original);
    assert_eq!(restored_bytes(original, original), original);
    assert_eq!(restored_bytes([0x90, 0x80], original), [0x90, 0x05]);
    assert_eq!(restored_bytes([0xcd, 0x90], original), [0x0f, 0x90]);
    assert_eq!(restored_bytes([0x90, 0x90], original), [0x90, 0x90]);
}

/// T6d: posix_spawn and system() create vfork children that share the
/// parent's table until they exec; the parent's sites stay patched and the
/// runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t6d_vfork_spawn_keeps_the_parent_patched() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("vfork_spawn").await;
    assert_report_has(
        &ptrace,
        &[
            "exec image getpid ok",
            "spawn child exited=1 code=0",
            "system exited=1 code=3",
            "parent getpid ok",
            "done",
        ],
    );
    for run in [&trap_only, &trap_only_tail] {
        assert_patched(run, SiteState::Live);
        assert_eq!(run.table_state, Some(TableState::Patchable));
        let vforks: Vec<_> = run
            .lifecycle
            .iter()
            .filter(|event| event.starts_with("new-child Vfork flags="))
            .collect();
        assert_eq!(vforks.len(), 2, "{:#?}", run.lifecycle);
        assert!(vforks.iter().all(|event| event.ends_with("shares=true")));
        assert!(
            !run.lifecycle
                .iter()
                .any(|event| event.starts_with("creating")),
            "a vfork must not restore the parent: {:#?}",
            run.lifecycle
        );
        assert_eq!(tables(run, "share").len(), 2);
        assert_eq!(tables(run, "exec").len(), 2);
    }
}

/// T7a: a guest seccomp filter (through the patched site, with TSYNC from a
/// two-thread process, or with prctl(PR_SET_SECCOMP)) restores every site
/// before it is installed and disables the lineage: the filter never sees an
/// IA-32 entry, the fork child and its exec'd image stay unpatched, and the
/// runs equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t7a_guest_seccomp_disables_the_lineage() {
    for (mode, how, install, site_reason) in [
        (
            "guest_seccomp",
            "site",
            "install seccomp GuestSeccomp",
            RetiredReason::GuestSeccomp,
        ),
        (
            "guest_seccomp_tsync",
            "tsync",
            "install seccomp GuestSeccomp",
            RetiredReason::MultiTask,
        ),
        (
            "guest_seccomp_prctl",
            "prctl",
            "install prctl GuestSeccomp",
            RetiredReason::GuestSeccomp,
        ),
    ] {
        let [ptrace, trap_only, _, trap_only_tail] = compare_mode(mode).await;
        assert_report_has(
            &ptrace,
            &[
                &format!("install {how} ret=0"),
                "after install site bytes 0f 05",
                "getpid 2 pid=1",
                "getppid ret=-1",
                "child getpid 2 pid=1",
                "exec image getpid ok",
                "child exited=1 code=0 signaled=0 sig=0",
                "sigsys handled=0",
            ],
        );
        if how == "tsync" {
            assert_report_has(&ptrace, &["thread getppid ret=-1"]);
        }
        let disabled = TableState::Disabled(DisabledReason::GuestSeccomp);
        for run in [&trap_only, &trap_only_tail] {
            let restored = lifecycle_has(run, install).unwrap();
            if how == "tsync" {
                // The second thread's creation already restored every site
                // and disabled the table; the install finds nothing left.
                assert!(
                    lifecycle_has(run, "creating clone").unwrap() >= 1,
                    "{mode}: the thread's creation restored the live sites"
                );
                assert_eq!(restored, 0, "{mode}: nothing left for the install");
            } else {
                assert!(restored >= 1, "{mode}: the install restored the live sites");
            }
            assert_eq!(run.table_state, Some(disabled), "{mode}");
            assert_eq!(
                run.site_state,
                Some(SiteState::Retired(site_reason)),
                "{mode}"
            );
            assert_eq!(run.patched_sites, 0, "{mode}");
            let fork = tables(run, "fork");
            let exec = tables(run, "exec");
            assert_eq!((fork.len(), exec.len()), (1, 1), "{mode}");
            for table in fork.iter().chain(&exec) {
                assert_eq!(table.state(), disabled, "{mode}");
                assert_eq!(table.patched_sites(), 0, "{mode}");
            }
            assert_eq!(
                exec[0].entries(),
                0,
                "{mode}: the exec'd image patched nothing"
            );
        }
    }
}

/// T7b: syscall user dispatch restores every site before it is enabled, so
/// that the dispatched SIGSYS reports the x86_64 `syscall` at the site
/// exactly as under ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t7b_syscall_user_dispatch_sees_the_original_site() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("sud").await;
    assert_report_has(
        &ptrace,
        &[
            "sud on ret=0",
            "after sud site bytes 0f 05",
            "dispatched getpid ret=1234 count=1 syscall=39 arch=0xc000003e call=tp_site_end",
            "sud off ret=0",
            "getpid 2 pid=1",
            "child getpid 2 pid=1",
            "child exited=1 code=0",
            "sud handled=1",
        ],
    );
    let disabled = TableState::Disabled(DisabledReason::Sud);
    for run in [&trap_only, &trap_only_tail] {
        assert!(lifecycle_has(run, "install prctl Sud").unwrap() >= 1);
        assert_eq!(run.table_state, Some(disabled));
        assert_eq!(run.site_state, Some(SiteState::Retired(RetiredReason::Sud)));
        let fork = tables(run, "fork");
        assert_eq!(fork.len(), 1);
        assert_eq!(fork[0].state(), disabled);
    }
}

/// A CLONE_UNTRACED thread gets no new-child stop, so every site is restored
/// at the creating stop, before the clone runs: the untraced thread executes
/// the original `syscall` (whose rcx is its return address), and its start
/// address is the guest's own. Cloned from libc and through the patched
/// site itself.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_untraced_thread_starts_on_restored_text() {
    for mode in ["untraced_thread", "untraced_thread_site"] {
        // compare_mode cannot compare these runs: the clone returns a host
        // TID that no traced task names.
        let ptrace = mask_untraced_tid(&run_p2(mode, None, false).await);
        let trap_only = mask_untraced_tid(&run_p2(mode, Some(SitePatching::On), false).await);
        assert_equal_runs(&trap_only, &ptrace);
        let ptrace_tail = run_p2(mode, None, true).await;
        let trap_only_tail = run_p2(mode, Some(SitePatching::On), true).await;
        assert_equal_runs(&trap_only_tail, &ptrace_tail);
        for run in [&ptrace, &ptrace_tail] {
            assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
            assert!(run.report.ends_with("done\n"), "{}", run.report);
        }
        assert_report_has(
            &ptrace,
            &[
                "untraced clone ok=1",
                "untraced thread getpid ret=-38 rcx=tp_site_end",
                "after untraced site bytes 0f 05",
            ],
        );
        for run in [&trap_only, &trap_only_tail] {
            assert!(lifecycle_has(run, "creating clone flags=").unwrap() >= 1);
            assert_eq!(
                run.table_state,
                Some(TableState::Disabled(DisabledReason::MultiTask))
            );
            assert_eq!(
                run.site_state,
                Some(SiteState::Retired(RetiredReason::MultiTask))
            );
        }
    }
}

/// A fork-like CLONE_UNTRACED child (without CLONE_VM), cloned through the
/// patched site, gets no new-child stop and its own copy of the text: every
/// site is restored at the creating stop and the clone runs at the site, so
/// the child starts after the guest's own `syscall` and executes the
/// original instruction there, exactly as under ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_untraced_fork_starts_on_restored_text() {
    let mode = "untraced_fork";
    // The clone returns a host PID that no traced task names.
    let ptrace = mask_untraced_tid(&run_p2(mode, None, false).await);
    let trap_only = mask_untraced_tid(&run_p2(mode, Some(SitePatching::On), false).await);
    assert_equal_runs(&trap_only, &ptrace);
    let ptrace_tail = mask_untraced_tid(&run_p2(mode, None, true).await);
    let trap_only_tail = mask_untraced_tid(&run_p2(mode, Some(SitePatching::On), true).await);
    assert_equal_runs(&trap_only_tail, &ptrace_tail);
    for run in [&ptrace, &ptrace_tail] {
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert!(run.report.ends_with("done\n"), "{}", run.report);
    }
    assert_report_has(
        &ptrace,
        &[
            "untraced fork clone ok=1",
            "untraced fork child done=1 clone rcx=tp_site_end r11=0x246 \
             getpid ret=-38 rcx=tp_site_end bytes 0f 05",
            // CLD_KILLED by the parent's SIGKILL.
            "untraced fork child code=2 status=9",
            "after untraced fork site bytes 0f 05",
        ],
    );
    // The child is untraced: no new-child stop, no table for it.
    assert_eq!(ptrace_tail.counts.fork_stops(), 0);
    assert_eq!(ptrace_tail.counts.clone_stops(), 0);
    for run in [&trap_only, &trap_only_tail] {
        let flags = libc::CLONE_UNTRACED | libc::SIGCHLD;
        let restored = lifecycle_has(run, &format!("creating clone flags={flags:#x} restored="));
        assert!(restored.unwrap() >= 1, "the clone restored the live site");
        assert!(tables(run, "fork").is_empty() && tables(run, "share").is_empty());
        assert_eq!(
            run.table_state,
            Some(TableState::Disabled(DisabledReason::MultiTask))
        );
        assert_eq!(
            run.site_state,
            Some(SiteState::Retired(RetiredReason::MultiTask))
        );
        assert_eq!(run.patched_sites, 0);
    }
}

/// T7a's guest has two host-timed interleavings: the TSYNC thread's exit
/// against the leader's join, and the fork child's exit (SIGCHLD) against
/// the parent's wait4. Neither may reach the Tool. `TP_ORDER=early` makes
/// the thread and the child almost surely finish first (the leader spins
/// before the join and before the wait); `TP_ORDER=late` makes them almost
/// surely finish last (the thread spins before it returns, the child before
/// it execs). The spins make no syscalls, so all four runs must be equal.
/// Before the fixture joined without syscalls and blocked SIGCHLD, the two
/// plain ptrace runs differed at the join's futex (present under `late`,
/// absent under `early`) and, with only the join fixed, at SIGCHLD (after
/// wait4 under `late`, before it under `early`).
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t7a_thread_and_child_order_do_not_reach_the_tool() {
    let run = |patching, order| async move {
        run_p2_env(
            "guest_seccomp_tsync",
            patching,
            false,
            P2Hook::None,
            Some(order),
        )
        .await
        .unwrap_or_else(|error| panic!("{patching:?} TP_ORDER={order} failed: {error}"))
    };
    let ptrace_early = run(None, "early").await;
    let ptrace_late = run(None, "late").await;
    assert_equal_runs(&ptrace_late, &ptrace_early);
    let trap_only_early = run(Some(SitePatching::On), "early").await;
    let trap_only_late = run(Some(SitePatching::On), "late").await;
    assert_equal_runs(&trap_only_early, &ptrace_late);
    assert_equal_runs(&trap_only_late, &ptrace_early);
    assert_report_has(
        &ptrace_early,
        &["thread getppid ret=-1", "sigsys handled=0"],
    );
}

/// Like `compare_mode`, except that each trap-only run also has exactly the
/// `internal` (invisible allowed-class) run-loop stops.
async fn compare_mode_with_internal(mode: &str, internal: &[&str]) -> [P2Run; 4] {
    let ptrace_inject = run_p2(mode, None, false).await;
    let trap_only_inject = run_p2(mode, Some(SitePatching::On), false).await;
    assert_equal_runs_with_internal(&trap_only_inject, &ptrace_inject, internal);
    let ptrace_tail = run_p2(mode, None, true).await;
    let trap_only_tail = run_p2(mode, Some(SitePatching::On), true).await;
    assert_equal_runs_with_internal(&trap_only_tail, &ptrace_tail, internal);
    for run in [&ptrace_inject, &ptrace_tail] {
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert!(run.report.ends_with("done\n"), "{}", run.report);
    }
    [ptrace_inject, trap_only_inject, ptrace_tail, trap_only_tail]
}

/// Attempts of one precise-timer comparison; see `compare_timer_mode`.
const TIMER_ATTEMPTS: usize = 3;

/// The assertions `compare_mode_with_internal` makes, on its four runs
/// (ptrace inject, trap-only inject, ptrace tail, trap-only tail).
fn assert_mode_runs(runs: &[P2Run; 4], internal: &[&str]) {
    let [ptrace_inject, trap_only_inject, ptrace_tail, trap_only_tail] = runs;
    assert_equal_runs_with_internal(trap_only_inject, ptrace_inject, internal);
    assert_equal_runs_with_internal(trap_only_tail, ptrace_tail, internal);
    for run in [ptrace_inject, ptrace_tail] {
        assert_eq!(run.status, ExitStatus::Exited(0), "{}", run.report);
        assert!(run.report.ends_with("done\n"), "{}", run.report);
    }
}

/// The text of a caught panic.
fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_else(|| "<non-string panic>".to_owned())
}

/// `compare_mode_with_internal` for a mode whose Tool arms precise timers,
/// followed by the test's own `check` of the four runs. An attempt is
/// retried, up to `TIMER_ATTEMPTS` attempts, only when it failed and one of
/// its runs had a host-timed timer outcome (`HostTimedTimerEvents`, counted
/// by the timer on this thread): the perf overflow signal was handled past
/// the target, or exactly at the target with no step to place the event, or
/// after another stop had already ended the timer although its overflow was
/// due. Each of these puts the timer event (or its absence) where the host's
/// signal delivery put it, under plain ptrace as much as under trap-only, so
/// such an attempt says nothing about trap-only.
///
/// A failed attempt without such an outcome fails the test at once. If
/// every attempt fails, each with such an outcome, the test fails too,
/// reporting that it measured nothing. A passing attempt passes whether or
/// not it had one. A trap-only defect that fails every attempt is therefore
/// always reported; one that fails only some attempts can pass only if each
/// failed attempt also had a host-timed outcome.
async fn compare_timer_mode(
    mode: &str,
    internal: &[&str],
    check: impl Fn(&[P2Run; 4]),
) -> [P2Run; 4] {
    let mut failures = Vec::new();
    for attempt in 1..=TIMER_ATTEMPTS {
        let _ = crate::timer::take_host_timed_timer_events();
        let runs = [
            run_p2(mode, None, false).await,
            run_p2(mode, Some(SitePatching::On), false).await,
            run_p2(mode, None, true).await,
            run_p2(mode, Some(SitePatching::On), true).await,
        ];
        let host_timed = crate::timer::take_host_timed_timer_events();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_mode_runs(&runs, internal);
            check(&runs);
        }));
        eprintln!(
            "TIMER-ATTEMPT {mode} attempt={attempt} passed={} host-timed={host_timed:?}",
            outcome.is_ok()
        );
        match outcome {
            Ok(()) => return runs,
            Err(panic) if host_timed.total() == 0 => std::panic::resume_unwind(panic),
            Err(panic) => {
                eprintln!(
                    "TIMER-RETRY {mode}: attempt {attempt} of {TIMER_ATTEMPTS} failed with \
                     host-timed timer outcomes {host_timed:?}"
                );
                failures.push(format!(
                    "attempt {attempt}: {host_timed:?}: {}",
                    panic_text(panic.as_ref())
                ));
            }
        }
    }
    panic!(
        "{mode}: no signal: all {TIMER_ATTEMPTS} attempts failed, each with a host-timed \
         timer outcome:\n{}",
        failures.join("\n")
    );
}

/// The Tool's timer events of a run, in order.
fn timer_events(run: &P2Run) -> Vec<&String> {
    run.all_events()
        .into_iter()
        .filter(|event| event.starts_with("timer "))
        .collect()
}

/// T1b: a child exits while the parent sleeps in a patched nanosleep. With
/// SIGCHLD ignored by default the sleep restarts; with a handler it returns
/// EINTR at S+2. Both equal ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t1b_sigchld_during_a_patched_nanosleep() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_mode("sigchld_nanosleep").await;
    assert_patched(&trap_only, SiteState::Live);
    assert_patched(&trap_only_tail, SiteState::Live);
    eprintln!("T1b ptrace report:\n{}", ptrace.report);
    assert_report_has(
        &ptrace,
        &[
            "sigchld-dfl ret=0 errno=0 rcx=tp_site_end r11=0x246",
            "sigchld-dfl slept-full=1 rem-set=1",
            "sigchld-dfl child exited=1 code=5",
            "sigchld-handled ret=-4 errno=4 rcx=tp_site_end r11=0x246",
            "sigchld-handled slept-full=0 rem-set=1",
            "sigchld-handled 0: sig=17 code=1 value=-1 rip=tp_site_end rax=-4 rcx=tp_site_end r11=0x246 ",
            "sigchld-handled child exited=1 code=5",
        ],
    );
}

/// The number of the root task's `name` syscall entries that a timer
/// single-step reached.
fn stepped_entries(run: &P2Run, name: &str) -> usize {
    let prefix = format!("{name} ");
    run.stepped_entries.get("task#0").map_or(0, |entries| {
        entries
            .iter()
            .filter(|entry| entry.starts_with(&prefix))
            .count()
    })
}

/// T4: a precise timer armed at a patched getppid, k = 1..9 branches out,
/// fires at the same place with the same clock as under ptrace. Measured on
/// both backends: only k = 1 and 2 fire (23 iterations each); for k >= 3 the
/// timer's single-steps reach the traced getpid first, which cancels the
/// timer, and that getpid is entered by a single-step. The stepped `syscall`
/// saved TF in r11, and plain ptrace's timer clears it at the seccomp stop
/// (remove_stepping_trap_flag in timer.rs), so the Tool and the guest see
/// r11 equal to the reported rflags; trap-only must give both the same r11
/// (O4 item G).
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t4_timer_loop() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    compare_timer_mode("timer_loop", &[], |runs| {
        let [ptrace, trap_only, _, trap_only_tail] = runs;
        assert_patched(trap_only, SiteState::Live);
        assert_patched(trap_only_tail, SiteState::Live);
        let timers = timer_events(ptrace);
        eprintln!("T4 ptrace timer events: {}", timers.len());
        assert_eq!(timers.len(), 46, "{timers:#?}");
        for run in [ptrace, trap_only, trap_only_tail] {
            let stepped = stepped_entries(run, "getpid");
            assert_eq!(
                stepped, 154,
                "stepped getpid entries: {:#?}",
                run.stepped_entries
            );
            assert_eq!(run.stepped_entries, ptrace.stepped_entries);
            let leaked = run.tool_events["task#0"]
                .iter()
                .filter(|event| {
                    event.starts_with("entry getpid ") && event.contains(" r11=rflags:false ")
                })
                .count();
            assert_eq!(
                leaked, 0,
                "getpid entries whose r11 is not rflags: {:#?}",
                run.tool_events
            );
        }
        assert!(
            ptrace.report.contains("timer loop sum=400\n"),
            "{}",
            ptrace.report
        );
        // The guest sees the stepped getpid's r11 too: the fixture reports
        // every iteration whose r11 is not 0x246, and there is none.
        let iters: Vec<&str> = ptrace
            .report
            .lines()
            .filter(|line| line.starts_with("iter "))
            .collect();
        assert_eq!(iters, Vec::<&str>::new(), "{}", ptrace.report);
    })
    .await;
}

/// T1d: a timer far enough out that perf's own overflow signal starts the
/// single-steps, targeted at branch counts that land before, at and after the
/// patched getpid that follows a long loop.
///
/// The targets sit next to that getpid on purpose, because the steps must
/// reach it; that is what this test is for, so they are not moved into the
/// loop as the timer-hop modes' were. It also means that where the host
/// delivers the overflow signal (programmed one skid margin before each
/// target) decides the outcome when it is late: handled past or exactly at
/// the target, the event fires where the guest happened to be; handled after
/// the getpid's stop, that stop cancels the timer, which then neither fires
/// nor steps onto the getpid (which is then not a stepped entry). The timer
/// counts each such outcome, and `compare_timer_mode` retries only an attempt
/// that failed with one.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t1d_perf_marker_steps_across_a_patched_site() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    compare_timer_mode("perf_marker", &[], |runs| {
        let [ptrace, trap_only, _, trap_only_tail] = runs;
        assert_patched(trap_only, SiteState::Live);
        assert_patched(trap_only_tail, SiteState::Live);
        let timers = timer_events(ptrace);
        eprintln!("T1d ptrace timer events: {timers:#?}");
        // Measured: the targets before the site (inside the loop, and at its
        // exit) fire; the targets at and after the site are cancelled when the
        // steps reach the traced getpid, which is then entered by a
        // single-step. The guest's r11 is 0x246 either way: plain ptrace's
        // timer clears the TF that the stepped `syscall` saved in r11.
        assert_eq!(timers.len(), 2, "{timers:#?}");
        for run in [ptrace, trap_only, trap_only_tail] {
            assert_eq!(
                stepped_entries(run, "getpid"),
                2,
                "stepped getpid entries: {:#?}",
                run.stepped_entries
            );
            assert_eq!(run.stepped_entries, ptrace.stepped_entries);
        }
        for (c, r11) in [(0, "0x246"), (1, "0x246"), (2, "0x246"), (3, "0x246")] {
            assert!(
                ptrace
                    .report
                    .contains(&format!("marker {c} getpid=1 r11={r11}\n")),
                "{}",
                ptrace.report
            );
        }
    })
    .await;
}

/// T4b: with getuid unsubscribed, trap-only does not patch at all and the
/// run is exactly plain ptrace's, stop for stop.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t4b_partial_subscription_patches_nothing() {
    for tail in [false, true] {
        let options = P2Options {
            tail,
            partial: true,
            ..Default::default()
        };
        let ptrace = run_p2_options("partial", None, options).await.unwrap();
        let trap_only = run_p2_options("partial", Some(SitePatching::On), options)
            .await
            .unwrap();
        assert_equal_runs(&trap_only, &ptrace);
        assert_eq!(
            trap_only.table_state,
            Some(TableState::Disabled(DisabledReason::PartialSubscription))
        );
        assert_eq!(trap_only.patched_sites, 0);
        assert_eq!(trap_only.site_state, None);
        assert_report_has(
            &ptrace,
            &[
                "getuid ok=1",
                "getpid after pid=1",
                "partial site bytes 0f 05",
            ],
        );
        assert_eq!(ptrace.status, ExitStatus::Exited(0));
        assert!(
            !ptrace
                .all_events()
                .iter()
                .any(|e| e.starts_with("entry getuid")),
            "getuid is unsubscribed"
        );
    }
}

/// T4c: rt_sigreturn through the warmed shared site (from the guest's own
/// restorer) is invisible to the Tool, restores the frame's registers and
/// mask (the handler's added SIGUSR2 wins), and retires the site as
/// allowed-class.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t4c_rt_sigreturn_through_a_patched_site() {
    let [ptrace, trap_only, _, trap_only_tail] =
        compare_mode_with_internal("sigreturn", &["seccomp 15"]).await;
    for run in [&trap_only, &trap_only_tail] {
        assert_patched(run, SiteState::Retired(RetiredReason::AllowClass));
        assert!(
            run.lifecycle
                .iter()
                .any(|entry| entry.starts_with("allow-class site=") && entry.ends_with(" nr=15")),
            "{:#?}",
            run.lifecycle
        );
    }
    eprintln!("T4c ptrace report:\n{}", ptrace.report);
    assert_report_has(
        &ptrace,
        &[
            "sigreturn 0: sig=10 code=-6 value=-1 ",
            "after sigreturn usr1-blocked=0 usr2-blocked=1",
            "getpid after sigreturn pid=1 rcx=tp_site_end r11=0x246",
            "after sigreturn site bytes 0f 05",
            "sigreturn again 0: sig=10 code=-6 value=-1 ",
        ],
    );
}

/// H4 with rt_sigreturn to a frame whose saved rip is the slot's own return
/// address (`SLOT_RET`, which the private page maps under plain ptrace too):
/// the frame's registers win, so the guest executes the `ud2` there and
/// takes SIGILL as under ptrace, instead of H4 mistaking the frame's rip for
/// the hop's return and rewriting it to the site.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_rt_sigreturn_to_the_slot_return_keeps_the_frame() {
    let [ptrace, trap_only, _, trap_only_tail] =
        compare_mode_with_internal("sigreturn_slot_ret", &["seccomp 15"]).await;
    for run in [&trap_only, &trap_only_tail] {
        assert_patched(run, SiteState::Retired(RetiredReason::AllowClass));
    }
    eprintln!("slot-ret ptrace report:\n{}", ptrace.report);
    assert_report_has(
        &ptrace,
        &[
            "slot-ret SIGILL addr-is-slot-ret=1 rip-is-slot-ret=1",
            "slot-ret getpid after pid=1",
            "slot-ret after site bytes 0f 05",
        ],
    );
}

/// rt_sigreturn through a warmed generic site with rsp at an unmapped page:
/// the tracer cannot read the frame (`sigreturn_frame_rip` is `None`), the
/// kernel returns 0 at the slot's return, which H4 rewrites to S+2, and the
/// forced SIGSEGV is delivered there, as under ptrace.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_rt_sigreturn_with_an_unreadable_frame() {
    let [ptrace, trap_only, _, trap_only_tail] =
        compare_mode_with_internal("sigreturn_bad_frame", &["seccomp 15"]).await;
    for run in [&trap_only, &trap_only_tail] {
        assert!(
            run.lifecycle
                .iter()
                .any(|entry| entry.starts_with("allow-class site=") && entry.ends_with(" nr=15")),
            "{:#?}",
            run.lifecycle
        );
    }
    eprintln!("bad-frame ptrace report:\n{}", ptrace.report);
    assert_report_has(
        &ptrace,
        &[
            "bad-frame SIGSEGV code=128 rip-next=1 rax=0 bytes after 0f 05",
            "bad-frame getpid after=1",
        ],
    );
}

/// rt_sigreturn through a warmed generic site at a frame on a PROT_NONE page
/// whose saved rip is SLOT_RET and whose saved rsp is the frame's own rsp.
/// The kernel's user copies fail, so it loads no register, returns 0 at the
/// slot's return and forces SIGSEGV; H4 must rewrite rip to S+2, as under
/// ptrace. A frame read through `/proc/<tid>/mem` (FOLL_FORCE) sees rip and
/// rsp both matching and keeps rip at SLOT_RET, where the guest takes the
/// SIGSEGV instead.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_rt_sigreturn_from_a_prot_none_frame_naming_the_slot_return() {
    let [ptrace, trap_only, _, trap_only_tail] =
        compare_mode_with_internal("sigreturn_prot_none_frame", &["seccomp 15"]).await;
    for run in [&trap_only, &trap_only_tail] {
        assert!(
            run.lifecycle
                .iter()
                .any(|entry| entry.starts_with("allow-class site=") && entry.ends_with(" nr=15")),
            "{:#?}",
            run.lifecycle
        );
    }
    eprintln!("prot-none-frame ptrace report:\n{}", ptrace.report);
    assert_report_has(
        &ptrace,
        &[
            "prot-none-frame SIGSEGV code=128 rip-next=1 rip-is-slot-ret=0 rax=0 bytes after 0f 05",
            "prot-none-frame getpid after=1",
        ],
    );
}

/// x86_64 335 (uretprobe) and 336 (uprobe) through a warmed generic site.
/// Seccomp passes both through without running the filter (upstream design),
/// so the slot's syscall would produce no TAG_SLOT stop. Plain ptrace runs
/// them (SIGILL for 335, -ENXIO for 336); trap-only fails closed at H0 with
/// `TrapOnlySeccompBypassingNumber`, by number, before any hop or Tool
/// dispatch, whether or not the syscalls crate knows the number.
///
/// Known divergence: on a kernel without these syscalls plain ptrace returns
/// -ENOSYS to the guest while trap-only still refuses the run. The refusal is
/// kept on purpose (trap-only does not probe the kernel for them), so this
/// test accepts either plain-ptrace outcome but always requires the refusal;
/// making trap-only return -ENOSYS there is a tracked follow-up.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_seccomp_bypassing_probe_numbers_fail_closed() {
    for (mode, nr, probe_line) in [
        ("probe_uretprobe", 335, "probe nr=335 SIGILL code=128"),
        ("probe_uprobe", 336, "probe nr=336 ret=-6"),
    ] {
        let ptrace = run_p2(mode, None, false).await;
        eprintln!("{mode} ptrace report:\n{}", ptrace.report);
        let enosys = format!("probe nr={nr} ret=-38");
        if ptrace.report.lines().any(|line| line == enosys) {
            eprintln!("{mode}: this kernel lacks syscall {nr}; trap-only refuses it anyway");
        } else {
            assert_report_has(&ptrace, &[probe_line]);
        }
        let error = run_p2_with(mode, Some(SitePatching::On), false, false)
            .await
            .expect_err("a seccomp-bypassing number at a patched site must end the run");
        let text = format!("{error:#} {error:?}");
        assert!(
            text.contains("TrapOnlySeccompBypassingNumber: site 0x"),
            "{mode}: {text}"
        );
        assert!(
            text.contains(&format!(
                " carries syscall {nr}, which seccomp does not filter"
            )),
            "{mode}: {text}"
        );
    }
}

/// The guest's own seccomp filter returns `SECCOMP_RET_TRACE` for number 500,
/// which the syscall table does not know (the tracer's filter does not trace
/// it). The seccomp stop's number cannot be decoded: `get_syscall` used to
/// panic in `Sysno::from` here on every backend, the default one included,
/// and now ends the run with an ENOSYS error. Both backends end it the same
/// way. Returning -ENOSYS to the guest instead is a tracked follow-up.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_guest_trace_of_an_unknown_number_ends_the_run() {
    for patching in [None, Some(SitePatching::On)] {
        let error = run_p2_with("guest_trace_unknown", patching, false, false)
            .await
            .expect_err("an undecodable seccomp stop must end the run");
        let text = format!("{error:#} {error:?}");
        eprintln!("{patching:?}: {text}");
        assert!(
            text.contains("read registers at seccomp stop"),
            "{patching:?}: {text}"
        );
        assert!(text.contains("ENOSYS"), "{patching:?}: {text}");
    }
}

/// The trap-only lifecycle decisions that start with `prefix`.
fn lifecycle_with<'a>(run: &'a P2Run, prefix: &str) -> Vec<&'a str> {
    run.lifecycle
        .iter()
        .filter(|decision| decision.starts_with(prefix))
        .map(String::as_str)
        .collect()
}

/// Runs `mode` like `compare_mode`, and also requires both trap-only runs to
/// have made exactly the `expected` SIGSTOP deferral decisions, so that the
/// equality is not vacuous.
async fn compare_sigstop_mode(mode: &str, expected: &[&str]) -> [P2Run; 4] {
    let runs = compare_mode(mode).await;
    for run in [&runs[1], &runs[3]] {
        assert_patched(run, SiteState::Live);
        let decisions: Vec<&str> = run
            .lifecycle
            .iter()
            .map(String::as_str)
            .filter(|decision| decision.contains(" SIGSTOP "))
            .collect();
        assert_eq!(decisions, expected, "{mode}: {:#?}", run.lifecycle);
    }
    runs
}

/// The signal-delivery stop of `signal` sent by `sender` with `code`, where
/// the call at the shared site (orig_rax `nr`) returned `rax`.
fn delivery_after_the_call(
    run: &P2Run,
    signal: &str,
    code: i32,
    sender: &str,
    rax: &str,
    nr: i64,
) -> String {
    let number = match signal {
        "SIGSTOP" => libc::SIGSTOP,
        "SIGCONT" => libc::SIGCONT,
        "SIGTSTP" => libc::SIGTSTP,
        "SIGTTIN" => libc::SIGTTIN,
        "SIGTTOU" => libc::SIGTTOU,
        _ => unreachable!("{signal}"),
    };
    format!(
        "{signal} signo={number} code={code} errno=0 pid={sender} uid={} rip={:#x} rax={rax} orig_rax={nr}",
        // SAFETY: getuid cannot fail.
        unsafe { libc::getuid() },
        run.site + 2
    )
}

/// P2d-sigstop, from the tracer: a SIGSTOP the Tool sends to the thread
/// (SI_TKILL) while a patched getpid is parked. Plain ptrace suppresses every
/// SIGSTOP at its delivery stop (`handle_sigstop`), after getpid returned;
/// trap-only's hop dequeues it at the slot, defers it and re-raises it to
/// the thread before getpid runs, so its delivery stop comes at the same
/// place, with the same siginfo, and the runs are equal.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_sigstop_from_the_tracer_is_deferred_past_the_call() {
    let deferral = [
        "slot SIGSTOP deferred code=-6 queue=private",
        "deferred SIGSTOP re-raised queue=private code=-6",
    ];
    let [ptrace, ..] =
        compare_sigstop_mode("sigstop_hop", &[&deferral[..], &deferral[..]].concat()).await;
    assert_report_has(
        &ptrace,
        &[
            "sigstop tail getpid returned pid=1",
            "sigstop inject getpid returned pid=1",
        ],
    );
    let stop = delivery_after_the_call(&ptrace, "SIGSTOP", libc::SI_TKILL, "tracer", "task#0", 39);
    let stops: Vec<&String> = ptrace.signals["task#0"]
        .iter()
        .filter(|signal| signal.starts_with("SIGSTOP "))
        .collect();
    assert_eq!(stops, [&stop, &stop]);
}

/// T1e: the guest's (traced) parent sends SIGSTOP to its child parked at a
/// patched write, then SIGCONT once the write's data and the child's next
/// output arrived. The write lands before the stop takes effect: the SIGSTOP
/// delivery stop is at the site's end with the write's result, carrying the
/// parent's siginfo (SI_USER), under both backends. The parent's
/// waitpid(WUNTRACED | WCONTINUED) statuses and SIGCHLD siginfo, and the
/// child's SIGCONT, equal plain ptrace's; as plain ptrace suppresses the
/// SIGSTOP, the parent never sees the child stopped or continued.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t1e_sigstop_from_the_parent_is_deferred_past_the_write() {
    let deferral = [
        "slot SIGSTOP deferred code=0 queue=shared",
        "deferred SIGSTOP re-raised queue=shared code=0",
    ];
    let [ptrace, ..] =
        compare_sigstop_mode("sigstop_parent", &[&deferral[..], &deferral[..]].concat()).await;
    for tag in ["tail", "inject"] {
        assert_report_has(
            &ptrace,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} child signal 0: sig=18 code=0 from-parent=1 rip=other rax=0"),
                &format!("{tag} parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
    }
    let stop = delivery_after_the_call(&ptrace, "SIGSTOP", libc::SI_USER, "task#0", "4", 1);
    for child in ["task#1", "task#2"] {
        let signals = &ptrace.signals[child];
        assert_eq!(signals.len(), 2, "{signals:#?}");
        assert_eq!(signals[0], stop);
        assert!(
            signals[1].starts_with("SIGCONT signo=18 code=0 errno=0 pid=task#0 "),
            "{signals:#?}"
        );
    }
}

/// A SIGCONT that arrives inside the hop's window (after the SIGSTOP was
/// dequeued at the slot, before the call runs): under plain ptrace it
/// discards the still-pending SIGSTOP, so trap-only drops the deferred one.
/// Neither backend has a SIGSTOP delivery stop; the SIGCONT is delivered
/// after the write.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_sigcont_in_the_window_discards_the_deferred_sigstop() {
    let deferral = [
        "slot SIGSTOP deferred code=0 queue=shared",
        "deferred SIGSTOP x1 discarded by a SIGCONT",
    ];
    let [ptrace, ..] = compare_sigstop_mode(
        "sigstop_cont_window",
        &[&deferral[..], &deferral[..]].concat(),
    )
    .await;
    for tag in ["tail", "inject"] {
        assert_report_has(
            &ptrace,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} child signal 0: sig=18 code=0 from-parent=1 rip=tp_site_end rax=4"),
                &format!("{tag} parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
    }
    let cont = delivery_after_the_call(&ptrace, "SIGCONT", libc::SI_USER, "task#0", "4", 1);
    for child in ["task#1", "task#2"] {
        assert_eq!(ptrace.signals[child], std::slice::from_ref(&cont));
    }
}

/// SIGTSTP with a handler installed is blockable: the hop's mask holds it,
/// whether it arrives at the site's stop or inside the hop, and it is handled
/// after the write returned, never a stop. (A control: it passes without the
/// SIGSTOP deferral too.)
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_sigtstp_with_a_handler_is_handled_after_the_write() {
    let [ptrace, ..] = compare_sigstop_mode("sigtstp_handler", &[]).await;
    for tag in ["tool", "hook"] {
        assert_report_has(
            &ptrace,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} child signal 0: sig=20 code=0 from-parent=1 rip=tp_site_end rax=4"),
                &format!("{tag} parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7"),
            ],
        );
    }
    let tstp = delivery_after_the_call(&ptrace, "SIGTSTP", libc::SI_USER, "task#0", "4", 1);
    for child in ["task#1", "task#2"] {
        assert_eq!(ptrace.signals[child], std::slice::from_ref(&tstp));
    }
}

/// SIGKILL at the site's stop (before the hop), inside the hop, and inside
/// the hop with a deferred SIGSTOP kills the child exactly as under plain
/// ptrace: the write never lands, and the parent sees the same statuses and
/// SIGCHLD.
///
/// Every parked Tool handler and hook stays parked once the kill has taken
/// effect, so the exit wins in both backends (see the Tool's SIGKILL park).
/// So the `entry` case (the parent's SIGKILL at the site's stop) never
/// reaches the hop, and the `hop` and `stop-hop` cases (the parent's SIGKILL
/// at the hop's early hook point) end inside that hook, before the hop reads
/// the pending signals. Only `stop-kill`, where the tracer sends SIGKILL and
/// the hook returns at once, reaches that read, which sees the thread dying
/// and drops the deferred SIGSTOP; the hook's late point then stays parked.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_sigkill_in_the_hop_kills_as_plain_ptrace() {
    let deferred = "slot SIGSTOP deferred code=0 queue=shared";
    let [ptrace, ..] = compare_sigstop_mode(
        "sigkill_hop",
        &[
            deferred,
            deferred,
            "deferred SIGSTOP x1 dropped: the thread is dying",
        ],
    )
    .await;
    for (tag, notified) in [("entry", 1), ("hop", 1), ("stop-hop", 2), ("stop-kill", 1)] {
        assert_report_has(
            &ptrace,
            &[
                &format!(
                    "{tag} parent notified={notified} data=0 after=0 restarted=-1 waitpid signaled:9"
                ),
                &format!("{tag} parent SIGCHLD code=2 status=9 from-child=1"),
            ],
        );
    }
    assert!(!ptrace.report.contains(" child "), "{}", ptrace.report);
}

/// Several SIGSTOPs in one call, into both signal queues, some of them sent
/// while the hop has already deferred others (P2-SPEC O1.4). Under plain
/// ptrace each queue holds one pending SIGSTOP, with the siginfo of the first
/// sent to it, and delivers it after the call: the private one first. The
/// hop defers every SIGSTOP it dequeues (four, then three), with no bound,
/// runs the slot again while one is pending at the slot stop, keeps each
/// queue's first siginfo, and raises one SIGSTOP per queue into that queue.
///
/// `parent-kill`: the tracer's tgkill and the parent's kill at the site's
/// stop, then the tracer's kill and tgkill at the hook's early point; the
/// shared queue must keep the parent's siginfo, not the tracer's.
/// `parent-tgkill`: the parent's tgkill at the site's stop, then the
/// tracer's kill and tgkill; the private queue must keep the parent's.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_several_sigstops_in_one_hop_deliver_one_per_queue() {
    let parent_kill = [
        "slot SIGSTOP deferred code=-6 queue=private",
        "slot SIGSTOP deferred code=0 queue=shared",
        "slot SIGSTOP pending at the slot stop: run the slot again",
        "slot SIGSTOP deferred code=-6 queue=private (coalesced)",
        "slot SIGSTOP deferred code=0 queue=shared (coalesced)",
        "deferred SIGSTOP re-raised queue=private code=-6",
        "deferred SIGSTOP re-raised queue=shared code=0",
    ];
    let parent_tgkill = [
        "slot SIGSTOP deferred code=-6 queue=private",
        "slot SIGSTOP pending at the slot stop: run the slot again",
        "slot SIGSTOP deferred code=-6 queue=private (coalesced)",
        "slot SIGSTOP deferred code=0 queue=shared",
        "deferred SIGSTOP re-raised queue=private code=-6",
        "deferred SIGSTOP re-raised queue=shared code=0",
    ];
    let [ptrace, ..] = compare_sigstop_mode(
        "sigstop_many",
        &[
            &parent_kill[..],
            &parent_kill[..],
            &parent_tgkill[..],
            &parent_tgkill[..],
        ]
        .concat(),
    )
    .await;
    for tag in [
        "parent-kill-tail",
        "parent-kill-inject",
        "parent-tgkill-tail",
        "parent-tgkill-inject",
    ] {
        assert_report_has(
            &ptrace,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!("{tag} parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
    }
    assert!(
        !ptrace.report.contains(" child signal "),
        "{}",
        ptrace.report
    );
    let stop = |code, sender| delivery_after_the_call(&ptrace, "SIGSTOP", code, sender, "4", 1);
    let parent_kill_stops = [
        stop(libc::SI_TKILL, "tracer"),
        stop(libc::SI_USER, "task#0"),
    ];
    let parent_tgkill_stops = [
        stop(libc::SI_TKILL, "task#0"),
        stop(libc::SI_USER, "tracer"),
    ];
    for (child, stops) in [
        ("task#1", &parent_kill_stops),
        ("task#2", &parent_kill_stops),
        ("task#3", &parent_tgkill_stops),
        ("task#4", &parent_tgkill_stops),
    ] {
        assert_eq!(&ptrace.signals[child], stops, "{child}");
    }
}

/// The residual the hop cannot close (P2-SPEC O1.4): a SIGCONT sent after
/// the hop's last read of the pending signals and before it raises the
/// deferred SIGSTOP again. Under plain ptrace the SIGCONT discards the
/// pending SIGSTOP and is delivered after the write, as in
/// `trap_only_p2_sigcont_in_the_window_discards_the_deferred_sigstop`; under
/// trap-only the re-raised SIGSTOP discards the SIGCONT. The Tool loses its
/// SIGCONT event, the guest's SIGCONT handler does not run, and a SIGSTOP
/// delivery stop happens instead. This pins the divergence exactly, so that
/// it cannot grow unnoticed (and so that closing it shows up here).
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_sigcont_after_the_pending_read_is_lost() {
    for tail in [false, true] {
        let ptrace = run_p2("sigstop_cont_late", None, tail).await;
        let trap_only = run_p2("sigstop_cont_late", Some(SitePatching::On), tail).await;
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        assert_eq!(trap_only.status, ptrace.status, "{}", trap_only.report);
        assert_patched(&trap_only, SiteState::Live);
        let deferral = [
            "slot SIGSTOP deferred code=0 queue=shared",
            "deferred SIGSTOP re-raised queue=shared code=0",
        ];
        assert_eq!(
            lifecycle_with(&trap_only, "")
                .into_iter()
                .filter(|decision| decision.contains(" SIGSTOP "))
                .collect::<Vec<_>>(),
            [&deferral[..], &deferral[..]].concat(),
            "{:#?}",
            trap_only.lifecycle
        );
        let cont = delivery_after_the_call(&ptrace, "SIGCONT", libc::SI_USER, "task#0", "4", 1);
        let stop = delivery_after_the_call(&ptrace, "SIGSTOP", libc::SI_USER, "task#0", "4", 1);
        for tag in ["tail", "inject"] {
            let common = [
                format!("{tag} child call ret=4 byte=0"),
                format!("{tag} parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7"),
                format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ];
            let common: Vec<&str> = common.iter().map(String::as_str).collect();
            assert_report_has(&ptrace, &common);
            assert_report_has(&trap_only, &common);
            let handled =
                format!("{tag} child signal 0: sig=18 code=0 from-parent=1 rip=tp_site_end rax=4");
            assert_report_has(&ptrace, &[&handled]);
            assert!(
                !trap_only.report.contains(&format!("{tag} child signal ")),
                "{}",
                trap_only.report
            );
        }
        for child in ["task#1", "task#2"] {
            assert_eq!(ptrace.signals[child], std::slice::from_ref(&cont));
            assert_eq!(trap_only.signals[child], std::slice::from_ref(&stop));
            let sigcont_events = |run: &P2Run| {
                run.tool_events[child]
                    .iter()
                    .filter(|event| event.starts_with("signal SIGCONT "))
                    .count()
            };
            assert_eq!(sigcont_events(&ptrace), 1, "{:#?}", ptrace.tool_events);
            assert_eq!(
                sigcont_events(&trap_only),
                0,
                "{:#?}",
                trap_only.tool_events
            );
        }
    }
}

/// A SIGCONT sent after the hop deferred a SIGSTOP, then a SIGTSTP, SIGTTIN
/// or SIGTTOU (handled), both before the hop reads the pending signals. The
/// stop signal discards the SIGCONT, which had discarded the SIGSTOP: under
/// plain ptrace only the stop signal is delivered, after the write, and
/// there is no SIGSTOP delivery stop and no SIGCONT. The read sees neither
/// the SIGSTOP nor the SIGCONT; raising the SIGSTOP again would add its
/// delivery stop (a signal event the Tool sees, and a restart of a blocking
/// call it interrupts). The hop cannot tell this from a stop signal that
/// followed no SIGCONT, so it fails closed, naming the stop signal.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_sigcont_then_a_stop_signal_fails_closed() {
    for (mode, tag, name, signal) in [
        ("sigstop_cont_tstp", "tstp", "SIGTSTP", libc::SIGTSTP),
        ("sigstop_cont_ttin", "ttin", "SIGTTIN", libc::SIGTTIN),
        ("sigstop_cont_ttou", "ttou", "SIGTTOU", libc::SIGTTOU),
    ] {
        let ptrace = run_p2(mode, None, false).await;
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        assert_report_has(
            &ptrace,
            &[
                &format!("{tag} child call ret=4 byte=0"),
                &format!(
                    "{tag} child signal 0: sig={signal} code=0 from-parent=1 rip=tp_site_end rax=4"
                ),
                &format!("{tag} parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7"),
                &format!("{tag} parent SIGCHLD code=1 status=7 from-child=1"),
            ],
        );
        assert!(
            !ptrace.report.contains(&format!("{tag} child signal 1:")),
            "{}",
            ptrace.report
        );
        let only = delivery_after_the_call(&ptrace, name, libc::SI_USER, "task#0", "4", 1);
        assert_eq!(
            ptrace.signals["task#1"],
            std::slice::from_ref(&only),
            "{mode}"
        );
        for tail in [false, true] {
            let error = run_p2_with(mode, Some(SitePatching::On), tail, false)
                .await
                .expect_err("a deferred SIGSTOP behind a stop signal must end the run");
            let text = format!("{error:#} {error:?}");
            assert!(
                text.contains(&format!(
                    "TrapOnlyHopDeferredStopBehindStopSignal: site {:#x} deferred a SIGSTOP \
                     while signal {signal} was pending",
                    ptrace.site
                )),
                "{mode} tail={tail}: {text}"
            );
        }
    }
}

/// A SIGCONT that discards a SIGSTOP the hop re-raised, followed by a new
/// SIGSTOP (the Tool's rt_tgsigqueueinfo, after an injected write returned
/// and before the thread returns to user mode), shaped like a re-raise
/// (SI_QUEUE) but with another value: the new SIGSTOP's delivery stop keeps
/// its own siginfo (SI_QUEUE from the tracer), as under plain ptrace. The
/// re-raise the SIGCONT discarded is still recorded then; it matches only a
/// delivery stop that carries its own tag.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_a_discarded_reraise_leaves_a_later_sigstop_alone() {
    let [ptrace, trap_only, _, trap_only_tail] = compare_sigstop_mode(
        "sigstop_stale",
        &[
            "slot SIGSTOP deferred code=0 queue=shared",
            "deferred SIGSTOP re-raised queue=shared code=0",
        ],
    )
    .await;
    for run in [&trap_only, &trap_only_tail] {
        assert!(
            run.all_events()
                .iter()
                .any(|event| event.starts_with("syscall write = 4")),
            "{:#?}",
            run.all_events()
        );
    }
    assert_report_has(
        &ptrace,
        &[
            "inject child call ret=4 byte=0",
            "inject parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7",
        ],
    );
    assert!(
        !ptrace.report.contains(" child signal "),
        "{}",
        ptrace.report
    );
    let stop = delivery_after_the_call(&ptrace, "SIGSTOP", libc::SI_QUEUE, "tracer", "4", 1);
    assert_eq!(ptrace.signals["task#1"], std::slice::from_ref(&stop));
}

/// A child with a second thread (which blocks every signal) parked at the
/// shared site, with a SIGSTOP from its parent and a SIGCONT inside the
/// window or after the write: the thread's creation retired every site of
/// the child's address space (the hop reads only the hopping thread's
/// pending signals, which settles a deferred SIGSTOP only for a single
/// thread), so the call runs as under plain ptrace and nothing is deferred.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_a_threaded_child_never_defers_a_sigstop() {
    let runs = compare_mode("sigstop_threaded").await;
    for run in [&runs[1], &runs[3]] {
        assert_patched(run, SiteState::Live);
        assert!(
            !run.lifecycle
                .iter()
                .any(|decision| decision.contains(" SIGSTOP ")),
            "{:#?}",
            run.lifecycle
        );
        // Each child's second thread restored every site of its address
        // space before it was created.
        let created = lifecycle_with(run, "creating clone3 ");
        assert_eq!(created.len(), 2, "{:#?}", run.lifecycle);
        assert!(
            created
                .iter()
                .all(|decision| !decision.ends_with(" restored=0")),
            "{created:#?}"
        );
    }
    let ptrace = &runs[0];
    assert_report_has(
        ptrace,
        &[
            "window child call ret=4 byte=0",
            "window child signal 0: sig=18 code=0 from-parent=1 rip=tp_site_end rax=4",
            "window parent notified=2 data=4 after=5 restarted=-1 waitpid exited:7",
            "late-cont child call ret=4 byte=0",
            "late-cont child signal 0: sig=18 code=0 from-parent=1 rip=other rax=0",
            "late-cont parent notified=1 data=4 after=5 restarted=-1 waitpid exited:7",
        ],
    );
}

/// A SIGSTOP pending when a blocking read starts interrupts it under plain
/// ptrace (ERESTARTSYS at the delivery stop), and the read restarts after
/// the suppressed stop, before any data arrived. This is why the hop
/// re-raises the deferred SIGSTOP before the call runs rather than after it
/// returns: the parent writes the data only once the restarted read reached
/// the Tool (or after 10 s without it).
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_sigstop_interrupts_a_blocking_read_in_the_hop() {
    let deferral = [
        "slot SIGSTOP deferred code=0 queue=shared",
        "deferred SIGSTOP re-raised queue=shared code=0",
    ];
    let [ptrace, ..] = compare_sigstop_mode(
        "sigstop_blocking_read",
        &[&deferral[..], &deferral[..]].concat(),
    )
    .await;
    for tag in ["tail", "inject"] {
        assert_report_has(
            &ptrace,
            &[
                &format!("{tag} child call ret=1 byte=100"),
                &format!("{tag} parent notified=1 data=-1 after=5 restarted=1 waitpid exited:7"),
            ],
        );
    }
    let stop = delivery_after_the_call(&ptrace, "SIGSTOP", libc::SI_USER, "task#0", "-512", 0);
    for child in ["task#1", "task#2"] {
        assert_eq!(ptrace.signals[child], std::slice::from_ref(&stop));
    }
}

/// T4d: a timer single-step that reaches a patched site carrying an allowed
/// number fails closed with `TrapOnlyAllowClassInTimerStep` (plain ptrace
/// steps over the unknown syscall and fires the timer).
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_t4d_timer_step_onto_an_allowed_number_fails_closed() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    let ptrace = run_p2("timer_allow", None, false).await;
    assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
    assert_report_has(&ptrace, &["timer allow ret=-38 errno=38 "]);
    assert_eq!(timer_events(&ptrace).len(), 1, "{:#?}", ptrace.all_events());
    let error = run_p2_with("timer_allow", Some(SitePatching::On), false, false)
        .await
        .expect_err("a timer step onto an allowed number must end the run");
    let text = format!("{error:#} {error:?}");
    assert!(text.contains("TrapOnlyAllowClassInTimerStep"), "{text}");
    assert!(text.contains("allowed syscall 500"), "{text}");
}

/// O4 rule 3 across a counting-phase timer: a precise timer armed at a
/// patched getppid stays armed across a later Allow-class hop (an unknown
/// number through a warmed generic site, and rt_sigreturn through the
/// warmed shared site from a signal handler that armed it), and fires at the
/// same rip, clock and step count as under plain ptrace. The hop's internal
/// stop must not advance the timer's cancellation state, which it did when
/// the run loop ticked the timer before routing the stop.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_timer_survives_an_allow_class_hop() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    // (mode, internal stop, report line, shared-site state, retired number)
    for (mode, internal, line, shared_site, nr) in [
        (
            "timer_hop_unknown",
            "seccomp 500",
            "timer hop unknown ret=-38 getpid=1 bytes after 0f 05",
            SiteState::Live,
            " nr=500",
        ),
        (
            "timer_hop_sigreturn",
            "seccomp 15",
            "timer hop sigreturn getpid=1 bytes after 0f 05",
            SiteState::Retired(RetiredReason::AllowClass),
            " nr=15",
        ),
    ] {
        compare_timer_mode(mode, &[internal], |runs| {
            let [ptrace, trap_only, ptrace_tail, trap_only_tail] = runs;
            for (ptrace, trap_only) in [(ptrace, trap_only), (ptrace_tail, trap_only_tail)] {
                // Not vacuous: plain ptrace fires the timer exactly once, in the
                // branch loop after the hop.
                assert_eq!(
                    timer_events(ptrace).len(),
                    1,
                    "{mode}: {:#?}",
                    ptrace.all_events()
                );
                assert_eq!(
                    timer_events(trap_only),
                    timer_events(ptrace),
                    "{mode}: timer events differ"
                );
                assert_patched(trap_only, shared_site);
                assert!(
                    trap_only
                        .lifecycle
                        .iter()
                        .any(|entry| entry.starts_with("allow-class site=") && entry.ends_with(nr)),
                    "{mode}: {:#?}",
                    trap_only.lifecycle
                );
                assert_report_has(ptrace, &[line]);
            }
        })
        .await;
    }
}

/// The other side of the timer rule: every stop that plain ptrace also
/// reports cancels an armed counting-phase timer under trap-only too, both a
/// live patched site's stop and an ordinary x86_64 stop. Only the last timer,
/// with no stop before its branch loop, fires.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_timer_is_cancelled_by_every_ptrace_visible_stop() {
    if !crate::perf::is_perf_supported() {
        eprintln!("skipping: perf counters are not supported here");
        return;
    }
    compare_timer_mode("timer_cancel", &[], |runs| {
        let [ptrace, trap_only, ptrace_tail, trap_only_tail] = runs;
        for (ptrace, trap_only) in [(ptrace, trap_only), (ptrace_tail, trap_only_tail)] {
            assert_patched(trap_only, SiteState::Live);
            assert_eq!(timer_events(ptrace).len(), 1, "{:#?}", ptrace.all_events());
            assert_eq!(timer_events(trap_only), timer_events(ptrace));
            assert_report_has(ptrace, &["timer cancel site=1 ordinary=1"]);
        }
    })
    .await;
}

/// The hop fails closed with `TrapOnlyHopExitRip` when the slot's syscall
/// leaves any rip other than the slot's return at its exit stop.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_hop_exit_rip_mismatch_fails_closed() {
    let options = P2Options {
        displace_hop_exit_rip: true,
        ..Default::default()
    };
    let error = run_p2_options("sig_pending", Some(SitePatching::On), options)
        .await
        .expect_err("a displaced hop exit rip must end the run");
    let text = format!("{error:#} {error:?}");
    assert!(text.contains("TrapOnlyHopExitRip"), "{text}");
}

/// Unknown and out-of-range syscall numbers through warmed generic sites
/// return -ENOSYS without any Tool event, as under ptrace, and retire their
/// site. A number with high bits set runs as its low 32 bits on both
/// backends; the one difference is the disclosed residual that the Tool (and
/// the stop trace) sees the full orig_rax under ptrace and the low 32 bits
/// under trap-only, because `int 0x80` truncates it.
#[tokio::test(flavor = "current_thread")]
async fn trap_only_p2_unknown_numbers_behave_as_under_ptrace() {
    let internal = [
        "seccomp 500",
        "seccomp 4294967295",
        "seccomp 337",
        "seccomp 500",
    ];
    let high = 0x1_0000_0027u64;
    for tail in [false, true] {
        let ptrace = run_p2("unknown", None, tail).await;
        let trap_only = run_p2("unknown", Some(SitePatching::On), tail).await;
        eprintln!("unknown ptrace report:\n{}", ptrace.report);
        // The residual, exactly: ptrace shows the full number where
        // trap-only shows 39.
        let unmask = |events: &BTreeMap<String, Vec<String>>, from: &str, to: &str| {
            let mut changed = 0;
            let mut events = events.clone();
            for event in events.values_mut().flatten() {
                if event.contains(from) {
                    changed += 1;
                    *event = event.replace(from, to);
                }
            }
            (events, changed)
        };
        let (tool_events, tool_changed) = unmask(
            &ptrace.tool_events,
            &format!("orig_rax={high}"),
            "orig_rax=39",
        );
        let (stops, stops_changed) =
            unmask(&ptrace.stops, &format!("seccomp {high}"), "seccomp 39");
        let (resumes, resumes_changed) =
            unmask(&ptrace.resumes, &format!("orig_rax={high}"), "orig_rax=39");
        assert_eq!(tool_changed, 1, "one Tool entry shows the full number");
        assert_eq!(stops_changed, 1, "one stop shows the full number");
        assert_eq!(resumes_changed, 1, "one resume shows the full number");
        let masked = P2Run {
            tool_events,
            stops,
            resumes,
            ..clone_run(&ptrace)
        };
        assert_equal_runs_with_internal(&trap_only, &masked, &internal);
        assert_eq!(ptrace.status, ExitStatus::Exited(0), "{}", ptrace.report);
        assert_report_has(
            &ptrace,
            &[
                "nr500 ret=-38 rcx-next=1 r11=0x246",
                "nr500 getpid after=1",
                "nr500 bytes after 0f 05",
                "nr-1 ret=-38 rcx-next=1 r11=0x246",
                "nr-1 bytes after 0f 05",
                "gap337 ret=-38 rcx-next=1 r11=0x246",
                "gap337 bytes after 0f 05",
                "high-getpid ret=<pid> rcx-next=1 r11=0x246",
                "high-getpid getpid after=1",
                "high500 ret=-38 rcx-next=1 r11=0x246",
                "high500 bytes after 0f 05",
            ],
        );
        assert!(
            !ptrace
                .all_events()
                .iter()
                .any(|event| event.contains("orig_rax=500") || event.contains("orig_rax=-1")),
            "an unknown number reached the Tool: {:#?}",
            ptrace.all_events()
        );
    }
}

/// The two runs of the T5 fixture (ptrace, trap-only), after checking that
/// they print the same lines and that the only differing lines outside
/// smaps are the two patched bytes read before the guest's mprotect.
async fn text_residual_runs() -> (P2Run, P2Run) {
    let ptrace = run_p2("text_residual", None, false).await;
    let trap_only = run_p2("text_residual", Some(SitePatching::On), false).await;
    eprintln!("T5 ptrace report:\n{}", ptrace.report);
    eprintln!("T5 trap-only report:\n{}", trap_only.report);
    assert_eq!(
        ptrace.report.lines().count(),
        trap_only.report.lines().count()
    );
    let bytes: Vec<(&str, &str)> = ptrace
        .report
        .lines()
        .zip(trap_only.report.lines())
        .filter(|(p, t)| p != t && !p.contains(" smaps "))
        .collect();
    assert_eq!(
        bytes,
        [
            ("before direct 0f 05", "before direct cd 80"),
            ("before procmem 0f 05", "before procmem cd 80"),
        ],
        "the only differing bytes"
    );
    (ptrace, trap_only)
}

/// One smaps field (kB) of the site's mapping, as the T5 fixture printed it
/// under `tag` ("before" or "after" the guest's mprotect).
fn text_residual_smaps(run: &P2Run, tag: &str, name: &str) -> i64 {
    let prefix = format!("{tag} smaps {name}: ");
    run.report
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {prefix:?} in {}", run.report))
        .parse()
        .expect("a kB count")
}

/// Asserts that the site's mapping under trap-only differs from ptrace's by
/// exactly one page moved from clean file-backed memory to anonymous dirty
/// memory (`moved` = 1) or not at all (`moved` = 0). Which of Shared_Clean
/// and Private_Clean the page leaves depends on whether another process maps
/// the fixture, so they are compared as their sum.
fn assert_text_residual_smaps(ptrace: &P2Run, trap_only: &P2Run, tag: &str, moved: i64) {
    let get = |run: &P2Run, name| text_residual_smaps(run, tag, name);
    let clean = |run: &P2Run| get(run, "Shared_Clean") + get(run, "Private_Clean");
    assert_eq!(get(trap_only, "Rss"), get(ptrace, "Rss"), "{tag} Rss");
    assert_eq!(clean(trap_only), clean(ptrace) - 4 * moved, "{tag} clean");
    for name in ["Private_Dirty", "Anonymous"] {
        assert_eq!(
            get(trap_only, name),
            get(ptrace, name) + 4 * moved,
            "{tag} {name}"
        );
    }
    for name in ["Shared_Dirty", "AnonHugePages"] {
        assert_eq!(get(trap_only, name), get(ptrace, name), "{tag} {name}");
    }
}

/// T5 as P2-SPEC states it: the text residual of a patched site is its two
/// bytes (read directly or through /proc/self/mem) and that page's smaps
/// accounting, and after the guest makes the page writable (which restores
/// the bytes) every read equals ptrace's.
///
/// Red at this head, so ignored rather than weakened: the tracer's write
/// COWs the private file page into anonymous memory, and restoring the bytes
/// does not make it a file page again, so the "after" smaps still show the
/// moved page. `traponly_text_residual_o5_smaps_witness` pins the measured
/// residual; closing it (tracer-side smaps virtualization, or a step-free
/// in-guest `MADV_DONTNEED` of the restored page) is the open O5 question.
#[tokio::test(flavor = "current_thread")]
#[ignore = "P2-SPEC O5/T5 open question: the restored page stays anonymous in smaps"]
async fn traponly_text_residual_is_exactly_the_site_bytes() {
    let (ptrace, trap_only) = text_residual_runs().await;
    assert_text_residual_smaps(&ptrace, &trap_only, "before", 1);
    let after: Vec<(&str, &str)> = ptrace
        .report
        .lines()
        .zip(trap_only.report.lines())
        .filter(|(p, t)| p.starts_with("after ") && p != t)
        .collect();
    assert!(
        after.is_empty(),
        "reads after the mprotect differ: {after:?}"
    );
}

/// The measured O5 residual that keeps T5 red, exactly: one page of the
/// site's mapping moves from clean file-backed memory to anonymous dirty
/// memory when the site is patched, and stays moved after the guest's
/// mprotect restores the bytes. Every other read after the mprotect equals
/// ptrace's. When the residual is closed this test fails, and T5 above is
/// un-ignored instead.
#[tokio::test(flavor = "current_thread")]
async fn traponly_text_residual_o5_smaps_witness() {
    let (ptrace, trap_only) = text_residual_runs().await;
    assert_text_residual_smaps(&ptrace, &trap_only, "before", 1);
    assert_text_residual_smaps(&ptrace, &trap_only, "after", 1);
    let after: Vec<(&str, &str)> = ptrace
        .report
        .lines()
        .zip(trap_only.report.lines())
        .filter(|(p, t)| p.starts_with("after ") && !p.contains(" smaps ") && p != t)
        .collect();
    assert!(
        after.is_empty(),
        "non-smaps reads after the mprotect differ: {after:?}"
    );
}
