/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A precise timer event is delivered at its target whether or not GDB's
//! breakpoints are near it.
//!
//! A breakpoint stop makes no Tool callback, so it must leave the timer event
//! as it was, as any stop the Tool does not see does: a scheduled event stays
//! scheduled, and the single steps toward an event that a breakpoint
//! interrupts go on once GDB lets the guest continue. When the breakpoint
//! stop instead decided the event, as a stop the Tool sees does, the event
//! was lost and the guest ran past its target; under Hermit's `--strict`
//! that is a skid overshoot, and the run is refused. GDB always has
//! breakpoints of its own in the dynamic loader, so a strict run whose
//! timer happened to be near one was refused only because GDB was attached.
//!
//! Each test drives Reverie's GDB server over the GDB remote protocol, as
//! GDB does, against a guest built from
//! `fixtures/gdbstub_timer_breakpoints.c`, whose Tool requests a precise
//! event and reports where it is delivered: the guest's clock, its %rip and
//! the loop counter in %rcx.
//!
//! The event's Tool callback, made where GDB's continue lets the guest go
//! on, can wait for another thread, as a Tool that runs one thread at a time
//! does. The breakpoint stop must not hold up a thread that stops at a
//! breakpoint meanwhile.
//!
//! A process gdb does not follow (a fork or vfork child, when gdb did not
//! ask to follow forks) carries gdb's breakpoints too, in its copy of the
//! parent's memory or in the memory it shares with it, and Reverie runs it
//! past them without gdb. Those stops make no Tool callback either.
//!
//! The tests with breakpoints among the single steps need the timer's
//! overflow records, which a kernel that is or may be `PREEMPT_RT` does not
//! get: without them, any stop without a Tool callback that close to the
//! target cancels the event (`Timer::disregard_stop`).

#![cfg(target_arch = "x86_64")]

use std::future::Future;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Duration;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::TracerBuilder;
use reverie_ptrace::ret_without_perf;
use serde::Deserialize;
use serde::Serialize;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Notify;

/// Closer to the request than any processor's skid margin, so the event is
/// driven by single steps from its request on.
const STEPPED_RCBS: u64 = 50;

/// Farther from the request than any processor's skid margin, so a
/// breakpoint right after the request finds the event scheduled, its PMU
/// notification still to come.
const SCHEDULED_RCBS: u64 = 100_000;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
enum Report {
    /// The event was requested at this clock.
    Requested(u64),
    Delivered(Delivery),
    /// From the main thread's timer callback, which then waits for
    /// `OtherPassed`.
    TimerCallbackBegan,
    /// From the second thread, before its breakpoint: waits for
    /// `TimerCallbackBegan`.
    AwaitTimerCallback,
    /// From the second thread, after its breakpoint.
    OtherPassed,
}

/// Where a timer event was delivered.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
struct Delivery {
    clock: u64,
    rip: u64,
    rcx: u64,
}

#[derive(Debug, Default)]
struct Log {
    requested: Mutex<Vec<u64>>,
    delivered: Mutex<Vec<Delivery>>,
    timer_callback_began: Notify,
    other_passed: Notify,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Report;
    type Response = ();
    /// Whether the guest runs its second thread (`Mode::Pair`).
    type Config = bool;

    async fn receive_rpc(&self, _from: Pid, report: Report) {
        match report {
            Report::Requested(clock) => self.requested.lock().unwrap().push(clock),
            Report::Delivered(delivery) => {
                self.delivered.lock().unwrap().push(delivery);
            }
            Report::TimerCallbackBegan => {
                self.timer_callback_began.notify_one();
                self.other_passed.notified().await;
            }
            Report::AwaitTimerCallback => self.timer_callback_began.notified().await,
            Report::OtherPassed => self.other_passed.notify_one(),
        }
    }
}

/// Requests a precise timer event as many conditional branches ahead as the
/// guest's `clock_getres` asks, and reports where it is delivered. With the
/// second thread, the event's callback then waits until that thread has
/// passed its breakpoint.
#[derive(Debug, Default, Clone)]
struct PreciseTimerTool;

#[reverie::tool]
impl Tool for PreciseTimerTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_cfg: &bool) -> Subscription {
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres, Sysno::getppid, Sysno::getpid]);
        s
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        match syscall.number() {
            Sysno::clock_getres => {
                let (_, args) = syscall.into_parts();
                guest.set_timer_precise(TimerSchedule::Rcbs(args.arg0 as u64))?;
                let clock = guest.read_clock()?;
                guest.send_rpc(Report::Requested(clock)).await;
                Ok(0)
            }
            Sysno::getppid => {
                guest.send_rpc(Report::AwaitTimerCallback).await;
                guest.tail_inject(syscall).await
            }
            Sysno::getpid => {
                guest.send_rpc(Report::OtherPassed).await;
                guest.tail_inject(syscall).await
            }
            _ => guest.tail_inject(syscall).await,
        }
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let clock = guest.read_clock().expect("read the guest's clock");
        let regs = guest.regs().await;
        guest
            .send_rpc(Report::Delivered(Delivery {
                clock,
                rip: regs.rip,
                rcx: regs.rcx,
            }))
            .await;
        if *guest.config() {
            guest.send_rpc(Report::TimerCallbackBegan).await;
        }
    }
}

/// The guest and the addresses of its labels.
struct TimerGuest {
    path: PathBuf,
    /// `reverie_bkpt_scheduled`, passed once, right after the request.
    scheduled: u64,
    /// `reverie_timer_loop`, the loop's first instruction.
    loop_start: u64,
    /// `reverie_bkpt_branch`, the loop's `jnz`.
    branch: u64,
    /// `reverie_bkpt_other`, passed once by the second thread.
    other: u64,
}

fn guest() -> &'static TimerGuest {
    static GUEST: LazyLock<TimerGuest> = LazyLock::new(|| {
        // Prefer the run-time CARGO_MANIFEST_DIR, which Cargo and the
        // fbsource BUCK rule set: the compile-time value is a directory on the
        // build host.
        let source = std::env::var_os("CARGO_MANIFEST_DIR")
            .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
            .join("tests/fixtures/gdbstub_timer_breakpoints.c");
        let directory = std::env::current_exe()
            .expect("locate the test binary")
            .parent()
            .expect("the test binary has a directory")
            .to_path_buf();
        let path = directory.join("reverie-gdbstub-timer-breakpoints");
        let staging = directory.join(format!(
            "reverie-gdbstub-timer-breakpoints.{}.tmp",
            std::process::id()
        ));
        let status = std::process::Command::new("cc")
            .args(["-O0", "-g", "-no-pie", "-pthread"])
            .arg(&source)
            .arg("-o")
            .arg(&staging)
            .status()
            .unwrap_or_else(|error| panic!("invoke cc for {}: {error}", source.display()));
        assert!(status.success(), "compile {}", source.display());
        std::fs::rename(&staging, &path)
            .unwrap_or_else(|error| panic!("publish {}: {error}", path.display()));

        let image = std::fs::read(&path).expect("read the guest");
        let elf = goblin::elf::Elf::parse(&image).expect("parse the guest");
        let symbol = |name: &str| {
            elf.syms
                .iter()
                .find(|sym| elf.strtab.get_at(sym.st_name) == Some(name))
                .unwrap_or_else(|| panic!("the guest has no symbol {name}"))
                .st_value
        };
        TimerGuest {
            scheduled: symbol("reverie_bkpt_scheduled"),
            loop_start: symbol("reverie_timer_loop"),
            branch: symbol("reverie_bkpt_branch"),
            other: symbol("reverie_bkpt_other"),
            path,
        }
    });
    &GUEST
}

/// A minimal GDB remote protocol client.
struct Remote {
    stream: UnixStream,
    received: Vec<u8>,
    /// The guest's process ID, from `qC`.
    pid: u32,
    /// The `p<pid>.<tid>` thread ID, from `qC`, in the protocol's hex.
    thread: String,
}

impl Remote {
    /// Connects once the server listens, turns acknowledgements off and asks
    /// for the stopped guest's thread.
    async fn connect(socket: &Path) -> Self {
        let mut attempts = 0;
        let stream = loop {
            match UnixStream::connect(socket).await {
                Ok(stream) => break stream,
                Err(error) => {
                    attempts += 1;
                    assert!(attempts < 3000, "connect to the GDB server: {error}");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        };
        let mut remote = Remote {
            stream,
            received: Vec::new(),
            pid: 0,
            thread: String::new(),
        };
        assert_eq!(remote.request("QStartNoAckMode").await, "OK");
        let current = remote.request("qC").await;
        let thread = current
            .strip_prefix("QC")
            .unwrap_or_else(|| panic!("unexpected qC reply {current:?}"));
        remote.pid = thread
            .strip_prefix('p')
            .and_then(|id| id.split('.').next())
            .and_then(|pid| u32::from_str_radix(pid, 16).ok())
            .unwrap_or_else(|| panic!("unexpected qC reply {current:?}"));
        remote.thread = thread.to_owned();
        remote
    }

    async fn request(&mut self, data: &str) -> String {
        let checksum = data.bytes().fold(0u8, |sum, byte| sum.wrapping_add(byte));
        self.stream
            .write_all(format!("${data}#{checksum:02x}").as_bytes())
            .await
            .expect("send a packet to the GDB server");
        loop {
            // Acknowledgements the server sent before no-ack mode.
            while self.received.first() == Some(&b'+') {
                self.received.remove(0);
            }
            if let Some(hash) = self.received.iter().position(|&byte| byte == b'#')
                && self.received.len() >= hash + 3
            {
                assert_eq!(self.received[0], b'$', "unexpected bytes from the server");
                let reply = String::from_utf8(self.received[1..hash].to_vec())
                    .expect("the GDB server's reply is text");
                self.received.drain(..hash + 3);
                return reply;
            }
            let mut chunk = [0u8; 4096];
            let len = self
                .stream
                .read(&mut chunk)
                .await
                .expect("receive from the GDB server");
            assert!(len > 0, "the GDB server closed the connection");
            self.received.extend_from_slice(&chunk[..len]);
        }
    }

    async fn insert(&mut self, addr: u64) {
        assert_eq!(self.request(&format!("Z0,{addr:x},1")).await, "OK");
    }

    async fn remove(&mut self, addr: u64) {
        assert_eq!(self.request(&format!("z0,{addr:x},1")).await, "OK");
    }

    /// Asks for SIGCHLD to be delivered without a stop, as gdb's default
    /// `handle SIGCHLD nostop noprint pass` does (`QPassSignals`, with gdb's
    /// number for SIGCHLD, 20).
    async fn pass_sigchld(&mut self) {
        assert_eq!(self.request("QPassSignals:14").await, "OK");
    }

    /// Resumes every thread of the guest, as GDB's `continue` does, and
    /// returns the next stop.
    async fn resume(&mut self) -> String {
        let pid = self.pid;
        self.request(&format!("vCont;c:p{pid:x}.-1")).await
    }

    /// GDB's step over the breakpoint at `addr` that `thread` stopped at:
    /// remove it, single-step the thread, and insert it again.
    async fn step_over(&mut self, thread: &str, addr: u64) {
        self.remove(addr).await;
        let stop = self.request(&format!("vCont;s:{thread}")).await;
        assert!(
            stop.starts_with("T05"),
            "the step over did not stop: {stop:?}"
        );
        self.insert(addr).await;
    }

    /// Continues until the guest exits, from every stop at a breakpoint,
    /// which it steps over as GDB does, and from every thread's creation.
    /// Returns the breakpoints the guest stopped at, in order.
    async fn continue_to_exit(&mut self) -> Vec<u64> {
        let mut stops = Vec::new();
        loop {
            let stop = self.resume().await;
            if stop.starts_with('W') {
                assert_exited_zero(&stop);
                return stops;
            }
            if stop.starts_with("T05create:") {
                continue;
            }
            assert!(stop.starts_with("T05swbreak:"), "{stop:?}");
            let addr = stop_rip(&stop);
            self.step_over(stop_thread(&stop), addr).await;
            stops.push(addr);
        }
    }
}

/// The `p<pid>.<tid>` thread a stop reply names.
fn stop_thread(reply: &str) -> &str {
    reply
        .split(';')
        .find_map(|field| field.strip_prefix("thread:"))
        .unwrap_or_else(|| panic!("no thread in the stop reply {reply:?}"))
}

/// The %rip, register 0x10, in a stop reply.
fn stop_rip(reply: &str) -> u64 {
    let hex = reply
        .split(';')
        .find_map(|field| field.strip_prefix("10:"))
        .unwrap_or_else(|| panic!("no %rip in the stop reply {reply:?}"));
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex register value"))
        .collect();
    u64::from_le_bytes(bytes.try_into().expect("an 8-byte %rip"))
}

/// The reply when the guest exits with status 0.
fn assert_exited_zero(reply: &str) {
    assert!(
        reply.starts_with("W00"),
        "expected the guest to exit 0, got {reply:?}"
    );
}

/// The skid overshoot count is process global; each test owns it while it
/// runs.
static OVERSHOOTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Where the guest runs its timed loop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// In the main thread, alone.
    Single,
    /// In the main thread, beside a second thread.
    Pair,
    /// In a fork child.
    Fork,
    /// In a vfork child, which shares the parent's memory.
    Vfork,
}

impl Mode {
    fn arg(self) -> Option<&'static str> {
        match self {
            Mode::Single => None,
            Mode::Pair => Some("pair"),
            Mode::Fork => Some("fork"),
            Mode::Vfork => Some("vfork"),
        }
    }
}

/// Runs the guest, asking for an event `rcbs` branches ahead and looping
/// `iterations` times where `mode` says, under Reverie's GDB server with
/// `client` as GDB, or without a server if `client` is `None`. Returns the
/// Tool's log.
async fn run_guest<F, Fut>(rcbs: u64, iterations: u64, mode: Mode, client: Option<F>) -> Log
where
    F: FnOnce(Remote) -> Fut,
    Fut: Future<Output = ()>,
{
    let pair = mode == Mode::Pair;
    let mut command = Command::new(&guest().path);
    command.arg(rcbs.to_string()).arg(iterations.to_string());
    if let Some(arg) = mode.arg() {
        command.arg(arg);
    }
    let socket = std::env::temp_dir().join(format!(
        "reverie-gdbstub-timer-{rcbs}-{iterations}-{mode:?}-{}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let builder = TracerBuilder::<PreciseTimerTool>::new(command).config(pair);
    let builder = if client.is_some() {
        builder.gdbserver(socket.clone())
    } else {
        builder
    };
    // With its second thread, a thread waits in a Tool callback while the
    // other passes its breakpoint, as under a Tool that runs one thread at
    // a time. The server must then not freeze the waiting thread with
    // SIGSTOP, which it could not take until its callback returned.
    let builder = if pair {
        builder.sequentialized_guest()
    } else {
        builder
    };
    let tracer = async {
        builder
            .spawn()
            .await
            .expect("spawn the guest")
            .wait()
            .await
            .expect("wait for the guest")
    };
    let gdb = async {
        if let Some(client) = client {
            client(Remote::connect(&socket).await).await;
        }
    };
    let ((status, log), ()) = tokio::time::timeout(Duration::from_secs(120), async {
        tokio::join!(tracer, gdb)
    })
    .await
    .expect("the guest and the GDB session finish");
    let _ = std::fs::remove_file(&socket);
    assert_eq!(status, ExitStatus::Exited(0));
    log
}

/// The run without a GDB server.
async fn run_without_gdb(rcbs: u64, iterations: u64, mode: Mode) -> Log {
    run_guest(
        rcbs,
        iterations,
        mode,
        None::<fn(Remote) -> std::future::Ready<()>>,
    )
    .await
}

/// Checks that the one event the guest requested was delivered at its target:
/// `rcbs` branches after the request, right after the loop's `rcbs`-th `jnz`,
/// and that no skid overshoot was recorded.
fn assert_on_target(log: &Log, rcbs: u64, iterations: u64) {
    let requested = log.requested.lock().unwrap().clone();
    let delivered = log.delivered.lock().unwrap().clone();
    assert_eq!(requested.len(), 1, "the guest requests one event");
    assert_eq!(
        delivered,
        [Delivery {
            clock: requested[0] + rcbs,
            rip: guest().loop_start,
            rcx: iterations - rcbs,
        }],
        "the event must be delivered once, right after the loop's {rcbs}-th branch"
    );
    assert_eq!(
        reverie::take_skid_overshoot_count(),
        0,
        "no skid overshoot may be recorded"
    );
}

/// Without GDB, the event lands where `assert_on_target` expects, for both
/// distances the tests use, and in a fork or vfork child.
#[tokio::test]
async fn without_gdb_the_event_is_on_target() {
    ret_without_perf!();
    let _owner = OVERSHOOTS.lock().await;
    let _ = reverie::take_skid_overshoot_count();
    for (rcbs, iterations, mode) in [
        (STEPPED_RCBS, 2 * STEPPED_RCBS, Mode::Single),
        (SCHEDULED_RCBS, 2 * SCHEDULED_RCBS, Mode::Single),
        (STEPPED_RCBS, 2 * STEPPED_RCBS, Mode::Fork),
        (STEPPED_RCBS, 2 * STEPPED_RCBS, Mode::Vfork),
    ] {
        let log = run_without_gdb(rcbs, iterations, mode).await;
        assert_on_target(&log, rcbs, iterations);
    }
}

/// A breakpoint on the loop's branch stops the guest on every iteration,
/// and so between every two single steps toward the event. GDB steps over
/// it each time, and so runs the branch that reaches the target itself.
#[tokio::test]
async fn breakpoints_among_the_timer_steps_leave_the_event_on_target() {
    ret_without_perf!();
    let _owner = OVERSHOOTS.lock().await;
    let _ = reverie::take_skid_overshoot_count();
    let (rcbs, iterations) = (STEPPED_RCBS, 2 * STEPPED_RCBS);
    let branch = guest().branch;
    let log = run_guest(
        rcbs,
        iterations,
        Mode::Single,
        Some(|mut remote: Remote| async move {
            remote.insert(branch).await;
            let stops = remote.continue_to_exit().await;
            assert_eq!(
                stops,
                vec![branch; iterations as usize],
                "one stop per iteration"
            );
        }),
    )
    .await;
    assert_on_target(&log, rcbs, iterations);
}

/// GDB removes the breakpoint the guest stopped at among the single steps
/// and continues without stepping over it, as after `finish`.
#[tokio::test]
async fn a_breakpoint_removed_among_the_timer_steps_leaves_the_event_on_target() {
    ret_without_perf!();
    let _owner = OVERSHOOTS.lock().await;
    let _ = reverie::take_skid_overshoot_count();
    let (rcbs, iterations) = (STEPPED_RCBS, 2 * STEPPED_RCBS);
    let branch = guest().branch;
    let log = run_guest(
        rcbs,
        iterations,
        Mode::Single,
        Some(|mut remote: Remote| async move {
            remote.insert(branch).await;
            let stop = remote.resume().await;
            assert!(stop.starts_with("T05swbreak:"), "{stop:?}");
            remote.remove(branch).await;
            assert_exited_zero(&remote.resume().await);
        }),
    )
    .await;
    assert_on_target(&log, rcbs, iterations);
}

/// A breakpoint right after the request stops the guest while the event is
/// still scheduled, far from its target. The event must stay scheduled.
#[tokio::test]
async fn a_breakpoint_before_a_scheduled_event_leaves_it_on_target() {
    ret_without_perf!();
    let _owner = OVERSHOOTS.lock().await;
    let _ = reverie::take_skid_overshoot_count();
    let (rcbs, iterations) = (SCHEDULED_RCBS, 2 * SCHEDULED_RCBS);
    let scheduled = guest().scheduled;
    let log = run_guest(
        rcbs,
        iterations,
        Mode::Single,
        Some(|mut remote: Remote| async move {
            remote.insert(scheduled).await;
            assert_eq!(remote.continue_to_exit().await, [scheduled]);
        }),
    )
    .await;
    assert_on_target(&log, rcbs, iterations);
}

/// The event's callback waits until a second thread has passed a breakpoint
/// of its own, which that thread reaches only once the callback has begun.
/// The second thread's breakpoint stop must not wait for the first thread's
/// to end.
#[tokio::test]
async fn a_timer_callback_after_a_breakpoint_lets_another_thread_stop_at_one() {
    ret_without_perf!();
    let _owner = OVERSHOOTS.lock().await;
    let _ = reverie::take_skid_overshoot_count();
    let (rcbs, iterations) = (STEPPED_RCBS, 2 * STEPPED_RCBS);
    let TimerGuest { branch, other, .. } = *guest();
    let log = run_guest(
        rcbs,
        iterations,
        Mode::Pair,
        Some(|mut remote: Remote| async move {
            remote.insert(branch).await;
            remote.insert(other).await;
            let stops = remote.continue_to_exit().await;
            assert_eq!(
                stops.iter().filter(|&&stop| stop == branch).count() as u64,
                iterations,
                "one stop per iteration"
            );
            assert_eq!(
                stops.iter().filter(|&&stop| stop == other).count(),
                1,
                "one stop of the second thread"
            );
        }),
    )
    .await;
    assert_on_target(&log, rcbs, iterations);
}

/// A fork child that gdb does not follow stops at gdb's breakpoint, which is
/// in its copy of the parent's memory, among its timer's single steps.
/// Reverie removes the breakpoint from the copy and runs the child on.
#[tokio::test]
async fn a_breakpoint_in_an_unfollowed_fork_child_leaves_its_event_on_target() {
    ret_without_perf!();
    let _owner = OVERSHOOTS.lock().await;
    let _ = reverie::take_skid_overshoot_count();
    let (rcbs, iterations) = (STEPPED_RCBS, 2 * STEPPED_RCBS);
    let branch = guest().branch;
    let log = run_guest(
        rcbs,
        iterations,
        Mode::Fork,
        Some(|mut remote: Remote| async move {
            remote.pass_sigchld().await;
            remote.insert(branch).await;
            let stops = remote.continue_to_exit().await;
            assert!(stops.is_empty(), "gdb follows only the parent: {stops:x?}");
        }),
    )
    .await;
    assert_on_target(&log, rcbs, iterations);
}

/// A vfork child that gdb does not follow shares the parent's memory, and so
/// gdb's breakpoint, which must stay there for the parent. It stops there on
/// every iteration, among its timer's single steps, and Reverie steps it over
/// the breakpoint each time.
#[tokio::test]
async fn a_breakpoint_shared_with_an_unfollowed_vfork_child_leaves_its_event_on_target() {
    ret_without_perf!();
    let _owner = OVERSHOOTS.lock().await;
    let _ = reverie::take_skid_overshoot_count();
    let (rcbs, iterations) = (STEPPED_RCBS, 2 * STEPPED_RCBS);
    let branch = guest().branch;
    let log = run_guest(
        rcbs,
        iterations,
        Mode::Vfork,
        Some(|mut remote: Remote| async move {
            remote.pass_sigchld().await;
            remote.insert(branch).await;
            let stops = remote.continue_to_exit().await;
            assert!(stops.is_empty(), "gdb follows only the parent: {stops:x?}");
        }),
    )
    .await;
    assert_on_target(&log, rcbs, iterations);
}
