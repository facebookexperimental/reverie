/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Timer events end to end: `Guest::set_timer` and
//! `Guest::set_timer_precise` through the production CPL3 SYSCALL transport
//! to `Tool::handle_timer_event`, under the Reverie contract. These tests
//! require KVM and the raw PMU event; unavailable hardware is not a pass.
//! A precise event must land exactly at its target, at the instruction
//! boundary right after the target branch, with the same registers in every
//! run.
//!
//! The guests run a loop of 3 RCBs per iteration far past each target, by at
//! least [`TAIL`] RCBs, so a kick has time to land however late its
//! interrupt comes; the guest's next subscribed syscall would otherwise
//! cancel the request. Every delivery is checked against a ceiling as well as
//! the target: it comes less than [`CEILING`] RCBs after the target. A test
//! that expects no event runs the same tail after the event that should
//! cancel the request, and each has a control without that event.

#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use futures::FutureExt;
use reverie::BackendStatsRequest;
use reverie::BackendStatsSource;
use reverie::CpuIdResult;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::ParkedObservationLease;
use reverie::Pid;
use reverie::ProcessAlarmSignalOutcome;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Signal;
use reverie::SignalEvent;
use reverie::SignalTarget;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::ArchPrctl;
use reverie::syscalls::ArchPrctlCmd;
use reverie::syscalls::Errno;
use reverie::syscalls::Execve;
use reverie::syscalls::ExitGroup;
use reverie::syscalls::Fork;
use reverie::syscalls::Getpid;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie::syscalls::Tgkill;
use reverie_kvm::KvmBackend;
use serde::Deserialize;
use serde::Serialize;

const MEMORY: usize = 16 * 1024 * 1024;

/// RCBs each guest runs past its last target: far beyond the longest kick
/// latency measured on a loaded host (about 320,000 RCBs).
const TAIL: u64 = 30_000_000;

/// How far past its target an event may come: three times that latency, and
/// a thirtieth of [`TAIL`].
const CEILING: u64 = 1_000_000;

/// Checks that `clock` lies in the delivery window of a request for `ticks`
/// RCBs made at clock `requested_at`: at or past its target, and less than
/// [`CEILING`] past it.
fn assert_delivered(clock: u64, requested_at: u64, ticks: u64, context: &str) {
    let target = requested_at + ticks;
    assert!(
        (target..target + CEILING).contains(&clock),
        "{context}: delivered at {clock}, target {target}"
    );
}

/// Runs `test` again in a child process with a time limit, as read_clock.rs
/// does, and checks that the child ran exactly that test. Returns false in
/// the child, which then runs the test body.
fn bounded(test: &str) -> bool {
    bounded_with(test, &[])
}

/// [`bounded`], with `env` set for the child.
fn bounded_with(test: &str, env: &[(&str, &str)]) -> bool {
    if std::env::var_os("REVERIE_KVM_TIMER_TEST_CHILD").is_some() {
        return false;
    }
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "120s"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env("REVERIE_KVM_TIMER_TEST_CHILD", "1")
        .envs(env.iter().copied())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{test}: {}\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

/// A static guest assembled from `body`, as in read_clock.rs, or a guest
/// compiled from C, and the guest memory it runs in.
struct Program {
    directory: PathBuf,
    executable: PathBuf,
    memory: usize,
}

impl Program {
    fn new(body: &str) -> Self {
        Self::build(
            "guest.S",
            &format!(".global _start\n.text\n_start:\n{body}\n"),
            &["-nostdlib", "-static", "-Wl,--build-id=none"],
            MEMORY,
        )
    }

    /// A dynamically linked guest compiled from the C `source` with `flags`,
    /// with room for its loader and libraries.
    fn c(source: &str, flags: &[&str]) -> Self {
        Self::build(
            "guest.c",
            source,
            &[&["-O2"], flags].concat(),
            256 * 1024 * 1024,
        )
    }

    fn build(name: &str, text: &str, flags: &[&str], memory: usize) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "reverie-kvm-timer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let source = directory.join(name);
        let executable = directory.join("guest");
        std::fs::write(&source, text).unwrap();
        let output = std::process::Command::new("timeout")
            .args(["--kill-after=2s", "10s", "/usr/bin/gcc"])
            .args(flags)
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            directory,
            executable,
            memory,
        }
    }

    /// The address of the label `name` in the guest's symbol table. The
    /// guests are static and not position-independent, so it is the address
    /// under both backends and natively.
    fn symbol(&self, name: &str) -> u64 {
        let image = std::fs::read(&self.executable).unwrap();
        let elf = goblin::elf::Elf::parse(&image).unwrap();
        elf.syms
            .iter()
            .find(|symbol| elf.strtab.get_at(symbol.st_name) == Some(name))
            .unwrap_or_else(|| panic!("the guest has no symbol {name}"))
            .st_value
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

/// A loop of at least `rcbs` RCBs, 3 per iteration (see read_clock.rs).
fn branches(rcbs: u64) -> String {
    let iterations = rcbs.div_ceil(3);
    format!(
        "mov ${iterations}, %rcx\n1: xor %eax,%eax\njz 2f\nud2\n2: jnz 3f\n3: dec %rcx\njnz 1b\n"
    )
}

const GETPPID: &str = "mov $110,%eax\nsyscall\n";
const EXIT: &str = "xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n";

/// Where a [`TimerTool`] requests its timer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
enum Arm {
    /// In `handle_thread_start`, before the initial exec.
    ThreadStart,
    /// In `handle_post_exec`: at the start of each image.
    #[default]
    PostExec,
    /// In the callback of the guest's `getppid`, the marker.
    Marker,
    /// In the callback of the guest's `execve`, before it runs.
    Execve,
}

/// An injection that a timer event's callback cannot perform on KVM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Refused {
    Fork,
    Exec,
    /// `tgkill` of SIGUSR1 to the thread itself.
    Signal,
    /// A tail injection other than an exit.
    Tail,
}

/// What a timer event's callback does after it polls a refused injection
/// once and drops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum AfterDropped {
    /// Tail-inject an exit.
    Exit,
    /// Retire the thread.
    Retire,
    /// Poll a getpid injection once, report whether it completed, and return.
    Inject,
}

/// A signal-mask change a timer event's callback injects while SIGUSR1 is
/// blocked and pending. The guest keeps the address of SIGUSR1's mask in
/// r14, with SIGUSR2's mask after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum MaskChange {
    /// Unblock SIGUSR1, which would make it deliverable.
    UnblockPending,
    /// Block SIGUSR2, which makes nothing deliverable.
    BlockAnother,
    /// Unblock SIGUSR1 with a sigset size of 4: `EINVAL`.
    BadSize,
    /// Unblock SIGUSR1 with an invalid `how`: `EINVAL`.
    BadHow,
    /// Unblock the signals of a mask at address 8, which the guest cannot
    /// read: `EFAULT`.
    BadSet,
}

impl MaskChange {
    fn request(self, masks: u64) -> RtSigprocmask {
        let (how, set, size) = match self {
            Self::UnblockPending => (libc::SIG_UNBLOCK, masks, 8),
            Self::BlockAnother => (libc::SIG_BLOCK, masks + 8, 8),
            Self::BadSize => (libc::SIG_UNBLOCK, masks, 4),
            Self::BadHow => (99, masks, 8),
            Self::BadSet => (libc::SIG_UNBLOCK, 8, 8),
        };
        RtSigprocmask::new()
            .with_how(how)
            .with_set(Addr::from_raw(set as usize))
            .with_oldset(None)
            .with_sigsetsize(size)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Plan {
    arm: Arm,
    /// RCB counts requested there, in order: each replaces the one before.
    requests: Vec<u64>,
    /// Requests made again from `handle_timer_event`, for the last count.
    rearm: u32,
    /// Subscribe to RDTSC.
    rdtsc: bool,
    /// Subscribe to CPUID.
    cpuid: bool,
    /// Leave `tgkill` unsubscribed, so that its signal is the only event.
    quiet_tgkill: bool,
    /// Subscribe to no syscall at all.
    no_syscalls: bool,
    /// End the run from the timer event.
    exit_at_event: bool,
    /// Request precise events (`Guest::set_timer_precise`).
    precise: bool,
    /// From the callback of the guest's `getpid`, request this many RCBs.
    rearm_at_getpid: Option<u64>,
    /// From the callback of each of the guest's `getpid`s, request the last
    /// request's target this many RCBs earlier, as a Tool that charges each
    /// syscall against a thread's budget renews its request.
    renew_at_getpid: Option<u64>,
    /// From a signal's callback, request this many RCBs.
    rearm_at_signal: Option<u64>,
    /// Ask for a precise event with an instruction offset, and for 0 RCBs
    /// precisely and imprecisely, after the requests.
    refusals: bool,
    /// Inject this from the timer event, ignore the error, and carry on.
    refused_at_event: Option<Refused>,
    /// Poll that injection once instead, drop it, and do this.
    after_dropped: Option<AfterDropped>,
    /// Inject this from the timer event, report its result, and carry on.
    mask_change: Option<MaskChange>,
    /// Report the registers the timer event sees.
    registers: bool,
    /// At the marker, after the request, queue a process SIGALRM and observe
    /// it while the marker's callback stays parked.
    parked_signal: bool,
    /// At the marker, return ERESTARTSYS from the first attempt of the
    /// callback, after the request; the attempt that follows requests again
    /// only if this is `Some(true)`.
    restart: Option<bool>,
    /// Hold the first timer event's callback until another thread's `tgkill`
    /// has run, and hold that `tgkill` until the callback has begun, as a
    /// Tool that runs one thread at a time would (see [`Gate`]). A `kill`
    /// takes part as a `tgkill` does; the main thread's own sends do not.
    rendezvous: bool,
    /// The sends (`tgkill` or `kill`) of the sending thread that each timer
    /// event's rendezvous waits for, by timer event of the thread it holds:
    /// the first `rendezvous_sends[0]` with its first timer event, the next
    /// `rendezvous_sends[1]` with its second, and so on. Empty means one
    /// rendezvous, with the first timer event, of [`Plan::sends`] sends.
    rendezvous_sends: Vec<u32>,
    /// Deliver every signal, and report the clock at its callback.
    deliver: bool,
    /// Subscribe to `tgkill` alone, and to the marker when the plan arms
    /// there.
    only_tgkill: bool,
    /// From SIGSEGV's callback, send SIGUSR1 to the thread itself.
    self_signal_at_fault: bool,
    /// Report the registers each signal's callback sees.
    signal_registers: bool,
    /// Hold a new thread's start until another thread's `tgkill` has run.
    hold_thread_start: bool,
    /// How many `tgkill`s must have run before [`Gate::Sent`] opens, under
    /// [`Plan::rendezvous`] or [`Plan::hold_thread_start`]: 0 means 1.
    sends: u32,
    /// Take the backend's signal control and grant a delivery permit at every
    /// boundary that has something to select, as a scheduler that runs one
    /// thread at a time does, logging each permit and its receipt.
    permits: bool,
    /// From SIGUSR1's callback, set the first segment base to the address in
    /// r13, and from SIGUSR2's, the second to the address in r14, each with an
    /// injected `arch_prctl`.
    bases_at_signals: Option<[SegmentBase; 2]>,
    /// From the callback of this signal only, request this many RCBs.
    rearm_at: Option<(i32, u64)>,
    /// Signals (a mask with bit `signal - 1`) whose callback suppresses
    /// them, also under [`Plan::deliver`].
    suppress: u64,
    /// Report every thread's exit and its status ([`Event::Exited`]).
    exits: bool,
    /// The first timer event's callback, after any rendezvous, waits until
    /// another thread has exited ([`Gate::Exited`]).
    timer_waits_for_exit: bool,
    /// The callback of this signal opens [`Gate::Hooked`] and then waits
    /// until another thread has exited.
    hook_waits_for_exit: Option<i32>,
    /// The callback of an `exit_group` waits until [`Gate::Hooked`] opens.
    exit_waits_for_hook: bool,
    /// Report the unsupported-operation refusal, if any, that each `kill`
    /// or `tgkill` the Tool injects leaves ([`Event::Refusal`]).
    refusals_of_sends: bool,
}

impl Plan {
    /// How many timer events of the held thread rendezvous.
    fn rendezvous_events(&self) -> u32 {
        if self.rendezvous_sends.is_empty() {
            1
        } else {
            self.rendezvous_sends.len() as u32
        }
    }

    /// The gate that the `send`th rendezvous send of a thread (counted from
    /// 0) belongs to, and how many sends that gate waits for; none past the
    /// last.
    fn send_gate(&self, send: u32) -> Option<(u32, u32)> {
        if self.rendezvous_sends.is_empty() {
            let needed = self.sends.max(1);
            return (send < needed).then_some((0, needed));
        }
        let mut first = 0;
        for (gate, &needed) in self.rendezvous_sends.iter().enumerate() {
            if send < first + needed {
                return Some((gate as u32, needed));
            }
            first += needed;
        }
        None
    }
}

/// A segment base that a signal's callback sets under
/// [`Plan::bases_at_signals`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum SegmentBase {
    Fs,
    Gs,
}

/// The points a [`Plan::rendezvous`] orders, by timer event of the held
/// thread, counted from 0, and the exit [`Plan::timer_waits_for_exit`] and
/// [`Plan::hook_waits_for_exit`] wait for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum Gate {
    /// That timer event's callback has begun.
    Timer(u32),
    /// The sends that timer event's rendezvous waits for have run.
    Sent(u32),
    /// A thread has exited (under [`Plan::exits`]).
    Exited,
    /// The callback of [`Plan::hook_waits_for_exit`]'s signal has begun.
    Hooked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Event {
    Requested {
        clock: u64,
        ticks: u64,
    },
    Refused(String),
    Timer {
        clock: u64,
    },
    Signal(i32),
    /// A signal's callback under [`Plan::deliver`], and the clock there.
    Signalled {
        signal: i32,
        clock: u64,
    },
    /// Opens a gate (not logged).
    Open(Gate),
    /// Waits until a gate is open (not logged).
    Wait(Gate),
    /// One more send of a rendezvous has run; that rendezvous's
    /// [`Gate::Sent`] opens once `needed` have (not logged).
    Sent {
        gate: u32,
        needed: u32,
    },
    /// A thread exited ([`Tool::on_exit_thread`]), with its status in
    /// wait(2) encoding; opens [`Gate::Exited`].
    Exited {
        tid: i32,
        status: i32,
    },
    /// The unsupported-operation refusal a send left, as text.
    Refusal(String),
    /// A delivery permit granted under [`Plan::permits`], by its sequence.
    Permit(u64),
    /// The receipt that settled a permit: its sequence and its outcome.
    Receipt(u64, String),
    Rdtsc,
    Cpuid,
    /// An attempt of the marker's callback.
    Attempt(u32),
    /// The registers a timer event saw.
    Registers(Registers),
    /// The result of an injection from a timer event.
    Injected(String),
}

/// The user registers a timer event's callback sees (`Guest::regs`), and the
/// thread's pid as the Tool sees it (`Guest::pid`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Registers {
    pid: u64,
    rip: u64,
    rax: u64,
    orig_rax: u64,
    rcx: u64,
    r11: u64,
    eflags: u64,
    rdi: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
    r9: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    rsp: u64,
    rbx: u64,
    rbp: u64,
    r15: u64,
    cs: u64,
    ss: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
    fs_base: u64,
    gs_base: u64,
}

#[derive(Default)]
struct Log {
    events: Mutex<Vec<Event>>,
    /// Each gate's latch, made when first named.
    latches: Mutex<std::collections::HashMap<Gate, std::sync::Arc<Latch>>>,
    /// The sends [`Event::Sent`] has counted, by rendezvous.
    sends: Mutex<std::collections::HashMap<u32, u32>>,
    /// [`Plan::permits`], and the signal control it takes.
    permits: bool,
    control: Mutex<Option<reverie::BackendSignalControl>>,
    /// The last permit's sequence.
    permit: AtomicU64,
}

/// A gate that opens once and stays open.
#[derive(Default)]
struct Latch(Mutex<(bool, Vec<std::task::Waker>)>);

impl Latch {
    fn open(&self) {
        let mut latch = self.0.lock().unwrap();
        latch.0 = true;
        latch.1.drain(..).for_each(std::task::Waker::wake);
    }

    async fn wait(&self) {
        futures::future::poll_fn(|context| {
            let mut latch = self.0.lock().unwrap();
            if latch.0 {
                return std::task::Poll::Ready(());
            }
            latch.1.push(context.waker().clone());
            std::task::Poll::Pending
        })
        .await
    }
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Config = Plan;
    type Request = Event;
    type Response = ();

    async fn init_global_state(plan: &Plan) -> Self {
        Self {
            permits: plan.permits,
            ..Self::default()
        }
    }

    fn install_backend_signal_control(
        &self,
        control: Option<reverie::BackendSignalControl>,
    ) -> Result<reverie::BackendSignalControlMode, reverie::Error> {
        if !self.permits {
            return Ok(reverie::BackendSignalControlMode::Unchanged);
        }
        *self.control.lock().unwrap() = Some(control.ok_or(Errno::ENOSYS)?);
        Ok(reverie::BackendSignalControlMode::ToolControlled)
    }

    fn skip_empty_signal_boundaries(&self) -> bool {
        self.permits
    }

    fn authorize_backend_signal_boundary(
        &self,
        task: reverie::SignalTaskIdentity,
    ) -> Result<Option<reverie::SignalDeliveryPermit>, reverie::Error> {
        let Some(control) = self.control.lock().unwrap().clone() else {
            return Ok(None);
        };
        let sequence = self.permit.fetch_add(1, Ordering::SeqCst) + 1;
        let permit = reverie::SignalDeliveryPermit {
            task,
            sequence,
            site: None,
        };
        control.process.reserve_delivery(permit)?;
        self.events.lock().unwrap().push(Event::Permit(sequence));
        Ok(Some(permit))
    }

    async fn on_backend_signal_boundary(
        &self,
        receipt: reverie::SignalBoundaryReceipt,
    ) -> Result<(), reverie::Error> {
        let outcome = format!("{:?}", receipt.outcome);
        self.events
            .lock()
            .unwrap()
            .push(Event::Receipt(receipt.permit.sequence, outcome));
        Ok(())
    }

    async fn receive_rpc(&self, _from: Pid, event: Event) {
        match event {
            Event::Open(gate) => self.latch(gate).open(),
            Event::Wait(gate) => {
                let latch = self.latch(gate);
                latch.wait().await
            }
            Event::Sent { gate, needed } => {
                let sent = {
                    let mut sends = self.sends.lock().unwrap();
                    let count = sends.entry(gate).or_default();
                    *count += 1;
                    *count
                };
                if sent >= needed {
                    self.latch(Gate::Sent(gate)).open();
                }
            }
            event @ Event::Exited { .. } => {
                self.events.lock().unwrap().push(event);
                self.latch(Gate::Exited).open();
            }
            event => self.events.lock().unwrap().push(event),
        }
    }
}

impl Log {
    fn latch(&self, gate: Gate) -> std::sync::Arc<Latch> {
        self.latches
            .lock()
            .unwrap()
            .entry(gate)
            .or_default()
            .clone()
    }
}

#[derive(Default)]
struct TimerTool;

/// Each thread's counts of its timer events and of its marker attempts.
#[derive(Default, Serialize, Deserialize)]
struct Counts {
    delivered: u32,
    attempts: u32,
    /// Timer events whose callback has begun.
    timers: u32,
    /// Rendezvous sends (`tgkill` or `kill`) the thread has made.
    sends: u32,
    /// The target of the thread's last request.
    target: u64,
}

/// A process SIGALRM, as the kernel would queue it.
fn alarm(pid: Pid) -> SignalEvent {
    let mut info = [0; reverie::SIGNAL_INFO_SIZE];
    info[..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    info[8..12].copy_from_slice(&libc::SI_KERNEL.to_ne_bytes());
    SignalEvent::new(libc::SIGALRM, info, SignalTarget::Process { pid }).unwrap()
}

/// Injects `refused` from a timer event's callback, which cannot perform it.
async fn inject_refused<G: Guest<TimerTool>>(
    guest: &mut G,
    refused: Refused,
) -> Result<i64, Errno> {
    let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
    match refused {
        Refused::Fork => guest.inject(Fork::new()).await,
        Refused::Exec => guest.inject(Execve::new()).await,
        Refused::Signal => {
            guest
                .inject(
                    Tgkill::new()
                        .with_tgid(pid)
                        .with_tid(tid)
                        .with_sig(libc::SIGUSR1),
                )
                .await
        }
        Refused::Tail => guest.tail_inject(Getpid::new()).await,
    }
}

/// Reports the user registers and the pid a callback sees.
async fn report_registers<G: Guest<TimerTool>>(guest: &mut G) {
    let r = guest.regs().await;
    let registers = Registers {
        pid: guest.pid().as_raw() as u64,
        rip: r.rip,
        rax: r.rax,
        orig_rax: r.orig_rax,
        rcx: r.rcx,
        r11: r.r11,
        eflags: r.eflags,
        rdi: r.rdi,
        rsi: r.rsi,
        rdx: r.rdx,
        r10: r.r10,
        r8: r.r8,
        r9: r.r9,
        r12: r.r12,
        r13: r.r13,
        r14: r.r14,
        rsp: r.rsp,
        rbx: r.rbx,
        rbp: r.rbp,
        r15: r.r15,
        cs: r.cs,
        ss: r.ss,
        ds: r.ds,
        es: r.es,
        fs: r.fs,
        gs: r.gs,
        fs_base: r.fs_base,
        gs_base: r.gs_base,
    };
    guest.send_rpc(Event::Registers(registers)).await;
}

/// Requests a timer event `ticks` RCBs on, precise if the plan says so.
async fn arm<G: Guest<TimerTool>>(guest: &mut G, ticks: u64) {
    let clock = guest.read_clock().unwrap();
    let schedule = TimerSchedule::Rcbs(ticks);
    if guest.config().precise {
        guest.set_timer_precise(schedule).unwrap();
    } else {
        guest.set_timer(schedule).unwrap();
    }
    guest.thread_state_mut().target = clock + ticks;
    guest.send_rpc(Event::Requested { clock, ticks }).await;
}

async fn request<G: Guest<TimerTool>>(guest: &mut G) {
    let plan = guest.config().clone();
    for ticks in plan.requests {
        arm(guest, ticks).await;
    }
    if plan.refusals {
        let schedule = TimerSchedule::RcbsAndInstructions(1_000, 3);
        let refused = match guest.set_timer_precise(schedule) {
            Err(reverie::Error::Io(error)) => format!("{:?}: {error}", error.kind()),
            other => format!("{other:?}"),
        };
        guest.send_rpc(Event::Refused(refused)).await;
        let refused = guest.set_timer_precise(TimerSchedule::Rcbs(0));
        guest.send_rpc(Event::Refused(format!("{refused:?}"))).await;
        let refused = guest.set_timer(TimerSchedule::Rcbs(0));
        guest.send_rpc(Event::Refused(format!("{refused:?}"))).await;
    }
}

#[reverie::tool]
impl Tool for TimerTool {
    type GlobalState = Log;
    type ThreadState = Counts;

    fn may_observe_signal_dequeues(plan: &Plan) -> bool {
        plan.parked_signal
    }

    fn subscriptions(plan: &Plan) -> Subscription {
        if plan.no_syscalls {
            return Subscription::none();
        }
        let mut subscription = Subscription::all_syscalls();
        if plan.rdtsc {
            subscription.rdtsc();
        }
        if plan.cpuid {
            subscription.cpuid();
        }
        if plan.quiet_tgkill {
            subscription.disable_syscall(Sysno::tgkill);
        }
        if plan.only_tgkill {
            subscription = Subscription::none();
            subscription.syscall(Sysno::tgkill);
            if plan.arm == Arm::Marker {
                subscription.syscall(Sysno::getppid);
            }
        }
        subscription
    }

    async fn handle_thread_start<G: Guest<Self>>(
        &self,
        guest: &mut G,
    ) -> Result<(), reverie::Error> {
        if guest.config().arm == Arm::ThreadStart {
            request(guest).await;
        }
        if guest.config().hold_thread_start && guest.tid() != guest.pid() {
            guest.send_rpc(Event::Wait(Gate::Sent(0))).await;
        }
        Ok(())
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        if guest.config().arm == Arm::PostExec {
            request(guest).await;
        }
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, reverie::Error> {
        let plan = guest.config().clone();
        match (plan.arm, syscall.number()) {
            (Arm::Marker, Sysno::getppid) => {
                let attempt = guest.thread_state().attempts;
                guest.thread_state_mut().attempts += 1;
                guest.send_rpc(Event::Attempt(attempt)).await;
                match (plan.restart, attempt) {
                    (Some(_), 0) => {
                        request(guest).await;
                        return Err(Errno::ERESTARTSYS.into());
                    }
                    (Some(false), _) => {}
                    _ => request(guest).await,
                }
                if plan.parked_signal {
                    let site = guest.parked_signal_site().expect("a parked callback site");
                    let pid = guest.pid();
                    let queued = guest.queue_process_alarm_signal(alarm(pid)).await;
                    assert!(
                        matches!(queued, ProcessAlarmSignalOutcome::Accepted(_)),
                        "{queued:?}"
                    );
                    guest
                        .observe_parked_signal(site, ParkedObservationLease { nonce: 1 })
                        .await
                        .unwrap();
                }
            }
            (Arm::Execve, Sysno::execve) => request(guest).await,
            (_, Sysno::tgkill | Sysno::kill)
                if (plan.rendezvous && guest.tid() != guest.pid()) || plan.hold_thread_start =>
            {
                let send = guest.thread_state().sends;
                guest.thread_state_mut().sends += 1;
                let gate = plan.send_gate(send);
                if plan.rendezvous
                    && let Some((gate, _)) = gate
                {
                    guest.send_rpc(Event::Wait(Gate::Timer(gate))).await;
                }
                let sent = guest.inject(syscall).await;
                if plan.refusals_of_sends
                    && let Some(refusal) = guest.take_unsupported_refusal()
                {
                    let refusal = format!("{:?}: {}", refusal.operation, refusal.diagnostic);
                    guest.send_rpc(Event::Refusal(refusal)).await;
                }
                if let Some((gate, needed)) = gate {
                    guest.send_rpc(Event::Sent { gate, needed }).await;
                }
                return Ok(sent?);
            }
            (_, Sysno::getpid) if plan.renew_at_getpid.is_some() => {
                let target = guest.thread_state().target - plan.renew_at_getpid.unwrap();
                let clock = guest.read_clock().unwrap();
                arm(guest, target - clock).await
            }
            (_, Sysno::getpid) if plan.rearm_at_getpid.is_some() => {
                arm(guest, plan.rearm_at_getpid.unwrap()).await
            }
            (_, Sysno::exit_group) if plan.exit_waits_for_hook => {
                guest.send_rpc(Event::Wait(Gate::Hooked)).await;
            }
            _ => {}
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        let plan = guest.config().clone();
        if plan.deliver {
            let clock = guest.read_clock().unwrap();
            let signal = signal as i32;
            guest.send_rpc(Event::Signalled { signal, clock }).await;
        } else {
            guest.send_rpc(Event::Signal(signal as i32)).await;
        }
        if plan.signal_registers {
            report_registers(guest).await;
        }
        if let Some(bases) = plan.bases_at_signals {
            let registers = guest.regs().await;
            let set = match signal {
                Signal::SIGUSR1 => Some((bases[0], registers.r13)),
                Signal::SIGUSR2 => Some((bases[1], registers.r14)),
                _ => None,
            };
            if let Some((base, address)) = set {
                let command = match base {
                    SegmentBase::Fs => ArchPrctlCmd::ARCH_SET_FS(address),
                    SegmentBase::Gs => ArchPrctlCmd::ARCH_SET_GS(address),
                };
                let set = guest.inject(ArchPrctl::new().with_cmd(command)).await;
                assert_eq!(set, Ok(0), "{base:?} {address:#x}");
            }
        }
        if plan.self_signal_at_fault && signal == Signal::SIGSEGV {
            let (pid, tid) = (guest.pid().as_raw(), guest.tid().as_raw());
            let sent = Tgkill::new()
                .with_tgid(pid)
                .with_tid(tid)
                .with_sig(libc::SIGUSR1);
            assert_eq!(guest.inject(sent).await, Ok(0));
        }
        if let Some(ticks) = plan.rearm_at_signal {
            arm(guest, ticks).await;
        }
        if let Some((at, ticks)) = plan.rearm_at
            && at == signal as i32
        {
            arm(guest, ticks).await;
        }
        if plan.hook_waits_for_exit == Some(signal as i32) {
            guest.send_rpc(Event::Open(Gate::Hooked)).await;
            guest.send_rpc(Event::Wait(Gate::Exited)).await;
        }
        let suppressed = ((signal == Signal::SIGUSR1 || signal == Signal::SIGALRM)
            && !plan.deliver)
            || plan.suppress & bit(signal as i32) != 0;
        Ok((!suppressed).then_some(signal))
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, Errno> {
        guest.send_rpc(Event::Rdtsc).await;
        Ok(RdtscResult::new(request))
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        eax: u32,
        ecx: u32,
    ) -> Result<CpuIdResult, Errno> {
        guest.send_rpc(Event::Cpuid).await;
        let host = std::arch::x86_64::__cpuid_count(eax, ecx);
        Ok(CpuIdResult {
            eax: host.eax,
            ebx: host.ebx,
            ecx: host.ecx,
            edx: host.edx,
        })
    }

    async fn handle_timer_event<G: Guest<Self>>(&self, guest: &mut G) {
        let clock = guest.read_clock().unwrap();
        guest.send_rpc(Event::Timer { clock }).await;
        let plan = guest.config().clone();
        let index = guest.thread_state().timers;
        guest.thread_state_mut().timers += 1;
        if plan.registers {
            report_registers(guest).await;
        }
        if plan.rendezvous && index < plan.rendezvous_events() {
            guest.send_rpc(Event::Open(Gate::Timer(index))).await;
            guest.send_rpc(Event::Wait(Gate::Sent(index))).await;
        }
        if plan.timer_waits_for_exit && index == 0 {
            guest.send_rpc(Event::Wait(Gate::Exited)).await;
        }
        if let Some(change) = plan.mask_change {
            let masks = guest.regs().await.r14;
            let result = guest.inject(change.request(masks)).await;
            guest.send_rpc(Event::Injected(format!("{result:?}"))).await;
            return;
        }
        if let Some(refused) = plan.refused_at_event {
            let Some(after) = plan.after_dropped else {
                // Each of these ends the run; a Tool that ignores the error,
                // as this one does, cannot carry on as if the syscall had
                // failed.
                let _ignored = inject_refused(guest, refused).await;
                return;
            };
            // Polled once and dropped, the refused injection still ends the
            // run, and what the callback does next neither replaces that
            // outcome nor reaches the guest.
            let _dropped = inject_refused(guest, refused).now_or_never();
            match after {
                AfterDropped::Exit => guest.tail_inject(ExitGroup::new().with_status(0)).await,
                AfterDropped::Retire => guest.retire_current_thread().await,
                AfterDropped::Inject => {
                    let later = guest.inject(Getpid::new()).now_or_never();
                    guest.send_rpc(Event::Injected(format!("{later:?}"))).await;
                }
            }
            return;
        }
        let counts = guest.thread_state_mut();
        counts.delivered += 1;
        if counts.delivered <= plan.rearm {
            let ticks = *plan.requests.last().unwrap();
            guest.set_timer(TimerSchedule::Rcbs(ticks)).unwrap();
            guest.send_rpc(Event::Requested { clock, ticks }).await;
            // A syscall the Tool injects is not an event: the request stays.
            assert!(guest.inject(Getpid::new()).await.unwrap() > 0);
        } else if plan.exit_at_event {
            guest.tail_inject(ExitGroup::new().with_status(0)).await
        }
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        tid: Pid,
        global_state: &G,
        _counts: Counts,
        status: ExitStatus,
    ) -> Result<(), reverie::Error> {
        if global_state.config().exits {
            let (tid, status) = (tid.as_raw(), status.into_raw());
            global_state.send_rpc(Event::Exited { tid, status }).await;
        }
        Ok(())
    }
}

/// How a run ended: the guest's exit code, stdout and stderr, or the run's
/// failure, as text.
type Ending = Result<(i32, Vec<u8>, Vec<u8>), String>;

/// Runs `program` under a [`TimerTool`] following `plan`, and returns the
/// Tool's events and how the run ended. The image is installed from its file,
/// which `/proc/self/exe` names.
/// The entries set up within a precise request's stepping window in the
/// last [`run_ending`] (`KvmBackendStats::timer_window_entries`): none means
/// that no step, run to a breakpoint or unstepped entry toward a precise
/// target began in that run.
static WINDOW_ENTRIES: AtomicU64 = AtomicU64::new(0);

fn run_ending(program: &Program, plan: Plan) -> (Vec<Event>, Ending) {
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend.set_backend_stats_request(BackendStatsRequest::ENABLED);
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<TimerTool>(plan, true),
    )
    .unwrap();
    let events = completion.global_state.events.into_inner().unwrap();
    WINDOW_ENTRIES.store(
        backend.backend_stats().timer_window_entries(),
        Ordering::Relaxed,
    );
    let ending = completion
        .result
        .map(|(status, out, err)| {
            let code = status
                .code()
                .unwrap_or_else(|| 128 + status.signal().expect("a signaled status"));
            (code, out, err)
        })
        .map_err(|error| error.to_string());
    (events, ending)
}

/// Runs `program` under a [`TimerTool`] following `plan`, checks that it
/// exits with status 0 and no output, and returns the Tool's events.
fn run(program: &Program, plan: Plan) -> Vec<Event> {
    let (events, ending) = run_ending(program, plan);
    assert_eq!(ending, Ok((0, vec![], vec![])), "{events:?}");
    events
}

fn timer_clocks(events: &[Event]) -> Vec<u64> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Timer { clock } => Some(*clock),
            _ => None,
        })
        .collect()
}

/// The clock at which the last request before the first timer event (or
/// the last request at all) was made, and its count.
fn last_request(events: &[Event]) -> (u64, u64) {
    let before_timer = events
        .iter()
        .take_while(|event| !matches!(event, Event::Timer { .. }));
    before_timer
        .filter_map(|event| match event {
            Event::Requested { clock, ticks } => Some((*clock, *ticks)),
            _ => None,
        })
        .last()
        .expect("a request was made")
}

fn skid_margin() -> u64 {
    reverie::pmu_config::try_get_pmu_config()
        .expect("the preemption timer requires this CPU's PMU profile")
        .skid_margin()
}

#[test]
fn a_timer_event_arrives_once_at_or_after_its_target() {
    if bounded("a_timer_event_arrives_once_at_or_after_its_target") {
        return;
    }
    let lead = 1_000;
    for ticks in [1, 2, 5, skid_margin(), 1_000_000, 100_000_000] {
        // Requested where the image starts, and in the callback of a syscall.
        let at_start = Program::new(&(branches(ticks + TAIL) + EXIT));
        let at_marker = Program::new(&(branches(lead) + GETPPID + &branches(ticks + TAIL) + EXIT));
        for (arm, program) in [(Arm::PostExec, &at_start), (Arm::Marker, &at_marker)] {
            let events = run(
                program,
                Plan {
                    arm,
                    requests: vec![ticks],
                    ..Plan::default()
                },
            );
            let (requested_at, _) = last_request(&events);
            let clocks = timer_clocks(&events);
            assert_eq!(clocks.len(), 1, "{arm:?} {ticks}: {events:?}");
            assert_delivered(
                clocks[0],
                requested_at,
                ticks,
                &format!("{arm:?} {ticks}: {events:?}"),
            );
            println!(
                "{arm:?}: requested {ticks} RCBs at {requested_at}, delivered at {}",
                clocks[0]
            );
        }
    }
}

#[test]
fn a_timer_event_reaches_a_guest_that_never_exits() {
    if bounded("a_timer_event_reaches_a_guest_that_never_exits") {
        return;
    }
    // One taken JZ per iteration, forever: no syscall, no fault.
    let program = Program::new("1: xor %eax,%eax\njz 1b\nud2\n");
    let events = run(
        &program,
        Plan {
            requests: vec![1_000_000],
            exit_at_event: true,
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    assert_delivered(clocks[0], 0, 1_000_000, &format!("{events:?}"));
}

#[test]
fn a_new_request_replaces_the_outstanding_one() {
    if bounded("a_new_request_replaces_the_outstanding_one") {
        return;
    }
    let program = Program::new(&(branches(100_000_000 + TAIL) + EXIT));
    for requests in [
        // A nearer request replaces a farther one, which then never fires.
        vec![100_000_000, 1_000_000],
        // A farther one replaces a nearer one, which then never fires.
        vec![1_000_000, 30_000_000],
    ] {
        let events = run(
            &program,
            Plan {
                requests: requests.clone(),
                ..Plan::default()
            },
        );
        let clocks = timer_clocks(&events);
        assert_eq!(clocks.len(), 1, "{requests:?}: {events:?}");
        let (requested_at, ticks) = last_request(&events);
        assert_eq!(ticks, requests[1]);
        assert_delivered(
            clocks[0],
            requested_at,
            ticks,
            &format!("{requests:?}: {events:?}"),
        );
    }
}

#[test]
fn another_event_cancels_an_outstanding_request() {
    if bounded("another_event_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    // getpid and gettid (kept in r12 and r13), then the marker, where the
    // request is made, then the event under test, then the tail.
    let program = |event: &str| {
        Program::new(
            &("mov $39,%eax\nsyscall\nmov %rax,%r12\nmov $186,%eax\nsyscall\nmov %rax,%r13\n"
                .to_owned()
                + &branches(1_000)
                + GETPPID
                + event
                + &branches(ticks + TAIL)
                + EXIT),
        )
    };
    let tgkill = "mov %r12,%rdi\nmov %r13,%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n";
    let plan = |rdtsc, cpuid, quiet_tgkill| Plan {
        arm: Arm::Marker,
        requests: vec![ticks],
        rdtsc,
        cpuid,
        quiet_tgkill,
        ..Plan::default()
    };
    for (name, event, plan, witness) in [
        (
            "a subscribed syscall",
            "mov $39,%eax\nsyscall\n",
            plan(false, false, false),
            None,
        ),
        (
            "a signal",
            tgkill,
            plan(false, false, true),
            Some(Event::Signal(libc::SIGUSR1)),
        ),
        (
            "RDTSC",
            "rdtsc\n",
            plan(true, false, false),
            Some(Event::Rdtsc),
        ),
        (
            "CPUID",
            "xor %eax,%eax\nxor %ecx,%ecx\ncpuid\n",
            plan(false, true, false),
            Some(Event::Cpuid),
        ),
    ] {
        let events = run(&program(event), plan.clone());
        assert_eq!(timer_clocks(&events), [0; 0], "{name}: {events:?}");
        if let Some(witness) = witness {
            assert!(events.contains(&witness), "{name}: {events:?}");
        }
        // The control: without the event, the request fires.
        let events = run(&program(""), plan);
        let clocks = timer_clocks(&events);
        assert_eq!(clocks.len(), 1, "{name} control: {events:?}");
        let (requested_at, _) = last_request(&events);
        assert_delivered(
            clocks[0],
            requested_at,
            ticks,
            &format!("{name}: {events:?}"),
        );
    }
}

#[test]
fn an_exec_cancels_an_outstanding_request() {
    if bounded("an_exec_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    // The first image executes itself with two arguments; the second, seeing
    // them, runs the tail.
    let program = Program::new(&format!(
        "cmpq $2, (%rsp)\nje after_exec\nlea self_path(%rip), %rdi\nlea arguments(%rip), %rsi\n\
         lea environment(%rip), %rdx\nmov $59, %eax\nsyscall\nneg %eax\nmov %eax, %edi\n\
         mov $231, %eax\nsyscall\nud2\nafter_exec:\n{}{EXIT}\
         .data\nself_path: .asciz \"/proc/self/exe\"\nfirst: .asciz \"timer\"\n\
         second: .asciz \"again\"\n.balign 8\narguments: .quad first, second, 0\n\
         environment: .quad 0\n",
        branches(ticks + TAIL)
    ));
    // Requested in the execve callback: the exec cancels it.
    let events = run(
        &program,
        Plan {
            arm: Arm::Execve,
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    assert_eq!(last_request(&events).1, ticks, "{events:?}");
    // Requested at thread start, before the initial exec, which cancels it.
    let tail = Program::new(&(branches(ticks + TAIL) + EXIT));
    let events = run(
        &tail,
        Plan {
            arm: Arm::ThreadStart,
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: requested at the start of each image, it fires in the
    // second (the execve's syscall event cancels the first image's request).
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

#[test]
fn a_timer_event_can_request_the_next_one() {
    if bounded("a_timer_event_can_request_the_next_one") {
        return;
    }
    let ticks = 1_000_000;
    let rearm = 4;
    let program = Program::new(&(branches(u64::from(rearm + 1) * (ticks + TAIL)) + EXIT));
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            rearm,
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), rearm as usize + 1, "{events:?}");
    assert_delivered(clocks[0], 0, ticks, &format!("{events:?}"));
    for pair in clocks.windows(2) {
        assert_delivered(pair[1], pair[0], ticks, &format!("{events:?}"));
    }
}

#[test]
fn instruction_offsets_and_zero_counts_are_refused() {
    if bounded("instruction_offsets_and_zero_counts_are_refused") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(ticks + TAIL) + EXIT));
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            refusals: true,
            ..Plan::default()
        },
    );
    let refusals: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Refused(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(refusals.len(), 3, "{events:?}");
    assert!(
        refusals[0].starts_with("Unsupported: ")
            && refusals[0].contains("TimerSchedule::RcbsAndInstructions"),
        "{events:?}"
    );
    assert_eq!(refusals[1..], ["Err(Errno(EINVAL))"; 2], "{events:?}");
    // Neither refusal disturbed the outstanding request.
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    assert_delivered(clocks[0], 0, ticks, &format!("{events:?}"));
}

#[test]
fn a_timer_event_reaches_a_guest_making_syscalls_the_tool_does_not_see() {
    if bounded("a_timer_event_reaches_a_guest_making_syscalls_the_tool_does_not_see") {
        return;
    }
    // A Tool that subscribes to no syscall, and a guest that makes 50,000
    // getpid calls, 4 RCBs apart, then the tail. The i-th call's exit is at
    // clock 4i + 3, so the first at or past the target of 100,000 is at
    // 100,003. A kick lands about 100 RCBs after its overflow, after that
    // call has left user mode (to land before it, it would have to come
    // within 3 RCBs), so the request comes due at that exit and is delivered
    // at that syscall's return. Left for a kick that finds the guest in user
    // mode instead, it would wait for a rare early kick or for the last call.
    //
    // Before the loop, the guest keeps getpid's result in r13, its stack
    // pointer in r12 and the address after the loop's syscall in r14, and
    // puts known values in the six argument registers, which the calls leave
    // as they are.
    let ticks = 100_000;
    let calls = 50_000;
    let due_exit = ticks + 3;
    let program = Program::new(&format!(
        "mov $39,%eax\nsyscall\nmov %rax,%r13\nmov %rsp,%r12\nlea 7f(%rip),%r14\n\
         mov $0x1111,%edi\nmov $0x2222,%esi\nmov $0x3333,%edx\n\
         mov $0x4444,%r10d\nmov $0x5555,%r8d\nmov $0x6666,%r9d\n\
         mov ${calls}, %r15\n4: mov $3, %rbx\n5: dec %rbx\njnz 5b\n\
         mov $39,%eax\nsyscall\n7: dec %r15\njnz 4b\n{}{EXIT}",
        branches(TAIL)
    ));
    let events = run(
        &program,
        Plan {
            requests: vec![ticks],
            no_syscalls: true,
            registers: true,
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    assert_eq!(
        clocks[0], due_exit,
        "target {ticks}, due at the exit at {due_exit}: {events:?}"
    );
    // The callback sees the registers the guest resumes with at that
    // syscall's return: rip at the instruction after the syscall, which is
    // where SYSCALL left rcx, r11 holding the flags SYSCALL saved, rax the
    // call's result, and the arguments and the stack pointer as the guest
    // left them. orig_rax reads -1.
    let r = events
        .iter()
        .find_map(|event| match event {
            Event::Registers(registers) => Some(registers),
            _ => None,
        })
        .expect("the timer event reported its registers");
    assert_ne!(r.pid, 0, "{r:#x?}");
    assert_eq!(r.r13, r.pid, "getpid's result before the loop: {r:#x?}");
    assert_eq!((r.rip, r.rcx), (r.r14, r.r14), "rip and rcx: {r:#x?}");
    assert_eq!(r.rax, r.pid, "rax, getpid's result: {r:#x?}");
    assert_eq!(r.r11, r.eflags, "r11, the flags SYSCALL saved: {r:#x?}");
    assert_eq!(
        [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9],
        [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666],
        "argument registers: {r:#x?}"
    );
    assert_eq!(r.rsp, r.r12, "rsp: {r:#x?}");
    assert_eq!(r.orig_rax, u64::MAX, "orig_rax: {r:#x?}");
    println!(
        "requested {ticks} RCBs during {calls} unsubscribed syscalls, delivered at {} with {r:#x?}",
        clocks[0]
    );
}

#[test]
fn a_timer_callback_cannot_inject_a_process_action_a_signal_or_a_tail() {
    if bounded("a_timer_callback_cannot_inject_a_process_action_a_signal_or_a_tail") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(ticks + TAIL) + EXIT));
    for (refused, syscall) in [
        (Refused::Fork, libc::SYS_fork),
        (Refused::Exec, libc::SYS_execve),
        (Refused::Signal, libc::SYS_tgkill),
        (Refused::Tail, libc::SYS_getpid),
    ] {
        let (events, ending) = run_ending(
            &program,
            Plan {
                requests: vec![ticks],
                refused_at_event: Some(refused),
                ..Plan::default()
            },
        );
        assert_eq!(timer_clocks(&events).len(), 1, "{refused:?}: {events:?}");
        // The Tool ignored the error and returned; the run fails anyway, and
        // says why.
        let failure = ending.expect_err("the run must fail");
        assert!(
            failure.contains(&format!(
                "KVM timer-event callback injected syscall {syscall}, which a timer event cannot perform"
            )),
            "{refused:?}: {failure}"
        );
    }
}

#[test]
fn a_refused_timer_injection_ends_the_run_even_when_dropped() {
    if bounded("a_refused_timer_injection_ends_the_run_even_when_dropped") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(ticks + TAIL) + EXIT));
    // A refusal at each of the three places that make one: an injection the
    // backend refuses (fork), one the provider refuses (tgkill of SIGUSR1 to
    // the thread), and a tail injection (getpid). The Tool polls it once,
    // drops it, and then exits, retires, or injects again.
    for (refused, syscall) in [
        (Refused::Fork, libc::SYS_fork),
        (Refused::Signal, libc::SYS_tgkill),
        (Refused::Tail, libc::SYS_getpid),
    ] {
        for after in [
            AfterDropped::Exit,
            AfterDropped::Retire,
            AfterDropped::Inject,
        ] {
            let (events, ending) = run_ending(
                &program,
                Plan {
                    requests: vec![ticks],
                    refused_at_event: Some(refused),
                    after_dropped: Some(after),
                    ..Plan::default()
                },
            );
            let context = format!("{refused:?}, then {after:?}: {events:?}");
            assert_eq!(timer_clocks(&events).len(), 1, "{context}");
            if after == AfterDropped::Inject {
                // The later injection never ran: polled once, it had not
                // completed.
                assert!(
                    events.contains(&Event::Injected("None".to_owned())),
                    "{context}"
                );
            }
            let failure = ending.expect_err(&format!("the run must fail: {context}"));
            assert!(
                failure.contains(&format!(
                    "KVM timer-event callback injected syscall {syscall}, which a timer event cannot perform"
                )),
                "{context}: {failure}"
            );
        }
    }
}

#[test]
fn a_timer_callback_cannot_make_a_pending_signal_deliverable() {
    if bounded("a_timer_callback_cannot_make_a_pending_signal_deliverable") {
        return;
    }
    let ticks = 1_000_000;
    // The guest blocks SIGUSR1 (r14 keeps the address of its mask, SIGUSR2's
    // follows), sends it to itself with a tgkill the Tool does not see, so
    // that it stays pending, then reaches the marker, where the request is
    // made, and the tail. It exits with its signal mask shifted right by 8
    // bits: 2 with SIGUSR1 blocked, 10 with SIGUSR2 blocked as well.
    let program = Program::new(&format!(
        "lea masks(%rip),%r14\n\
         xor %edi,%edi\nmov %r14,%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n\
         mov $39,%eax\nsyscall\nmov %rax,%r12\nmov $186,%eax\nsyscall\nmov %rax,%r13\n\
         mov %r12,%rdi\nmov %r13,%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
         {}{GETPPID}{}\
         xor %edi,%edi\nxor %esi,%esi\nlea 16(%r14),%rdx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n\
         mov 16(%r14),%rdi\nshr $8,%rdi\nmov $60,%eax\nsyscall\nud2\n\
         .data\n.balign 8\nmasks: .quad 0x200, 0x800, 0\n",
        branches(1_000),
        branches(ticks + TAIL)
    ));
    for (change, expected) in [
        // Refused: the run fails, though the Tool ignores the error.
        (MaskChange::UnblockPending, None),
        // The controls run, and return their own results.
        (MaskChange::BlockAnother, Some(("Ok(0)", 10))),
        (MaskChange::BadSize, Some(("Err(EINVAL)", 2))),
        (MaskChange::BadHow, Some(("Err(EINVAL)", 2))),
        (MaskChange::BadSet, Some(("Err(EFAULT)", 2))),
    ] {
        let (events, ending) = run_ending(
            &program,
            Plan {
                arm: Arm::Marker,
                requests: vec![ticks],
                quiet_tgkill: true,
                mask_change: Some(change),
                ..Plan::default()
            },
        );
        let context = format!("{change:?}: {events:?}");
        assert_eq!(timer_clocks(&events).len(), 1, "{context}");
        let injected: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Injected(result) => Some(result.as_str()),
                _ => None,
            })
            .collect();
        match expected {
            None => {
                assert_eq!(injected, [""; 0], "{context}");
                let failure = ending.expect_err(&format!("the run must fail: {context}"));
                assert!(
                    failure.contains(&format!(
                        "KVM timer-event callback injected syscall {}, which a timer event cannot perform",
                        libc::SYS_rt_sigprocmask
                    )),
                    "{context}: {failure}"
                );
            }
            Some((result, code)) => {
                assert_eq!(injected, [result], "{context}");
                assert_eq!(ending, Ok((code, vec![], vec![])), "{context}");
            }
        }
    }
}

#[test]
fn a_parked_signal_cancels_an_outstanding_request() {
    if bounded("a_parked_signal_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(1_000) + GETPPID + &branches(ticks + TAIL) + EXIT));
    // The marker's callback makes the request, then queues a SIGALRM and
    // observes it while parked: the signal's callback cancels the request.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            parked_signal: true,
            ..Plan::default()
        },
    );
    assert!(events.contains(&Event::Signal(libc::SIGALRM)), "{events:?}");
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: without the signal, the request fires.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

#[test]
fn a_fault_signal_cancels_an_outstanding_request() {
    if bounded("a_fault_signal_cancels_an_outstanding_request") {
        return;
    }
    let ticks = 1_000_000;
    // A SIGILL handler that steps over the faulting ud2, installed first;
    // then the marker, where the request is made, then the fault, whose
    // signal's callback cancels the request, then the tail.
    let program = |fault: &str| {
        Program::new(&format!(
            "mov ${}, %edi\nlea action(%rip), %rsi\nxor %edx, %edx\nmov $8, %r10d\nmov $13, %eax\nsyscall\n\
             test %rax, %rax\njnz failed\n{}{GETPPID}{fault}{}{EXIT}\
             failed: mov $1, %edi\nmov $60, %eax\nsyscall\nud2\n\
             handler: addq $2, 168(%rdx)\nret\nrestorer: mov $15, %eax\nsyscall\nud2\n\
             .data\n.balign 8\naction: .quad handler, 0x4000004, restorer, 0\n",
            libc::SIGILL,
            branches(1_000),
            branches(ticks + TAIL)
        ))
    };
    let plan = Plan {
        arm: Arm::Marker,
        requests: vec![ticks],
        ..Plan::default()
    };
    let events = run(&program("ud2\n"), plan.clone());
    assert!(events.contains(&Event::Signal(libc::SIGILL)), "{events:?}");
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: without the fault, the request fires.
    let events = run(&program(""), plan);
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

#[test]
fn a_restarted_callback_cancels_the_request_of_the_attempt_before() {
    if bounded("a_restarted_callback_cancels_the_request_of_the_attempt_before") {
        return;
    }
    let ticks = 1_000_000;
    let program = Program::new(&(branches(1_000) + GETPPID + &branches(ticks + TAIL) + EXIT));
    // The marker's first attempt makes the request and returns ERESTARTSYS,
    // with no signal pending, so the callback runs again at once: that
    // attempt is the syscall's event again, and cancels the request.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            restart: Some(false),
            ..Plan::default()
        },
    );
    assert!(
        events.contains(&Event::Attempt(0)) && events.contains(&Event::Attempt(1)),
        "{events:?}"
    );
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // The control: the second attempt requests again, and that request fires.
    let events = run(
        &program,
        Plan {
            arm: Arm::Marker,
            requests: vec![ticks],
            restart: Some(true),
            ..Plan::default()
        },
    );
    let clocks = timer_clocks(&events);
    assert_eq!(clocks.len(), 1, "{events:?}");
    let (requested_at, _) = last_request(&events);
    assert_delivered(clocks[0], requested_at, ticks, &format!("{events:?}"));
}

/// How many times each precise test runs its guest.
const REPEATS: usize = 20;

/// RCBs a precise test's guest runs past its target: an event delivered
/// late, by a kick, still comes before the guest exits.
const PRECISE_TAIL: u64 = 1_000_000;

/// Exits with bit 8 of r15, where a guest collects the trap flag of the
/// flags images it reads, as its status.
const EXIT_WITH_TRAP_FLAG_SEEN: &str = "mov %r15d,%edi\nshr $8,%edi\nmov $60,%eax\nsyscall\nud2\n";

/// Ten RCBs, with a label `branches` does not use.
const TEN_RCBS: &str = "mov $10,%ecx\n7: dec %ecx\njnz 7b\n";

/// A guest that keeps the addresses of `branches`' labels in r12 (label 1,
/// where a loop's third branch leaves RIP), r13 (label 2, after its first)
/// and r14 (label 3, after its second), runs `before`, which must not use
/// those labels, then a loop of `rcbs` RCBs, then `exit`.
fn labelled(before: &str, rcbs: u64, exit: &str) -> Program {
    Program::new(&format!(
        "lea 1f(%rip),%r12\nlea 2f(%rip),%r13\nlea 3f(%rip),%r14\n{before}{}{exit}",
        branches(rcbs)
    ))
}

/// Where the loop's `branch`-th branch, counted from 1, leaves RIP.
fn after_branch(registers: &Registers, branch: u64) -> u64 {
    match branch % 3 {
        1 => registers.r13,
        2 => registers.r14,
        _ => registers.r12,
    }
}

/// The most guests [`lands_exactly`] runs for one target: as many again as
/// the exact runs it needs, for kicks proven late. How often a kick comes
/// late depends on the host, its load and how long the guest ran before it
/// (see the limits in reverie-kvm's `preemption_timer.rs`); as many as one
/// in seven came late when these tests ran at a load average of 43.
const ATTEMPTS: usize = 2 * REPEATS;

/// A plan that requests one precise event of `ticks` RCBs at the start of
/// each image.
fn precise(ticks: u64) -> Plan {
    Plan {
        requests: vec![ticks],
        precise: true,
        ..Plan::default()
    }
}

/// What one guest of [`lands_exactly`] showed: an exact event, or a kick
/// proven late before any entry of its stepping window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Landing {
    Exact,
    ProvenLate,
}

/// Runs guests through `land`, given each one's attempt number, until
/// [`REPEATS`] land exactly, running a proven-late one again, but never more
/// than [`ATTEMPTS`] guests in all. Returns how many came late, or the
/// refusal of a guest past that budget.
fn within_attempts(mut land: impl FnMut(usize) -> Landing) -> Result<usize, String> {
    let (mut exact, mut late) = (0, 0);
    while exact < REPEATS {
        if exact + late == ATTEMPTS {
            return Err(format!(
                "{late} proven-late guests left {ATTEMPTS} too few for {REPEATS} exact ones"
            ));
        }
        match land(exact + late + 1) {
            Landing::Exact => exact += 1,
            Landing::ProvenLate => late += 1,
        }
    }
    Ok(late)
}

#[test]
fn the_guest_budget_of_a_precise_target_is_a_total() {
    // The first `late` guests come late, proven so, and the rest exactly:
    // what `within_attempts` returns, and how many guests it ran.
    let run = |late: usize| {
        let mut guests = 0;
        let result = within_attempts(|_| {
            guests += 1;
            if guests <= late {
                Landing::ProvenLate
            } else {
                Landing::Exact
            }
        });
        (result, guests)
    };
    assert_eq!(run(0), (Ok(0), REPEATS));
    assert_eq!(run(REPEATS), (Ok(REPEATS), ATTEMPTS));
    assert!(matches!(run(REPEATS + 1), (Err(_), ATTEMPTS)));
}

/// Runs `program` under `plan`, with registers reported, until `REPEATS`
/// runs have exited with status 0 and got one timer event exactly at
/// `target`, with RIP where `rip` says, and the same registers every time.
///
/// A request whose last notification is a kick (`kicked`: its target lies
/// more than the skid margin plus the single-step allowance past the clock
/// where it is requested) can come late: now and then its kick's exit comes
/// past the margin, more often after a longer run and on a busier host (see
/// the limits in reverie-kvm's `preemption_timer.rs`).
/// Such a run gets its one event at or past the target before any entry of
/// the window began (see [`WINDOW_ENTRIES`]), recorded as late: exactly at
/// the target too, since an asynchronous exit may have run past the boundary
/// right after the target branch. It is run again, within [`ATTEMPTS`]
/// guests in all (see [`within_attempts`]). Every other run must land exactly
/// and record no skid overshoot (the process-global witness count), so a
/// miss after the window's entries began fails.
fn lands_exactly(
    program: &Program,
    plan: Plan,
    target: u64,
    rip: impl Fn(&Registers) -> u64,
    kicked: bool,
) -> Registers {
    let mut first: Option<Registers> = None;
    let _ = reverie::take_skid_overshoot_count();
    within_attempts(|attempt| {
        let events = run(
            program,
            Plan {
                registers: true,
                ..plan.clone()
            },
        );
        let witnessed = reverie::take_skid_overshoot_count();
        let entries = WINDOW_ENTRIES.load(Ordering::Relaxed);
        let context = format!(
            "target {target}, attempt {attempt}, {witnessed} recorded, {entries} window entries: \
             {events:?}"
        );
        let clocks = timer_clocks(&events);
        if kicked && clocks.len() == 1 && clocks[0] >= target && entries == 0 {
            // No step came first, so the event is late even at exactly the
            // target, and must have been recorded as late.
            assert!(witnessed > 0, "a late event is recorded: {context}");
            println!(
                "late run: target {target}, attempt {attempt}, delivered at {} before any \
                 window entry",
                clocks[0]
            );
            return Landing::ProvenLate;
        }
        assert_eq!(clocks, [target], "{context}");
        assert_eq!(witnessed, 0, "{context}");
        let registers = registers_of(&events);
        assert_eq!(registers.rip, rip(&registers), "{context}");
        match &first {
            None => first = Some(registers),
            Some(first) => assert_eq!(&registers, first, "{context}"),
        }
        Landing::Exact
    })
    .unwrap_or_else(|refusal| panic!("target {target}: {refusal}"));
    first.unwrap()
}

/// The registers the run's one timer event saw.
fn registers_of(events: &[Event]) -> Registers {
    events
        .iter()
        .find_map(|event| match event {
            Event::Registers(registers) => Some(registers.clone()),
            _ => None,
        })
        .unwrap()
}

/// A precise event `k` RCBs from where the image starts, for each `k`.
fn precise_events_land_exactly(ticks: &[u64]) {
    for &k in ticks {
        let program = labelled("", k + PRECISE_TAIL, EXIT);
        let plan = precise(k);
        let kicked = k > skid_margin() + reverie::pmu_config::SINGLESTEP_TIMEOUT_RCBS;
        let registers = lands_exactly(&program, plan, k, |r| after_branch(r, k), kicked);
        // The loop counts RCX down once per iteration of three branches,
        // before the third: after branch k it has done floor(k / 3) of them.
        assert_eq!(
            registers.rcx,
            (k + PRECISE_TAIL).div_ceil(3) - k / 3,
            "{registers:x?}"
        );
        println!("precise {k} RCBs: {REPEATS} runs at clock {k}, {registers:x?}");
    }
}

#[test]
fn a_precise_event_lands_exactly_one_to_six_rcbs_on() {
    if bounded("a_precise_event_lands_exactly_one_to_six_rcbs_on") {
        return;
    }
    precise_events_land_exactly(&[1, 2, 3, 4, 5, 6]);
}

#[test]
fn a_precise_event_lands_exactly_around_the_skid_margin() {
    if bounded("a_precise_event_lands_exactly_around_the_skid_margin") {
        return;
    }
    let margin = skid_margin();
    precise_events_land_exactly(&[margin - 1, margin, margin + 5, margin + 6]);
}

#[test]
fn a_precise_event_lands_exactly_around_the_staging_edge() {
    if bounded("a_precise_event_lands_exactly_around_the_staging_edge") {
        return;
    }
    // The longest request that is not staged, and the shortest that is.
    let edge = reverie::pmu_config::try_get_pmu_config()
        .unwrap()
        .first_stage_margin()
        + reverie::pmu_config::SINGLESTEP_TIMEOUT_RCBS;
    precise_events_land_exactly(&[edge, edge + 1]);
}

#[test]
fn a_precise_event_lands_exactly_far_off() {
    if bounded("a_precise_event_lands_exactly_far_off") {
        return;
    }
    precise_events_land_exactly(&[1_000_000, 100_000_000]);
}

/// A hand-built IRETQ to the next instruction, in the same mode.
const IRETQ_TO_NEXT: &str = "mov %ss,%eax\npush %rax\nlea 8(%rsp),%rax\npush %rax\npushfq\n\
     mov %cs,%eax\npush %rax\nlea 9f(%rip),%rax\npush %rax\niretq\n9:\n";

#[test]
fn a_stepped_guest_never_sees_the_trap_flag() {
    if bounded("a_stepped_guest_never_sees_the_trap_flag") {
        return;
    }
    // In the window, the guest ORs into r15 the TF of the images it reads
    // through PUSHF of both widths, also after RDTSC, CPUID and a getpid,
    // then loads CF, PF, AF, ZF, SF and OF with POPF, reads them back into
    // rbx, and keeps rsp in rbp.
    let read = "pushfq\npop %rax\nand $0x100,%eax\nor %eax,%r15d\n";
    let read16 = "pushfw\nmovzwl (%rsp),%eax\nadd $2,%rsp\nand $0x100,%eax\nor %eax,%r15d\n";
    let before = format!(
        "xor %r15d,%r15d\n{read}{read16}pushfw\npopfw\nrdtsc\n{read}xor %eax,%eax\ncpuid\n{read}\
         mov $39,%eax\nsyscall\n{read16}mov %rsp,%rbp\npush $0x8d7\npopfq\npushfq\npop %rbx\n"
    );
    let k = 40;
    let program = labelled(&before, k + PRECISE_TAIL, EXIT_WITH_TRAP_FLAG_SEEN);
    let plan = Plan {
        no_syscalls: true,
        ..precise(k)
    };
    let r = lands_exactly(&program, plan.clone(), k, |r| after_branch(r, k), false);
    // As a CPL 3 POPF loads them: IF stays as it was.
    assert_eq!(
        (r.rbx, r.rsp),
        (0x8d7 | (r.eflags & 0x200), r.rbp),
        "{r:x?}"
    );
    // Refused by name inside the window: a POPF of either width that sets
    // TF, a load of SS, and IRETQ. The latter two run as usual outside it.
    for (before, refusal) in [
        (
            "pushfq\norq $0x100,(%rsp)\npopfq\n",
            "sets its own trap flag",
        ),
        (
            "pushfw\norw $0x100,(%rsp)\npopfw\n",
            "sets its own trap flag",
        ),
        ("mov %ss,%eax\nmov %eax,%ss\n", "loads SS"),
        (IRETQ_TO_NEXT, "runs IRETQ"),
    ] {
        let program = labelled(before, k + PRECISE_TAIL, EXIT);
        let (events, ending) = run_ending(&program, plan.clone());
        let failure = ending.expect_err(&format!("{refusal}: the run must fail: {events:?}"));
        assert!(failure.contains(refusal), "{failure}");
        if !refusal.contains("trap flag") {
            let mut outside = plan.clone();
            outside.precise = false;
            run(&program, outside);
        }
    }
}

/// After `lead` (`base` RCBs), 100-byte REP MOVSB and REP STOSB, five LOOP
/// iterations, a JRCXZ and a JNZ to a REP MOVSB: a precise request for each
/// of their branches lands exactly. Adopted from a review's probes.
fn loop_jrcxz_and_rep_land_exactly(lead: &str, base: u64) {
    let program = Program::new(&format!(
        "lea 8f(%rip),%r12\nlea 5f(%rip),%r13\nlea 6f(%rip),%r14\nlea 4f(%rip),%r8\n{lead}\
         lea srcbuf(%rip),%rsi\nlea dstbuf(%rip),%rdi\nmov $100,%ecx\nrep movsb\n\
         mov $100,%ecx\nrep stosb\nmov $5,%ecx\n8: loop 8b\n5: xor %ecx,%ecx\njrcxz 6f\nnop\n\
         6: mov $1,%eax\nmov $64,%ecx\nlea srcbuf(%rip),%rsi\nlea dstbuf(%rip),%rdi\n\
         test %eax,%eax\njnz 4f\nnop\n4: rep movsb\n{}{EXIT}\
         .data\nsrcbuf: .fill 256,1,0x5a\ndstbuf: .fill 256,1,0\n",
        branches(PRECISE_TAIL)
    ));
    for (offset, rip, rcx) in [
        (1, (|r: &Registers| r.r12) as fn(&Registers) -> u64, 4),
        (3, |r| r.r12, 2),
        (4, |r| r.r12, 1),
        (5, |r| r.r13, 0),
        (6, |r| r.r14, 0),
        (7, |r| r.r8, 64),
    ] {
        let k = base + offset;
        let plan = precise(k);
        let kicked = k > skid_margin() + reverie::pmu_config::SINGLESTEP_TIMEOUT_RCBS;
        let registers = lands_exactly(&program, plan, k, rip, kicked);
        assert_eq!(registers.rcx, rcx, "{k}: {registers:x?}");
    }
}

#[test]
fn loop_jrcxz_and_rep_land_exactly_inside_the_window() {
    if bounded("loop_jrcxz_and_rep_land_exactly_inside_the_window") {
        return;
    }
    loop_jrcxz_and_rep_land_exactly("", 0);
}

#[test]
fn loop_jrcxz_and_rep_land_exactly_after_a_kick() {
    if bounded("loop_jrcxz_and_rep_land_exactly_after_a_kick") {
        return;
    }
    loop_jrcxz_and_rep_land_exactly(&branches(999_993), 999_993);
}

/// A getpid right after branch 999, the last of its loop, then the tail;
/// r8 holds the getpid's first instruction.
fn getpid_after_branch_999() -> Program {
    labelled(
        "lea 4f(%rip),%r8\n",
        999,
        &format!("4: mov $39,%eax\nsyscall\n{}{EXIT}", branches(PRECISE_TAIL)),
    )
}

/// A guest whose SIGSEGV handler steps over the 8-byte load that faults,
/// retires `rcbs` RCBs and, right after the last, makes the rt_sigreturn
/// itself, to return to a loop that makes no syscall. r12 holds the
/// instruction it returns to.
fn signal_return_program(rcbs: usize) -> Program {
    Program::new(&format!(
        "lea 9f(%rip),%r12\nmov ${}, %edi\nlea action(%rip), %rsi\nxor %edx, %edx\n\
         mov $8, %r10d\nmov $13, %eax\nsyscall\nmovq 0x10,%rax\n9:\n{}{EXIT}\
         handler: addq $8,168(%rdx)\nadd $8,%rsp\nmov $15,%eax\n{}syscall\nrestorer: ud2\n\
         .data\n.balign 8\naction: .quad handler, 0x4000004, restorer, 0\n",
        libc::SIGSEGV,
        branches(PRECISE_TAIL),
        "xor %ecx,%ecx\njz 7f\n7:\n".repeat(rcbs),
    ))
}

#[test]
fn a_request_due_at_rt_sigreturn_is_delivered_with_the_registers_it_restores() {
    if bounded("a_request_due_at_rt_sigreturn_is_delivered_with_the_registers_it_restores") {
        return;
    }
    // The signal's callback requests 1 RCB. The handler's one branch reaches
    // the target and the earliest overflow, 2 RCBs on, comes later, so
    // rt_sigreturn's exit is the first at the target.
    let plan = Plan {
        requests: vec![],
        rearm_at_signal: Some(1),
        registers: true,
        ..Plan::default()
    };
    let events = run(&signal_return_program(1), plan);
    let (requested_at, _) = last_request(&events);
    assert_eq!(timer_clocks(&events), [requested_at + 1], "{events:?}");
    let r = registers_of(&events);
    assert_eq!(r.rip, r.r12, "{r:x?}");
}

#[test]
fn with_no_skid_margin_a_precise_request_is_late_and_still_delivered() {
    // With no skid margin, a request is programmed at its target.
    if bounded_with(
        "with_no_skid_margin_a_precise_request_is_late_and_still_delivered",
        &[(reverie::pmu_config::SKID_MARGIN_OVERRIDE_ENV, "0")],
    ) {
        return;
    }
    assert_eq!(skid_margin(), 0);
    // An unstepped exit exactly at the target, the getpid right after branch
    // 999 or the kick before it, is late.
    let program = getpid_after_branch_999();
    let plan = Plan {
        no_syscalls: true,
        ..precise(999)
    };
    for _ in 0..REPEATS {
        let _ = reverie::take_skid_overshoot_count();
        let events = run(&program, plan.clone());
        assert_eq!(timer_clocks(&events), [999], "{events:?}");
        assert_eq!(reverie::take_skid_overshoot_count(), 1, "{events:?}");
        assert_eq!(WINDOW_ENTRIES.load(Ordering::Relaxed), 0, "{events:?}");
    }
    // A request for 6 RCBs from the signal's callback passes its target in
    // the handler, unstepped, and is late at rt_sigreturn (or at an earlier
    // kick), and delivered once to a guest that makes no syscall after it.
    let program = signal_return_program(6);
    let plan = Plan {
        requests: vec![],
        rearm_at_signal: Some(6),
        precise: true,
        registers: true,
        ..Plan::default()
    };
    let mut at_return = 0;
    for _ in 0..REPEATS {
        let _ = reverie::take_skid_overshoot_count();
        let events = run(&program, plan.clone());
        let (requested_at, _) = last_request(&events);
        assert_eq!(timer_clocks(&events), [requested_at + 6], "{events:?}");
        assert_eq!(reverie::take_skid_overshoot_count(), 1, "{events:?}");
        let r = registers_of(&events);
        at_return += usize::from(r.rip == r.r12);
    }
    assert!(at_return > 0, "never delivered at rt_sigreturn");
    println!("late at its target, delivered at rt_sigreturn in {at_return} of {REPEATS} runs");
}

#[test]
fn a_syscall_inside_the_stepping_window() {
    if bounded("a_syscall_inside_the_stepping_window") {
        return;
    }
    // A request for 100 RCBs, then a getpid at clock 10.
    let program = labelled(
        &format!("{TEN_RCBS}mov $39,%eax\nsyscall\n"),
        1_000 + PRECISE_TAIL,
        EXIT,
    );
    let plan = precise(100);
    // Subscribed, the getpid cancels the request; one made in its callback
    // lands exactly, and without one nothing comes.
    let rearmed = Plan {
        rearm_at_getpid: Some(50),
        ..plan.clone()
    };
    lands_exactly(&program, rearmed, 60, |r| after_branch(r, 50), false);
    let events = run(&program, plan.clone());
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // Unsubscribed, the backend answers it and the steps go on after it.
    let quiet = Plan {
        no_syscalls: true,
        ..plan
    };
    lands_exactly(&program, quiet.clone(), 100, |r| after_branch(r, 90), false);
    // The guest of the unstepped arrival control (see
    // `with_no_skid_margin_a_precise_request_is_late_and_still_delivered`):
    // stepped from the start, its request lands exactly at the getpid.
    let quiet = Plan {
        requests: vec![999],
        ..quiet
    };
    lands_exactly(&getpid_after_branch_999(), quiet, 999, |r| r.r8, false);
}

#[test]
fn rdtsc_and_cpuid_inside_the_stepping_window() {
    if bounded("rdtsc_and_cpuid_inside_the_stepping_window") {
        return;
    }
    let program = labelled(
        &format!("{TEN_RCBS}rdtsc\nxor %eax,%eax\ncpuid\n"),
        1_000 + PRECISE_TAIL,
        EXIT,
    );
    let plan = precise(100);
    // Unsubscribed, each runs unstepped to the next instruction, and the
    // steps go on from there.
    lands_exactly(&program, plan.clone(), 100, |r| after_branch(r, 90), false);
    // Subscribed, each is an event of its own, which cancels the request.
    for (name, plan, witness) in [
        (
            "RDTSC",
            Plan {
                rdtsc: true,
                ..plan.clone()
            },
            Event::Rdtsc,
        ),
        (
            "CPUID",
            Plan {
                cpuid: true,
                ..plan
            },
            Event::Cpuid,
        ),
    ] {
        let events = run(&program, plan);
        assert!(events.contains(&witness), "{name}: {events:?}");
        assert_eq!(timer_clocks(&events), [0; 0], "{name}: {events:?}");
    }
}

#[test]
fn a_fault_inside_the_stepping_window_leaves_no_trap_flag_in_its_frame() {
    if bounded("a_fault_inside_the_stepping_window_leaves_no_trap_flag_in_its_frame") {
        return;
    }
    // A SIGSEGV handler that collects the trap flag of the frame's saved
    // RFLAGS into the frame's r15, and steps over the 8-byte load that
    // faults; installed first. Then the marker, where 300 RCBs are
    // requested, ten RCBs, the load at clock 10, and the loop.
    let program = |fault: &str| {
        labelled(
            &format!(
                "mov ${}, %edi\nlea action(%rip), %rsi\nxor %edx, %edx\nmov $8, %r10d\n\
                 mov $13, %eax\nsyscall\nxor %r15d,%r15d\n{GETPPID}{TEN_RCBS}{fault}",
                libc::SIGSEGV
            ),
            1_000 + PRECISE_TAIL,
            &format!(
                "{EXIT_WITH_TRAP_FLAG_SEEN}\
                 handler: mov 176(%rdx),%rax\nand $0x100,%eax\nor %rax,96(%rdx)\n\
                 addq $8,168(%rdx)\nret\nrestorer: mov $15,%eax\nsyscall\nud2\n\
                 .data\n.balign 8\naction: .quad handler, 0x4000004, restorer, 0\n"
            ),
        )
    };
    let faulting = program("movq 0x10,%rax\n");
    let plan = Plan {
        arm: Arm::Marker,
        ..precise(300)
    };
    // The fault's signal is an event of its own, which cancels the request.
    let events = run(&faulting, plan.clone());
    assert!(events.contains(&Event::Signal(libc::SIGSEGV)), "{events:?}");
    assert_eq!(timer_clocks(&events), [0; 0], "{events:?}");
    // One made in the signal's callback lands exactly: the steps go on
    // through the handler and after its rt_sigreturn.
    let rearmed = Plan {
        rearm_at_signal: Some(200),
        ..plan.clone()
    };
    lands_exactly(&faulting, rearmed, 210, |r| after_branch(r, 200), false);
    // The control: without the fault, the request lands exactly.
    lands_exactly(&program(""), plan, 300, |r| after_branch(r, 290), false);
}

#[test]
fn a_replaced_or_stale_precise_request_still_lands_exactly() {
    if bounded("a_replaced_or_stale_precise_request_still_lands_exactly") {
        return;
    }
    let program = labelled("", 600 + PRECISE_TAIL, EXIT);
    for (requests, target) in [(vec![500, 300], 300), (vec![300, 500], 500)] {
        let plan = Plan {
            requests,
            precise: true,
            ..Plan::default()
        };
        lands_exactly(&program, plan, target, |r| after_branch(r, target), false);
    }
    // A request for 3,000 RCBs, programmed 1,000 RCBs on, cancelled by a
    // getpid at clock 10 whose callback requests 100,000: the event keeps
    // its pending overflow at 1,000, now stale, which changes nothing.
    let plan = precise(3_000);
    let program = |call: &str| labelled(&format!("{TEN_RCBS}{call}"), 200_000 + PRECISE_TAIL, EXIT);
    let rearmed = Plan {
        rearm_at_getpid: Some(100_000),
        ..plan.clone()
    };
    lands_exactly(
        &program("mov $39,%eax\nsyscall\n"),
        rearmed,
        100_010,
        |r| after_branch(r, 100_000),
        true,
    );
    // The control: without the getpid, the first request lands exactly.
    lands_exactly(&program(""), plan, 3_000, |r| after_branch(r, 2_990), true);
}

/// A precise request renewed at each of 20 getpids, each time earlier, as a
/// Tool that charges each syscall against a thread's budget renews it, lands
/// exactly at the last target, with the same registers every time. The
/// first renewal moves the point the request needs before the pending
/// overflow, which the next entry reprograms with slack (see reverie-kvm's
/// `preemption_timer.rs`). Renewals 1,000 RCBs apart then stay within that
/// slack, and ones 200,000 apart move past it and reprogram it again. Either
/// way the guest then runs into the overflow the slack brought forward, an
/// early kick that decides nothing, before its first stage, second stage and
/// single steps take it to the target.
#[test]
fn a_precise_request_renewed_earlier_at_each_syscall_still_lands_exactly() {
    if bounded("a_precise_request_renewed_earlier_at_each_syscall_still_lands_exactly") {
        return;
    }
    const RENEWALS: u64 = 20;
    // Ten RCBs, then a getpid, for each renewal: the loop starts 200 RCBs
    // on.
    let calls = format!("{TEN_RCBS}mov $39,%eax\nsyscall\n").repeat(RENEWALS as usize);
    let before = 10 * RENEWALS;
    for (first, by) in [(4_000_000, 1_000), (10_000_000, 200_000)] {
        let target = first - RENEWALS * by;
        let program = labelled(&calls, target - before + PRECISE_TAIL, EXIT);
        let plan = Plan {
            renew_at_getpid: Some(by),
            ..precise(first)
        };
        let registers = lands_exactly(
            &program,
            plan,
            target,
            |r| after_branch(r, target - before),
            true,
        );
        println!(
            "renewed precise request: {first} RCBs, renewed {RENEWALS} times {by} RCBs earlier: \
             {REPEATS} runs at clock {target}, {registers:x?}"
        );
    }
}

/// Where the guests of the signal tests below keep their SIGUSR1 handler's
/// record, which they write to stdout before they exit: the interrupted
/// context in the handler's frame (rip, rax, rbx, rcx, eflags, r12, r14 and
/// r15), then how many times the handler ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    rip: u64,
    rax: u64,
    rbx: u64,
    rcx: u64,
    eflags: u64,
    r12: u64,
    r14: u64,
    r15: u64,
    count: u64,
}

impl Record {
    fn read(stdout: &[u8]) -> Self {
        assert_eq!(stdout.len(), 72, "{stdout:?}");
        let quad = |i: usize| u64::from_ne_bytes(stdout[8 * i..8 * i + 8].try_into().unwrap());
        Self {
            rip: quad(0),
            rax: quad(1),
            rbx: quad(2),
            rcx: quad(3),
            eflags: quad(4),
            r12: quad(5),
            r14: quad(6),
            r15: quad(7),
            count: quad(8),
        }
    }
}

/// SA_RESTORER and SA_SIGINFO.
const HANDLER_FLAGS: u64 = 0x0400_0004;

/// The SIGUSR1 handler that fills the [`Record`] from its frame's ucontext
/// (in rdx) and sets `flag`, its restorer, and the data both use. `actions`
/// adds sigaction records before `usr1_action`.
fn signal_record(flags: u64, actions: &str) -> String {
    let save: String = [168, 144, 128, 152, 176, 72, 88, 96]
        .iter()
        .enumerate()
        .map(|(i, at)| format!("mov {at}(%rdx),%rax\nmov %rax,record+{}(%rip)\n", 8 * i))
        .collect();
    format!(
        "usr1:\nincq record+64(%rip)\n{save}movb $1,flag(%rip)\nret\n\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\n{actions}usr1_action: .quad usr1, {flags:#x}, restorer, 0\n\
         record: .quad 0,0,0,0,0,0,0,0,0\npid: .quad 0\ntid: .quad 0\nmask: .quad 0x200\n\
         flag: .byte 0\n.bss\n.balign 16\nstack: .skip 65536\nstack_end:\n"
    )
}

/// Writes the [`Record`] and exits with status 0.
const WRITE_RECORD: &str = "mov $1,%edi\nlea record(%rip),%rsi\nmov $72,%edx\nmov $1,%eax\nsyscall\n\
     xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n";

/// Installs the SIGUSR1 handler of [`signal_record`] and starts a sibling
/// thread that sends SIGUSR1 to this one, with a `tgkill`, and exits.
const SIBLING: &str = "mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\n\
     mov $13,%eax\nsyscall\nmov $39,%eax\nsyscall\nmov %rax,pid(%rip)\n\
     mov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
     mov $0x50f00,%edi\nlea stack_end(%rip),%rsi\nxor %edx,%edx\nxor %r10d,%r10d\n\
     xor %r8d,%r8d\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 8f\n\
     mov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
     xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n8:\n";

/// How many iterations the spinner of [`spinner`] runs at most.
const SPINS: u64 = 1_000_000;

/// A guest whose sibling sends it SIGUSR1 (see [`SIBLING`]), which then
/// reaches the marker and spins without a syscall, 2 RCBs an iteration, with
/// rax at -ERESTARTSYS and r12 at the loop's head, until its handler has run
/// or for [`SPINS`] iterations. With `blocked`, SIGUSR1 is blocked before the
/// marker and unblocked after the loop, with r12 at that call's return.
fn spinner(flags: u64, blocked: bool) -> Program {
    spinner_after(flags, blocked, "")
}

/// [`spinner`], running `prefix` right before the marker.
fn spinner_after(flags: u64, blocked: bool, prefix: &str) -> Program {
    let mask = |how: u32| {
        format!(
            "mov ${how},%edi\nlea mask(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n"
        )
    };
    let (block, unblock) = if blocked {
        (mask(0), format!("lea 3f(%rip),%r12\n{}3:\n", mask(1)))
    } else {
        (String::new(), String::new())
    };
    Program::new(&format!(
        "{SIBLING}{block}{prefix}{GETPPID}lea 1f(%rip),%r12\nmov $-512,%rax\nxor %ebx,%ebx\nmov ${SPINS},%rcx\n\
         1: inc %rbx\ncmpb $0,flag(%rip)\njne 2f\ndec %rcx\njnz 1b\n2:\n{unblock}{WRITE_RECORD}{}",
        signal_record(flags, "")
    ))
}

/// A precise request for this many RCBs at the marker: stepped from the
/// marker on, so it is never late.
const SPIN_TICKS: u64 = 1_000;

fn spinner_plan() -> Plan {
    Plan {
        arm: Arm::Marker,
        requests: vec![SPIN_TICKS],
        precise: true,
        registers: true,
        rendezvous: true,
        deliver: true,
        ..Plan::default()
    }
}

/// Runs `program`, checks that it exits with status 0, and returns the
/// Tool's events and the guest's [`Record`].
fn run_recorded(program: &Program, plan: Plan) -> (Vec<Event>, Record) {
    let (events, ending) = run_ending(program, plan);
    let (code, stdout, stderr) = ending.unwrap_or_else(|failure| panic!("{failure}: {events:?}"));
    assert_eq!((code, stderr), (0, vec![]), "{events:?}");
    (events, Record::read(&stdout))
}

/// The clock at the callback of each delivered SIGUSR1, and the index of
/// its event.
fn sigusr1_clocks(events: &[Event]) -> Vec<(usize, u64)> {
    events
        .iter()
        .enumerate()
        .filter_map(|(at, event)| match event {
            Event::Signalled { signal, clock } if *signal == libc::SIGUSR1 => Some((at, *clock)),
            _ => None,
        })
        .collect()
}

/// The index of the first timer event, and its clock.
fn first_timer(events: &[Event]) -> (usize, u64) {
    events
        .iter()
        .enumerate()
        .find_map(|(at, event)| match event {
            Event::Timer { clock } => Some((at, *clock)),
            _ => None,
        })
        .expect("a timer event")
}

#[test]
fn a_spinner_signalled_by_a_sibling_gets_its_handler_at_the_next_timer_boundary() {
    if bounded("a_spinner_signalled_by_a_sibling_gets_its_handler_at_the_next_timer_boundary") {
        return;
    }
    // The sibling's tgkill runs while the timer event's callback waits for
    // it, so SIGUSR1 is pending when the callback returns, at the boundary
    // right after branch 1,000. It is delivered there, before the guest runs
    // on: the handler's frame holds the registers the timer event saw, and
    // the loop's head, its 500 iterations and rax as the loop left it. That
    // rax is -ERESTARTSYS changes nothing, with SA_RESTART or without: no
    // syscall is interrupted there, so nothing restarts.
    let mut first = None;
    for flags in [HANDLER_FLAGS, HANDLER_FLAGS | libc::SA_RESTART as u64] {
        let program = spinner(flags, false);
        for _ in 0..REPEATS {
            let (events, record) = run_recorded(&program, spinner_plan());
            let context = format!("{flags:#x}: {record:x?} {events:?}");
            let (requested_at, _) = last_request(&events);
            let target = requested_at + SPIN_TICKS;
            let (timer_at, timer_clock) = first_timer(&events);
            assert_eq!(timer_clocks(&events), [target], "{context}");
            let delivered = sigusr1_clocks(&events);
            assert_eq!(delivered.len(), 1, "{context}");
            assert!(delivered[0].0 > timer_at, "{context}");
            assert_eq!(delivered[0].1, timer_clock, "{context}");
            let r = registers_of(&events);
            assert_eq!(record.count, 1, "{context}");
            assert_eq!(
                (
                    record.rip,
                    record.rax,
                    record.rbx,
                    record.rcx,
                    record.eflags
                ),
                (r.rip, r.rax, r.rbx, r.rcx, r.eflags),
                "{context}"
            );
            assert_eq!(record.rip, record.r12, "{context}");
            assert_eq!(record.rax, -512_i64 as u64, "{context}");
            assert_eq!(record.rbx, SPIN_TICKS / 2, "{context}");
            assert_eq!(record.rcx, SPINS - SPIN_TICKS / 2, "{context}");
            assert_eq!(*first.get_or_insert(record), record, "{context}");
        }
    }
    println!("delivered at the timer boundary with {first:x?}");
}

/// Sets the FS base to the address of `record`, kept in r13, and the GS base
/// to that of `pid`, kept in r15 (arch_prctl ARCH_SET_FS and ARCH_SET_GS).
const SET_BASES: &str = "lea record(%rip),%r13\nmov $0x1002,%edi\nmov %r13,%rsi\nmov $158,%eax\nsyscall\n\
     lea pid(%rip),%r15\nmov $0x1001,%edi\nmov %r15,%rsi\nmov $158,%eax\nsyscall\n";

#[test]
fn a_signal_hook_at_a_timer_boundary_sees_the_timer_events_registers() {
    if bounded("a_signal_hook_at_a_timer_boundary_sees_the_timer_events_registers") {
        return;
    }
    // With the FS and GS bases set, the signal's callback at the timer
    // boundary sees the complete user registers the timer event's callback
    // saw there: the general registers, orig_rax -1, the segment selectors
    // and both bases.
    let plan = Plan {
        signal_registers: true,
        ..spinner_plan()
    };
    let (events, record) = run_recorded(&spinner_after(HANDLER_FLAGS, false, SET_BASES), plan);
    let context = format!("{record:x?} {events:?}");
    assert_eq!(record.count, 1, "{context}");
    let seen: Vec<&Registers> = events
        .iter()
        .filter_map(|event| match event {
            Event::Registers(registers) => Some(registers),
            _ => None,
        })
        .collect();
    assert_eq!(seen.len(), 2, "{context}");
    assert_eq!(seen[0], seen[1], "{context}");
    let r = seen[1];
    assert_ne!((r.r13, r.r15), (0, 0), "{context}");
    assert_eq!((r.fs_base, r.gs_base), (r.r13, r.r15), "{context}");
    assert_eq!(
        (r.orig_rax, r.cs & 3, r.ss & 3),
        (u64::MAX, 3, 3),
        "{context}"
    );
}

#[test]
fn a_signal_hook_before_a_new_threads_first_instruction_sees_its_registers() {
    if bounded("a_signal_hook_before_a_new_threads_first_instruction_sees_its_registers") {
        return;
    }
    // The user boundary of a new thread shares the timer boundary's signal
    // hook context. The guest clones a thread whose TLS (the FS base) is
    // `record`, and sends it SIGUSR1 while the Tool holds its start; the
    // thread takes it before its first instruction, and the signal's
    // callback sees its complete registers: the FS base it was given (also
    // in r8, the clone's TLS argument), user segment selectors, orig_rax -1.
    let program = Program::new(&format!(
        "mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
         mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\n\
         mov $0xd0f00,%edi\nlea stack_end(%rip),%rsi\nxor %edx,%edx\nxor %r10d,%r10d\n\
         lea record(%rip),%r8\nmov $56,%eax\nsyscall\ntest %rax,%rax\njz 8f\n\
         mov pid(%rip),%rdi\nmov %rax,%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
         mov $2000000000,%ecx\n9: cmpb $0,flag(%rip)\njne 7f\ndec %rcx\njnz 9b\n7:\n{WRITE_RECORD}\
         8: xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n{}",
        signal_record(HANDLER_FLAGS, "")
    ));
    let plan = Plan {
        hold_thread_start: true,
        signal_registers: true,
        deliver: true,
        ..Plan::default()
    };
    let (events, record) = run_recorded(&program, plan);
    let context = format!("{record:x?} {events:?}");
    assert_eq!(record.count, 1, "{context}");
    let r = registers_of(&events);
    assert_ne!(r.r8, 0, "{context}");
    assert_eq!(r.fs_base, r.r8, "{context}");
    assert_eq!(
        (r.orig_rax, r.rax, r.cs & 3, r.ss & 3),
        (u64::MAX, 0, 3, 3),
        "{context}"
    );
    assert_eq!(record.rip, r.rip, "{context}");
}

#[test]
fn a_blocked_signal_waits_at_the_timer_boundary_for_its_unblock() {
    if bounded("a_blocked_signal_waits_at_the_timer_boundary_for_its_unblock") {
        return;
    }
    // SIGUSR1 is blocked, so the timer boundary leaves it pending: the loop
    // runs to its end, and the unblock's return delivers it, with the
    // handler's frame at that call's return (where SYSCALL left rcx).
    let (events, record) = run_recorded(&spinner(HANDLER_FLAGS, true), spinner_plan());
    let context = format!("{record:x?} {events:?}");
    let (requested_at, _) = last_request(&events);
    assert_eq!(
        timer_clocks(&events),
        [requested_at + SPIN_TICKS],
        "{context}"
    );
    assert_eq!(record.count, 1, "{context}");
    assert_eq!((record.rip, record.rax), (record.r12, 0), "{context}");
    assert_eq!((record.rbx, record.rcx), (SPINS, record.rip), "{context}");
    let delivered = sigusr1_clocks(&events);
    assert_eq!(delivered.len(), 1, "{context}");
    assert_eq!(delivered[0].1, requested_at + 2 * SPINS, "{context}");
}

#[test]
fn a_signal_pending_at_a_syscall_return_timer_event_follows_it() {
    if bounded("a_signal_pending_at_a_syscall_return_timer_event_follows_it") {
        return;
    }
    // The guest of
    // `a_timer_event_reaches_a_guest_making_syscalls_the_tool_does_not_see`,
    // with the sibling: its tgkill is the only syscall the Tool sees, and it
    // runs while the timer event's callback, at the return of a getpid,
    // waits for it. The signal is delivered at that same return, after the
    // callback, as the getpid's own: the handler's frame holds the registers
    // the timer event saw, with getpid's result and the loop's count.
    let program = Program::new(&format!(
        "{SIBLING}lea 7f(%rip),%r14\nmov $50000,%r15\n4: mov $3,%rbx\n5: dec %rbx\njnz 5b\n\
         mov $39,%eax\nsyscall\n7: dec %r15\njnz 4b\n{WRITE_RECORD}{}",
        signal_record(HANDLER_FLAGS, "")
    ));
    let plan = Plan {
        requests: vec![100_000],
        only_tgkill: true,
        registers: true,
        rendezvous: true,
        deliver: true,
        ..Plan::default()
    };
    let (events, record) = run_recorded(&program, plan);
    let context = format!("{record:x?} {events:?}");
    let (timer_at, timer_clock) = first_timer(&events);
    assert_eq!(timer_clocks(&events).len(), 1, "{context}");
    let delivered = sigusr1_clocks(&events);
    assert_eq!(delivered.len(), 1, "{context}");
    assert!(delivered[0].0 > timer_at, "{context}");
    assert_eq!(delivered[0].1, timer_clock, "{context}");
    let r = registers_of(&events);
    assert_eq!(
        r.rip, r.r14,
        "the timer event at a getpid's return: {context}"
    );
    assert_eq!(record.count, 1, "{context}");
    assert_eq!(
        (record.rip, record.rax, record.rbx, record.r14, record.r15),
        (r.rip, r.rax, r.rbx, r.r14, r.r15),
        "{context}"
    );
}

#[test]
fn a_signal_pending_at_an_rt_sigreturn_timer_event_follows_it() {
    if bounded("a_signal_pending_at_an_rt_sigreturn_timer_event_follows_it") {
        return;
    }
    // The guest of
    // `a_request_due_at_rt_sigreturn_is_delivered_with_the_registers_it_restores`,
    // with SIGUSR1 blocked by the SIGSEGV handler's mask. SIGSEGV's callback
    // sends SIGUSR1 to the thread, which stays pending through the handler,
    // and requests 1 RCB, which comes due at the handler's rt_sigreturn. The
    // mask that call restores unblocks SIGUSR1, which is delivered at its
    // return, after the timer event, with the registers it restores.
    let program = Program::new(&format!(
        "lea 9f(%rip),%r12\nmov $11,%edi\nlea segv_action(%rip),%rsi\nxor %edx,%edx\n\
         mov $8,%r10d\nmov $13,%eax\nsyscall\nmov $10,%edi\nlea usr1_action(%rip),%rsi\n\
         xor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\nmovq 0x10,%rax\n\
         9: mov ${SPINS},%rcx\n1: cmpb $0,flag(%rip)\njne 2f\ndec %rcx\njnz 1b\n2:\n{WRITE_RECORD}\
         segv: addq $8,168(%rdx)\nadd $8,%rsp\nmov $15,%eax\nxor %ecx,%ecx\njz 7f\n7: syscall\nud2\n\
         {}",
        signal_record(
            HANDLER_FLAGS,
            &format!("segv_action: .quad segv, {HANDLER_FLAGS:#x}, restorer, 0x200\n")
        )
    ));
    let plan = Plan {
        requests: vec![],
        rearm_at_signal: Some(1),
        registers: true,
        deliver: true,
        self_signal_at_fault: true,
        ..Plan::default()
    };
    let (events, record) = run_recorded(&program, plan);
    let context = format!("{record:x?} {events:?}");
    let (timer_at, timer_clock) = first_timer(&events);
    let delivered = sigusr1_clocks(&events);
    assert_eq!(delivered.len(), 1, "{context}");
    assert!(delivered[0].0 > timer_at, "{context}");
    assert_eq!(delivered[0].1, timer_clock, "{context}");
    let r = registers_of(&events);
    assert_eq!(r.rip, r.r12, "the timer event at rt_sigreturn: {context}");
    assert_eq!(record.count, 1, "{context}");
    assert_eq!((record.rip, record.rax), (r.rip, r.rax), "{context}");
}

/// The x87, SSE and AVX state a guest of the FPU tests below reads: MXCSR
/// (STMXCSR), the x87 control word (FNSTCW), the x87 status and tag words
/// (FNSTENV, whose instruction and operand pointers are left out), and YMM5,
/// whose low half is XMM5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FpuState {
    mxcsr: u32,
    control: u16,
    status: u16,
    tags: u16,
    ymm5: [u64; 4],
}

impl FpuState {
    /// Linux's initial state, which `handle_signal` gives a handler
    /// (`fpu__clear_user_states`): MXCSR 0x1f80, x87 control word 0x37f, an
    /// empty x87 stack (TOP 0, every register tagged empty) and zero vector
    /// registers.
    const INITIAL: Self = Self {
        mxcsr: 0x1f80,
        control: 0x37f,
        status: 0,
        tags: 0xffff,
        ymm5: [0; 4],
    };

    /// The state [`FPU_LOAD`] leaves, with TOP 6 (bits 11 to 13) and no
    /// other bit of the status word, whose condition codes FLD leaves
    /// undefined.
    const LOADED: Self = Self {
        mxcsr: 0x7f80,
        control: 0x027f,
        status: 6 << 11,
        tags: 0x0fff,
        ymm5: FPU_YMM5,
    };

    /// The block [`fpu_save`] writes at the start of `bytes`.
    fn read(bytes: &[u8]) -> Self {
        let half = |at: usize| u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap());
        let quad = |at: usize| u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap());
        Self {
            mxcsr: u32::from_ne_bytes(bytes[..4].try_into().unwrap()),
            control: half(8),
            // FNSTENV's 28-byte image: the control, status and tag words
            // each fill four bytes.
            status: half(20),
            tags: half(24),
            ymm5: [quad(48), quad(56), quad(64), quad(72)],
        }
    }
}

/// What a guest of the FPU tests below writes to stdout before it exits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FpuRecord {
    /// The state at the handler's first instruction.
    handler: FpuState,
    /// How many times the handler ran.
    entries: u64,
    /// The interrupted rip in the handler's frame, and the frame's r12, where
    /// the guest keeps the instruction at which the signal should come.
    rip: u64,
    r12: u64,
    /// The state after the handler returned.
    after: FpuState,
    /// ST0 and ST1 after the handler returned, as FSTP m80 stores them.
    stack: [[u8; 10]; 2],
}

impl FpuRecord {
    fn read(stdout: &[u8]) -> Self {
        assert_eq!(stdout.len(), FPU_RECORD_SIZE, "{stdout:?}");
        let quad = |at: usize| u64::from_ne_bytes(stdout[at..at + 8].try_into().unwrap());
        Self {
            handler: FpuState::read(&stdout[..80]),
            entries: quad(80),
            rip: quad(88),
            r12: quad(96),
            after: FpuState::read(&stdout[104..184]),
            stack: [
                stdout[184..194].try_into().unwrap(),
                stdout[200..210].try_into().unwrap(),
            ],
        }
    }

    /// Everything but the frame's rip and r12, which tell where the signal
    /// came: natively, a sibling's signal comes wherever the guest then is.
    fn fpu(&self) -> (FpuState, u64, FpuState, [[u8; 10]; 2]) {
        (self.handler, self.entries, self.after, self.stack)
    }
}

const FPU_RECORD_SIZE: usize = 216;

/// MXCSR 0x7f80 (round toward zero), x87 control word 0x027f (double
/// precision), 1.5 and then -3.25 on the x87 stack, and a nonzero YMM5: the
/// interrupted state, which a handler must not see and which must be intact
/// after it returns.
const FPU_LOAD: &str = "ldmxcsr fpu_mxcsr(%rip)\nfldcw fpu_control(%rip)\nfldt fpu_first(%rip)\n\
     fldt fpu_second(%rip)\nvmovdqu fpu_ymm5(%rip),%ymm5\n";

/// The bytes of -3.25 and 1.5 as FSTP m80 stores them: ST0 and ST1 after
/// [`FPU_LOAD`].
const FPU_STACK: [[u8; 10]; 2] = [
    [0, 0, 0, 0, 0, 0, 0, 0xd0, 0x00, 0xc0],
    [0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0x3f],
];

const FPU_YMM5: [u64; 4] = [
    0x1111_1111_1111_1111,
    0x2222_2222_2222_2222,
    0x3333_3333_3333_3333,
    0x4444_4444_4444_4444,
];

/// Saves an [`FpuState`] at `offset` in `fpu_record`.
fn fpu_save(offset: usize) -> String {
    format!(
        "stmxcsr fpu_record+{offset}(%rip)\nfnstcw fpu_record+{}(%rip)\n\
         fnstenv fpu_record+{}(%rip)\nvmovdqu %ymm5,fpu_record+{}(%rip)\n",
        offset + 8,
        offset + 16,
        offset + 48
    )
}

/// After the handler returned: saves the state, pops ST0 and ST1 into the
/// record, writes the record and exits with status 0.
fn fpu_after() -> String {
    format!(
        "{}fstpt fpu_record+184(%rip)\nfstpt fpu_record+200(%rip)\n\
         mov $1,%edi\nlea fpu_record(%rip),%rsi\nmov ${FPU_RECORD_SIZE},%edx\nmov $1,%eax\nsyscall\n\
         xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n",
        fpu_save(104)
    )
}

/// Installs the handler of [`fpu_handler`] for `signal`, with the sigaction
/// record `action`.
fn fpu_install(signal: i32, action: &str) -> String {
    format!(
        "mov ${signal},%edi\nlea {action}(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n"
    )
}

/// The handler, its restorer and the data. The handler saves the state it
/// starts with, counts its entries, keeps its frame's rip and r12, runs
/// `extra` and sets `flag`; `action` names its sigaction record. The data
/// includes what [`SIBLING`] uses.
fn fpu_handler(action: &str, extra: &str) -> String {
    fpu_handler_loading(action, extra, 0x7f80)
}

/// [`fpu_handler`], with [`FPU_LOAD`] loading `mxcsr` as MXCSR.
fn fpu_handler_loading(action: &str, extra: &str, mxcsr: u32) -> String {
    format!(
        "fpu_handler:\n{}incq fpu_record+80(%rip)\nmov 168(%rdx),%rax\nmov %rax,fpu_record+88(%rip)\n\
         mov 72(%rdx),%rax\nmov %rax,fpu_record+96(%rip)\n{extra}movb $1,flag(%rip)\nret\n\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\n{action}: .quad fpu_handler, {HANDLER_FLAGS:#x}, restorer, 0\n\
         pid: .quad 0\ntid: .quad 0\nflag: .byte 0\n\
         fpu_mxcsr: .long {mxcsr:#x}\nfpu_control: .short 0x027f\n\
         .balign 16\nfpu_first: .quad 0xc000000000000000\n.short 0x3fff\n\
         .balign 16\nfpu_second: .quad 0xd000000000000000\n.short 0xc000\n\
         .balign 32\nfpu_ymm5: .quad {:#x}, {:#x}, {:#x}, {:#x}\n\
         .balign 64\nfpu_record: .zero {FPU_RECORD_SIZE}\n\
         .bss\n.balign 16\nstack: .skip 65536\nstack_end:\n",
        fpu_save(0),
        FPU_YMM5[0],
        FPU_YMM5[1],
        FPU_YMM5[2],
        FPU_YMM5[3],
    )
}

/// Checks a record of a guest that loaded [`FPU_LOAD`] and then took one
/// signal: its handler started in Linux's initial state, and the interrupted
/// code found its own state again after the handler returned.
fn check_fpu_record(record: &FpuRecord, context: &str) {
    check_loaded_fpu_record(record, context, 0x7f80);
}

/// [`check_fpu_record`], where the interrupted code finds MXCSR `mxcsr`
/// after the handler returned.
fn check_loaded_fpu_record(record: &FpuRecord, context: &str, mxcsr: u32) {
    let context = format!("{context}: {record:x?}");
    assert_eq!(record.entries, 1, "{context}");
    assert_eq!(record.handler, FpuState::INITIAL, "{context}");
    let after = FpuState {
        status: record.after.status & 7 << 11,
        ..record.after
    };
    let loaded = FpuState {
        mxcsr,
        ..FpuState::LOADED
    };
    assert_eq!(after, loaded, "{context}");
    assert_eq!(record.stack, FPU_STACK, "{context}");
}

/// Runs `program` natively, the Linux reference, checks that it exits with
/// status 0 and writes nothing to stderr, and returns its stdout.
fn native_stdout(program: &Program) -> Vec<u8> {
    let output = std::process::Command::new("timeout")
        .args(["--kill-after=2s", "30s"])
        .arg(&program.executable)
        .current_dir(&program.directory)
        .output()
        .unwrap();
    assert!(
        output.status.success() && output.stderr.is_empty(),
        "native: {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// Runs `program` natively and returns its record.
fn native_fpu_record(program: &Program) -> FpuRecord {
    FpuRecord::read(&native_stdout(program))
}

/// Runs `program` under the backend's own runtime, with no Tool, checks that
/// it exits with status 0 and writes nothing to stderr, and returns its
/// stdout.
fn direct_stdout(program: &Program) -> Vec<u8> {
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
    assert_eq!((code, stderr), (0, vec![]));
    stdout
}

/// Runs `program` under the backend's own runtime and returns its record.
fn direct_fpu_record(program: &Program) -> FpuRecord {
    FpuRecord::read(&direct_stdout(program))
}

/// Runs `program` under a [`TimerTool`] following `plan`, checks that it
/// exits with status 0 and writes nothing to stderr, and returns the Tool's
/// events and its stdout.
fn tool_stdout(program: &Program, plan: Plan) -> (Vec<Event>, Vec<u8>) {
    let (events, ending) = run_ending(program, plan);
    let (code, stdout, stderr) = ending.unwrap_or_else(|failure| panic!("{failure}: {events:?}"));
    assert_eq!((code, stderr), (0, vec![]), "{events:?}");
    (events, stdout)
}

/// Runs `program` under a [`TimerTool`] following `plan` and returns the
/// Tool's events and the record.
fn tool_fpu_record(program: &Program, plan: Plan) -> (Vec<Event>, FpuRecord) {
    let (events, stdout) = tool_stdout(program, plan);
    (events, FpuRecord::read(&stdout))
}

/// The stdout of `program` under the backend's own runtime and under a Tool
/// that delivers every signal.
fn kvm_stdouts(program: &Program) -> [(&'static str, Vec<u8>); 2] {
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    [
        ("runtime", direct_stdout(program)),
        ("tool", tool_stdout(program, plan).1),
    ]
}

/// Checks a guest whose signal comes at the instruction it marks in r12, in
/// every run: natively, under the backend's runtime and under a Tool. Each
/// run's handler starts in Linux's initial FPU state, the interrupted code's
/// state is intact after it, and KVM's records equal the native one.
fn fpu_state_matches_native_at_mark(program: &Program) {
    fpu_matches_native_at_mark(program, check_fpu_record);
}

/// [`fpu_state_matches_native_at_mark`], with `check` for each record.
fn fpu_matches_native_at_mark(program: &Program, check: impl Fn(&FpuRecord, &str)) {
    let native = native_fpu_record(program);
    check(&native, "native");
    assert_eq!(native.rip, native.r12, "native: {native:x?}");
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    for (name, record) in [
        ("runtime", direct_fpu_record(program)),
        ("tool", tool_fpu_record(program, plan).1),
    ] {
        check(&record, name);
        assert_eq!(record.rip, record.r12, "{name}: {record:x?}");
        assert_eq!(
            record.fpu(),
            native.fpu(),
            "{name} {record:x?}, native {native:x?}"
        );
    }
}

#[test]
fn a_handler_at_a_syscall_return_starts_with_linuxs_initial_fpu_state() {
    if bounded("a_handler_at_a_syscall_return_starts_with_linuxs_initial_fpu_state") {
        return;
    }
    // The guest loads its FPU state and sends SIGUSR1 to itself with tgkill,
    // which is delivered at that call's return.
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", ""));
    fpu_state_matches_native_at_mark(&program);
}

/// A guest that runs `load` and sends SIGUSR1 to itself with tgkill, marking
/// that call's return in r12, and installs `handler` (an [`fpu_handler`])
/// for it.
fn fpu_at_syscall_return(load: &str, handler: &str) -> Program {
    Program::new(&format!(
        "{}mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\nmov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
         {load}mov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $10,%edx\nlea 1f(%rip),%r12\n\
         mov $234,%eax\nsyscall\n1:\n{}{handler}",
        fpu_install(libc::SIGUSR1, "usr1_action"),
        fpu_after(),
    ))
}

#[test]
fn a_handler_at_a_user_trap_starts_with_linuxs_initial_fpu_state() {
    if bounded("a_handler_at_a_user_trap_starts_with_linuxs_initial_fpu_state") {
        return;
    }
    // The guest loads its FPU state and runs a ud2, whose SIGILL handler
    // steps over it.
    let program = Program::new(&format!(
        "{}{FPU_LOAD}lea 1f(%rip),%r12\n1: ud2\n{}{}",
        fpu_install(libc::SIGILL, "ill_action"),
        fpu_after(),
        fpu_handler("ill_action", "addq $2,168(%rdx)\n")
    ));
    fpu_state_matches_native_at_mark(&program);
}

#[test]
fn a_handler_at_a_timer_boundary_starts_with_linuxs_initial_fpu_state() {
    if bounded("a_handler_at_a_timer_boundary_starts_with_linuxs_initial_fpu_state") {
        return;
    }
    // The spinner of `a_spinner_signalled_by_a_sibling_gets_its_handler_at_the_next_timer_boundary`,
    // which loads its FPU state before it starts the sibling and spins until
    // its handler has run. Natively, the sibling's SIGUSR1 comes wherever
    // the guest then is; under the Tool, at the timer boundary at the loop's
    // head.
    let program = Program::new(&format!(
        "{FPU_LOAD}{SIBLING}{GETPPID}lea 1f(%rip),%r12\nmov $2000000000,%rcx\n\
         1: cmpb $0,flag(%rip)\njne 2f\ndec %rcx\njnz 1b\n2:\n{}{}",
        fpu_after(),
        fpu_handler("usr1_action", "")
    ));
    let native = native_fpu_record(&program);
    check_fpu_record(&native, "native");
    for _ in 0..REPEATS {
        let (events, record) = tool_fpu_record(&program, spinner_plan());
        let context = format!("{record:x?} {events:?}");
        let (timer_at, timer_clock) = first_timer(&events);
        let delivered = sigusr1_clocks(&events);
        assert_eq!(delivered.len(), 1, "{context}");
        assert!(delivered[0].0 > timer_at, "{context}");
        assert_eq!(delivered[0].1, timer_clock, "{context}");
        let r = registers_of(&events);
        assert_eq!((record.rip, record.r12), (r.rip, r.rip), "{context}");
        check_fpu_record(&record, "tool");
        assert_eq!(record.fpu(), native.fpu(), "{context}, native {native:x?}");
    }
}

/// The MXCSR_MASK field of an FXSAVE image taken on this CPU, which Linux
/// writes into every signal frame.
fn cpu_mxcsr_mask() -> u32 {
    #[repr(C, align(16))]
    struct FxsaveArea([u8; 512]);
    let mut area = FxsaveArea([0; 512]);
    // SAFETY: FXSAVE writes exactly this 512-byte, 16-byte-aligned area.
    unsafe { std::arch::x86_64::_fxsave64(area.0.as_mut_ptr()) };
    u32::from_ne_bytes(area.0[28..32].try_into().unwrap())
}

/// DAZ, MXCSR bit 6: denormal operands are read as zero.
const DAZ: u32 = 1 << 6;

#[test]
fn an_interrupted_mxcsr_with_daz_survives_a_signal_handler() {
    if bounded("an_interrupted_mxcsr_with_daz_survives_a_signal_handler") {
        return;
    }
    assert_ne!(cpu_mxcsr_mask() & DAZ, 0, "this CPU has no DAZ");
    // The guest loads MXCSR 0x1fc0, with DAZ, as -ffast-math startup code
    // does; Linux saves it in the frame and restores it at rt_sigreturn.
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler_loading("usr1_action", "", 0x1fc0));
    fpu_matches_native_at_mark(&program, |record, context| {
        check_loaded_fpu_record(record, context, 0x1fc0)
    });
}

#[test]
fn a_handler_may_set_daz_in_its_frames_mxcsr() {
    if bounded("a_handler_may_set_daz_in_its_frames_mxcsr") {
        return;
    }
    assert_ne!(cpu_mxcsr_mask() & DAZ, 0, "this CPU has no DAZ");
    // The handler writes MXCSR 0x5fc0 (DAZ, rounding up) into its frame, and
    // the interrupted code resumes with it.
    let edit = "mov 224(%rdx),%rax\nmovl $0x5fc0,24(%rax)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_at_mark(&program, |record, context| {
        check_loaded_fpu_record(record, context, 0x5fc0)
    });
}

/// A C program built with -ffast-math, whose startup code sets DAZ and FTZ,
/// that takes a signal and returns from its handler.
const FAST_MATH_GUEST: &str = r#"#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>

static volatile sig_atomic_t entries;
static volatile unsigned int handler_mxcsr;

static void handler(int signal) {
  (void)signal;
  handler_mxcsr = _mm_getcsr();
  entries++;
}

int main(void) {
  struct sigaction action;
  memset(&action, 0, sizeof action);
  action.sa_handler = handler;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL) != 0)
    return 1;
  unsigned int before = _mm_getcsr();
  if (raise(SIGUSR1) != 0)
    return 2;
  unsigned int after = _mm_getcsr();
  volatile float tiny = 1e-40f;
  volatile float sum = tiny + 0.0f;
  printf("mxcsr %#x before, %#x in the handler, %#x after; %d handler entries; subnormal + 0 is %s\n",
         before, handler_mxcsr, after, (int)entries, sum == 0.0f ? "zero" : "subnormal");
  return 0;
}
"#;

#[test]
fn a_fast_math_program_returns_from_a_signal_handler() {
    if bounded("a_fast_math_program_returns_from_a_signal_handler") {
        return;
    }
    let program = Program::c(FAST_MATH_GUEST, &["-ffast-math"]);
    let native = native_stdout(&program);
    assert_eq!(
        String::from_utf8_lossy(&native),
        "mxcsr 0x9fc0 before, 0x1f80 in the handler, 0x9fc0 after; 1 handler entries; \
         subnormal + 0 is zero\n",
        "native"
    );
    for (name, stdout) in kvm_stdouts(&program) {
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&native),
            "{name}"
        );
    }
}

#[test]
fn a_handlers_edits_to_fpu_state_the_interrupted_code_never_used_take_effect() {
    if bounded("a_handlers_edits_to_fpu_state_the_interrupted_code_never_used_take_effect") {
        return;
    }
    // The guest uses no x87, SSE or AVX instruction before its signal, so
    // that state is initial. Its handler sets the frame's x87 control word to
    // 0x027f, MXCSR to 0x5f80 and XMM5 to a pattern; Linux marks x87 and SSE
    // present in every frame, so rt_sigreturn applies the three edits.
    let edit = "mov 224(%rdx),%rax\nmovw $0x027f,(%rax)\nmovl $0x5f80,24(%rax)\n\
                movabs $0x5555555555555555,%rcx\nmov %rcx,240(%rax)\nmov %rcx,248(%rax)\n";
    let program = fpu_at_syscall_return("", &fpu_handler("usr1_action", edit));
    fpu_matches_native_at_mark(&program, |record, context| {
        let context = format!("{context}: {record:x?}");
        assert_eq!(record.entries, 1, "{context}");
        assert_eq!(record.handler, FpuState::INITIAL, "{context}");
        let pattern = 0x5555_5555_5555_5555;
        assert_eq!(
            (record.after.control, record.after.mxcsr, record.after.ymm5),
            (0x027f, 0x5f80, [pattern, pattern, 0, 0]),
            "{context}"
        );
    });
}

#[test]
fn rt_sigreturn_takes_mxcsr_from_a_frame_whose_header_leaves_sse_initial() {
    if bounded("rt_sigreturn_takes_mxcsr_from_a_frame_whose_header_leaves_sse_initial") {
        return;
    }
    // The handler sets its frame's MXCSR to 0x5f80 and clears the SSE and YMM
    // bits of its XSTATE_BV, keeping the x87 bit or clearing it too. Linux's
    // XRSTOR then zeroes XMM5 and YMM5 but still loads MXCSR from the frame.
    for header in [1, 0] {
        let edit = format!("mov 224(%rdx),%rax\nmovl $0x5f80,24(%rax)\nmovq ${header},512(%rax)\n");
        let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", &edit));
        fpu_matches_native_at_mark(&program, |record, context| {
            let context = format!("{context}, XSTATE_BV {header}: {record:x?}");
            assert_eq!(record.entries, 1, "{context}");
            assert_eq!(
                (record.after.mxcsr, record.after.ymm5),
                (0x5f80, [0; 4]),
                "{context}"
            );
        });
    }
}

/// Whether this process's soft RLIMIT_CORE is 1, the native runs' limit.
fn limit_is_one() -> bool {
    // SAFETY: limit is writable for the call.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) == 0 && limit.rlim_cur == 1 }
}

/// Runs `program` natively, with no core dump, and returns how it ended.
fn native_output(program: &Program) -> std::process::Output {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new("timeout");
    command
        .args(["--kill-after=2s", "30s"])
        .arg(&program.executable)
        .current_dir(&program.directory);
    // SAFETY: setrlimit is async-signal-safe and touches no memory the
    // parent shares.
    unsafe {
        command.pre_exec(|| {
            // A core_pattern that pipes core dumps to a program ignores
            // RLIMIT_CORE except for the value 1, with which the kernel
            // skips the dump.
            let one = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            match libc::setrlimit(libc::RLIMIT_CORE, &one) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        });
    }
    command.output().unwrap()
}

/// Checks that `program` ends with SIGSEGV and writes nothing, natively,
/// under the backend's own runtime and under a Tool that delivers every
/// signal.
fn segfaults_natively_and_on_kvm(program: &Program) {
    use std::os::unix::process::ExitStatusExt;
    let output = native_output(program);
    // timeout ends itself with the signal that ended its child.
    assert_eq!(
        (output.status.signal(), output.stdout, output.stderr),
        (Some(libc::SIGSEGV), vec![], vec![]),
        "native: {}",
        output.status
    );
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    assert_eq!(
        backend.run_static_elf_captured().unwrap(),
        (128 + libc::SIGSEGV, vec![], vec![]),
        "runtime"
    );
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    let (events, ending) = run_ending(program, plan);
    assert_eq!(
        ending,
        Ok((128 + libc::SIGSEGV, vec![], vec![])),
        "tool: {events:?}"
    );
}

#[test]
fn rt_sigreturn_ignores_mxcsr_where_linux_does_not_load_it() {
    if bounded("rt_sigreturn_ignores_mxcsr_where_linux_does_not_load_it") {
        return;
    }
    // The handler sets a reserved MXCSR bit in its frame, and the frame's
    // software xfeatures and XSTATE_BV to x87 alone or to nothing. XRSTOR
    // loads, and so checks, MXCSR only for requested SSE or YMM state, and
    // Linux initializes SSE and YMM state afterwards: MXCSR 0x1f80 and zero
    // YMM5. x87 state comes from the frame when it is requested, and is
    // initialized otherwise, which leaves FSTP an empty stack to store.
    for bit in [16, 31] {
        let reserved = 1u32 << bit;
        for features in [1, 0] {
            let edit = format!(
                "mov 224(%rdx),%rax\norl ${reserved:#x},24(%rax)\nmovq ${features},472(%rax)\n\
                 movq ${features},512(%rax)\n"
            );
            let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", &edit));
            fpu_matches_native_at_mark(&program, |record, context| {
                let context =
                    format!("{context}, MXCSR bit {bit}, features {features}: {record:x?}");
                assert_eq!(record.entries, 1, "{context}");
                assert_eq!(record.handler, FpuState::INITIAL, "{context}");
                assert_eq!(
                    (record.after.mxcsr, record.after.ymm5),
                    (0x1f80, [0; 4]),
                    "{context}"
                );
                if features == 1 {
                    assert_eq!(
                        (record.after.control, record.after.tags, record.stack),
                        (0x027f, FpuState::LOADED.tags, FPU_STACK),
                        "{context}"
                    );
                } else {
                    assert_eq!(
                        (record.after.control, record.after.status, record.after.tags),
                        (0x037f, 0, 0xffff),
                        "{context}"
                    );
                }
            });
        }
        // With SSE requested, as in the frame as built, the bit faults.
        let edit = format!("mov 224(%rdx),%rax\norl ${reserved:#x},24(%rax)\n");
        let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", &edit));
        segfaults_natively_and_on_kvm(&program);
    }
}

#[test]
fn rt_sigreturn_initializes_ymm_state_the_frames_features_leave_out() {
    if bounded("rt_sigreturn_initializes_ymm_state_the_frames_features_leave_out") {
        return;
    }
    // The handler sets its frame's software xfeatures to x87 and SSE,
    // leaving XSTATE_BV marking YMM present. XRSTOR ignores that bit, and
    // Linux initializes YMM state afterwards: YMM5's upper half is zero,
    // and the rest comes from the frame, MXCSR 0x7f80 included where the
    // host's format keeps it.
    let edit = "mov 224(%rdx),%rax\nmovq $3,472(%rax)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_but_mxcsr_at_mark(&program, 0x7f80, |record, context| {
        let context = format!("{context}: {record:x?}");
        assert_eq!(record.entries, 1, "{context}");
        assert_eq!(
            (record.after.control, record.stack),
            (0x027f, FPU_STACK),
            "{context}"
        );
        assert_eq!(
            record.after.ymm5,
            [FPU_YMM5[0], FPU_YMM5[1], 0, 0],
            "{context}"
        );
    });
}

#[test]
fn rt_sigreturn_restores_a_frame_without_magic2_as_legacy_state() {
    if bounded("rt_sigreturn_restores_a_frame_without_magic2_as_legacy_state") {
        return;
    }
    // The handler sets its frame's MXCSR to 0x5f80 and XMM5 to a pattern,
    // and clears FP_XSTATE_MAGIC2 after the frame's xstate_size bytes.
    // Linux then restores the frame's legacy FXSAVE image, the edits
    // included (MXCSR where the host's format keeps it), and initializes
    // YMM state.
    let edit = "mov 224(%rdx),%rax\nmovl $0x5f80,24(%rax)\nmovabs $0x5555555555555555,%rcx\n\
                mov %rcx,240(%rax)\nmov %rcx,248(%rax)\nmov 480(%rax),%ecx\nmovl $0,(%rax,%rcx)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_but_mxcsr_at_mark(&program, 0x5f80, |record, context| {
        let context = format!("{context}: {record:x?}");
        assert_eq!(record.entries, 1, "{context}");
        let pattern = 0x5555_5555_5555_5555;
        assert_eq!(
            (record.after.control, record.stack),
            (0x027f, FPU_STACK),
            "{context}"
        );
        assert_eq!(record.after.ymm5, [pattern, pattern, 0, 0], "{context}");
    });
}

/// Whether this host's Linux keeps FPU state in the compacted format, as it
/// does when it uses XSAVEC or XSAVES (`fpu__init_system_xstate`); the
/// kernel lists the features it uses in /proc/cpuinfo.
fn linux_uses_compacted_xstate() -> bool {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap();
    let flags = cpuinfo
        .lines()
        .find(|line| line.starts_with("flags"))
        .expect("a flags line in /proc/cpuinfo");
    flags
        .split_whitespace()
        .any(|flag| flag == "xsavec" || flag == "xsaves")
}

/// [`fpu_matches_native_at_mark`] for a frame whose features include SSE but
/// not YMM, or that Linux restores as a legacy FXSAVE image. Linux then
/// initializes YMM state with an XRSTOR of its initial state, which on a
/// host whose kernel keeps FPU state in the standard format also loads that
/// state's MXCSR, 0x1f80; with the compacted format MXCSR stays `restored`,
/// the frame's. So natively MXCSR must be Linux's answer for this host;
/// under KVM it must be `restored`, the backend's answer on every host; and
/// every other field must equal the native one.
fn fpu_matches_native_but_mxcsr_at_mark(
    program: &Program,
    restored: u32,
    check: impl Fn(&FpuRecord, &str),
) {
    let native = native_fpu_record(program);
    let native_mxcsr = if linux_uses_compacted_xstate() {
        restored
    } else {
        0x1f80
    };
    assert_eq!(native.after.mxcsr, native_mxcsr, "native: {native:x?}");
    check(&native, "native");
    assert_eq!(native.rip, native.r12, "native: {native:x?}");
    // Everything but the MXCSR the guest finds after the return.
    let rest = |record: &FpuRecord| {
        let mut fpu = record.fpu();
        fpu.2.mxcsr = 0;
        fpu
    };
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    for (name, record) in [
        ("runtime", direct_fpu_record(program)),
        ("tool", tool_fpu_record(program, plan).1),
    ] {
        assert_eq!(record.after.mxcsr, restored, "{name}: {record:x?}");
        check(&record, name);
        assert_eq!(record.rip, record.r12, "{name}: {record:x?}");
        assert_eq!(
            rest(&record),
            rest(&native),
            "{name} {record:x?}, native {native:x?}"
        );
    }
}

#[test]
fn rt_sigreturn_ignores_the_software_reserved_padding() {
    if bounded("rt_sigreturn_ignores_the_software_reserved_padding") {
        return;
    }
    // The handler sets its frame's MXCSR to 0x5f80 and a padding byte of
    // the software-reserved bytes, which Linux never reads.
    let edit = "mov 224(%rdx),%rax\nmovl $0x5f80,24(%rax)\nmovb $0xa5,490(%rax)\n";
    let program = fpu_at_syscall_return(FPU_LOAD, &fpu_handler("usr1_action", edit));
    fpu_matches_native_at_mark(&program, |record, context| {
        check_loaded_fpu_record(record, context, 0x5f80)
    });
}

/// What the guest of
/// `a_frame_after_a_null_fpregs_return_carries_the_cpus_mxcsr_mask` writes:
/// how many times each handler ran; the MXCSR_MASK and MXCSR in SIGUSR2's
/// frame; MXCSR as SIGUSR2's handler starts; the bits of a subnormal plus
/// zero there, computed with DAZ when that frame's mask offers it; the
/// frame's rip and r12; MXCSR once both handlers have returned; the frame's
/// XSTATE_BV; and YMM5 once both handlers have returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QueuedRecord {
    first_entries: u64,
    second_entries: u64,
    frame_mask: u32,
    frame_mxcsr: u32,
    handler_mxcsr: u32,
    sum: u32,
    rip: u64,
    r12: u64,
    after_mxcsr: u32,
    frame_xstate_bv: u64,
    after_ymm5: [u64; 4],
}

impl QueuedRecord {
    fn read(stdout: &[u8]) -> Self {
        assert_eq!(stdout.len(), 112, "{stdout:?}");
        let quad = |i: usize| u64::from_ne_bytes(stdout[8 * i..8 * i + 8].try_into().unwrap());
        Self {
            first_entries: quad(0),
            second_entries: quad(1),
            frame_mask: quad(2) as u32,
            frame_mxcsr: quad(3) as u32,
            handler_mxcsr: quad(4) as u32,
            sum: quad(5) as u32,
            rip: quad(6),
            r12: quad(7),
            after_mxcsr: quad(8) as u32,
            frame_xstate_bv: quad(9),
            after_ymm5: [quad(10), quad(11), quad(12), quad(13)],
        }
    }

    /// The record without what may differ from the native one: the frame's
    /// rip and r12, and its XSTATE_BV bit for PKRU, which the guest lacks.
    fn comparable(self) -> Self {
        const PKRU: u64 = 1 << 9;
        Self {
            rip: 0,
            r12: 0,
            frame_xstate_bv: self.frame_xstate_bv & !PKRU,
            ..self
        }
    }
}

#[test]
fn a_frame_after_a_null_fpregs_return_carries_the_cpus_mxcsr_mask() {
    if bounded("a_frame_after_a_null_fpregs_return_carries_the_cpus_mxcsr_mask") {
        return;
    }
    // The guest loads MXCSR 0x7f80 and a nonzero YMM5 and sends itself
    // SIGUSR1, whose handler blocks SIGUSR2 (its sa_mask), sends it, sets
    // uc_mcontext.fpregs to NULL and returns. rt_sigreturn installs the
    // initial FPU state and unblocks SIGUSR2, which is delivered at once, at
    // the same return; its frame records that state with the CPU's
    // MXCSR_MASK, and with x87 and SSE state present and YMM state absent.
    // Its handler sets DAZ when that mask offers it, as a program probing
    // for DAZ does, and adds zero to a subnormal; it also writes the upper
    // half of YMM5 in its frame without marking YMM present, an edit
    // rt_sigreturn ignores.
    let program = Program::new(
        "mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
         mov $12,%edi\nlea usr2_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\n\
         mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\nmov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
         ldmxcsr loaded(%rip)\nvmovdqu loaded_ymm5(%rip),%ymm5\n\
         mov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $10,%edx\nlea 1f(%rip),%r12\n\
         mov $234,%eax\nsyscall\n1: stmxcsr rec+64(%rip)\nvmovdqu %ymm5,rec+80(%rip)\n\
         mov $1,%edi\nlea rec(%rip),%rsi\nmov $112,%edx\nmov $1,%eax\nsyscall\n\
         xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n\
         first: mov %rdx,%r9\nmov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov $12,%edx\nmov $234,%eax\nsyscall\n\
         movq $0,224(%r9)\nincq rec(%rip)\nret\n\
         second: mov 224(%rdx),%r8\nmov 28(%r8),%eax\nmov %rax,rec+16(%rip)\n\
         mov 24(%r8),%eax\nmov %rax,rec+24(%rip)\nstmxcsr rec+32(%rip)\n\
         mov 168(%rdx),%rax\nmov %rax,rec+48(%rip)\nmov 72(%rdx),%rax\nmov %rax,rec+56(%rip)\n\
         mov 512(%r8),%rax\nmov %rax,rec+72(%rip)\n\
         movabs $0x6666666666666666,%rax\nmov %rax,656(%r8)\nmov %rax,664(%r8)\n\
         testl $0x40,28(%r8)\njz 2f\nldmxcsr daz(%rip)\n\
         2: movss subnormal(%rip),%xmm0\naddss zero(%rip),%xmm0\nmovd %xmm0,%eax\nmov %rax,rec+40(%rip)\n\
         incq rec+8(%rip)\nret\n\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\nusr1_action: .quad first, 0x4000004, restorer, 0x800\n\
         usr2_action: .quad second, 0x4000004, restorer, 0\npid: .quad 0\ntid: .quad 0\n\
         loaded: .long 0x7f80\ndaz: .long 0x1fc0\nsubnormal: .long 1\nzero: .long 0\n\
         .balign 32\nloaded_ymm5: .quad 0x1111111111111111, 0x2222222222222222, \
         0x3333333333333333, 0x4444444444444444\n\
         .balign 8\nrec: .zero 112\n",
    );
    let native = QueuedRecord::read(&native_stdout(&program));
    let mask = cpu_mxcsr_mask();
    let expected = QueuedRecord {
        first_entries: 1,
        second_entries: 1,
        frame_mask: mask,
        frame_mxcsr: 0x1f80,
        handler_mxcsr: 0x1f80,
        sum: if mask & DAZ != 0 { 0 } else { 1 },
        after_mxcsr: 0x1f80,
        after_ymm5: [0; 4],
        ..native
    };
    assert_eq!(native, expected, "native");
    assert_eq!(native.rip, native.r12, "native: {native:x?}");
    assert_eq!(
        native.comparable().frame_xstate_bv,
        0b011,
        "native: {native:x?}"
    );
    for (name, stdout) in kvm_stdouts(&program) {
        let record = QueuedRecord::read(&stdout);
        assert_eq!(record.rip, record.r12, "{name}: {record:x?}");
        assert_eq!(
            record.comparable(),
            native.comparable(),
            "{name}: {record:x?}, native {native:x?}"
        );
    }
}

// Every eligible signal at one return to user mode
// (<https://github.com/rrnewton/reverie/issues/1188>).
//
// Linux's `exit_to_user_mode_loop` calls `arch_do_signal_or_restart` again
// while a signal is pending that the mask leaves unblocked: each frame goes on
// top of the last, so the handler of the last signal selected runs first, and
// its frame saves the handler of the frame below at its first instruction. The
// guests below make two or more signals eligible at one return, at each of the
// backend's delivery points, and log what every handler finds at its first
// instruction. Each log is compared with the same binary's natively, run under
// a minimal ptrace tracer (see [`traced_native`]), which stops the guest where a
// Tool's signal hook runs.

/// Quads in one entry of a stacked-signal guest's log (see [`record_entry`]);
/// [`q`] names them.
const ENTRY_QUADS: usize = 40;
/// Entries a stacked-signal guest's log holds.
const MAX_ENTRIES: usize = 8;
/// Quads before the entries: their count, the signal mask and the alternate
/// stack (sp, flags, size) once the handlers have returned, the alternate
/// stack as [`QUERY_STACK`] found it, if the guest ran it (zeros otherwise),
/// and [`RESULTS`] syscall results the guest kept with [`keep_result`].
const HEADER_QUADS: usize = 8 + RESULTS;
/// The syscall results a stacked-signal guest can keep in its header.
const RESULTS: usize = 4;
/// The bytes a stacked-signal guest writes to stdout before it exits.
const LOG_BYTES: usize = 8 * (HEADER_QUADS + MAX_ENTRIES * ENTRY_QUADS);

/// The quads of a log entry: what the handler's registers held at its first
/// instruction (rdi, rsp, rsi, rdx, rflags and its own address), and then what
/// its siginfo and ucontext hold.
mod q {
    pub const SIGNAL: usize = 0;
    pub const ENTRY_RSP: usize = 1;
    pub const ENTRY_RSI: usize = 2;
    pub const ENTRY_RDX: usize = 3;
    pub const ENTRY_RFLAGS: usize = 4;
    pub const HANDLER: usize = 5;
    pub const SI_SIGNO: usize = 6;
    pub const SI_CODE: usize = 7;
    pub const UC_FLAGS: usize = 8;
    pub const UC_LINK: usize = 9;
    pub const SS_SP: usize = 10;
    pub const SS_FLAGS: usize = 11;
    pub const SS_SIZE: usize = 12;
    pub const RDI: usize = 13;
    pub const RSI: usize = 14;
    pub const RBP: usize = 15;
    pub const RBX: usize = 16;
    pub const RDX: usize = 17;
    pub const RAX: usize = 18;
    pub const RCX: usize = 19;
    pub const RSP: usize = 20;
    pub const RIP: usize = 21;
    pub const EFLAGS: usize = 22;
    pub const ERR: usize = 23;
    pub const TRAPNO: usize = 24;
    pub const OLDMASK: usize = 25;
    pub const CR2: usize = 26;
    pub const SIGMASK: usize = 27;
    pub const R12: usize = 28;
    pub const MXCSR: usize = 29;
    /// The x87 control word, then the status word at bit 16 and the
    /// abridged tag word at bit 32.
    pub const X87: usize = 30;
    pub const XSTATE_BV: usize = 31;
    /// The low quad of XMM5.
    pub const XMM5: usize = 32;
}

/// Every logged quad a stacked-signal test compares between runs, by name.
/// The handler's rsp, rsi and rdx at its first instruction are addresses that
/// the run's signal-frame size decides, so they are compared only through the
/// frames that saved them (see [`comparable`]).
const COMPARED: [(&str, usize); 30] = [
    ("signal", q::SIGNAL),
    ("entry rflags", q::ENTRY_RFLAGS),
    ("handler", q::HANDLER),
    ("si_signo", q::SI_SIGNO),
    ("si_code", q::SI_CODE),
    ("uc_flags", q::UC_FLAGS),
    ("uc_link", q::UC_LINK),
    ("ss_sp", q::SS_SP),
    ("ss_flags", q::SS_FLAGS),
    ("ss_size", q::SS_SIZE),
    ("rdi", q::RDI),
    ("rsi", q::RSI),
    ("rbp", q::RBP),
    ("rbx", q::RBX),
    ("rdx", q::RDX),
    ("rax", q::RAX),
    ("rcx", q::RCX),
    ("rsp", q::RSP),
    ("rip", q::RIP),
    ("eflags", q::EFLAGS),
    ("err", q::ERR),
    ("trapno", q::TRAPNO),
    ("oldmask", q::OLDMASK),
    ("cr2", q::CR2),
    ("uc_sigmask", q::SIGMASK),
    ("r12", q::R12),
    ("mxcsr", q::MXCSR),
    ("x87", q::X87),
    ("xstate_bv", q::XSTATE_BV),
    ("xmm5", q::XMM5),
];

/// Assembly, at the first instruction of the handler for `signal`, that
/// appends an entry to `log` and counts it in the first header quad. It reads
/// rflags first, before any instruction that sets flags, and uses rax, rcx,
/// r8 to r11 and the stack below rsp, all free in a handler that returns
/// through rt_sigreturn.
fn record_entry(signal: i32) -> String {
    let at = |quad: usize| 8 * quad;
    let mut code = format!(
        "pushfq\npop %r8\n\
         mov header(%rip),%r11\ncmp ${MAX_ENTRIES},%r11\njae 8f\nlea 1(%r11),%r10\nmov %r10,header(%rip)\n\
         imul ${},%r11,%r9\nlea log(%rip),%r10\nadd %r10,%r9\nmov %r8,{}(%r9)\n\
         mov %rdi,{}(%r9)\nmov %rsp,{}(%r9)\nmov %rsi,{}(%r9)\nmov %rdx,{}(%r9)\n\
         lea handler_{signal}(%rip),%rax\nmov %rax,{}(%r9)\n",
        8 * ENTRY_QUADS,
        at(q::ENTRY_RFLAGS),
        at(q::SIGNAL),
        at(q::ENTRY_RSP),
        at(q::ENTRY_RSI),
        at(q::ENTRY_RDX),
        at(q::HANDLER),
    );
    // Quads of the siginfo (rsi) and the ucontext (rdx). The 32-bit fields
    // are read alone: Linux leaves the padding after them unwritten.
    let quads = [
        ("0(%rsi)", q::SI_SIGNO),
        ("0(%rdx)", q::UC_FLAGS),
        ("8(%rdx)", q::UC_LINK),
        ("16(%rdx)", q::SS_SP),
        ("32(%rdx)", q::SS_SIZE),
        ("104(%rdx)", q::RDI),
        ("112(%rdx)", q::RSI),
        ("120(%rdx)", q::RBP),
        ("128(%rdx)", q::RBX),
        ("136(%rdx)", q::RDX),
        ("144(%rdx)", q::RAX),
        ("152(%rdx)", q::RCX),
        ("160(%rdx)", q::RSP),
        ("168(%rdx)", q::RIP),
        ("176(%rdx)", q::EFLAGS),
        ("192(%rdx)", q::ERR),
        ("200(%rdx)", q::TRAPNO),
        ("208(%rdx)", q::OLDMASK),
        ("216(%rdx)", q::CR2),
        ("296(%rdx)", q::SIGMASK),
        ("72(%rdx)", q::R12),
    ];
    for (source, quad) in quads {
        code += &format!("mov {source},%rax\nmov %rax,{}(%r9)\n", at(quad));
    }
    for (source, quad) in [("8(%rsi)", q::SI_CODE), ("24(%rdx)", q::SS_FLAGS)] {
        code += &format!("movl {source},%eax\nmov %rax,{}(%r9)\n", at(quad));
    }
    // The frame's FPU state, which uc_mcontext.fpregs points to.
    code += &format!(
        "mov 224(%rdx),%r8\nmovl 24(%r8),%eax\nmov %rax,{}(%r9)\n\
         movzwl 0(%r8),%eax\nmovzwl 2(%r8),%ecx\nshl $16,%rcx\nor %rcx,%rax\n\
         movzbl 4(%r8),%ecx\nshl $32,%rcx\nor %rcx,%rax\nmov %rax,{}(%r9)\n\
         mov 512(%r8),%rax\nmov %rax,{}(%r9)\nmov 240(%r8),%rax\nmov %rax,{}(%r9)\n8:\n",
        at(q::MXCSR),
        at(q::X87),
        at(q::XSTATE_BV),
        at(q::XMM5),
    );
    code
}

/// A signal handler of a stacked-signal guest.
struct Handler {
    signal: i32,
    /// sigaction flags besides SA_SIGINFO and SA_RESTORER.
    flags: u64,
    /// sa_mask.
    mask: u64,
    /// What the handler runs after it logs its entry, before it returns.
    actions: String,
}

impl Handler {
    fn new(signal: i32) -> Self {
        Self {
            signal,
            flags: 0,
            mask: 0,
            actions: String::new(),
        }
    }

    fn flags(self, flags: u64) -> Self {
        Self { flags, ..self }
    }

    fn mask(self, mask: u64) -> Self {
        Self { mask, ..self }
    }

    fn actions(self, actions: &str) -> Self {
        Self {
            actions: actions.to_owned(),
            ..self
        }
    }
}

const SA_ONSTACK: u64 = 0x0800_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SS_AUTODISARM: u64 = 1 << 31;
const SS_DISABLE: u64 = 2;

/// The bit of `signal` in a signal mask.
const fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}

/// Values the stacked-signal guests keep in rbx and rbp, which their frames
/// then save.
const RBX: u64 = 0x0123_4567_89ab_cdef;
const RBP: u64 = 0x1122_3344_5566_7788;

/// The MXCSR and XMM5 low quad a stacked-signal guest loads with
/// [`LOAD_FPU`]: the interrupted state that the first frame saves.
const LOADED_MXCSR: u64 = 0x7f80;
const LOADED_XMM5: u64 = 0x1111_1111_1111_1111;
const LOAD_FPU: &str = "ldmxcsr loaded_mxcsr(%rip)\nmovdqu loaded_xmm5(%rip),%xmm5\n";

/// A static guest that keeps its argument count in `argc`, switches to its own
/// stack, sets rbx and rbp to [`RBX`] and [`RBP`], disables the alternate stack
/// (unless it has arguments: an image the guest itself executed), installs
/// `handlers` (exiting with status 1 if that or an install fails), keeps its
/// pid and tid in `pid` and `tid`, runs `body`, writes its log ([`StackedLog`])
/// to stdout and exits with status 0. `data` adds to its data, and `bss` to its
/// zeroed memory.
///
/// The guest disables the alternate stack itself because a frame's uc_stack
/// saves the stack's flags as the task holds them, and exec clears only the
/// stack's address and size (`begin_new_exec` in fs/exec.c): natively a guest
/// would otherwise keep its launcher's flags (0 from a Rust test thread, which
/// has an alternate stack of its own), while KVM starts every guest with
/// Linux's initial SS_DISABLE.
fn stacked_program(handlers: &[Handler], body: &str, data: &str, bss: &str) -> Program {
    let install: String = handlers
        .iter()
        .map(|handler| {
            format!(
                "mov ${s},%edi\nlea action_{s}(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\n\
                 syscall\ntest %rax,%rax\njnz 99f\n",
                s = handler.signal
            )
        })
        .collect();
    let code: String = handlers
        .iter()
        .map(|handler| {
            format!(
                "handler_{}:\n{}{}ret\n",
                handler.signal,
                record_entry(handler.signal),
                handler.actions
            )
        })
        .collect();
    let actions: String = handlers
        .iter()
        .map(|handler| {
            format!(
                "action_{s}: .quad handler_{s}, {:#x}, restorer, {:#x}\n",
                HANDLER_FLAGS | handler.flags,
                handler.mask,
                s = handler.signal
            )
        })
        .collect();
    Program::new(&format!(
        "mov (%rsp),%rax\nmov %rax,argc(%rip)\n\
         lea stack_end(%rip),%rsp\nmovabs ${RBX:#x},%rbx\nmovabs ${RBP:#x},%rbp\n\
         cmpq $1,argc(%rip)\njne 97f\n\
         lea no_altstack(%rip),%rdi\nxor %esi,%esi\nmov $131,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n\
         97:\n{install}\
         mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\nmov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
         {body}\
         xor %edi,%edi\nxor %esi,%esi\nlea header+8(%rip),%rdx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n\
         xor %edi,%edi\nlea header+16(%rip),%rsi\nmov $131,%eax\nsyscall\n\
         mov $1,%edi\nlea header(%rip),%rsi\nmov ${LOG_BYTES},%edx\nmov $1,%eax\nsyscall\n\
         xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n\
         99: mov $1,%edi\nmov $231,%eax\nsyscall\nud2\n\
         {code}\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\n{actions}pid: .quad 0\ntid: .quad 0\nargc: .quad 0\n\
         no_altstack: .quad 0\n.long {SS_DISABLE}, 0\n.quad 0\n\
         loaded_mxcsr: .long {LOADED_MXCSR:#x}\n.balign 16\nloaded_xmm5: .quad {LOADED_XMM5:#x}, 0\n\
         {data}\n.balign 64\nheader: .zero {}\nlog: .zero {}\n\
         .bss\n.balign 64\nstack: .skip 65536\nstack_end:\n{bss}\n",
        8 * HEADER_QUADS,
        8 * MAX_ENTRIES * ENTRY_QUADS,
    ))
}

/// rt_sigprocmask(`how`, the mask at label `mask`, NULL, 8).
fn sigprocmask(how: i32, mask: &str) -> String {
    format!(
        "mov ${how},%edi\nlea {mask}(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $14,%eax\nsyscall\n"
    )
}

/// tgkill of `signal` to the guest's main thread.
fn tgkill_self(signal: i32) -> String {
    format!("mov pid(%rip),%rdi\nmov tid(%rip),%rsi\nmov ${signal},%edx\nmov $234,%eax\nsyscall\n")
}

/// kill of `signal` to the guest's process.
fn kill_self(signal: i32) -> String {
    format!("mov pid(%rip),%rdi\nmov ${signal},%esi\nmov $62,%eax\nsyscall\n")
}

/// Loads [`LOAD_FPU`], blocks the signals at label `pending`, makes them
/// pending with `sends`, and unblocks them with an rt_sigprocmask whose return
/// r12 marks.
fn unblocked_at_syscall_return(sends: &str) -> String {
    format!(
        "{LOAD_FPU}{}{sends}lea 1f(%rip),%r12\n{}1:\n",
        sigprocmask(libc::SIG_BLOCK, "pending"),
        sigprocmask(libc::SIG_UNBLOCK, "pending")
    )
}

/// sigaltstack(NULL, the header's last three quads): the alternate stack as
/// the guest finds it there, which [`StackedLog::queried_stack`] reads.
const QUERY_STACK: &str = "xor %edi,%edi\nlea header+40(%rip),%rsi\nmov $131,%eax\nsyscall\n";

/// Keeps rax, a syscall's result, as result `index` of the guest's header
/// ([`StackedLog::results`]).
fn keep_result(index: usize) -> String {
    assert!(index < RESULTS);
    format!("mov %rax,header+{}(%rip)\n", 8 * (8 + index))
}

/// sigaltstack(the stack_t at `label`, NULL), its result kept as result
/// `index`.
fn set_altstack(label: &str, index: usize) -> String {
    format!(
        "lea {label}(%rip),%rdi\nxor %esi,%esi\nmov $131,%eax\nsyscall\n{}",
        keep_result(index)
    )
}

/// A stack_t at `label`: `sp` (an address or label), `flags` and `size`.
fn stack_t(label: &str, sp: &str, flags: u64, size: u64) -> String {
    format!("{label}: .quad {sp}\n.long {flags:#x}, 0\n.quad {size}\n")
}

/// Installs the alternate stack that [`altstack_data`] describes, exiting with
/// status 1 if that fails.
const ARM_ALTSTACK: &str = "lea altstack_desc(%rip),%rdi\nxor %esi,%esi\nmov $131,%eax\nsyscall\n\
     test %rax,%rax\njnz 99f\n";

/// The stack_t of a 64 KiB alternate stack at [`ALTSTACK`] with `flags`.
fn altstack_data(flags: u64) -> String {
    format!("altstack_desc: .quad altstack\n.long {flags:#x}, 0\n.quad 65536\n")
}

/// The memory of the alternate stack of [`altstack_data`].
const ALTSTACK: &str = ".balign 64\naltstack: .skip 65536\n";

/// One handler's entry in a stacked-signal guest's log.
#[derive(Clone, Copy, PartialEq, Eq)]
struct LoggedEntry([u64; ENTRY_QUADS]);

impl std::fmt::Debug for LoggedEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for (name, quad) in [
            ("entry rsp", q::ENTRY_RSP),
            ("entry rsi", q::ENTRY_RSI),
            ("entry rdx", q::ENTRY_RDX),
        ]
        .into_iter()
        .chain(COMPARED)
        {
            map.entry(&name, &format_args!("{:#x}", self.0[quad]));
        }
        map.finish()
    }
}

/// What a stacked-signal guest writes to stdout before it exits.
#[derive(Debug)]
struct StackedLog {
    entries: Vec<LoggedEntry>,
    /// The signal mask once every handler has returned.
    final_mask: u64,
    /// The alternate stack then: sp, flags and size.
    final_stack: [u64; 3],
    /// The alternate stack where the guest ran [`QUERY_STACK`]: sp, flags
    /// and size, or zeros.
    queried_stack: [u64; 3],
    /// The syscall results the guest kept with [`keep_result`], or zeros.
    results: [u64; RESULTS],
}

impl StackedLog {
    fn read(stdout: &[u8]) -> Self {
        assert_eq!(stdout.len(), LOG_BYTES, "{stdout:?}");
        let quad = |i: usize| u64::from_ne_bytes(stdout[8 * i..8 * i + 8].try_into().unwrap());
        let count = usize::try_from(quad(0)).unwrap();
        assert!(count <= MAX_ENTRIES, "{count} entries");
        let entries = (0..count)
            .map(|entry| {
                let first = HEADER_QUADS + entry * ENTRY_QUADS;
                LoggedEntry(std::array::from_fn(|i| quad(first + i)))
            })
            .collect();
        Self {
            entries,
            final_mask: quad(1),
            final_stack: [quad(2), quad(3) & u64::from(u32::MAX), quad(4)],
            queried_stack: [quad(5), quad(6) & u64::from(u32::MAX), quad(7)],
            results: std::array::from_fn(|i| quad(8 + i)),
        }
    }

    /// The signal of each entry, in the order the handlers ran.
    fn signals(&self) -> Vec<i32> {
        self.entries
            .iter()
            .map(|entry| entry.0[q::SIGNAL] as i32)
            .collect()
    }

    fn entry(&self, index: usize) -> &[u64; ENTRY_QUADS] {
        &self.entries[index].0
    }
}

/// A logged quad, as the runs compare it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    Value(u64),
    /// The value the handler of this entry found in this register at its
    /// first instruction: an address that the run's frame size decides.
    EntryOf(usize, &'static str),
    /// Left out of the comparison: where an interrupt landed.
    Varies,
}

/// What [`comparable`] returns: each entry's compared quads, by name.
type ComparedEntries = Vec<Vec<(&'static str, Seen)>>;

/// The entries of `log` as the runs compare them: every [`COMPARED`] quad,
/// with a saved rsp, rsi or rdx that some handler found in that register at
/// its first instruction written as that entry, XSTATE_BV cut to the x87, SSE
/// and AVX bits (the native frame adds what the host has, such as PKRU), and
/// the quads `varies` names left out. Every interrupted context the guests
/// compare is a call that takes no pid or tid, which differ between runs.
fn comparable(log: &StackedLog, varies: &dyn Fn(usize, usize) -> bool) -> ComparedEntries {
    let entry_of = |value: u64, register: usize| {
        let (name, at) = match register {
            q::RSP => ("rsp", q::ENTRY_RSP),
            q::RSI => ("rsi", q::ENTRY_RSI),
            q::RDX => ("rdx", q::ENTRY_RDX),
            _ => return None,
        };
        log.entries
            .iter()
            .position(|entry| entry.0[at] == value)
            .map(|index| Seen::EntryOf(index, name))
    };
    log.entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            COMPARED
                .iter()
                .map(|&(name, quad)| {
                    let value = entry.0[quad];
                    let seen = if varies(index, quad) {
                        Seen::Varies
                    } else if quad == q::XSTATE_BV {
                        Seen::Value(value & 0b111)
                    } else {
                        entry_of(value, quad).unwrap_or(Seen::Value(value))
                    };
                    (name, seen)
                })
                .collect()
        })
        .collect()
}

/// Checks that the frame of entry `top` went on top of entry `below`'s at the
/// same return, as Linux builds it: it saved `below`'s handler at its first
/// instruction (rip the handler, rsp its frame, rdi, rsi and rdx its
/// arguments, rax 0, its rflags) and the FPU state the delivery below
/// installed, Linux's initial state, and it lies below that frame and its red
/// zone.
fn assert_stacked_on(log: &StackedLog, top: usize, below: usize, context: &str) {
    let (t, b) = (log.entry(top), log.entry(below));
    let context = format!("{context}: entry {top} on entry {below}: {log:#x?}");
    assert_eq!(
        [
            t[q::RIP],
            t[q::RSP],
            t[q::RDI],
            t[q::RSI],
            t[q::RDX],
            t[q::RAX],
            t[q::EFLAGS]
        ],
        [
            b[q::HANDLER],
            b[q::ENTRY_RSP],
            b[q::SIGNAL],
            b[q::ENTRY_RSI],
            b[q::ENTRY_RDX],
            0,
            b[q::ENTRY_RFLAGS]
        ],
        "{context}"
    );
    assert_eq!(
        [t[q::MXCSR], t[q::X87], t[q::XSTATE_BV] & 0b111, t[q::XMM5]],
        [0x1f80, 0x037f, 0b011, 0],
        "{context}"
    );
    assert!(t[q::ENTRY_RSP] + 128 < b[q::ENTRY_RSP], "{context}");
}

/// Checks that entry `index` saved the interrupted code that loaded
/// [`LOAD_FPU`], at the instruction r12 marks, with rbx and rbp intact.
fn assert_interrupted_at_mark(log: &StackedLog, index: usize, context: &str) {
    let e = log.entry(index);
    let context = format!("{context}: entry {index}: {log:#x?}");
    assert_eq!(e[q::RIP], e[q::R12], "{context}");
    assert_eq!([e[q::RBX], e[q::RBP]], [RBX, RBP], "{context}");
    assert_eq!(
        [e[q::MXCSR], e[q::XMM5], e[q::XSTATE_BV] & 0b111],
        [LOADED_MXCSR, LOADED_XMM5, 0b011],
        "{context}"
    );
}

/// How [`traced_native`] answers a stop of the native guest. A Tool's signal
/// hook runs where ptrace stops a guest for a signal, so the tracer can put a
/// native run in the state a Tool's callbacks or the backend's own delivery
/// points put a KVM run in, without depending on the host scheduler.
#[derive(Clone, Copy, Debug)]
enum Tracing {
    /// Delivers each signal at its stop.
    Deliver,
    /// At the main thread's first stop for `first`, waits until `then` is
    /// pending for it as well, and delivers `first`: as a Tool's timer
    /// callback holds a thread while a sibling sends it both.
    HoldUntilPending { first: i32, then: i32 },
    /// Suppresses `deferred` at the main thread's stops until it stops for
    /// `fault`, then sends `deferred` to it again and delivers `fault`, so
    /// that `deferred` is pending at the fault's return: as when a sibling
    /// sends it to a thread that runs no syscall until it faults, under a
    /// backend with no preemption.
    DeferUntil { deferred: i32, fault: i32 },
    /// Holds each new thread at its first stop, before its first
    /// instruction, until both `signals` have reached it (pending, or the
    /// one that stop dequeued): as a Tool that holds a new thread's start
    /// until another thread has sent them.
    HoldNewThread { signals: [i32; 2] },
}

/// What [`traced_native_with`] does besides its [`Tracing`]: the stops at
/// which a Tool's callbacks would suppress a signal or hold a thread while
/// another thread ends the group.
#[derive(Clone, Copy, Debug, Default)]
struct TraceOptions {
    /// Signals (a mask with bit `signal - 1`) that the tracer suppresses at
    /// every signal-delivery stop, as a Tool's signal hook suppresses them.
    suppress: u64,
    /// At the main thread's first signal-delivery stop for this signal, the
    /// tracer leaves the thread stopped, as a Tool's signal hook holds it;
    /// only a group exit can then end it.
    hold_until_exit: Option<i32>,
    /// The tracer follows the main thread's syscalls and leaves it stopped at
    /// the exit of its first call with this number, before any signal is
    /// selected there, as a Tool's timer callback holds it; only a group
    /// exit can then end it.
    hold_at_syscall_exit: Option<i64>,
    /// The tracer follows the other threads' syscalls and holds another
    /// thread's `exit_group` at its entry until the main thread is held, as a
    /// Tool holds that call until the main thread's callback has begun.
    exit_group_after_hold: bool,
}

/// A native run under [`traced_native`]: its stdout, and the signals the
/// tracer delivered, in the order of their stops.
struct TracedRun {
    stdout: Vec<u8>,
    delivered: Vec<i32>,
    /// The synthetic SIGSTOPs of new threads that the tracer suppressed.
    synthetic_stops: usize,
    /// The signal of every signal-delivery stop the tracer reported, in
    /// order, whatever it did with it: the signals a Tool's signal hook
    /// would see.
    stops: Vec<i32>,
    /// How the main thread ended, in wait(2) encoding.
    status: i32,
    /// How each thread ended, in the order the tracer reaped them.
    threads: Vec<(libc::pid_t, i32)>,
    /// The stops the tracer left the main thread in: the signal of each
    /// signal-delivery stop, and -1 for a syscall-exit stop.
    held: Vec<i32>,
    /// The stderr the run wrote.
    stderr: Vec<u8>,
}

/// What PTRACE_GETSIGINFO shows for a stop that is not a ptrace event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopInfo {
    /// A signal-delivery stop: the signal, its si_code and its si_pid.
    Signal { signo: i32, code: i32, sender: i32 },
    /// A group-stop report, which has no siginfo (EINVAL).
    GroupStop,
    /// The thread is no longer stopped (ESRCH): a group exit's SIGKILL woke
    /// and ended it after its stop was reported. Its end is reported next.
    Gone,
}

/// Reads the siginfo of thread `tid`'s stop.
fn stop_info(tid: libc::pid_t) -> StopInfo {
    // SAFETY: an all-zero siginfo_t is valid, and PTRACE_GETSIGINFO writes
    // one siginfo_t into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let got = unsafe {
        libc::ptrace(
            libc::PTRACE_GETSIGINFO,
            tid,
            0,
            &mut info as *mut libc::siginfo_t,
        )
    };
    if got == 0 {
        StopInfo::Signal {
            signo: info.si_signo,
            code: info.si_code,
            // SAFETY: the kill, tkill and queue layouts, the only ones
            // classify_sigstop accepts a sender from, hold si_pid here.
            sender: unsafe { info.si_pid() },
        }
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return StopInfo::Gone;
        }
        assert_eq!(
            error.raw_os_error(),
            Some(libc::EINVAL),
            "PTRACE_GETSIGINFO of thread {tid}: {error}"
        );
        StopInfo::GroupStop
    }
}

/// What the native tracer does with a SIGSTOP stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SigstopAction {
    /// Suppresses the SIGSTOP the tracer's own PTRACE_O_TRACECLONE queued for
    /// a new thread, which no guest sent.
    SuppressSynthetic,
    /// Forwards a SIGSTOP that a task sent, as any other signal.
    Forward,
}

/// Classifies a SIGSTOP stop of thread `tid` of process `pid` by where the
/// signal came from, its si_code and si_pid. PTRACE_O_TRACECLONE adds SIGSTOP
/// to a new thread's pending set with no siginfo (`ptrace_init_task`,
/// <https://github.com/gregkh/linux/blob/v7.1.3/include/linux/ptrace.h#L200-L216>),
/// and `collect_signal` reports a signal with no siginfo as SI_USER from pid
/// 0 (<https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c#L588-L600>),
/// whenever the thread dequeues it; a signal that a task sent with kill,
/// tkill, tgkill or rt_sigqueueinfo carries the sender's pid. So the
/// synthetic stop is known by its provenance, not by being a thread's first
/// SIGSTOP, and a sent SIGSTOP is forwarded even when it is. Anything else is
/// refused, as is a second synthetic stop or one for the main thread, which
/// the tracer never gets one for. A SIGSTOP a task sends while a new thread's
/// synthetic one is still pending merges into it (`legacy_queue`,
/// <https://github.com/gregkh/linux/blob/v7.1.3/kernel/signal.c#L1035-L1038>),
/// so the kernel itself keeps no trace of that send.
fn classify_sigstop(
    tid: libc::pid_t,
    pid: libc::pid_t,
    code: i32,
    sender: libc::pid_t,
    synthetic: &[libc::pid_t],
) -> Result<SigstopAction, String> {
    match (code, sender) {
        (libc::SI_USER, 0) if tid != pid && !synthetic.contains(&tid) => {
            Ok(SigstopAction::SuppressSynthetic)
        }
        (libc::SI_USER, 0) if tid == pid => {
            Err("SI_USER from pid 0 for the main thread".to_owned())
        }
        (libc::SI_USER, 0) => Err("a second SI_USER stop from pid 0".to_owned()),
        (libc::SI_USER | libc::SI_TKILL | libc::SI_QUEUE, sender) if sender > 0 => {
            Ok(SigstopAction::Forward)
        }
        (code, sender) => Err(format!("si_code {code} from pid {sender}")),
    }
}

/// Waits until every one of `signals` is pending for thread `tid` of process
/// `pid`, thread-directed or process-wide.
fn wait_pending(pid: libc::pid_t, tid: libc::pid_t, signals: &[i32]) {
    let path = format!("/proc/{pid}/task/{tid}/status");
    let wanted = signals.iter().fold(0, |mask, &signal| mask | bit(signal));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let status = std::fs::read_to_string(&path).unwrap();
        let pending = ["SigPnd:", "ShdPnd:"]
            .iter()
            .map(|key| {
                let line = status.lines().find(|line| line.starts_with(key)).unwrap();
                u64::from_str_radix(line[key.len()..].trim(), 16).unwrap()
            })
            .fold(0, |all, set| all | set);
        if pending & wanted == wanted {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{signals:?} never became pending: {pending:#x}"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

/// Runs `program` natively, the Linux reference, under a ptrace tracer that
/// answers its stops as `tracing` says, follows its threads, and checks that it
/// exits with status 0 and writes nothing to stderr. A tracer changes no frame
/// Linux builds: it only decides, at each signal's stop, whether and when the
/// signal is delivered.
fn traced_native(program: &Program, tracing: Tracing) -> TracedRun {
    let run = traced_native_with(program, tracing, TraceOptions::default());
    assert!(
        libc::WIFEXITED(run.status) && libc::WEXITSTATUS(run.status) == 0 && run.stderr.is_empty(),
        "native: status {:#x}: {}",
        run.status,
        String::from_utf8_lossy(&run.stderr)
    );
    run
}

/// [`traced_native`], doing also what `options` says, and returning however
/// the run ended: the tracer reaps every thread, and reports how each ended.
/// The guest may not dump core (RLIMIT_CORE 1: see [`native_output`]).
fn traced_native_with(program: &Program, tracing: Tracing, options: TraceOptions) -> TracedRun {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(&program.executable);
    command
        .current_dir(&program.directory)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // SAFETY: setrlimit, sigprocmask and ptrace(PTRACE_TRACEME) are
    // async-signal-safe and touch no memory the parent shares.
    unsafe {
        command.pre_exec(|| {
            let one = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 1,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &one) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Linux's initial mask, as a KVM guest starts with: a thread
            // that ran a KVM timer keeps the kick signal blocked, and exec
            // keeps the mask.
            let mut empty: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut empty);
            if libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            match libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            }
        });
    }
    let mut child = command.spawn().unwrap();
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    // SAFETY: plain wait and ptrace calls on this test's own tracee. A
    // thread that a group exit's SIGKILL woke from its stop, and so ended,
    // cannot be resumed (ESRCH); its end is reported next.
    let resume_with = |request: libc::c_uint, tid: libc::pid_t, signal: i32| {
        let resumed = unsafe { libc::ptrace(request, tid, 0, signal as libc::c_long) };
        if resumed != 0 {
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::ESRCH), "{error}");
        }
    };
    // The registers of thread `tid`'s stop, or none if it has ended since.
    let registers_of_stop = |tid: libc::pid_t| {
        // SAFETY: an all-zero user_regs_struct is valid, and PTRACE_GETREGS
        // writes one into it.
        let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let got = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGS,
                tid,
                0,
                &mut regs as *mut libc::user_regs_struct,
            )
        };
        if got == 0 {
            return Some(regs);
        }
        let error = std::io::Error::last_os_error();
        assert_eq!(error.raw_os_error(), Some(libc::ESRCH), "{error}");
        None
    };
    // The stop at exec.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::__WALL) },
        pid
    );
    assert!(
        libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGTRAP,
        "{status:#x}"
    );
    // An exec of the guest's own stops as an event, not as a SIGTRAP to
    // deliver. Following the main thread's syscalls, its syscall stops come
    // with SIGTRAP | 0x80.
    let mut options_set =
        libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL;
    if options.hold_at_syscall_exit.is_some() || options.exit_group_after_hold {
        options_set |= libc::PTRACE_O_TRACESYSGOOD;
    }
    assert_eq!(
        unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, options_set) },
        0
    );
    // How the main thread is resumed: syscall by syscall until it is held at
    // its syscall exit, if it is to be.
    let follow = |held_at_exit: bool| {
        if options.hold_at_syscall_exit.is_some() && !held_at_exit {
            libc::PTRACE_SYSCALL
        } else {
            libc::PTRACE_CONT
        }
    };
    resume_with(follow(false), pid, 0);
    let mut threads = vec![pid];
    // The cloned threads whose synthetic SIGSTOP the tracer has suppressed.
    let mut synthetic = Vec::new();
    // Whether the tracer has forwarded a stop signal, which group-stop
    // reports then follow.
    let mut stop_forwarded = false;
    let mut delivered = Vec::new();
    let mut stops = Vec::new();
    let mut held_stops = Vec::new();
    let mut ended = Vec::new();
    let mut leader_status = None;
    let (mut held, mut faulted) = (false, false);
    // Whether the main thread is inside a syscall, between its entry and
    // exit stops, while the tracer follows its syscalls.
    let mut in_syscall = false;
    let mut held_at_exit = false;
    // The other threads inside a syscall, while the tracer follows theirs,
    // and the one whose exit_group waits for the main thread to be held.
    let mut others_in_syscall = Vec::new();
    let mut waiting_exit: Option<libc::pid_t> = None;
    loop {
        let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if tid < 0 {
            let error = std::io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::ECHILD), "waitpid: {error}");
            break;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            ended.push((tid, status));
            if tid == pid {
                leader_status = Some(status);
            }
            continue;
        }
        assert!(libc::WIFSTOPPED(status), "{status:#x}");
        let signal = libc::WSTOPSIG(status);
        if !threads.contains(&tid) {
            threads.push(tid);
            // A new thread's first stop, before its first instruction.
            if let Tracing::HoldNewThread { signals } = tracing {
                // This stop dequeued its signal; the others must be pending.
                let others: Vec<i32> = signals.into_iter().filter(|&s| s != signal).collect();
                wait_pending(pid, tid, &others);
            }
        }
        let request = if tid == pid {
            follow(held_at_exit)
        } else if options.exit_group_after_hold {
            libc::PTRACE_SYSCALL
        } else {
            libc::PTRACE_CONT
        };
        if signal == libc::SIGTRAP | 0x80 && tid != pid {
            // A syscall stop of another thread, which the tracer follows.
            if let Some(at) = others_in_syscall.iter().position(|&other| other == tid) {
                others_in_syscall.swap_remove(at);
            } else {
                others_in_syscall.push(tid);
                let Some(regs) = registers_of_stop(tid) else {
                    continue;
                };
                if regs.orig_rax as i64 == libc::SYS_exit_group && held_stops.is_empty() {
                    assert!(waiting_exit.is_none(), "a second exit_group waits");
                    waiting_exit = Some(tid);
                    continue;
                }
            }
            resume_with(request, tid, 0);
            continue;
        }
        if signal == libc::SIGTRAP | 0x80 && tid == pid {
            // A syscall stop of the main thread, which the tracer follows.
            if in_syscall
                && let Some(number) = options.hold_at_syscall_exit
                && !held_at_exit
            {
                let Some(regs) = registers_of_stop(tid) else {
                    continue;
                };
                if regs.orig_rax as i64 == number {
                    held_at_exit = true;
                    held_stops.push(-1);
                    in_syscall = false;
                    if let Some(waiting) = waiting_exit.take() {
                        resume_with(libc::PTRACE_SYSCALL, waiting, 0);
                    }
                    // Left stopped: only the group exit ends it.
                    continue;
                }
            }
            in_syscall = !in_syscall;
            resume_with(request, tid, 0);
            continue;
        }
        // A clone or exec event stop has no siginfo of its own to read.
        let info = (status >> 16 == 0).then(|| stop_info(tid));
        if info == Some(StopInfo::Gone) {
            continue;
        }
        let deliver = if info.is_none() {
            // A clone or exec event stop.
            0
        } else if let Some(StopInfo::GroupStop) = info {
            // A group-stop report: it delivers nothing, and resuming from it
            // continues the thread.
            assert!(
                stop_forwarded,
                "a group-stop of thread {tid} with no stop signal forwarded"
            );
            0
        } else if let Some(StopInfo::Signal {
            signo,
            code,
            sender,
        }) = info
            && signal == libc::SIGSTOP
        {
            assert_eq!(signo, signal, "thread {tid}'s siginfo");
            match classify_sigstop(tid, pid, code, sender, &synthetic) {
                Ok(SigstopAction::SuppressSynthetic) => {
                    synthetic.push(tid);
                    0
                }
                Ok(SigstopAction::Forward) => {
                    stops.push(signal);
                    stop_forwarded = true;
                    signal
                }
                Err(why) => panic!("an unclassifiable SIGSTOP stop of thread {tid}: {why}"),
            }
        } else {
            stops.push(signal);
            if [libc::SIGTSTP, libc::SIGTTIN, libc::SIGTTOU].contains(&signal) {
                stop_forwarded = true;
            }
            if tid == pid && options.hold_until_exit == Some(signal) && held_stops.is_empty() {
                held_stops.push(signal);
                if let Some(waiting) = waiting_exit.take() {
                    resume_with(libc::PTRACE_SYSCALL, waiting, 0);
                }
                // Left stopped: only the group exit ends it.
                continue;
            }
            let deliver = match tracing {
                Tracing::HoldUntilPending { first, then }
                    if tid == pid && signal == first && !held =>
                {
                    held = true;
                    wait_pending(pid, tid, &[then]);
                    signal
                }
                Tracing::DeferUntil { deferred, .. }
                    if tid == pid && signal == deferred && !faulted =>
                {
                    0
                }
                Tracing::DeferUntil { deferred, fault } if tid == pid && signal == fault => {
                    faulted = true;
                    let sent = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, deferred) };
                    assert_eq!(sent, 0, "{}", std::io::Error::last_os_error());
                    signal
                }
                _ => signal,
            };
            if options.suppress & bit(signal) != 0 {
                0
            } else {
                deliver
            }
        };
        if deliver != 0 {
            delivered.push(deliver);
        }
        resume_with(request, tid, deliver);
    }
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    // The tracer has reaped the child: its handle must not wait for it.
    std::mem::forget(child);
    TracedRun {
        stdout,
        delivered,
        synthetic_stops: synthetic.len(),
        stops,
        status: leader_status.expect("the main thread was reaped"),
        threads: ended,
        held: held_stops,
        stderr,
    }
}

/// The order of the Tool's signal hooks in a run's events.
fn signal_hooks(events: &[Event]) -> Vec<i32> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Signalled { signal, .. } => Some(*signal),
            _ => None,
        })
        .collect()
}

/// The runs [`stacked_matches_native`] compared.
struct StackedRuns {
    /// The native log, for the caller's checks of Linux's frames.
    native: StackedLog,
    /// The log under the Tool, and the Tool's events.
    tool: StackedLog,
    events: Vec<Event>,
}

/// Runs `program` natively under `tracing` and on KVM, under the backend's
/// own runtime when `direct` and under a Tool following `plan` (whose
/// `deliver` delivers every signal), and checks every KVM log against the
/// native one ([`comparable`], with `varies`), and the order of the Tool's
/// signal hooks against the order of the tracer's deliveries.
fn stacked_matches_native(
    program: &Program,
    tracing: Tracing,
    direct: bool,
    plan: Plan,
    varies: &dyn Fn(usize, usize) -> bool,
) -> StackedRuns {
    let native = traced_native(program, tracing);
    let native_log = StackedLog::read(&native.stdout);
    let expected = comparable(&native_log, varies);
    if direct {
        let log = StackedLog::read(&direct_stdout(program));
        assert_eq!(
            comparable(&log, varies),
            expected,
            "runtime {log:#x?}, native {native_log:#x?}"
        );
        assert_eq!(
            (
                log.final_mask,
                log.final_stack,
                log.queried_stack,
                log.results
            ),
            (
                native_log.final_mask,
                native_log.final_stack,
                native_log.queried_stack,
                native_log.results
            ),
            "runtime"
        );
    }
    let plan = Plan {
        deliver: true,
        ..plan
    };
    let (events, stdout) = tool_stdout(program, plan);
    let log = StackedLog::read(&stdout);
    assert_eq!(
        comparable(&log, varies),
        expected,
        "tool {log:#x?}, native {native_log:#x?}, {events:?}"
    );
    assert_eq!(
        (
            log.final_mask,
            log.final_stack,
            log.queried_stack,
            log.results
        ),
        (
            native_log.final_mask,
            native_log.final_stack,
            native_log.queried_stack,
            native_log.results
        ),
        "tool"
    );
    assert_eq!(
        signal_hooks(&events),
        native.delivered,
        "tool hooks against the native tracer's deliveries: {events:?}"
    );
    StackedRuns {
        native: native_log,
        tool: log,
        events,
    }
}

/// [`stacked_matches_native`] for a guest whose signals all come at syscall
/// returns: natively, its tracer delivers each signal as it comes, and the
/// run without a tracer writes the same log; on KVM, under both runtimes.
/// Returns the native log.
fn stacked_at_syscall_returns_matches_native(program: &Program) -> StackedLog {
    let untraced = native_stdout(program);
    let runs = stacked_matches_native(program, Tracing::Deliver, true, Plan::default(), &|_, _| {
        false
    });
    assert_eq!(
        StackedLog::read(&untraced).entries,
        runs.native.entries,
        "native runs with and without the tracer"
    );
    runs.native
}

const SIGUSR1: i32 = libc::SIGUSR1;
const SIGUSR2: i32 = libc::SIGUSR2;
const SIGWINCH: i32 = libc::SIGWINCH;

/// A guest whose SIGUSR1 and SIGUSR2 are pending and blocked when it unblocks
/// both, with an rt_sigprocmask whose return r12 marks.
fn pending_pair_program() -> Program {
    stacked_program(
        &[Handler::new(SIGUSR1), Handler::new(SIGUSR2)],
        &unblocked_at_syscall_return(&(tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2))),
        &format!("pending: .quad {:#x}\n", bit(SIGUSR1) | bit(SIGUSR2)),
        "",
    )
}

#[test]
fn two_signals_pending_at_a_syscall_return_stack_their_frames() {
    if bounded("two_signals_pending_at_a_syscall_return_stack_their_frames") {
        return;
    }
    // SIGUSR1 and SIGUSR2 are pending and blocked; the guest unblocks both.
    // Linux builds SIGUSR1's frame at that call's return, then SIGUSR2's on
    // top, under the mask SIGUSR1's delivery left: SIGUSR2's handler runs
    // first and returns to SIGUSR1's, which returns to the guest.
    let log = stacked_at_syscall_returns_matches_native(&pending_pair_program());
    let context = "native";
    assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{log:#x?}");
    assert_stacked_on(&log, 0, 1, context);
    assert_interrupted_at_mark(&log, 1, context);
    let (top, below) = (log.entry(0), log.entry(1));
    // SIGUSR1's frame saves the mask its call left, none; SIGUSR2's, the
    // mask SIGUSR1's handler runs under.
    assert_eq!(
        [below[q::SIGMASK], top[q::SIGMASK], below[q::RAX]],
        [0, bit(SIGUSR1), 0],
        "{log:#x?}"
    );
    assert_eq!(log.final_mask, 0, "{log:#x?}");
}

#[test]
fn each_stacked_signal_has_its_own_permit_hook_and_receipt() {
    if bounded("each_stacked_signal_has_its_own_permit_hook_and_receipt") {
        return;
    }
    // The guest of `two_signals_pending_at_a_syscall_return_stack_their_frames`,
    // under a Tool that controls signal delivery with permits and lets the
    // backend skip empty boundaries, as a scheduler that runs one thread at a
    // time does. Each signal at the unblocking call's return is a boundary of
    // its own, as each signal has its own stop under ptrace: a permit, the
    // signal's hook, which sees that call as orig_rax, and the permit's
    // Caught receipt, SIGUSR1's before SIGUSR2's.
    let plan = Plan {
        permits: true,
        signal_registers: true,
        ..Plan::default()
    };
    let runs = stacked_matches_native(
        &pending_pair_program(),
        Tracing::Deliver,
        false,
        plan,
        &|_, _| false,
    );
    assert_eq!(runs.native.signals(), [SIGUSR2, SIGUSR1]);
    let boundaries: Vec<String> = runs
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Permit(sequence) => Some(format!("permit {sequence}")),
            Event::Signalled { signal, .. } => Some(format!("hook {signal}")),
            Event::Registers(r) => Some(format!("orig_rax {}", r.orig_rax)),
            Event::Receipt(sequence, outcome) => Some(format!("receipt {sequence} {outcome}")),
            _ => None,
        })
        .collect();
    let unblock = libc::SYS_rt_sigprocmask;
    assert_eq!(
        boundaries,
        [
            "permit 1".to_owned(),
            format!("hook {SIGUSR1}"),
            format!("orig_rax {unblock}"),
            "receipt 1 Caught".to_owned(),
            "permit 2".to_owned(),
            format!("hook {SIGUSR2}"),
            format!("orig_rax {unblock}"),
            "receipt 2 Caught".to_owned(),
        ],
        "{:?}",
        runs.events
    );
}

#[test]
fn two_signals_pending_at_rt_sigsuspend_stack_their_frames() {
    if bounded("two_signals_pending_at_rt_sigsuspend_stack_their_frames") {
        return;
    }
    // The same pending pair, released by an rt_sigsuspend with an empty
    // mask. SIGUSR1's frame saves the mask rt_sigsuspend saved, which blocks
    // both; SIGUSR2's frame saves the temporary mask with SIGUSR1 added, so
    // SIGUSR2 is delivered at the same return. Delivering one frame per
    // return would leave SIGUSR2 pending, and blocked again once SIGUSR1's
    // handler returned.
    let program = stacked_program(
        &[Handler::new(SIGUSR1), Handler::new(SIGUSR2)],
        &format!(
            "{LOAD_FPU}{}{}{}lea 1f(%rip),%r12\nlea empty(%rip),%rdi\nmov $8,%esi\nmov $130,%eax\nsyscall\n1:\n",
            sigprocmask(libc::SIG_BLOCK, "pending"),
            tgkill_self(SIGUSR1),
            tgkill_self(SIGUSR2)
        ),
        &format!(
            "pending: .quad {:#x}\nempty: .quad 0\n",
            bit(SIGUSR1) | bit(SIGUSR2)
        ),
        "",
    );
    let log = stacked_at_syscall_returns_matches_native(&program);
    let context = "native";
    assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{log:#x?}");
    assert_stacked_on(&log, 0, 1, context);
    assert_interrupted_at_mark(&log, 1, context);
    let (top, below) = (log.entry(0), log.entry(1));
    let both = bit(SIGUSR1) | bit(SIGUSR2);
    assert_eq!(
        [below[q::SIGMASK], top[q::SIGMASK], below[q::RAX]],
        [both, bit(SIGUSR1), -i64::from(libc::EINTR) as u64],
        "{log:#x?}"
    );
    assert_eq!(log.final_mask, both, "{log:#x?}");
}

#[test]
fn a_signal_the_first_handlers_mask_blocks_waits_for_its_rt_sigreturn() {
    if bounded("a_signal_the_first_handlers_mask_blocks_waits_for_its_rt_sigreturn") {
        return;
    }
    // SIGUSR1, SIGUSR2 and SIGWINCH are released at one return. SIGUSR1's
    // sa_mask blocks SIGUSR2, so SIGWINCH's frame goes on top of SIGUSR1's,
    // and SIGUSR2 waits for SIGUSR1's rt_sigreturn, whose return delivers it
    // with the guest's context restored.
    let program = stacked_program(
        &[
            Handler::new(SIGUSR1).mask(bit(SIGUSR2)),
            Handler::new(SIGUSR2),
            Handler::new(SIGWINCH),
        ],
        &unblocked_at_syscall_return(
            &(tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2) + &tgkill_self(SIGWINCH)),
        ),
        &format!(
            "pending: .quad {:#x}\n",
            bit(SIGUSR1) | bit(SIGUSR2) | bit(SIGWINCH)
        ),
        "",
    );
    let log = stacked_at_syscall_returns_matches_native(&program);
    let context = "native";
    assert_eq!(log.signals(), [SIGWINCH, SIGUSR1, SIGUSR2], "{log:#x?}");
    assert_stacked_on(&log, 0, 1, context);
    assert_interrupted_at_mark(&log, 1, context);
    assert_interrupted_at_mark(&log, 2, context);
    assert_eq!(
        log.entry(0)[q::SIGMASK],
        bit(SIGUSR1) | bit(SIGUSR2),
        "{log:#x?}"
    );
}

#[test]
fn sa_nodefer_stacks_a_second_instance_of_the_same_signal() {
    if bounded("sa_nodefer_stacks_a_second_instance_of_the_same_signal") {
        return;
    }
    // SIGUSR1 is pending twice, for the thread (tgkill, SI_TKILL) and for
    // the process (kill, SI_USER). With SA_NODEFER its delivery does not
    // block it, so the process instance's frame goes on top of the thread
    // instance's at the same return. Without SA_NODEFER the second instance
    // waits for the first handler's rt_sigreturn.
    for nodefer in [true, false] {
        let program = stacked_program(
            &[Handler::new(SIGUSR1).flags(if nodefer { SA_NODEFER } else { 0 })],
            &unblocked_at_syscall_return(&(tgkill_self(SIGUSR1) + &kill_self(SIGUSR1))),
            &format!("pending: .quad {:#x}\n", bit(SIGUSR1)),
            "",
        );
        let log = stacked_at_syscall_returns_matches_native(&program);
        let context = format!("native, SA_NODEFER {nodefer}");
        assert_eq!(log.signals(), [SIGUSR1, SIGUSR1], "{context}: {log:#x?}");
        let codes = [log.entry(0)[q::SI_CODE], log.entry(1)[q::SI_CODE]];
        let (tkill, user) = (libc::SI_TKILL as u32 as u64, libc::SI_USER as u32 as u64);
        if nodefer {
            assert_eq!(codes, [user, tkill], "{context}: {log:#x?}");
            assert_stacked_on(&log, 0, 1, &context);
            assert_interrupted_at_mark(&log, 1, &context);
            assert_eq!(log.entry(0)[q::SIGMASK], 0, "{context}: {log:#x?}");
        } else {
            assert_eq!(codes, [tkill, user], "{context}: {log:#x?}");
            assert_interrupted_at_mark(&log, 0, &context);
            assert_interrupted_at_mark(&log, 1, &context);
        }
    }
}

#[test]
fn frames_stacked_on_an_alternate_stack_nest_on_it() {
    if bounded("frames_stacked_on_an_alternate_stack_nest_on_it") {
        return;
    }
    // Both handlers are SA_ONSTACK. SIGUSR1's frame switches to the top of
    // the alternate stack; SIGUSR2's goes below it, past its red zone, on
    // the same stack. Each frame's uc_stack holds the stack's own flags:
    // with SS_AUTODISARM, SIGUSR1's delivery disarms the stack, so SIGUSR2's
    // frame saves none, and SIGUSR1's rt_sigreturn arms it again.
    for (flags, top_saved) in [(0, None), (SS_AUTODISARM, Some([0, SS_DISABLE, 0]))] {
        let program = stacked_program(
            &[
                Handler::new(SIGUSR1).flags(SA_ONSTACK),
                Handler::new(SIGUSR2).flags(SA_ONSTACK),
            ],
            &format!(
                "{ARM_ALTSTACK}{}",
                unblocked_at_syscall_return(&(tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2)))
            ),
            &format!(
                "pending: .quad {:#x}\n{}",
                bit(SIGUSR1) | bit(SIGUSR2),
                altstack_data(flags)
            ),
            ALTSTACK,
        );
        let log = stacked_at_syscall_returns_matches_native(&program);
        let context = format!("native, ss_flags {flags:#x}");
        assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{context}: {log:#x?}");
        assert_stacked_on(&log, 0, 1, &context);
        assert_interrupted_at_mark(&log, 1, &context);
        let (top, below) = (log.entry(0), log.entry(1));
        let armed = [below[q::SS_SP], flags, 65536];
        assert_eq!(
            [below[q::SS_SP], below[q::SS_FLAGS], below[q::SS_SIZE]],
            armed,
            "{context}: {log:#x?}"
        );
        assert_eq!(
            [top[q::SS_SP], top[q::SS_FLAGS], top[q::SS_SIZE]],
            top_saved.unwrap_or(armed),
            "{context}: {log:#x?}"
        );
        // Both frames lie on the alternate stack.
        let stack = armed[0]..armed[0] + 65536;
        assert!(
            stack.contains(&below[q::ENTRY_RSP]) && stack.contains(&top[q::ENTRY_RSP]),
            "{context}: {log:#x?}"
        );
        assert_eq!(log.final_stack, armed, "{context}: {log:#x?}");
    }
}

#[test]
fn two_signals_pending_at_rt_sigreturn_stack_their_frames() {
    if bounded("two_signals_pending_at_rt_sigreturn_stack_their_frames") {
        return;
    }
    // SIGUSR1's handler, whose sa_mask blocks SIGUSR2 and SIGWINCH, sends
    // both to the thread and returns. Its rt_sigreturn restores the guest's
    // mask, which blocks neither: SIGUSR2's frame, with the guest's restored
    // context, and SIGWINCH's on top of it, at that call's return. SIGUSR1
    // itself comes at the return of the call that unblocks it.
    let program = stacked_program(
        &[
            Handler::new(SIGUSR1)
                .mask(bit(SIGUSR2) | bit(SIGWINCH))
                .actions(&(tgkill_self(SIGUSR2) + &tgkill_self(SIGWINCH))),
            Handler::new(SIGUSR2),
            Handler::new(SIGWINCH),
        ],
        &unblocked_at_syscall_return(&tgkill_self(SIGUSR1)),
        &format!("pending: .quad {:#x}\n", bit(SIGUSR1)),
        "",
    );
    let log = stacked_at_syscall_returns_matches_native(&program);
    let context = "native";
    assert_eq!(log.signals(), [SIGUSR1, SIGWINCH, SIGUSR2], "{log:#x?}");
    assert_interrupted_at_mark(&log, 0, context);
    assert_stacked_on(&log, 1, 2, context);
    assert_interrupted_at_mark(&log, 2, context);
}

#[test]
fn a_fatal_signal_selected_after_a_frame_ends_the_group_before_its_handler_runs() {
    if bounded("a_fatal_signal_selected_after_a_frame_ends_the_group_before_its_handler_runs") {
        return;
    }
    // SIGUSR1 has a handler, which writes a byte; SIGUSR2 has none. Linux
    // builds SIGUSR1's frame, then selects SIGUSR2 at the same return, whose
    // default action ends the thread group before any handler runs: no byte.
    let program = stacked_program(
        &[Handler::new(SIGUSR1)
            .actions("mov $1,%edi\nlea byte(%rip),%rsi\nmov $1,%edx\nmov $1,%eax\nsyscall\n")],
        &unblocked_at_syscall_return(&(tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2))),
        &format!(
            "pending: .quad {:#x}\nbyte: .ascii \"x\"\n",
            bit(SIGUSR1) | bit(SIGUSR2)
        ),
        "",
    );
    let killed = (128 + SIGUSR2, vec![], vec![]);
    use std::os::unix::process::ExitStatusExt;
    let native = native_output(&program);
    assert_eq!(
        (native.status.signal(), native.stdout, native.stderr),
        (Some(SIGUSR2), vec![], vec![]),
        "native: {}",
        native.status
    );
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    assert_eq!(
        backend.run_static_elf_captured().unwrap(),
        killed,
        "runtime"
    );
    let plan = Plan {
        deliver: true,
        ..Plan::default()
    };
    let (events, ending) = run_ending(&program, plan);
    assert_eq!(ending, Ok(killed), "tool: {events:?}");
    assert_eq!(signal_hooks(&events), [SIGUSR1, SIGUSR2], "{events:?}");
}

#[test]
fn a_frame_that_overflows_the_alternate_stack_ends_the_group_with_sigsegv() {
    if bounded("a_frame_that_overflows_the_alternate_stack_ends_the_group_with_sigsegv") {
        return;
    }
    // The guest measures one SA_ONSTACK frame on a large alternate stack
    // (SIGUSR1 sent to itself), then installs an alternate stack with room
    // for one such frame and not two, at least MINSIGSTKSZ (2048) bytes, and
    // releases SIGUSR1 and SIGUSR2 at one return. SIGUSR1's frame fits, 384
    // bytes or more above the stack's base, so that SIGUSR2's goes below it
    // past its red zone (Linux switches to the top of the stack again when
    // the red zone reaches below the base); SIGUSR2's frame does not fit, and
    // Linux forces SIGSEGV, whose default action ends the group before either
    // handler runs.
    let size = "mov log+8(%rip),%rax\nlea altstack_end(%rip),%rcx\nsub %rax,%rcx\nadd $384,%rcx\n\
                cmp $2048,%rcx\njae 2f\nmov $2048,%ecx\n2: mov %rcx,small_desc+16(%rip)\n\
                lea small_end(%rip),%rax\nsub %rcx,%rax\nmov %rax,small_desc(%rip)\n";
    let program = stacked_program(
        &[
            Handler::new(SIGUSR1).flags(SA_ONSTACK),
            Handler::new(SIGUSR2).flags(SA_ONSTACK),
        ],
        &format!(
            "lea altstack_desc(%rip),%rdi\nxor %esi,%esi\nmov $131,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n\
             {}{size}lea small_desc(%rip),%rdi\nxor %esi,%esi\nmov $131,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n{}",
            tgkill_self(SIGUSR1),
            unblocked_at_syscall_return(&(tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2)))
        ),
        &format!(
            "pending: .quad {:#x}\naltstack_desc: .quad altstack\n.long 0, 0\n.quad 65536\n\
             small_desc: .quad 0\n.long 0, 0\n.quad 0\n",
            bit(SIGUSR1) | bit(SIGUSR2)
        ),
        ".balign 64\naltstack: .skip 65536\naltstack_end:\n.balign 64\nsmall: .skip 65536\nsmall_end:\n",
    );
    segfaults_natively_and_on_kvm(&program);
}

/// Creates a sibling thread, on the stack ending at `sibling_stack_end`, that
/// runs `body` and exits.
fn sibling(body: &str) -> String {
    format!(
        "mov $0x50f00,%edi\nlea sibling_stack_end(%rip),%rsi\nxor %edx,%edx\nxor %r10d,%r10d\n\
         xor %r8d,%r8d\nmov $56,%eax\nsyscall\ntest %rax,%rax\njnz 6f\n{body}\
         xor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n6:\n"
    )
}

const SIBLING_STACK: &str = ".balign 64\nsibling_stack: .skip 65536\nsibling_stack_end:\n";

#[test]
fn a_user_trap_and_a_pending_signal_stack_their_frames() {
    if bounded("a_user_trap_and_a_pending_signal_stack_their_frames") {
        return;
    }
    // A sibling sends SIGUSR1 to the main thread and then sets `flag`; the
    // main thread spins without a syscall until it sees the flag, and then
    // reads page zero. With no preemption, KVM has SIGUSR1 pending at the
    // fault, as the native tracer arranges by deferring it to the fault's
    // stop. Linux selects the fault's SIGSEGV first, as a synchronous
    // signal, then SIGUSR1, whose frame goes on top: its handler runs first,
    // and the frame saves the thread's last trap, the page fault, as every
    // frame does. SIGSEGV's handler steps over the read.
    let program = stacked_program(
        &[
            Handler::new(libc::SIGSEGV).actions("addq $8,168(%rdx)\n"),
            Handler::new(SIGUSR1),
        ],
        &format!(
            "{LOAD_FPU}{}5: cmpb $0,flag(%rip)\nje 5b\nmov $0x77,%eax\nxor %ecx,%ecx\nlea 2f(%rip),%r12\n\
             2: movq 0x10,%rax\n",
            sibling(&(tgkill_self(SIGUSR1) + "movb $1,flag(%rip)\n"))
        ),
        "flag: .byte 0\n",
        SIBLING_STACK,
    );
    let log = stacked_matches_native(
        &program,
        Tracing::DeferUntil {
            deferred: SIGUSR1,
            fault: libc::SIGSEGV,
        },
        true,
        Plan::default(),
        &|_, _| false,
    )
    .native;
    let context = "native";
    assert_eq!(log.signals(), [SIGUSR1, libc::SIGSEGV], "{log:#x?}");
    assert_stacked_on(&log, 0, 1, context);
    assert_interrupted_at_mark(&log, 1, context);
    // Read, user mode, page not present, at address 0x10, in both frames.
    let trap = [14, 4, 0x10];
    for index in [0, 1] {
        let e = log.entry(index);
        assert_eq!([e[q::TRAPNO], e[q::ERR], e[q::CR2]], trap, "{log:#x?}");
    }
}

#[test]
fn two_signals_pending_at_a_new_threads_first_instruction_stack_their_frames() {
    if bounded("two_signals_pending_at_a_new_threads_first_instruction_stack_their_frames") {
        return;
    }
    // The guest clones a thread and sends it SIGUSR1 and SIGUSR2, which the
    // Tool (holding the thread's start) and the native tracer (holding its
    // first stop) make pending before its first instruction. Both frames
    // are built there, SIGUSR2's on top; SIGUSR1's saves the thread's first
    // instruction, with rax 0 and its stack. The thread then sets `done`.
    let program = stacked_program(
        &[Handler::new(SIGUSR1), Handler::new(SIGUSR2)],
        "lea 9f(%rip),%r12\nmov $0x50f00,%edi\nlea sibling_stack_end(%rip),%rsi\nxor %edx,%edx\n\
         xor %r10d,%r10d\nxor %r8d,%r8d\nmov $56,%eax\nsyscall\n\
         9: test %rax,%rax\njz 7f\nmov %rax,child(%rip)\n\
         mov pid(%rip),%rdi\nmov child(%rip),%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
         mov pid(%rip),%rdi\nmov child(%rip),%rsi\nmov $12,%edx\nmov $234,%eax\nsyscall\n\
         5: cmpb $0,done(%rip)\nje 5b\njmp 4f\n\
         7: movb $1,done(%rip)\nxor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n4:\n",
        "child: .quad 0\ndone: .byte 0\n",
        SIBLING_STACK,
    );
    let plan = Plan {
        hold_thread_start: true,
        sends: 2,
        ..Plan::default()
    };
    let log = stacked_matches_native(
        &program,
        Tracing::HoldNewThread {
            signals: [SIGUSR1, SIGUSR2],
        },
        false,
        plan,
        &|_, _| false,
    )
    .native;
    let context = "native";
    assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{log:#x?}");
    assert_stacked_on(&log, 0, 1, context);
    let first = log.entry(1);
    assert_eq!(first[q::RIP], first[q::R12], "{log:#x?}");
    assert_eq!(first[q::RAX], 0, "{log:#x?}");
}

/// The guest of `two_signals_pending_at_a_timer_boundary_stack_their_frames`:
/// a sibling waits until the main thread spins, without a syscall, and sends
/// it SIGUSR1 and then SIGUSR2. The main thread announces the spin once r12
/// and rcx are set, so that natively the signals interrupt the loop itself.
fn pair_at_timer_boundary_program() -> Program {
    stacked_program(
        &[Handler::new(SIGUSR1), Handler::new(SIGUSR2)],
        &format!(
            "{LOAD_FPU}{}{GETPPID}xor %eax,%eax\nlea 1f(%rip),%r12\nmov $2000000000,%rcx\n\
             movb $1,spinning(%rip)\n1: cmpq $2,header(%rip)\njae 2f\ndec %rcx\njnz 1b\n2:\n",
            sibling(&format!(
                "5: cmpb $0,spinning(%rip)\nje 5b\n{}{}",
                tgkill_self(SIGUSR1),
                tgkill_self(SIGUSR2)
            )),
        ),
        "spinning: .byte 0\n",
        SIBLING_STACK,
    )
}

#[test]
fn two_signals_pending_at_a_timer_boundary_stack_their_frames() {
    if bounded("two_signals_pending_at_a_timer_boundary_stack_their_frames") {
        return;
    }
    // A sibling waits until the main thread spins, without a syscall, and
    // sends it SIGUSR1 and then SIGUSR2. The Tool's precise timer event
    // lands in the spin and holds the thread until both are sent; the native
    // tracer holds SIGUSR1's stop, at the interrupt that brought it, until
    // SIGUSR2 is pending too. Both frames are built at that boundary,
    // SIGUSR2's on top. Where the interrupt landed differs between the runs:
    // the first frame's rip, rcx and flags, and so the flags and rcx its
    // handler starts with, which the second frame saves.
    let program = pair_at_timer_boundary_program();
    let plan = Plan {
        sends: 2,
        ..spinner_plan()
    };
    let varies =
        |_: usize, quad: usize| [q::RIP, q::RCX, q::EFLAGS, q::ENTRY_RFLAGS].contains(&quad);
    let runs = stacked_matches_native(
        &program,
        Tracing::HoldUntilPending {
            first: SIGUSR1,
            then: SIGUSR2,
        },
        false,
        plan,
        &varies,
    );
    let (log, events) = (&runs.native, &runs.events);
    let context = "native";
    assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{log:#x?}");
    assert_stacked_on(log, 0, 1, context);
    assert_stacked_on(&runs.tool, 0, 1, "tool");
    // On KVM both signals come at the timer event's boundary, whose
    // registers the first frame saves.
    let first = runs.tool.entry(1);
    let r = registers_of(events);
    assert_eq!(
        [
            first[q::RIP],
            first[q::RCX],
            first[q::EFLAGS],
            first[q::R12]
        ],
        [r.rip, r.rcx, r.eflags, r.r12],
        "{:#x?}",
        runs.tool
    );
    let (timer_at, timer_clock) = first_timer(events);
    let delivered: Vec<(usize, u64)> = events
        .iter()
        .enumerate()
        .filter_map(|(at, event)| match event {
            Event::Signalled { clock, .. } => Some((at, *clock)),
            _ => None,
        })
        .collect();
    assert_eq!(delivered.len(), 2, "{events:?}");
    for (at, clock) in delivered {
        assert!(at > timer_at && clock == timer_clock, "{events:?}");
    }
}

/// What the thread of
/// [`hooks_before_a_new_threads_first_instruction_set_both_segment_bases`]
/// can read through its FS and GS bases: the targets that the two signal
/// callbacks set, and the bases it inherits.
const FIRST_TARGET: u64 = 0x5151_5151_5151_5151;
const SECOND_TARGET: u64 = 0x5252_5252_5252_5252;
const OLD_FS: u64 = 0x0f0f_0f0f_0f0f_0f0f;
const OLD_GS: u64 = 0x6767_6767_6767_6767;

#[test]
fn hooks_before_a_new_threads_first_instruction_set_both_segment_bases() {
    if bounded("hooks_before_a_new_threads_first_instruction_set_both_segment_bases") {
        return;
    }
    // The guest points its own FS and GS bases at `old_fs` and `old_gs`,
    // keeps the addresses of `first` and `second` in r13 and r14, and clones
    // a thread, which inherits all four. It sends the thread SIGUSR1 and
    // SIGUSR2 while the Tool holds its start, so both frames are built before
    // its first instruction, SIGUSR2's on top. SIGUSR1's callback sets one
    // base to `first` with arch_prctl, and SIGUSR2's sets the other to
    // `second`. Once both handlers have returned, the thread reads through
    // each base and keeps what it read in the header's last quads. The
    // backend stages one base at a time for the vCPU, and SIGUSR2's callback
    // reads the vCPU's registers: SIGUSR1's base must reach the vCPU first.
    for bases in [
        [SegmentBase::Gs, SegmentBase::Fs],
        [SegmentBase::Fs, SegmentBase::Gs],
    ] {
        let program = stacked_program(
            &[Handler::new(SIGUSR1), Handler::new(SIGUSR2)],
            "lea old_fs(%rip),%rsi\nmov $0x1002,%edi\nmov $158,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n\
             lea old_gs(%rip),%rsi\nmov $0x1001,%edi\nmov $158,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n\
             lea first(%rip),%r13\nlea second(%rip),%r14\n\
             mov $0x50f00,%edi\nlea sibling_stack_end(%rip),%rsi\nxor %edx,%edx\n\
             xor %r10d,%r10d\nxor %r8d,%r8d\nmov $56,%eax\nsyscall\n\
             test %rax,%rax\njz 7f\nmov %rax,child(%rip)\n\
             mov pid(%rip),%rdi\nmov child(%rip),%rsi\nmov $10,%edx\nmov $234,%eax\nsyscall\n\
             mov pid(%rip),%rdi\nmov child(%rip),%rsi\nmov $12,%edx\nmov $234,%eax\nsyscall\n\
             5: cmpb $0,done(%rip)\nje 5b\njmp 4f\n\
             7: mov %fs:0,%rax\nmov %rax,header+40(%rip)\nmov %gs:0,%rax\nmov %rax,header+48(%rip)\n\
             movb $1,done(%rip)\nxor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n4:\n",
            &format!(
                "child: .quad 0\ndone: .byte 0\n.balign 8\nfirst: .quad {FIRST_TARGET:#x}\n\
                 second: .quad {SECOND_TARGET:#x}\nold_fs: .quad {OLD_FS:#x}\nold_gs: .quad {OLD_GS:#x}\n"
            ),
            SIBLING_STACK,
        );
        let plan = Plan {
            hold_thread_start: true,
            sends: 2,
            deliver: true,
            bases_at_signals: Some(bases),
            ..Plan::default()
        };
        let (events, stdout) = tool_stdout(&program, plan);
        let log = StackedLog::read(&stdout);
        let context = format!("{bases:?}: {log:#x?} {events:?}");
        assert_eq!(signal_hooks(&events), [SIGUSR1, SIGUSR2], "{context}");
        assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{context}");
        assert_stacked_on(&log, 0, 1, &context);
        let quad = |i: usize| u64::from_ne_bytes(stdout[8 * i..8 * i + 8].try_into().unwrap());
        // What the thread read through FS, then through GS.
        let expected = match bases {
            [SegmentBase::Gs, SegmentBase::Fs] => [SECOND_TARGET, FIRST_TARGET],
            _ => [FIRST_TARGET, SECOND_TARGET],
        };
        assert_eq!([quad(5), quad(6)], expected, "{context}");
    }
}

#[test]
fn a_delivery_off_an_autodisarm_stack_disarms_it_for_the_next_frame() {
    if bounded("a_delivery_off_an_autodisarm_stack_disarms_it_for_the_next_frame") {
        return;
    }
    // The alternate stack is armed with SS_AUTODISARM; SIGUSR1's handler is
    // not SA_ONSTACK, and SIGUSR2's is. Linux's signal_delivered disarms such
    // a stack after every delivery: SIGUSR1's frame goes on the ordinary
    // stack and saves the stack armed, and SIGUSR2's frame then finds no
    // stack, goes below SIGUSR1's on the ordinary stack and saves none. Each
    // rt_sigreturn restores the stack its frame saved: armed at the end.
    let program = stacked_program(
        &[
            Handler::new(SIGUSR1),
            Handler::new(SIGUSR2).flags(SA_ONSTACK),
        ],
        &format!(
            "{ARM_ALTSTACK}{}",
            unblocked_at_syscall_return(&(tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2)))
        ),
        &format!(
            "pending: .quad {:#x}\n{}",
            bit(SIGUSR1) | bit(SIGUSR2),
            altstack_data(SS_AUTODISARM)
        ),
        ALTSTACK,
    );
    let log = stacked_at_syscall_returns_matches_native(&program);
    let context = "native";
    assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{log:#x?}");
    assert_stacked_on(&log, 0, 1, context);
    assert_interrupted_at_mark(&log, 1, context);
    let (top, below) = (log.entry(0), log.entry(1));
    let armed = [below[q::SS_SP], SS_AUTODISARM, 65536];
    assert_ne!(armed[0], 0, "{log:#x?}");
    assert_eq!(
        [below[q::SS_SP], below[q::SS_FLAGS], below[q::SS_SIZE]],
        armed,
        "{log:#x?}"
    );
    assert_eq!(
        [top[q::SS_SP], top[q::SS_FLAGS], top[q::SS_SIZE]],
        [0, SS_DISABLE, 0],
        "{log:#x?}"
    );
    // Neither frame lies on the alternate stack.
    let stack = armed[0]..armed[0] + 65536;
    assert!(
        !stack.contains(&below[q::ENTRY_RSP]) && !stack.contains(&top[q::ENTRY_RSP]),
        "{log:#x?}"
    );
    assert_eq!(log.final_stack, armed, "{log:#x?}");
}

#[test]
fn a_handler_off_an_autodisarm_stack_finds_it_disarmed() {
    if bounded("a_handler_off_an_autodisarm_stack_finds_it_disarmed") {
        return;
    }
    // The alternate stack is armed with SS_AUTODISARM, and SIGUSR1's handler,
    // which is not SA_ONSTACK, queries it. Linux disarms the stack at the
    // delivery, so the handler finds none; its frame saved the stack armed,
    // and its rt_sigreturn arms it again.
    let program = stacked_program(
        &[Handler::new(SIGUSR1).actions(QUERY_STACK)],
        &format!(
            "{ARM_ALTSTACK}{}",
            unblocked_at_syscall_return(&tgkill_self(SIGUSR1))
        ),
        &format!(
            "pending: .quad {:#x}\n{}",
            bit(SIGUSR1),
            altstack_data(SS_AUTODISARM)
        ),
        ALTSTACK,
    );
    let log = stacked_at_syscall_returns_matches_native(&program);
    assert_eq!(log.signals(), [SIGUSR1], "{log:#x?}");
    assert_interrupted_at_mark(&log, 0, "native");
    let entry = log.entry(0);
    let armed = [entry[q::SS_SP], SS_AUTODISARM, 65536];
    assert_ne!(armed[0], 0, "{log:#x?}");
    assert_eq!(
        [entry[q::SS_SP], entry[q::SS_FLAGS], entry[q::SS_SIZE]],
        armed,
        "{log:#x?}"
    );
    assert!(
        !(armed[0]..armed[0] + 65536).contains(&entry[q::ENTRY_RSP]),
        "{log:#x?}"
    );
    assert_eq!(log.queried_stack, [0, SS_DISABLE, 0], "{log:#x?}");
    assert_eq!(log.final_stack, armed, "{log:#x?}");
}

#[test]
fn exec_keeps_the_alternate_stacks_flags_for_later_frames() {
    if bounded("exec_keeps_the_alternate_stacks_flags_for_later_frames") {
        return;
    }
    // The guest arms an alternate stack with `flags` and executes itself; the
    // new image (argc 2) keeps what exec left of the stack. Linux's
    // begin_new_exec clears the stack's address and size and keeps its flags:
    // sigaltstack then reports SS_DISABLE with the stored SS_AUTODISARM, and
    // a frame's uc_stack holds no stack and the flags themselves. With
    // SS_AUTODISARM, the delivery resets the stack to SS_DISABLE.
    for flags in [0, SS_AUTODISARM] {
        let program = stacked_program(
            &[Handler::new(SIGUSR1)],
            &format!(
                "cmpq $1,argc(%rip)\njne 3f\n{ARM_ALTSTACK}\
                 lea self_exe(%rip),%rdi\nlea exec_argv(%rip),%rsi\nlea exec_envp(%rip),%rdx\n\
                 mov $59,%eax\nsyscall\njmp 99f\n3:\n{QUERY_STACK}{}",
                unblocked_at_syscall_return(&tgkill_self(SIGUSR1))
            ),
            &format!(
                "pending: .quad {:#x}\n{}self_exe: .asciz \"/proc/self/exe\"\nexec_arg: .asciz \"x\"\n\
                 .balign 8\nexec_argv: .quad self_exe, exec_arg, 0\nexec_envp: .quad 0\n",
                bit(SIGUSR1),
                altstack_data(flags)
            ),
            ALTSTACK,
        );
        let log = stacked_at_syscall_returns_matches_native(&program);
        let context = format!("native, ss_flags {flags:#x}: {log:#x?}");
        assert_eq!(log.signals(), [SIGUSR1], "{context}");
        let entry = log.entry(0);
        assert_eq!(
            [entry[q::SS_SP], entry[q::SS_FLAGS], entry[q::SS_SIZE]],
            [0, flags, 0],
            "{context}"
        );
        assert_eq!(log.queried_stack, [0, SS_DISABLE | flags, 0], "{context}");
        assert_eq!(log.final_stack, [0, SS_DISABLE, 0], "{context}");
    }
}

#[test]
fn sigaltstack_takes_back_what_it_reports_for_the_stack_exec_leaves() {
    if bounded("sigaltstack_takes_back_what_it_reports_for_the_stack_exec_leaves") {
        return;
    }
    // The guest arms an alternate stack with `flags` and executes itself;
    // exec keeps the flags and clears the address and size. The new image
    // then, comparing each result with Linux's do_sigaltstack:
    // - asks for that stack unchanged, which returns 0 before any size check;
    // - queries it (SS_DISABLE, with any SS_AUTODISARM) and gives back what
    //   the query reported, which a disabling mode keeps as given;
    // - asks for a stack with an invalid mode (EINVAL) and queries again;
    // - takes SIGUSR1, whose frame saves the stack as held.
    let einval = (-i64::from(libc::EINVAL)) as u64;
    for flags in [0, SS_AUTODISARM] {
        let program = stacked_program(
            &[Handler::new(SIGUSR1)],
            &format!(
                "cmpq $1,argc(%rip)\njne 3f\n{ARM_ALTSTACK}\
                 lea self_exe(%rip),%rdi\nlea exec_argv(%rip),%rsi\nlea exec_envp(%rip),%rdx\n\
                 mov $59,%eax\nsyscall\njmp 99f\n3:\n{}{QUERY_STACK}{}{}\
                 xor %edi,%edi\nlea second_query(%rip),%rsi\nmov $131,%eax\nsyscall\n\
                 mov second_query+8(%rip),%eax\n{}{}",
                set_altstack("unchanged", 0),
                set_altstack("header+40", 1),
                set_altstack("bad_mode", 2),
                keep_result(3),
                unblocked_at_syscall_return(&tgkill_self(SIGUSR1))
            ),
            &format!(
                "pending: .quad {:#x}\n{}{}{}self_exe: .asciz \"/proc/self/exe\"\n\
                 exec_arg: .asciz \"x\"\n.balign 8\nexec_argv: .quad self_exe, exec_arg, 0\n\
                 exec_envp: .quad 0\nsecond_query: .zero 24\n",
                bit(SIGUSR1),
                altstack_data(flags),
                stack_t("unchanged", "0", flags, 0),
                stack_t("bad_mode", "0", 4, 0),
            ),
            ALTSTACK,
        );
        let log = stacked_at_syscall_returns_matches_native(&program);
        let context = format!("native, ss_flags {flags:#x}: {log:#x?}");
        let reported = [0, SS_DISABLE | flags, 0];
        assert_eq!(log.signals(), [SIGUSR1], "{context}");
        assert_eq!(log.queried_stack, reported, "{context}");
        assert_eq!(log.results, [0, 0, einval, SS_DISABLE | flags], "{context}");
        let entry = log.entry(0);
        assert_eq!(
            [entry[q::SS_SP], entry[q::SS_FLAGS], entry[q::SS_SIZE]],
            reported,
            "{context}"
        );
        assert_eq!(log.final_stack, reported, "{context}");
    }
}

#[test]
fn sigaltstack_takes_ss_onstack_as_an_input_mode() {
    if bounded("sigaltstack_takes_ss_onstack_as_an_input_mode") {
        return;
    }
    // The guest asks for an alternate stack with SS_ONSTACK as its mode,
    // which Linux's do_sigaltstack takes as it takes 0 and stores as given,
    // then for one with an invalid mode (EINVAL) and for one below
    // MINSIGSTKSZ (ENOMEM), which leave the stack as it is. SIGUSR1's handler
    // is SA_ONSTACK: its frame goes on the stack and saves the flags as
    // given; on the stack, the handler queries it (SS_ONSTACK, which the
    // report shows while the caller runs on it) and asks for another (EPERM).
    let errno = |value: i32| (-i64::from(value)) as u64;
    let ss_onstack = libc::SS_ONSTACK as u64;
    let program = stacked_program(
        &[Handler::new(SIGUSR1)
            .flags(SA_ONSTACK)
            .actions(&format!("{QUERY_STACK}{}", set_altstack("plain", 3)))],
        &format!(
            "{}{}{}{}",
            set_altstack("onstack_mode", 0),
            set_altstack("bad_mode", 1),
            set_altstack("too_small", 2),
            unblocked_at_syscall_return(&tgkill_self(SIGUSR1))
        ),
        &format!(
            "pending: .quad {:#x}\n{}{}{}{}",
            bit(SIGUSR1),
            stack_t("onstack_mode", "altstack", ss_onstack, 65536),
            stack_t("bad_mode", "altstack", 4, 65536),
            stack_t("too_small", "altstack", 0, 1024),
            stack_t("plain", "altstack", 0, 65536),
        ),
        ALTSTACK,
    );
    let log = stacked_at_syscall_returns_matches_native(&program);
    assert_eq!(log.signals(), [SIGUSR1], "{log:#x?}");
    assert_interrupted_at_mark(&log, 0, "native");
    let entry = log.entry(0);
    let sp = entry[q::SS_SP];
    assert_ne!(sp, 0, "{log:#x?}");
    assert_eq!(
        [entry[q::SS_SP], entry[q::SS_FLAGS], entry[q::SS_SIZE]],
        [sp, ss_onstack, 65536],
        "{log:#x?}"
    );
    assert!((sp..sp + 65536).contains(&entry[q::ENTRY_RSP]), "{log:#x?}");
    assert_eq!(log.queried_stack, [sp, ss_onstack, 65536], "{log:#x?}");
    assert_eq!(
        log.results,
        [
            0,
            errno(libc::EINVAL),
            errno(libc::ENOMEM),
            errno(libc::EPERM)
        ],
        "{log:#x?}"
    );
    assert_eq!(log.final_stack, [sp, 0, 65536], "{log:#x?}");
}

#[test]
fn the_native_tracer_classifies_sigstop_by_provenance() {
    // What PTRACE_GETSIGINFO shows decides, not the order of the stops: the
    // synthetic SIGSTOP of a new thread is suppressed wherever it comes, once,
    // and a sent SIGSTOP is forwarded, also as a thread's first SIGSTOP (as
    // when SIGCONT cleared the synthetic one before the thread dequeued it).
    let (pid, child) = (100, 101);
    use SigstopAction::*;
    assert_eq!(
        classify_sigstop(child, pid, libc::SI_USER, 0, &[]),
        Ok(SuppressSynthetic)
    );
    for (code, synthetic) in [
        (libc::SI_TKILL, &[][..]),
        (libc::SI_TKILL, &[child][..]),
        (libc::SI_USER, &[][..]),
        (libc::SI_QUEUE, &[child][..]),
    ] {
        assert_eq!(
            classify_sigstop(child, pid, code, pid, synthetic),
            Ok(Forward),
            "si_code {code}"
        );
    }
    assert_eq!(
        classify_sigstop(pid, pid, libc::SI_TKILL, pid, &[]),
        Ok(Forward)
    );
    // Refused: a second synthetic stop, one for the main thread, a send with
    // no sender, and any other provenance.
    for (tid, code, sender, synthetic) in [
        (child, libc::SI_USER, 0, &[child][..]),
        (pid, libc::SI_USER, 0, &[][..]),
        (child, libc::SI_TKILL, 0, &[][..]),
        (child, libc::SI_KERNEL, 0, &[][..]),
        (child, libc::SI_KERNEL, pid, &[][..]),
    ] {
        assert!(
            classify_sigstop(tid, pid, code, sender, synthetic).is_err(),
            "tid {tid} si_code {code} from {sender}"
        );
    }
}

#[test]
fn the_native_tracer_forwards_a_sent_sigstop_and_suppresses_only_the_synthetic_one() {
    if bounded("the_native_tracer_forwards_a_sent_sigstop_and_suppresses_only_the_synthetic_one") {
        return;
    }
    // Native only: KVM supports no stopped state, so a stop signal a guest
    // sends ends a KVM run. The guest clones a thread, which sends itself
    // SIGSTOP with tgkill and then lets the main thread finish. The tracer
    // suppresses the thread's synthetic SIGSTOP (SI_USER from pid 0), forwards
    // the sent one (SI_TKILL from the guest), which stops the whole process,
    // and resumes each thread from the group-stop that follows, which
    // delivers nothing.
    let program = stacked_program(
        &[],
        "mov $0x50f00,%edi\nlea sibling_stack_end(%rip),%rsi\nxor %edx,%edx\n\
         xor %r10d,%r10d\nxor %r8d,%r8d\nmov $56,%eax\nsyscall\n\
         test %rax,%rax\njz 7f\n\
         5: cmpb $0,done(%rip)\nje 5b\njmp 4f\n\
         7: mov $186,%eax\nsyscall\nmov pid(%rip),%rdi\nmov %rax,%rsi\nmov $19,%edx\n\
         mov $234,%eax\nsyscall\nmovb $1,done(%rip)\nxor %edi,%edi\nmov $60,%eax\nsyscall\nud2\n\
         4:\n",
        "done: .byte 0\n",
        SIBLING_STACK,
    );
    let native = traced_native(&program, Tracing::Deliver);
    assert_eq!(native.delivered, [libc::SIGSTOP]);
    assert_eq!(native.synthetic_stops, 1);
}

// Outcomes at a timer boundary (https://github.com/rrnewton/reverie/issues/1188
// added the stacked frames these build on): the termination outcomes, a
// signal the Tool suppresses or the guest ignores, the alternate stack, the
// red zone, a boundary inside a running handler, and a process-directed
// signal in a process with several threads. Each guest is compared with the
// same binary's native Linux run, under the native tracer where a Tool's
// signal hook decides something (see [`traced_native_with`]). On KVM the
// boundary is a precise timer event at a fixed RCB target, in the main
// thread's spin, which holds the thread while a sibling sends it signals (the
// rendezvous of [`spinner_plan`]); natively a sibling's signal interrupts the
// spin wherever it then is, so where the interrupt landed (the first frame's
// rip, rcx and flags) is left out of the comparison.

/// A stacked-signal guest (see [`stacked_program`]) whose main thread runs
/// `before`, starts a sibling that waits until the main thread spins and then
/// runs `sends`, reaches the marker, and spins without a syscall, with r12 at
/// the loop's head, until `entries` handlers have logged their entries (or
/// for 2,000,000,000 iterations), and then runs `after`. The main thread
/// announces the spin right before its loop, once r12 and rcx are set, so a
/// signal the sibling sends natively interrupts the loop itself. The sibling
/// exits once `sends` is done, unless `sends` keeps it.
fn timer_boundary_program(
    handlers: &[Handler],
    before: &str,
    sends: &str,
    entries: usize,
    after: &str,
    data: &str,
    bss: &str,
) -> Program {
    stacked_program(
        handlers,
        &format!(
            "{before}{}{GETPPID}xor %eax,%eax\nlea 1f(%rip),%r12\nmov $2000000000,%rcx\n\
             movb $1,spinning(%rip)\n1: cmpq ${entries},header(%rip)\njae 2f\ndec %rcx\njnz 1b\n2:\n{after}",
            sibling(&format!("5: cmpb $0,spinning(%rip)\nje 5b\n{sends}")),
        ),
        &format!("spinning: .byte 0\n{data}"),
        &format!("{SIBLING_STACK}{bss}"),
    )
}

/// The quads where the interrupt that delivers a timer-boundary guest's
/// first signal natively lands, which only the KVM runs fix: the first
/// frame's rip, rcx and flags, and so the flags its handler starts with.
fn interrupt_varies(index: usize, quad: usize) -> bool {
    index == 0 && [q::RIP, q::RCX, q::EFLAGS, q::ENTRY_RFLAGS].contains(&quad)
}

/// How a run ended: its status in wait(2) encoding, stdout and stderr, or
/// the run's failure, as text.
type StatusEnding = Result<(i32, Vec<u8>, Vec<u8>), String>;

/// Runs `program` under a [`TimerTool`] following `plan`, and returns the
/// Tool's events and how the run ended.
fn run_status(program: &Program, plan: Plan) -> (Vec<Event>, StatusEnding) {
    let mut backend = KvmBackend::new(program.memory).unwrap();
    backend
        .install_static_elf_file_with_context(
            std::fs::File::open(&program.executable).unwrap(),
            &[program.executable.to_str().unwrap()],
            &[],
            &program.directory,
        )
        .unwrap();
    let completion = futures::executor::block_on(
        backend.run_static_elf_with_tool_completion::<TimerTool>(plan, true),
    )
    .unwrap();
    let events = completion.global_state.events.into_inner().unwrap();
    let ending = completion
        .result
        .map(|(status, out, err)| (status.into_raw(), out, err))
        .map_err(|error| error.to_string());
    (events, ending)
}

/// Every thread's exit status that the Tool saw ([`Event::Exited`]), sorted
/// by status.
fn exit_statuses(events: &[Event]) -> Vec<i32> {
    let mut statuses: Vec<i32> = events
        .iter()
        .filter_map(|event| match event {
            Event::Exited { status, .. } => Some(*status),
            _ => None,
        })
        .collect();
    statuses.sort();
    statuses
}

/// prctl(PR_SET_DUMPABLE, 0): the process may not dump core.
const NOT_DUMPABLE: &str =
    "mov $4,%edi\nxor %esi,%esi\nmov $157,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n";

#[test]
fn a_fatal_signal_at_a_timer_boundary_ends_every_thread_with_linuxs_status() {
    if bounded("a_fatal_signal_at_a_timer_boundary_ends_every_thread_with_linuxs_status") {
        return;
    }
    // A sibling waits until the main thread spins, without a syscall, sends
    // it `signal`, whose action is the default, and spins on. The Tool's
    // precise timer event lands in the main thread's spin and holds it until
    // the signal is sent; the native tracer delivers the signal at its stop.
    // The default action ends the group before any handler runs: the main
    // thread, then the sibling, end with the signal's status, which carries
    // the core flag only when a core dump was written (coredump_finish in
    // fs/coredump.c). A process that is not dumpable writes none
    // (coredump_skip), and natively the tracer's RLIMIT_CORE of 1 aborts the
    // dump of one that is, so Linux sets the flag in neither case here.
    for (signal, dumpable) in [
        (libc::SIGTERM, true),
        (libc::SIGQUIT, false),
        (libc::SIGQUIT, true),
    ] {
        let program = timer_boundary_program(
            &[],
            if dumpable { "" } else { NOT_DUMPABLE },
            &format!("{}3: jmp 3b\n", tgkill_self(signal)),
            1,
            "",
            "",
            "",
        );
        let context = format!("signal {signal}, dumpable {dumpable}");
        let native = traced_native_with(&program, Tracing::Deliver, TraceOptions::default());
        assert_eq!(
            (
                native.status,
                native.stdout.as_slice(),
                native.stderr.as_slice()
            ),
            (signal, &[][..], &[][..]),
            "native, {context}"
        );
        assert_eq!(native.delivered, [signal], "native, {context}");
        let mut native_threads: Vec<i32> =
            native.threads.iter().map(|&(_, status)| status).collect();
        native_threads.sort();
        assert_eq!(native_threads, [signal; 2], "native, {context}");
        let plan = Plan {
            exits: true,
            ..spinner_plan()
        };
        let (events, ending) = run_status(&program, plan);
        let context = format!("{context}: {events:?}");
        // KVM decides the core flag as Linux does, from this process's
        // RLIMIT_CORE and the host's core_pattern
        // (`reverie_linuxemu::core_dump`). This process's limit is not the
        // native tracer's 1, so the flag follows the rule; where the limit is
        // 1 (as in validation), it is the native status exactly.
        let core = reverie_linuxemu::core_dump::guest_writes_core(signal, dumpable);
        let kvm_status = signal | if core { 0x80 } else { 0 };
        if limit_is_one() {
            assert_eq!(kvm_status, native.status, "{context}");
        }
        assert_eq!(ending, Ok((kvm_status, vec![], vec![])), "{context}");
        assert_eq!(exit_statuses(&events), [kvm_status; 2], "{context}");
        let (timer_at, timer_clock) = first_timer(&events);
        let (requested_at, _) = last_request(&events);
        assert_eq!(timer_clock, requested_at + SPIN_TICKS, "{context}");
        let hooks: Vec<(usize, i32, u64)> = events
            .iter()
            .enumerate()
            .filter_map(|(at, event)| match event {
                Event::Signalled { signal, clock } => Some((at, *signal, *clock)),
                _ => None,
            })
            .collect();
        assert_eq!(hooks.len(), 1, "{context}");
        assert_eq!((hooks[0].1, hooks[0].2), (signal, timer_clock), "{context}");
        assert!(hooks[0].0 > timer_at, "{context}");
        println!(
            "signal {signal}, dumpable {dumpable}: native status {:#x}, threads {native_threads:#x?}; \
             KVM status {kvm_status:#x} at the timer boundary at clock {timer_clock}, threads {:#x?}",
            native.status,
            exit_statuses(&events)
        );
    }
}

/// exit_group(42).
const EXIT_GROUP_42: &str = "mov $42,%edi\nmov $231,%eax\nsyscall\nud2\n";

/// How every thread of the group-exit guests below ends: exited, status 42.
const EXITED_42: i32 = 42 << 8;

#[test]
fn a_group_exit_while_a_timer_callback_holds_a_thread_ends_it_before_any_signal() {
    if bounded("a_group_exit_while_a_timer_callback_holds_a_thread_ends_it_before_any_signal") {
        return;
    }
    // The main thread writes a byte to a pipe, reaches the marker and spins;
    // a sibling reads the byte, sends SIGUSR1 to the main thread, whose
    // handler would log an entry, and ends the group with exit_group(42).
    // Both happen while the main thread is held: on KVM in the callback of
    // its precise timer event in the spin, which waits until the sibling has
    // exited; natively in its write, which the sibling's read waits for, and
    // at that write's syscall-exit stop, before any signal is selected
    // there (a group exit that comes before the stop ends the thread on the
    // way to it, with no stop: ptrace_stop skips one while a fatal signal is
    // pending). Linux's get_signal takes the group exit before it dequeues
    // any signal (SIGNAL_GROUP_EXIT, at the top of its loop in
    // kernel/signal.c), so the main thread ends without a signal-delivery
    // stop, its handler never runs, and every thread ends with status 42.
    let program = stacked_program(
        &[Handler::new(SIGUSR1)],
        &format!(
            "lea pipe_fds(%rip),%rdi\nxor %esi,%esi\nmov $293,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n{}\
             mov pipe_fds+4(%rip),%edi\nlea one_byte(%rip),%rsi\nmov $1,%edx\nmov $1,%eax\nsyscall\n\
             {GETPPID}lea 1f(%rip),%r12\nmov $2000000000,%rcx\n\
             1: cmpq $1,header(%rip)\njae 2f\ndec %rcx\njnz 1b\n2:\n",
            sibling(&format!(
                "mov pipe_fds(%rip),%edi\nlea sibling_byte(%rip),%rsi\nmov $1,%edx\nxor %eax,%eax\nsyscall\n\
                 {}{EXIT_GROUP_42}",
                tgkill_self(SIGUSR1)
            )),
        ),
        "pipe_fds: .long 0, 0\none_byte: .byte 0x78\nsibling_byte: .byte 0\n",
        SIBLING_STACK,
    );
    let native = traced_native_with(
        &program,
        Tracing::Deliver,
        TraceOptions {
            hold_at_syscall_exit: Some(libc::SYS_write),
            ..TraceOptions::default()
        },
    );
    let mut native_threads: Vec<i32> = native.threads.iter().map(|&(_, status)| status).collect();
    native_threads.sort();
    assert_eq!(
        (
            native.status,
            native.stdout.as_slice(),
            native.stderr.as_slice()
        ),
        (EXITED_42, &[][..], &[][..]),
        "native"
    );
    assert_eq!(native_threads, [EXITED_42; 2], "native");
    assert_eq!(native.stops, [0; 0], "native: no signal-delivery stop");
    assert!(
        native.held.is_empty() || native.held == [-1],
        "native: held {:?}",
        native.held
    );
    let plan = Plan {
        exits: true,
        timer_waits_for_exit: true,
        ..spinner_plan()
    };
    let (events, ending) = run_status(&program, plan);
    assert_eq!(ending, Ok((EXITED_42, vec![], vec![])), "{events:?}");
    assert_eq!(exit_statuses(&events), [EXITED_42; 2], "{events:?}");
    assert_eq!(timer_clocks(&events).len(), 1, "{events:?}");
    assert_eq!(
        signal_hooks(&events),
        [0; 0],
        "no signal hook after the group exit: {events:?}"
    );
    println!(
        "ended with status {EXITED_42:#x} before any signal: native held {:?}, KVM {events:?}",
        native.held
    );
}

/// What SIGUSR1's hook leaves of SIGUSR1 in the held-hook guests of
/// [`held_hook_group_exit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeldSignal {
    /// The hook returns SIGUSR1, whose handler is installed.
    Delivered,
    /// The hook suppresses SIGUSR1.
    Suppressed,
    /// The hook returns SIGUSR1, whose action is SIG_IGN, so that it is
    /// discarded after its hook (a traced Linux thread, and a Tool's hook,
    /// see an ignored signal: sig_ignored in kernel/signal.c).
    Ignored,
}

/// A held-hook guest: a sibling waits until the main thread spins, sends it
/// SIGUSR1 (and, with `pair`, SIGUSR2, whose handler would log an entry),
/// and ends the group with exit_group(42), which the Tool holds until
/// SIGUSR1's callback has begun, and the native tracer at its entry until the
/// main thread's SIGUSR1 stop. That callback, at the main thread's timer
/// boundary, waits until the sibling has exited and then leaves SIGUSR1 as
/// `held` says; natively the tracer leaves the stop as it is, which only the
/// group exit ends. Checks that natively and on KVM every thread ends with
/// status 42, that natively SIGUSR1's is the one signal-delivery stop, and
/// that on KVM SIGUSR1's is the one hook, at the timer event's clock; then
/// runs the guest again under a Tool that controls delivery with permits and
/// returns that run's permits, hooks and receipts ([`boundaries`]).
fn held_hook_group_exit(pair: bool, held: HeldSignal) -> Vec<String> {
    let sends = if pair {
        tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2)
    } else {
        tgkill_self(SIGUSR1)
    };
    let (handlers, before, data) = if held == HeldSignal::Ignored {
        (
            vec![Handler::new(SIGUSR2)],
            format!(
                "mov ${SIGUSR1},%edi\nlea ignore_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\n\
                 mov $13,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n"
            ),
            format!(".balign 8\nignore_action: .quad 1, {HANDLER_FLAGS:#x}, restorer, 0\n"),
        )
    } else {
        (
            vec![Handler::new(SIGUSR1), Handler::new(SIGUSR2)],
            String::new(),
            String::new(),
        )
    };
    let program = timer_boundary_program(
        &handlers,
        &before,
        &format!("{sends}{EXIT_GROUP_42}"),
        1,
        "",
        &data,
        "",
    );
    let native = traced_native_with(
        &program,
        Tracing::Deliver,
        TraceOptions {
            hold_until_exit: Some(SIGUSR1),
            exit_group_after_hold: true,
            ..TraceOptions::default()
        },
    );
    let context = format!("pair {pair}, {held:?}");
    let mut native_threads: Vec<i32> = native.threads.iter().map(|&(_, status)| status).collect();
    native_threads.sort();
    assert_eq!(
        (
            native.status,
            native.stdout.as_slice(),
            native.stderr.as_slice()
        ),
        (EXITED_42, &[][..], &[][..]),
        "native, {context}"
    );
    assert_eq!(native_threads, [EXITED_42; 2], "native, {context}");
    assert_eq!(
        (native.held.as_slice(), native.stops.as_slice()),
        (&[SIGUSR1][..], &[SIGUSR1][..]),
        "native, {context}"
    );
    let plan = Plan {
        exits: true,
        hook_waits_for_exit: Some(SIGUSR1),
        exit_waits_for_hook: true,
        sends: if pair { 2 } else { 1 },
        suppress: if held == HeldSignal::Suppressed {
            bit(SIGUSR1)
        } else {
            0
        },
        ..spinner_plan()
    };
    let (events, ending) = run_status(&program, plan.clone());
    let kvm_context = format!("{context}: {events:?}");
    assert_eq!(ending, Ok((EXITED_42, vec![], vec![])), "{kvm_context}");
    assert_eq!(exit_statuses(&events), [EXITED_42; 2], "{kvm_context}");
    let (timer_at, timer_clock) = first_timer(&events);
    let hooks: Vec<(usize, i32, u64)> = events
        .iter()
        .enumerate()
        .filter_map(|(at, event)| match event {
            Event::Signalled { signal, clock } => Some((at, *signal, *clock)),
            _ => None,
        })
        .collect();
    assert_eq!(hooks.len(), 1, "only SIGUSR1's hook: {kvm_context}");
    assert!(hooks[0].0 > timer_at, "{kvm_context}");
    assert_eq!(
        (hooks[0].1, hooks[0].2),
        (SIGUSR1, timer_clock),
        "{kvm_context}"
    );
    let (events, ending) = run_status(
        &program,
        Plan {
            permits: true,
            ..plan
        },
    );
    let permits_context = format!("{context}, with permits: {events:?}");
    assert_eq!(ending, Ok((EXITED_42, vec![], vec![])), "{permits_context}");
    assert_eq!(exit_statuses(&events), [EXITED_42; 2], "{permits_context}");
    println!(
        "{context}: ended with status {EXITED_42:#x}: native stops {:?}, KVM boundaries {:?}",
        native.stops,
        boundaries(&events)
    );
    boundaries(&events)
}

#[test]
fn a_group_exit_while_a_signal_hook_holds_a_thread_ends_it_before_its_handler() {
    if bounded("a_group_exit_while_a_signal_hook_holds_a_thread_ends_it_before_its_handler") {
        return;
    }
    // SIGUSR1's hook returns SIGUSR1, whose handler is installed, after the
    // group exit (see held_hook_group_exit). Linux's ptrace_signal requeues a
    // signal whose stop a fatal signal (the group exit's SIGKILL) ended, and
    // get_signal then takes the group exit before it selects another signal
    // (kernel/signal.c): no handler runs, SIGUSR2 gets no stop, and every
    // thread ends with status 42. On KVM no handler runs either, and SIGUSR2
    // gets no hook; but SIGUSR1, whose hook was running, still gets its frame,
    // which the thread never runs, and a Tool that controls delivery a Caught
    // receipt for it, where Linux requeues it: a named limit
    // (https://github.com/rrnewton/reverie/issues/1208).
    for pair in [false, true] {
        assert_eq!(
            held_hook_group_exit(pair, HeldSignal::Delivered),
            ["permit 1", "hook 10", "receipt 1 Caught"],
            "pair {pair}"
        );
    }
}

#[test]
fn a_group_exit_during_a_hook_that_drops_its_signal_selects_no_other_signal() {
    if bounded("a_group_exit_during_a_hook_that_drops_its_signal_selects_no_other_signal") {
        return;
    }
    // SIGUSR1 and SIGUSR2 are pending, and SIGUSR1's hook, after the group
    // exit, suppresses SIGUSR1 (first guest), or returns it to be discarded,
    // its action being SIG_IGN (second guest). Linux comes back to
    // get_signal's group-exit test, before any other dequeue, both after
    // ptrace_signal returns no signal and after it discards an ignored one
    // (kernel/signal.c), so SIGUSR2 gets no stop either way. On KVM the
    // selection after the dropped signal stops at the group exit too: only
    // SIGUSR1's hook runs, nothing is delivered, and the boundary's permit
    // settles with NoHandler.
    for held in [HeldSignal::Suppressed, HeldSignal::Ignored] {
        assert_eq!(
            held_hook_group_exit(true, held),
            ["permit 1", "hook 10", "receipt 1 NoHandler"],
            "{held:?}"
        );
    }
}

/// The permits, hooks and receipts of a run under [`Plan::permits`], as
/// text, in order.
fn boundaries(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Permit(sequence) => Some(format!("permit {sequence}")),
            Event::Signalled { signal, .. } => Some(format!("hook {signal}")),
            Event::Receipt(sequence, outcome) => Some(format!("receipt {sequence} {outcome}")),
            _ => None,
        })
        .collect()
}

/// Runs a timer-boundary guest natively under `tracing` and `options` and on
/// KVM under the Tool following `plan` (with [`Plan::deliver`] and, when
/// `permits`, [`Plan::permits`]), and checks that both exit with status 0
/// and write logs that compare equal (with [`interrupt_varies`]), and that
/// the Tool's hooks come in the order of the tracer's signal-delivery stops.
/// Returns the native log, the KVM log and the Tool's events.
fn timer_boundary_matches_native(
    program: &Program,
    tracing: Tracing,
    options: TraceOptions,
    plan: Plan,
) -> (StackedLog, StackedLog, Vec<Event>) {
    let native = traced_native_with(program, tracing, options);
    assert!(
        libc::WIFEXITED(native.status)
            && libc::WEXITSTATUS(native.status) == 0
            && native.stderr.is_empty(),
        "native: status {:#x}: {}",
        native.status,
        String::from_utf8_lossy(&native.stderr)
    );
    let native_log = StackedLog::read(&native.stdout);
    let (events, stdout) = tool_stdout(
        program,
        Plan {
            deliver: true,
            ..plan
        },
    );
    let log = StackedLog::read(&stdout);
    assert_eq!(
        comparable(&log, &interrupt_varies),
        comparable(&native_log, &interrupt_varies),
        "tool {log:#x?}, native {native_log:#x?}, {events:?}"
    );
    assert_eq!(
        (
            log.final_mask,
            log.final_stack,
            log.queried_stack,
            log.results
        ),
        (
            native_log.final_mask,
            native_log.final_stack,
            native_log.queried_stack,
            native_log.results
        ),
        "tool {log:#x?}, native {native_log:#x?}"
    );
    assert_eq!(
        signal_hooks(&events),
        native.stops,
        "tool hooks against the native tracer's stops: {events:?}"
    );
    (native_log, log, events)
}

/// rt_sigpending into the header's result `index`.
fn pending_into_result(index: usize) -> String {
    assert!(index < RESULTS);
    format!(
        "lea header+{}(%rip),%rdi\nmov $8,%esi\nmov $127,%eax\nsyscall\n",
        8 * (8 + index)
    )
}

#[test]
fn a_signal_a_tool_suppresses_at_a_timer_boundary_runs_no_handler() {
    if bounded("a_signal_a_tool_suppresses_at_a_timer_boundary_runs_no_handler") {
        return;
    }
    // A sibling waits until the main thread spins and sends it SIGUSR1, then,
    // in the second guest, SIGUSR2 as well. The Tool's precise timer event
    // holds the main thread in its spin until they are sent, and its hook
    // suppresses SIGUSR1 at that boundary; the native tracer suppresses
    // SIGUSR1 at its stop (and holds that stop until SIGUSR2 is pending).
    // Suppressed, SIGUSR1 runs no handler and leaves nothing pending; Linux's
    // get_signal goes on to the next signal, so SIGUSR2's frame is built at
    // the same boundary, saving the interrupted spin. The guest spins until
    // the sibling has finished and then reads its pending set.
    for pair in [false, true] {
        let sends = if pair {
            tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2)
        } else {
            tgkill_self(SIGUSR1)
        };
        let program = timer_boundary_program(
            &[Handler::new(SIGUSR1), Handler::new(SIGUSR2)],
            LOAD_FPU,
            &format!("{sends}movb $1,sent(%rip)\n"),
            usize::from(pair),
            &format!("3: cmpb $0,sent(%rip)\nje 3b\n{}", pending_into_result(0)),
            "sent: .byte 0\n",
            "",
        );
        let tracing = if pair {
            Tracing::HoldUntilPending {
                first: SIGUSR1,
                then: SIGUSR2,
            }
        } else {
            Tracing::Deliver
        };
        let options = TraceOptions {
            suppress: bit(SIGUSR1),
            ..TraceOptions::default()
        };
        let base = Plan {
            sends: if pair { 2 } else { 1 },
            suppress: bit(SIGUSR1),
            ..spinner_plan()
        };
        let (native, log, events) =
            timer_boundary_matches_native(&program, tracing, options, base.clone());
        let context = format!("pair {pair}: {log:#x?} {events:?}");
        let expected: &[i32] = if pair { &[SIGUSR2] } else { &[] };
        assert_eq!(native.signals(), expected, "{context}");
        assert_eq!(native.results[0], 0, "nothing pending: {context}");
        if pair {
            // SIGUSR2's frame saved the spin at the timer event's boundary.
            let r = registers_of(&events);
            let e = log.entry(0);
            assert_eq!(
                [e[q::RIP], e[q::RCX], e[q::EFLAGS], e[q::R12]],
                [r.rip, r.rcx, r.eflags, r.r12],
                "{context}"
            );
            assert_interrupted_at_mark_but_rip(&native, 0, "native");
        }
        // The receipts, under a Tool that controls signal delivery with
        // permits: SIGUSR1, suppressed, shares the boundary of the signal
        // selected after it, and alone ends its boundary with NoHandler.
        let (_, _, events) = timer_boundary_matches_native(
            &program,
            tracing,
            options,
            Plan {
                permits: true,
                ..base
            },
        );
        let expected = if pair {
            vec![
                "permit 1".to_owned(),
                format!("hook {SIGUSR1}"),
                format!("hook {SIGUSR2}"),
                "receipt 1 Caught".to_owned(),
            ]
        } else {
            vec![
                "permit 1".to_owned(),
                format!("hook {SIGUSR1}"),
                "receipt 1 NoHandler".to_owned(),
            ]
        };
        assert_eq!(boundaries(&events), expected, "pair {pair}: {events:?}");
        println!(
            "pair {pair}: suppressed SIGUSR1, handlers {:?}, receipts {:?}",
            native.signals(),
            boundaries(&events)
        );
    }
}

/// [`assert_interrupted_at_mark`] for an entry whose rip is where an
/// interrupt landed in the spin: rbx, rbp and the loaded FPU state intact.
fn assert_interrupted_at_mark_but_rip(log: &StackedLog, index: usize, context: &str) {
    let e = log.entry(index);
    let context = format!("{context}: entry {index}: {log:#x?}");
    assert_eq!([e[q::RBX], e[q::RBP]], [RBX, RBP], "{context}");
    assert_eq!(
        [e[q::MXCSR], e[q::XMM5], e[q::XSTATE_BV] & 0b111],
        [LOADED_MXCSR, LOADED_XMM5, 0b011],
        "{context}"
    );
}

#[test]
fn an_ignored_signal_at_a_timer_boundary_is_discarded_as_linux_discards_it() {
    if bounded("an_ignored_signal_at_a_timer_boundary_is_discarded_as_linux_discards_it") {
        return;
    }
    // SIGUSR1's action is SIG_IGN, set before the sibling starts. The sibling
    // waits until the main thread spins and sends it SIGUSR1 and SIGUSR2,
    // during the Tool's timer event at the spin. A traced thread queues an
    // ignored signal (sig_ignored in kernel/signal.c), so the tracer and the
    // Tool's hook see it, and get_signal then discards it and goes on to
    // SIGUSR2, whose frame is built at the same boundary; nothing is left
    // pending. The second guest sends SIGUSR1 alone: discarded, no handler.
    for pair in [false, true] {
        let sends = if pair {
            tgkill_self(SIGUSR1) + &tgkill_self(SIGUSR2)
        } else {
            tgkill_self(SIGUSR1)
        };
        let program = timer_boundary_program(
            &[Handler::new(SIGUSR2)],
            &format!(
                "mov ${SIGUSR1},%edi\nlea ignore_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\n\
                 mov $13,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n{LOAD_FPU}"
            ),
            &format!("{sends}movb $1,sent(%rip)\n"),
            usize::from(pair),
            &format!("3: cmpb $0,sent(%rip)\nje 3b\n{}", pending_into_result(0)),
            &format!(
                "sent: .byte 0\n.balign 8\nignore_action: .quad 1, {HANDLER_FLAGS:#x}, restorer, 0\n"
            ),
            "",
        );
        let tracing = if pair {
            Tracing::HoldUntilPending {
                first: SIGUSR1,
                then: SIGUSR2,
            }
        } else {
            Tracing::Deliver
        };
        let base = Plan {
            sends: if pair { 2 } else { 1 },
            ..spinner_plan()
        };
        let (native, log, events) =
            timer_boundary_matches_native(&program, tracing, TraceOptions::default(), base.clone());
        let context = format!("pair {pair}: {log:#x?} {events:?}");
        let expected: &[i32] = if pair { &[SIGUSR2] } else { &[] };
        assert_eq!(native.signals(), expected, "{context}");
        assert_eq!(native.results[0], 0, "nothing pending: {context}");
        if pair {
            let r = registers_of(&events);
            let e = log.entry(0);
            assert_eq!(
                [e[q::RIP], e[q::RCX], e[q::EFLAGS], e[q::R12]],
                [r.rip, r.rcx, r.eflags, r.r12],
                "{context}"
            );
            assert_interrupted_at_mark_but_rip(&native, 0, "native");
        }
        // Under permits, the ignored SIGUSR1 shares the boundary of the
        // signal selected after it, and alone ends its boundary with
        // NoHandler.
        let (_, _, events) = timer_boundary_matches_native(
            &program,
            tracing,
            TraceOptions::default(),
            Plan {
                permits: true,
                ..base
            },
        );
        let expected = if pair {
            vec![
                "permit 1".to_owned(),
                format!("hook {SIGUSR1}"),
                format!("hook {SIGUSR2}"),
                "receipt 1 Caught".to_owned(),
            ]
        } else {
            vec![
                "permit 1".to_owned(),
                format!("hook {SIGUSR1}"),
                "receipt 1 NoHandler".to_owned(),
            ]
        };
        assert_eq!(boundaries(&events), expected, "pair {pair}: {events:?}");
        println!(
            "pair {pair}: ignored SIGUSR1, handlers {:?}, receipts {:?}",
            native.signals(),
            boundaries(&events)
        );
    }
}

/// Quads a guest writes in the 128-byte red zone below its rsp, which no
/// signal frame may touch (get_sigframe in arch/x86/kernel/signal.c).
const CANARY: u64 = 0x5afe_c0de_0000_0000;

/// Writes 16 canary quads, `CANARY + i` at `-8 * (i + 1)(%rsp)`: the whole
/// red zone below the current rsp. Uses rax.
fn write_canaries() -> String {
    (0..16)
        .map(|i| {
            format!(
                "movabs ${:#x},%rax\nmov %rax,{}(%rsp)\n",
                CANARY + i,
                -8 * (i as i64 + 1)
            )
        })
        .collect()
}

/// Counts the canaries of [`write_canaries`] still intact below the current
/// rsp into the header's result `index`. Uses rax and r8.
fn check_canaries(index: usize) -> String {
    assert!(index < RESULTS);
    let checks: String = (0..16)
        .map(|i| {
            format!(
                "movabs ${:#x},%rax\ncmp %rax,{}(%rsp)\njne 7f\ninc %r8\n7:\n",
                CANARY + i,
                -8 * (i as i64 + 1)
            )
        })
        .collect();
    format!(
        "xor %r8d,%r8d\n{checks}mov %r8,header+{}(%rip)\n",
        8 * (8 + index)
    )
}

/// The guest of the nested-boundary tests below. Its main thread writes
/// canaries below its rsp, starts a sibling and spins, as in
/// [`timer_boundary_program`]. The sibling sends it SIGUSR1, waits until
/// SIGUSR1's handler runs, and sends SIGUSR2. SIGUSR1's handler writes
/// canaries below its own rsp, keeps the head of its loop in r12, and spins
/// without a syscall until SIGUSR2's handler, which queries the alternate
/// stack, has run; then it checks its canaries (result 1). The main thread
/// checks its own once both handlers have returned (result 0). With
/// `altstack`, both handlers are SA_ONSTACK and the guest arms a 64 KiB
/// alternate stack with those flags first.
fn nested_boundaries_program(altstack: Option<u64>) -> Program {
    let onstack = if altstack.is_some() { SA_ONSTACK } else { 0 };
    timer_boundary_program(
        &[
            Handler::new(SIGUSR1).flags(onstack).actions(&format!(
                "{}lea 3f(%rip),%r12\nmov $2000000000,%rcx\nmovb $1,in_handler(%rip)\n\
                 3: cmpb $0,second(%rip)\njne 4f\ndec %rcx\njnz 3b\n4:\n{}",
                write_canaries(),
                check_canaries(1)
            )),
            Handler::new(SIGUSR2)
                .flags(onstack)
                .actions(&format!("{QUERY_STACK}movb $1,second(%rip)\n")),
        ],
        &format!(
            "{}{LOAD_FPU}{}",
            if altstack.is_some() { ARM_ALTSTACK } else { "" },
            write_canaries()
        ),
        &format!(
            "{}3: cmpb $0,in_handler(%rip)\nje 3b\n{}",
            tgkill_self(SIGUSR1),
            tgkill_self(SIGUSR2)
        ),
        2,
        &check_canaries(0),
        &format!(
            "in_handler: .byte 0\nsecond: .byte 0\n{}",
            altstack.map(altstack_data).unwrap_or_default()
        ),
        if altstack.is_some() { ALTSTACK } else { "" },
    )
}

/// RCBs from SIGUSR1's callback to the second timer event of the
/// nested-boundary tests, which lands in SIGUSR1's handler's loop.
const NESTED_TICKS: u64 = 1_000;

/// The plan of the nested-boundary tests: the spinner's precise event, with
/// SIGUSR1 sent during it, and a second precise event requested in
/// SIGUSR1's callback, with SIGUSR2 sent during it.
fn nested_plan() -> Plan {
    Plan {
        rendezvous_sends: vec![1, 1],
        rearm_at: Some((SIGUSR1, NESTED_TICKS)),
        ..spinner_plan()
    }
}

/// Where the interrupts that deliver the nested-boundary guests' signals
/// natively land, which only the KVM runs fix: each frame's rip, rcx and
/// flags, and the flags its handler starts with.
fn interrupts_vary(_: usize, quad: usize) -> bool {
    [q::RIP, q::RCX, q::EFLAGS, q::ENTRY_RFLAGS].contains(&quad)
}

/// The registers each timer event saw, in order.
fn timer_registers(events: &[Event]) -> Vec<Registers> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Registers(registers) => Some(registers.clone()),
            _ => None,
        })
        .collect()
}

/// Runs a nested-boundary guest natively, delivering each signal at its stop,
/// and on KVM under [`nested_plan`]; checks that both exit with status 0,
/// write logs that compare equal with [`interrupts_vary`], and see their
/// hooks and stops in one order; and checks the chain both build: SIGUSR1's
/// frame saved the main thread's spin and SIGUSR2's saved SIGUSR1's handler
/// in its loop, on its stack (rsp, and its arguments in rdi, rsi and rdx),
/// below its red zone. On KVM each frame saved the registers of the timer
/// event at whose boundary it was built. Returns the native log, the KVM
/// log and the Tool's events.
fn nested_boundaries_match_native(program: &Program) -> (StackedLog, StackedLog, Vec<Event>) {
    let native = traced_native(program, Tracing::Deliver);
    let native_log = StackedLog::read(&native.stdout);
    let (events, stdout) = tool_stdout(program, nested_plan());
    let log = StackedLog::read(&stdout);
    assert_eq!(
        comparable(&log, &interrupts_vary),
        comparable(&native_log, &interrupts_vary),
        "tool {log:#x?}, native {native_log:#x?}, {events:?}"
    );
    assert_eq!(
        (
            log.final_mask,
            log.final_stack,
            log.queried_stack,
            log.results
        ),
        (
            native_log.final_mask,
            native_log.final_stack,
            native_log.queried_stack,
            native_log.results
        ),
        "tool {log:#x?}, native {native_log:#x?}"
    );
    assert_eq!(signal_hooks(&events), native.delivered, "{events:?}");
    for (name, log) in [("native", &native_log), ("tool", &log)] {
        let context = format!("{name}: {log:#x?}");
        assert_eq!(log.signals(), [SIGUSR1, SIGUSR2], "{context}");
        let (first, second) = (log.entry(0), log.entry(1));
        // Each saved rip lies in the loop whose head the frame's r12 holds:
        // four instructions, at most 20 bytes.
        for e in [first, second] {
            assert!(
                (e[q::R12]..e[q::R12] + 20).contains(&e[q::RIP]),
                "{context}"
            );
        }
        assert_interrupted_at_mark_but_rip(log, 0, name);
        assert_eq!(
            [
                second[q::RSP],
                second[q::RDI],
                second[q::RSI],
                second[q::RDX]
            ],
            [
                first[q::ENTRY_RSP],
                SIGUSR1 as u64,
                first[q::ENTRY_RSI],
                first[q::ENTRY_RDX]
            ],
            "{context}"
        );
        assert!(
            second[q::ENTRY_RSP] + 128 < first[q::ENTRY_RSP],
            "{context}"
        );
        // The mask SIGUSR1's handler runs under, which SIGUSR2's frame saved.
        assert_eq!(
            [first[q::SIGMASK], second[q::SIGMASK], log.final_mask],
            [0, bit(SIGUSR1), 0],
            "{context}"
        );
        // No frame touched a red zone.
        assert_eq!(log.results[..2], [16, 16], "{context}");
    }
    let r = timer_registers(&events);
    assert_eq!(r.len(), 2, "{events:?}");
    for (index, r) in r.iter().enumerate() {
        let e = log.entry(index);
        assert_eq!(
            [e[q::RIP], e[q::RCX], e[q::EFLAGS], e[q::RSP], e[q::R12]],
            [r.rip, r.rcx, r.eflags, r.rsp, r.r12],
            "frame {index}: {log:#x?} {events:?}"
        );
    }
    // Each signal's hook ran at its timer event's clock.
    let clocks: Vec<u64> = events
        .iter()
        .filter_map(|event| match event {
            Event::Timer { clock } | Event::Signalled { clock, .. } => Some(*clock),
            _ => None,
        })
        .collect();
    assert_eq!(clocks.len(), 4, "{events:?}");
    assert_eq!((clocks[0], clocks[2]), (clocks[1], clocks[3]), "{events:?}");
    (native_log, log, events)
}

#[test]
fn a_timer_boundary_inside_a_running_handler_nests_its_frame_as_linux_does() {
    if bounded("a_timer_boundary_inside_a_running_handler_nests_its_frame_as_linux_does") {
        return;
    }
    // SIGUSR1 is delivered at the main thread's first timer boundary, in its
    // spin; SIGUSR1's callback requests a second precise event, which lands
    // in its handler's loop, and SIGUSR2 is delivered at that boundary.
    // Linux builds SIGUSR2's frame below the interrupted handler's rsp and
    // red zone, saving the handler's registers and the mask it runs under;
    // SIGUSR2's rt_sigreturn returns to the handler's loop, and SIGUSR1's to
    // the spin. Natively the same signals come wherever the sibling's sends
    // interrupt the thread.
    let (native, _, events) = nested_boundaries_match_native(&nested_boundaries_program(None));
    println!(
        "nested at a timer boundary in SIGUSR1's handler: native {native:#x?}, KVM timer registers {:#x?}",
        timer_registers(&events)
    );
}

#[test]
fn frames_at_timer_boundaries_enter_and_nest_on_an_alternate_stack() {
    if bounded("frames_at_timer_boundaries_enter_and_nest_on_an_alternate_stack") {
        return;
    }
    // The guest of
    // `a_timer_boundary_inside_a_running_handler_nests_its_frame_as_linux_does`,
    // with SA_ONSTACK handlers and an armed alternate stack. At the first
    // timer boundary SIGUSR1's frame switches to the top of the stack; at the
    // second, inside SIGUSR1's handler, which runs on the stack, SIGUSR2's
    // frame nests below the handler's rsp and red zone, still on the stack,
    // and its handler finds itself on the stack (SS_ONSTACK). With
    // SS_AUTODISARM, SIGUSR1's delivery disarms the stack: SIGUSR2's frame
    // then saves no stack and goes below the handler's rsp all the same, its
    // handler finds the stack disabled, and SIGUSR1's rt_sigreturn arms it
    // again (signal_delivered and sas_ss_reset in Linux).
    for flags in [0, SS_AUTODISARM] {
        let (native, log, _) =
            nested_boundaries_match_native(&nested_boundaries_program(Some(flags)));
        let context = format!("ss_flags {flags:#x}: {native:#x?}");
        let (first, second) = (native.entry(0), native.entry(1));
        let armed = [first[q::SS_SP], flags, 65536];
        assert_ne!(armed[0], 0, "{context}");
        assert_eq!(
            [first[q::SS_SP], first[q::SS_FLAGS], first[q::SS_SIZE]],
            armed,
            "{context}"
        );
        let (second_saved, queried) = if flags == SS_AUTODISARM {
            ([0, SS_DISABLE, 0], [0, SS_DISABLE, 0])
        } else {
            (armed, [armed[0], libc::SS_ONSTACK as u64, 65536])
        };
        assert_eq!(
            [second[q::SS_SP], second[q::SS_FLAGS], second[q::SS_SIZE]],
            second_saved,
            "{context}"
        );
        assert_eq!(native.queried_stack, queried, "{context}");
        assert_eq!(native.final_stack, armed, "{context}");
        // Both frames lie on the alternate stack, in both runs.
        for log in [&native, &log] {
            let stack = log.entry(0)[q::SS_SP]..log.entry(0)[q::SS_SP] + 65536;
            assert!(
                stack.contains(&log.entry(0)[q::ENTRY_RSP])
                    && stack.contains(&log.entry(1)[q::ENTRY_RSP]),
                "{context}: {log:#x?}"
            );
        }
        println!(
            "ss_flags {flags:#x}: SIGUSR1 entered the stack, SIGUSR2 nested on it: {native:#x?}"
        );
    }
}

/// Where the main thread of [`red_zone_program`] spins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpinStack {
    /// On its own stack, with an ordinary SIGUSR1 handler.
    Ordinary,
    /// On its own stack, with an SA_ONSTACK handler and an armed alternate
    /// stack, which the frame enters.
    Entering,
    /// 64 bytes above the armed alternate stack's top, with an SA_ONSTACK
    /// handler: its red zone reaches 64 bytes into the stack.
    AboveTop,
    /// On the armed alternate stack, 64 bytes above its base, with an
    /// SA_ONSTACK handler: its red zone reaches 64 bytes below the stack.
    NearBase,
}

/// A timer-boundary guest whose main thread spins where `spin` says, with
/// canaries in the red zone below its rsp there, which it checks once the
/// spin has ended (result 0), and whose sibling sends it SIGUSR1.
fn red_zone_program(spin: SpinStack) -> Program {
    let (flags, at) = match spin {
        SpinStack::Ordinary => (0, None),
        SpinStack::Entering => (SA_ONSTACK, None),
        SpinStack::AboveTop => (SA_ONSTACK, Some("altstack_end+64")),
        SpinStack::NearBase => (SA_ONSTACK, Some("altstack+64")),
    };
    let switch = at
        .map(|at| format!("lea {at}(%rip),%rsp\n"))
        .unwrap_or_default();
    timer_boundary_program(
        &[Handler::new(SIGUSR1).flags(flags)],
        &format!(
            "{}{LOAD_FPU}mov %rsp,%r15\n{switch}{}",
            if flags == SA_ONSTACK {
                ARM_ALTSTACK
            } else {
                ""
            },
            write_canaries()
        ),
        &tgkill_self(SIGUSR1),
        1,
        &format!("{}mov %r15,%rsp\n", check_canaries(0)),
        &altstack_data(0),
        ".balign 64\n.skip 4096\naltstack: .skip 65536\naltstack_end:\n.skip 4096\n",
    )
}

#[test]
fn a_frame_at_a_timer_boundary_leaves_the_red_zone_untouched() {
    if bounded("a_frame_at_a_timer_boundary_leaves_the_red_zone_untouched") {
        return;
    }
    // The main thread writes canaries in the 128 bytes below its rsp and
    // spins; SIGUSR1 comes at the Tool's timer boundary in the spin, and
    // natively wherever the sibling's send interrupts it. Linux's
    // get_sigframe (arch/x86/kernel/signal.c) subtracts the red zone from the
    // interrupted rsp first, then switches an SA_ONSTACK handler to the top
    // of the alternate stack only when that adjusted rsp is not on the stack
    // (sas_ss_flags), and checks that a frame fits only when the interrupted
    // rsp itself, or the switch, is on it. So:
    // - on the thread's own stack, the frame goes below the red zone;
    // - entering the stack, the frame goes at its top;
    // - with the rsp 64 bytes above the stack's top, the adjusted rsp is on
    //   the stack, so there is no switch: the frame goes below the red zone,
    //   within the stack, and no check applies;
    // - with the rsp on the stack 64 bytes above its base, the adjusted rsp
    //   is below the stack, so the frame starts at the stack's top again.
    // Every canary is intact after the handler returns.
    for spin in [
        SpinStack::Ordinary,
        SpinStack::Entering,
        SpinStack::AboveTop,
        SpinStack::NearBase,
    ] {
        let program = red_zone_program(spin);
        let (native, log, events) = timer_boundary_matches_native(
            &program,
            Tracing::Deliver,
            TraceOptions::default(),
            spinner_plan(),
        );
        let context = format!("{spin:?}: native {native:#x?}, tool {log:#x?}, {events:?}");
        assert_eq!(native.results[0], 16, "{context}");
        for log in [&native, &log] {
            let e = log.entry(0);
            let interrupted = e[q::RSP];
            let (base, top) = (e[q::SS_SP], e[q::SS_SP] + 65536);
            assert!(
                e[q::ENTRY_RSP] + 128 < interrupted
                    || spin == SpinStack::NearBase
                    || spin == SpinStack::Entering,
                "{context}"
            );
            match spin {
                SpinStack::Ordinary => assert_eq!(base, 0, "{context}"),
                SpinStack::Entering | SpinStack::NearBase => {
                    // At the top of the stack: within its last 4 KiB.
                    assert!((top - 4096..top).contains(&e[q::ENTRY_RSP]), "{context}")
                }
                SpinStack::AboveTop => {
                    assert_eq!(interrupted, top + 64, "{context}");
                    assert!((base..top - 64).contains(&e[q::ENTRY_RSP]), "{context}")
                }
            }
        }
        let r = registers_of(&events);
        assert_eq!(log.entry(0)[q::RSP], r.rsp, "{context}");
        println!(
            "{spin:?}: canaries intact; native frame at {:#x}, interrupted rsp {:#x}",
            native.entry(0)[q::ENTRY_RSP],
            native.entry(0)[q::RSP]
        );
    }
}

/// What the exact-base guest of
/// `a_frame_that_would_start_at_the_alternate_stacks_base_is_refused_as_on_linux`
/// writes before its last signal: how far below the interrupted rsp a frame
/// starts, the alternate stack's base, and where the control frame started.
#[derive(Debug, PartialEq, Eq)]
struct ExactBase {
    depth: u64,
    base: u64,
    control: u64,
}

impl ExactBase {
    fn read(stdout: &[u8]) -> Self {
        assert!(stdout.len() >= 24, "{stdout:?}");
        let quad = |i: usize| u64::from_ne_bytes(stdout[8 * i..8 * i + 8].try_into().unwrap());
        Self {
            depth: quad(0),
            base: quad(1),
            control: quad(2),
        }
    }
}

#[test]
fn a_frame_that_would_start_at_the_alternate_stacks_base_is_refused_as_on_linux() {
    if bounded("a_frame_that_would_start_at_the_alternate_stacks_base_is_refused_as_on_linux") {
        return;
    }
    // Linux's get_sigframe refuses a frame on the alternate stack unless
    // __on_sig_stack holds for its address, which for a stack that grows
    // down means strictly above the base: the stack is (base, base + size]
    // (https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/signal.c#L150-L158,
    // https://github.com/gregkh/linux/blob/v7.1.3/include/linux/sched/signal.h#L574-L583).
    // A frame starts at round_down(sp, 16) - 8, so only a base 8 above a
    // multiple of 16 can be a frame's address. The guest measures how far
    // below an interrupted rsp a nested frame starts (its depth, which each
    // backend's floating-point state decides and which depends only on that
    // rsp modulo 64), with a SIGUSR2 sent from a 64-aligned rsp, and arms an
    // alternate stack whose base is congruent to that frame modulo 64. Its
    // SIGUSR1 handler, on that stack, moves rsp to the base plus the depth
    // plus an offset and sends itself SIGUSR2, whose frame then starts at the
    // base plus the offset: 64 above it, the control, which both run, and
    // then exactly at it, which Linux refuses with SIGSEGV.
    //
    // One difference is pinned, not allowed: Linux's failed frame forces a
    // SIGSEGV that goes through get_signal, which the tracer sees as a last
    // signal stop, where this backend's refusal ends the process with that
    // SIGSEGV's status, with no signal hook
    // (https://github.com/rrnewton/reverie/issues/1192). So the native run's
    // signals end in SIGSEGV, and the KVM run's hooks are the five before it.
    let program = Program::new(&format!(
        "mov $39,%eax\nsyscall\nmov %rax,pid(%rip)\nmov $186,%eax\nsyscall\nmov %rax,tid(%rip)\n\
         mov $12,%edi\nlea usr2_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\n\
         syscall\ntest %rax,%rax\njnz 99f\n\
         mov $10,%edi\nlea usr1_action(%rip),%rsi\nxor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\n\
         syscall\ntest %rax,%rax\njnz 99f\n\
         mov %rsp,%r15\nlea probe_top(%rip),%rsp\n{usr2}mov %r15,%rsp\n\
         lea probe_top(%rip),%rax\nsub entry(%rip),%rax\nmov %rax,depth(%rip)\n\
         mov entry(%rip),%rax\nand $63,%rax\nlea altstack(%rip),%rbx\nadd %rax,%rbx\n\
         mov %rbx,alt_base(%rip)\nmov %rbx,exact_altstack(%rip)\n\
         lea exact_altstack(%rip),%rdi\nxor %esi,%esi\nmov $131,%eax\nsyscall\ntest %rax,%rax\njnz 99f\n\
         movq $64,offset(%rip)\n{usr1}\
         mov depth(%rip),%rax\nmov %rax,record(%rip)\nmov alt_base(%rip),%rax\nmov %rax,record+8(%rip)\n\
         mov entry(%rip),%rax\nmov %rax,record+16(%rip)\n\
         mov $1,%edi\nlea record(%rip),%rsi\nmov $24,%edx\nmov $1,%eax\nsyscall\n\
         movq $0,offset(%rip)\n{usr1}\
         mov $1,%edi\nlea entry(%rip),%rsi\nmov $8,%edx\nmov $1,%eax\nsyscall\n\
         xor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n\
         99: mov $1,%edi\nmov $231,%eax\nsyscall\nud2\n\
         usr1: mov %rsp,%r14\nmov alt_base(%rip),%rsp\nadd depth(%rip),%rsp\nadd offset(%rip),%rsp\n\
         {usr2}mov %r14,%rsp\nret\n\
         usr2: mov %rsp,entry(%rip)\nret\n\
         restorer: mov $15,%eax\nsyscall\nud2\n\
         .data\n.balign 8\n\
         usr1_action: .quad usr1, {usr1_flags:#x}, restorer, 0\n\
         usr2_action: .quad usr2, {HANDLER_FLAGS:#x}, restorer, 0\n\
         exact_altstack: .quad 0\n.long 0, 0\n.quad 65536\n\
         pid: .quad 0\ntid: .quad 0\ndepth: .quad 0\nalt_base: .quad 0\noffset: .quad 0\n\
         entry: .quad 0\nrecord: .quad 0, 0, 0\n\
         .bss\n.balign 64\n.skip 4096\nprobe_stack: .skip 65536\nprobe_top:\n.skip 4096\n\
         altstack: .skip 65600\n.skip 4096\n",
        usr1 = tgkill_self(SIGUSR1),
        usr2 = tgkill_self(SIGUSR2),
        usr1_flags = HANDLER_FLAGS | SA_ONSTACK,
    ));
    let native = traced_native_with(&program, Tracing::Deliver, TraceOptions::default());
    let context = format!(
        "native: status {:#x}, stdout {:?}",
        native.status, native.stdout
    );
    assert!(
        libc::WIFSIGNALED(native.status) && libc::WTERMSIG(native.status) == libc::SIGSEGV,
        "{context}"
    );
    assert_eq!(native.stdout.len(), 24, "{context}");
    let linux = ExactBase::read(&native.stdout);
    assert_eq!(linux.control, linux.base + 64, "{context}: {linux:#x?}");
    assert_eq!(linux.base % 16, 8, "{context}: {linux:#x?}");
    assert_eq!(
        native.delivered,
        [SIGUSR2, SIGUSR1, SIGUSR2, SIGUSR1, SIGUSR2, libc::SIGSEGV],
        "{context}"
    );
    let (events, ending) = run_ending(
        &program,
        Plan {
            deliver: true,
            ..Plan::default()
        },
    );
    let (code, stdout, stderr) = ending.unwrap_or_else(|failure| panic!("{failure}: {events:?}"));
    let context = format!("KVM: exit code {code}, stdout {stdout:?}, {events:?}");
    assert_eq!((code, stderr), (128 + libc::SIGSEGV, vec![]), "{context}");
    assert_eq!(stdout.len(), 24, "{context}");
    let kvm = ExactBase::read(&stdout);
    assert_eq!(kvm.control, kvm.base + 64, "{context}: {kvm:#x?}");
    assert_eq!(kvm.base % 16, 8, "{context}: {kvm:#x?}");
    // No SIGSEGV hook: https://github.com/rrnewton/reverie/issues/1192.
    assert_eq!(
        signal_hooks(&events),
        [SIGUSR2, SIGUSR1, SIGUSR2, SIGUSR1, SIGUSR2],
        "{context}"
    );
    println!(
        "a frame at the base: natively SIGSEGV ({linux:#x?}), on KVM exit code {code} ({kvm:#x?})"
    );
}

/// Handler actions that keep, as result `index`, which thread runs the
/// handler: 1 for the main thread, 2 for another.
fn keep_taker(index: usize) -> String {
    assert!(index < RESULTS);
    let at = 8 * (8 + index);
    format!(
        "mov $186,%eax\nsyscall\ncmp tid(%rip),%rax\njne 4f\nmovq $1,header+{at}(%rip)\njmp 5f\n\
         4: movq $2,header+{at}(%rip)\n5:\n"
    )
}

#[test]
fn a_process_directed_signal_at_a_timer_boundary_goes_where_linux_can_send_it() {
    if bounded("a_process_directed_signal_at_a_timer_boundary_goes_where_linux_can_send_it") {
        return;
    }
    // Which thread takes a process-directed signal. Linux queues it for the
    // process and complete_signal (kernel/signal.c) wakes one thread that
    // wants it: the thread the pid names, the main thread, when it has the
    // signal unblocked and is running or has nothing pending, else another.
    // Any thread that reaches get_signal with the signal unblocked before
    // that one may dequeue it instead, but a thread reaches get_signal only
    // when it was woken or its own recalc_sigpending (after a mask change,
    // for one) found the signal.
    //
    // First, kill(pid, SIGUSR1) from a sibling while the main thread spins,
    // during the Tool's timer event there. Natively the main thread, running
    // with SIGUSR1 unblocked, takes it. KVM refuses a process-directed
    // signal sent while the process has another live thread, rather than
    // choose its recipient: kill returns ENOSYS with the typed refusal, and
    // no thread takes the signal. So KVM never gives such a signal to a
    // thread Linux could not; it gives it to none
    // (https://github.com/rrnewton/reverie/issues/1205).
    let sent = timer_boundary_program(
        &[Handler::new(SIGUSR1).actions(&keep_taker(1))],
        LOAD_FPU,
        &format!(
            "{}{}movb $1,sent(%rip)\n",
            kill_self(SIGUSR1),
            keep_result(0)
        ),
        0,
        "3: cmpb $0,sent(%rip)\nje 3b\n",
        "sent: .byte 0\n",
        "",
    );
    let native = traced_native(&sent, Tracing::Deliver);
    let native_log = StackedLog::read(&native.stdout);
    assert_eq!(native_log.signals(), [SIGUSR1], "native: {native_log:#x?}");
    assert_eq!(
        native_log.results[..2],
        [0, 1],
        "native: the main thread took it: {native_log:#x?}"
    );
    let plan = Plan {
        refusals_of_sends: true,
        ..spinner_plan()
    };
    let (events, stdout) = tool_stdout(&sent, plan);
    let log = StackedLog::read(&stdout);
    let enosys = -i64::from(libc::ENOSYS) as u64;
    assert_eq!(log.signals(), [0; 0], "{log:#x?} {events:?}");
    assert_eq!(log.results[..2], [enosys, 0], "{log:#x?} {events:?}");
    assert!(
        events.contains(&Event::Refusal(
            "Signal: KVM signal delivery refused: KVM cannot choose the recipient of a \
             process-directed signal in a process with several threads"
                .to_owned()
        )),
        "{events:?}"
    );
    assert_eq!(signal_hooks(&events), [0; 0], "{events:?}");
    assert_eq!(timer_clocks(&events).len(), 1, "{events:?}");
    // Second, a process-directed SIGUSR1 queued while the process has one
    // thread, which blocks it: the main thread blocks SIGUSR1, sends it to
    // the process and starts a sibling, which inherits that mask, then
    // spins. The sibling sends SIGUSR2 to the main thread, waits until
    // SIGUSR2's handler has run, and unblocks SIGUSR1. Natively the main
    // thread takes only SIGUSR2, SIGUSR1 being blocked for it, and the
    // sibling's unblocking call, whose recalc_sigpending sends it to
    // get_signal at its return, takes SIGUSR1. KVM refuses to create a
    // thread while a process-directed signal is pending, rather than choose
    // its recipient later: clone returns ENOSYS, SIGUSR1 stays pending for
    // the one thread, and the main thread stops waiting for the sibling.
    let queued = stacked_program(
        &[
            Handler::new(SIGUSR1).actions(&keep_taker(1)),
            Handler::new(SIGUSR2).actions("movb $1,usr2_done(%rip)\n"),
        ],
        &format!(
            "{LOAD_FPU}{}{}{}{}{}{GETPPID}movb $1,spinning(%rip)\nlea 1f(%rip),%r12\n\
             mov $2000000000,%rcx\n1: cmpq $2,header(%rip)\njae 2f\ncmpq $0,header+80(%rip)\njs 2f\n\
             dec %rcx\njnz 1b\n2:\n",
            sigprocmask(libc::SIG_BLOCK, "usr1"),
            kill_self(SIGUSR1),
            keep_result(0),
            sibling(&format!(
                "5: cmpb $0,spinning(%rip)\nje 5b\n{}3: cmpb $0,usr2_done(%rip)\nje 3b\n{}",
                tgkill_self(SIGUSR2),
                sigprocmask(libc::SIG_UNBLOCK, "usr1")
            )),
            keep_result(2),
        ),
        &format!(
            "spinning: .byte 0\nusr2_done: .byte 0\n.balign 8\nusr1: .quad {:#x}\n",
            bit(SIGUSR1)
        ),
        SIBLING_STACK,
    );
    let native = traced_native(&queued, Tracing::Deliver);
    let native_log = StackedLog::read(&native.stdout);
    assert_eq!(
        native_log.signals(),
        [SIGUSR2, SIGUSR1],
        "native: {native_log:#x?}"
    );
    assert_eq!(
        native_log.results[..2],
        [0, 2],
        "native: the sibling took SIGUSR1: {native_log:#x?}"
    );
    assert!(
        (native_log.results[2] as i64) > 0,
        "native: the sibling's tid: {native_log:#x?}"
    );
    assert_eq!(
        native_log.final_mask,
        bit(SIGUSR1),
        "native: {native_log:#x?}"
    );
    let (events, stdout) = tool_stdout(&queued, spinner_plan());
    let log = StackedLog::read(&stdout);
    assert_eq!(log.signals(), [0; 0], "{log:#x?} {events:?}");
    assert_eq!(log.results[..3], [0, 0, enosys], "{log:#x?} {events:?}");
    assert_eq!(log.final_mask, bit(SIGUSR1), "{log:#x?} {events:?}");
    assert_eq!(signal_hooks(&events), [0; 0], "{events:?}");
    println!(
        "kill to a process with several threads: natively the main thread took it, KVM refused the \
         kill; a thread created while one is pending: natively the sibling took it, KVM refused \
         the clone"
    );
}

// The ptrace comparison: one guest under reverie-ptrace, the reference
// backend, and under this one, with the same Tool ([`TimerTool`]) following
// the same plan, at the three points where a timer event and a signal meet:
// a precise event in a spinner, an event due at a syscall's return, and one
// due at rt_sigreturn, and with two signals pending at the precise event.
// Under reverie-ptrace the guest runs natively, so its signal frames are
// Linux's own.

/// Runs `program` under reverie-ptrace with a [`TimerTool`] following
/// `plan`, as [`run_ending`] runs it on KVM: no environment, its directory as
/// the working directory. Returns the Tool's events and how the run ended.
fn run_on_ptrace(program: &Program, plan: Plan) -> (Vec<Event>, Ending) {
    use reverie::process::Command;
    use reverie::process::Stdio;
    assert!(
        reverie_ptrace::is_perf_supported(),
        "the ptrace comparison requires the PMU"
    );
    let mut command = Command::new(&program.executable);
    command
        .current_dir(&program.directory)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .unwrap();
    let result = runtime.block_on(async move {
        tokio::task::LocalSet::new()
            .run_until(async move {
                let tracer = reverie_ptrace::TracerBuilder::<TimerTool>::new(command)
                    .config(plan)
                    .spawn()
                    .await?;
                tracer.wait_with_output().await
            })
            .await
    });
    match result {
        Ok((output, log)) => {
            let status = output.status;
            let code = status
                .code()
                .unwrap_or_else(|| 128 + status.signal().expect("a signaled status"));
            (
                log.events.into_inner().unwrap(),
                Ok((code, output.stdout, output.stderr)),
            )
        }
        Err(error) => (vec![], Err(error.to_string())),
    }
}

/// A run's events as the backends compare them: each timer event's
/// registers without what the backends lay out differently and Linux
/// allocates or randomizes: the pid (this backend's guest pids start at 1),
/// and r11, the flags the guest's last SYSCALL saved, which come from its
/// test of the tid its clone returned; the segment selectors (this backend's
/// descriptor table has its own); and rsp (the initial stack, which Linux
/// randomizes and this backend places at a fixed address). Every other event
/// is as it is.
fn comparable_events(events: &[Event]) -> Vec<Event> {
    events
        .iter()
        .map(|event| match event {
            Event::Registers(registers) => Event::Registers(Registers {
                pid: 0,
                r11: 0,
                rsp: 0,
                cs: 0,
                ss: 0,
                ds: 0,
                es: 0,
                fs: 0,
                gs: 0,
                ..registers.clone()
            }),
            event => event.clone(),
        })
        .collect()
}

/// One timer event's registers as [`comparable_events`] compares them.
fn comparable_timer_registers(registers: &Registers) -> Registers {
    match comparable_events(&[Event::Registers(registers.clone())]).pop() {
        Some(Event::Registers(registers)) => registers,
        _ => unreachable!("comparable_events keeps each event's kind"),
    }
}

/// How many times each ptrace comparison runs its guest on each backend.
const COMPARED_RUNS: usize = 3;

#[test]
fn a_signal_at_a_precise_timer_boundary_matches_ptrace() {
    if bounded("a_signal_at_a_precise_timer_boundary_matches_ptrace") {
        return;
    }
    // The guest of
    // `a_spinner_signalled_by_a_sibling_gets_its_handler_at_the_next_timer_boundary`:
    // a precise event 1,000 RCBs after the marker lands in the spin, its
    // callback waits for the sibling's tgkill of SIGUSR1, and the signal is
    // delivered at the same boundary, with SA_RESTART and without. Under
    // reverie-ptrace the event is a stop the steps end at, and Linux's
    // get_signal delivers SIGUSR1 when the tracer resumes the thread, before
    // it runs on. Both backends show the Tool the same events: the request
    // and its clock, the event at the target with the same registers, and
    // the signal's hook at the event's clock; and the handler's frame saves
    // the same interrupted context.
    for flags in [HANDLER_FLAGS, HANDLER_FLAGS | libc::SA_RESTART as u64] {
        let program = spinner(flags, false);
        let mut first: Option<(Vec<Event>, Record)> = None;
        for backend in ["ptrace", "kvm"] {
            for run in 0..COMPARED_RUNS {
                let (events, ending) = match backend {
                    "ptrace" => run_on_ptrace(&program, spinner_plan()),
                    _ => run_ending(&program, spinner_plan()),
                };
                let context = format!("{backend} run {run}, flags {flags:#x}: {events:?}");
                let (code, stdout, stderr) =
                    ending.unwrap_or_else(|failure| panic!("{failure}: {context}"));
                assert_eq!((code, stderr), (0, vec![]), "{context}");
                let record = Record::read(&stdout);
                let (requested_at, _) = last_request(&events);
                assert_eq!(
                    timer_clocks(&events),
                    [requested_at + SPIN_TICKS],
                    "{context}"
                );
                assert_eq!(record.count, 1, "{context}");
                let seen = (comparable_events(&events), record);
                match &first {
                    None => first = Some(seen),
                    Some(first) => assert_eq!(&seen, first, "{context}"),
                }
            }
        }
        println!("flags {flags:#x}: ptrace and KVM agree: {first:x?}");
    }
}

#[test]
fn two_signals_at_a_precise_timer_boundary_match_ptrace() {
    if bounded("two_signals_at_a_precise_timer_boundary_match_ptrace") {
        return;
    }
    // The guest of `two_signals_pending_at_a_timer_boundary_stack_their_frames`:
    // the precise event's callback waits until the sibling has sent SIGUSR1
    // and SIGUSR2, and both are delivered at that boundary. Under
    // reverie-ptrace, Linux's get_signal stops for SIGUSR1, builds its frame,
    // then stops for SIGUSR2 and builds that frame on top, before the thread
    // runs on; this backend gives every eligible signal its own selection at
    // the boundary. The Tool sees the same events on both, with SIGUSR1's
    // hook before SIGUSR2's at the event's clock, and every handler finds the
    // same frame at its first instruction (addresses that a frame's size
    // decides compared as the handler entry that saw them).
    let program = pair_at_timer_boundary_program();
    let plan = Plan {
        sends: 2,
        ..spinner_plan()
    };
    // reverie-ptrace steps the thread to the target with PTRACE_SINGLESTEP,
    // whose debug traps set Linux's trap number to X86_TRAP_DB (send_sigtrap,
    // https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/ptrace.c#L1408-L1418),
    // which every later frame saves; this backend's steps never reach the
    // guest, which keeps its own last trap, none here, as an untraced Linux
    // thread does. That field aside, the frames are equal.
    let trapno = |_: usize, quad: usize| quad == q::TRAPNO;
    let mut first: Option<(Vec<Event>, ComparedEntries)> = None;
    for backend in ["ptrace", "kvm"] {
        for run in 0..COMPARED_RUNS {
            let (events, ending) = match backend {
                "ptrace" => run_on_ptrace(&program, plan.clone()),
                _ => run_ending(&program, plan.clone()),
            };
            let context = format!("{backend} run {run}: {events:?}");
            let (code, stdout, stderr) =
                ending.unwrap_or_else(|failure| panic!("{failure}: {context}"));
            assert_eq!((code, stderr), (0, vec![]), "{context}");
            let log = StackedLog::read(&stdout);
            assert_eq!(log.signals(), [SIGUSR2, SIGUSR1], "{context}: {log:#x?}");
            assert_stacked_on(&log, 0, 1, &context);
            let stepped_trap = if backend == "ptrace" { 1 } else { 0 };
            for index in [0, 1] {
                assert_eq!(
                    log.entry(index)[q::TRAPNO],
                    stepped_trap,
                    "{context}: {log:#x?}"
                );
            }
            let seen = (comparable_events(&events), comparable(&log, &trapno));
            match &first {
                None => first = Some(seen),
                Some(first) => assert_eq!(&seen, first, "{context}: {log:#x?}"),
            }
        }
    }
    let (events, _) = first.unwrap();
    let (_, timer_clock) = first_timer(&events);
    assert_eq!(signal_hooks(&events), [SIGUSR1, SIGUSR2], "{events:?}");
    assert!(
        events.iter().all(|event| match event {
            Event::Signalled { clock, .. } => *clock == timer_clock,
            _ => true,
        }),
        "{events:?}"
    );
    println!("two signals at a precise boundary: ptrace and KVM agree: {events:x?}");
}

/// How many iterations the loop of the syscall-return comparison's guest
/// runs; each retires four conditional branches, three in its inner loop and
/// one in its outer one.
const SYSCALL_RETURN_LOOP: u64 = 50_000;

/// The conditional branches the syscall-return comparison's guest has
/// retired since its marker when it stands at `registers.rip`, one of its
/// loop's labelled instructions `labels` (sr0 to sr6), with the rbx and r15
/// `registers` hold there, or `None` when the rip is none of them.
fn syscall_return_loop_rcbs(registers: &Registers, labels: &[u64; 7]) -> Option<u64> {
    let at = labels.iter().position(|&label| label == registers.rip)?;
    // The outer iterations completed: sr6's jnz follows r15's decrement.
    let done = SYSCALL_RETURN_LOOP - registers.r15 - u64::from(at == 6);
    let inner = match at {
        // mov $3,%rbx: an iteration's first instruction.
        0 => 0,
        // dec %rbx, before its decrement: one jnz per decrement done.
        1 => 3 - registers.rbx,
        // jnz 5b, after the decrement.
        2 => 2 - registers.rbx,
        // After the inner loop: mov $39,%eax, syscall, dec %r15, jnz 4b.
        _ => 3,
    };
    Some(4 * done + inner)
}

/// Where the syscall-return comparison's event landed on `backend`, given
/// its registers `r`, the loop's labels (sr0 to sr6), the request's clock
/// `requested_at`, its `ticks` and the event's clock `timer_clock`; or why
/// that backend cannot deliver it there (see the test).
fn syscall_return_landing(
    backend: &str,
    r: &Registers,
    labels: &[u64; 7],
    requested_at: u64,
    ticks: u64,
    timer_clock: u64,
) -> Result<&'static str, String> {
    let at = labels
        .iter()
        .position(|&label| label == r.rip)
        .ok_or_else(|| format!("rip {:#x} is none of the loop's instructions", r.rip))?;
    let landing = if backend == "ptrace" && r.orig_rax == libc::SYS_getpid as u64 {
        if at != 5 {
            return Err(format!("orig_rax 39 at sr{at}, not at a getpid's return"));
        }
        "a getpid's return"
    } else if r.orig_rax != u64::MAX {
        return Err(format!("orig_rax {:#x}", r.orig_rax));
    } else if at == 5 {
        "a getpid's return, or a kick right after it"
    } else {
        "between instructions"
    };
    let delay = timer_clock - requested_at;
    if backend == "kvm" {
        if delay > ticks + 3 {
            return Err(format!(
                "{delay} RCBs after the request, past the target's first exit"
            ));
        }
        if at == 6 {
            return Err("sr6, after the getpid return that had to deliver it".to_owned());
        }
    }
    let retired = syscall_return_loop_rcbs(r, labels);
    if retired != Some(delay) {
        return Err(format!(
            "{delay} RCBs after the request where the loop has retired {retired:?} \
             (rbx {}, r15 {})",
            r.rbx, r.r15
        ));
    }
    Ok(landing)
}

#[test]
fn the_syscall_return_comparison_refuses_landings_kvm_cannot_make() {
    // syscall_return_landing against registers made up for each case, with
    // made-up label addresses: no guest runs. A landing is the event's rip,
    // rbx, r15 and orig_rax and the clock it came at.
    let labels = [0x1000, 0x1005, 0x1008, 0x100a, 0x100f, 0x1011, 0x1014];
    let (requested_at, ticks) = (1, 100_000);
    let landing = |at: usize, rbx: u64, r15: u64, orig_rax: u64| Registers {
        rip: labels[at],
        rbx,
        r15,
        orig_rax,
        ..Registers::default()
    };
    let check = |backend: &str, r: &Registers, delay: u64| {
        syscall_return_landing(
            backend,
            r,
            &labels,
            requested_at,
            ticks,
            requested_at + delay,
        )
    };
    // KVM at sr6 (the jnz after the getpid's return and its dec %r15), at the
    // target plus 3, whose RCB count the loop does retire there. No branch retires between the return at sr5 and sr6,
    // so that return found the request due at the same clock and delivered
    // it: KVM never stands at sr6 with it. reverie-ptrace, whose PMU
    // notification comes some RCBs after the counter overflowed, may.
    let sr6 = landing(6, 0, 24_999, u64::MAX);
    assert_eq!(syscall_return_loop_rcbs(&sr6, &labels), Some(100_003));
    assert_eq!(
        check("kvm", &sr6, 100_003),
        Err("sr6, after the getpid return that had to deliver it".to_owned())
    );
    assert_eq!(check("ptrace", &sr6, 100_003), Ok("between instructions"));
    // A later getpid's return, at the target plus 7, as a delivery that
    // missed the first due return would show.
    let later = landing(5, 0, 24_999, u64::MAX);
    assert_eq!(syscall_return_loop_rcbs(&later, &labels), Some(100_007));
    assert!(check("kvm", &later, 100_007).is_err());
    // KVM's documented landings: the target's first exit, the getpid return
    // at the target plus 3, and a kick between two of the loop's instructions
    // before it.
    assert_eq!(
        check("kvm", &landing(5, 0, 25_000, u64::MAX), 100_003),
        Ok("a getpid's return, or a kick right after it")
    );
    for (at, rbx, delay) in [
        (0, 0, 100_000),
        (1, 3, 100_000),
        (1, 2, 100_001),
        (1, 1, 100_002),
        (2, 2, 100_000),
        (2, 1, 100_001),
        (2, 0, 100_002),
        (3, 0, 100_003),
        (4, 0, 100_003),
    ] {
        assert_eq!(
            check("kvm", &landing(at, rbx, 25_000, u64::MAX), delay),
            Ok("between instructions"),
            "sr{at} with rbx {rbx}"
        );
    }
    // reverie-ptrace at a getpid's return shows the call's number, and only there.
    assert_eq!(
        check("ptrace", &landing(5, 0, 24_999, 39), 100_007),
        Ok("a getpid's return")
    );
    assert!(check("ptrace", &landing(4, 0, 25_000, 39), 100_003).is_err());
}

#[test]
fn a_signal_at_a_syscall_return_timer_event_matches_ptrace_but_for_where_it_lands() {
    if bounded("a_signal_at_a_syscall_return_timer_event_matches_ptrace_but_for_where_it_lands") {
        return;
    }
    // The guest of `a_signal_pending_at_a_syscall_return_timer_event_follows_it`,
    // with the marker after the clone: reverie-ptrace's new-child stop
    // cancels a request made before it, where this backend keeps it
    // (https://github.com/rrnewton/reverie/issues/1176). The marker requests
    // an imprecise event 100,000 RCBs on; the guest makes getpid calls the
    // Tool does not see, 4 RCBs apart, and the event's callback waits for the
    // sibling's tgkill of SIGUSR1.
    //
    // Where the event comes depends on host timing, as both backends
    // document: an imprecise request is delivered at the first exit at or
    // past its target. On this backend that is a getpid's return, where
    // orig_rax reads -1, when the getpid comes before the kick that the
    // counter's overflow sends, or the kick itself, between two of the loop's
    // instructions, also with orig_rax -1; under reverie-ptrace it is where
    // its PMU notification is taken: a getpid's return, where orig_rax shows
    // the call (39), or between two of the loop's instructions, with
    // orig_rax -1. So each run is checked against itself, and the runs
    // against each other on what does not depend on that timing:
    // - the events are the request, one timer event at or past the target,
    //   its registers and SIGUSR1's hook at the event's clock;
    // - on this backend the event comes no later than the target's first
    //   exit, a getpid's return 3 RCBs past it at most: the loop's getpid
    //   returns are at 4i + 3 RCBs, and the exit of a syscall that made no
    //   Tool callback delivers a due request at its return (see
    //   `preemption_timer.rs` and `KvmBackend::syscall_return_timer_boundary`),
    //   so a kick can only make it earlier, and never at sr6, which that
    //   return precedes with no branch between; reverie-ptrace takes its PMU
    //   notification some RCBs later, which only the generic ceiling bounds;
    // - the event is at one of those allowed places, with its exact
    //   orig_rax, and the RCB count the Tool sees there is the one the loop
    //   has retired at that instruction with those rbx and r15;
    // - SIGUSR1's frame saves the registers the event saw: all eight that
    //   the handler records (rip, rax, rbx, rcx, eflags, r12, r14 and r15),
    //   rcx being the address after the last getpid's syscall instruction;
    // - every run made its request at the same clock.
    let program = Program::new(&format!(
        "{SIBLING}{GETPPID}lea 7f(%rip),%r14\nmov ${SYSCALL_RETURN_LOOP},%r15\n\
         4:\nsr0: mov $3,%rbx\n5:\nsr1: dec %rbx\nsr2: jnz 5b\nsr3: mov $39,%eax\nsr4: syscall\n\
         7:\nsr5: dec %r15\nsr6: jnz 4b\n{WRITE_RECORD}{}",
        signal_record(HANDLER_FLAGS, "")
    ));
    let labels = ["sr0", "sr1", "sr2", "sr3", "sr4", "sr5", "sr6"].map(|name| program.symbol(name));
    let ticks = 100_000;
    let plan = Plan {
        arm: Arm::Marker,
        requests: vec![ticks],
        only_tgkill: true,
        registers: true,
        rendezvous: true,
        deliver: true,
        ..Plan::default()
    };
    let mut requests = vec![];
    for backend in ["ptrace", "kvm"] {
        for run in 0..COMPARED_RUNS {
            let (events, ending) = match backend {
                "ptrace" => run_on_ptrace(&program, plan.clone()),
                _ => run_ending(&program, plan.clone()),
            };
            let context = format!("{backend} run {run}: {events:?}");
            let (code, stdout, stderr) =
                ending.unwrap_or_else(|failure| panic!("{failure}: {context}"));
            assert_eq!((code, stderr), (0, vec![]), "{context}");
            let record = Record::read(&stdout);
            let shape: Vec<&str> = events
                .iter()
                .map(|event| match event {
                    Event::Requested { .. } => "request",
                    Event::Timer { .. } => "timer",
                    Event::Registers(_) => "registers",
                    Event::Signalled { .. } => "signal",
                    _ => "other",
                })
                .collect();
            assert_eq!(
                shape,
                ["other", "request", "timer", "registers", "signal"],
                "{context}"
            );
            let (requested_at, _) = last_request(&events);
            let (_, timer_clock) = first_timer(&events);
            assert_delivered(timer_clock, requested_at, ticks, &context);
            assert_eq!(sigusr1_clocks(&events)[0].1, timer_clock, "{context}");
            let r = registers_of(&events);
            assert_eq!(record.count, 1, "{context}");
            assert_eq!(
                record,
                Record {
                    rip: r.rip,
                    rax: r.rax,
                    rbx: r.rbx,
                    rcx: r.rcx,
                    eflags: r.eflags,
                    r12: r.r12,
                    r14: r.r14,
                    r15: r.r15,
                    count: 1,
                },
                "SIGUSR1's frame against the event's registers: {context}"
            );
            assert_eq!(
                (r.r14, r.rcx),
                (labels[5], labels[5]),
                "r14 and the last getpid's return address: {context}"
            );
            // Where the event came, at what clock, and the RCBs the loop has
            // retired there.
            let landing =
                syscall_return_landing(backend, &r, &labels, requested_at, ticks, timer_clock)
                    .unwrap_or_else(|why| panic!("{why}: {context}"));
            requests.push(requested_at);
            println!(
                "{backend} run {run}: requested at {requested_at}, delivered at {timer_clock}, \
                 rip {:#x} ({landing}), orig_rax {:#x}",
                r.rip, r.orig_rax
            );
        }
    }
    assert!(
        requests.iter().all(|&at| at == requests[0]),
        "every run's request clock: {requests:?}"
    );
}

/// The timer events of `events` and their registers, in order.
fn timer_events_with_registers(events: &[Event]) -> Vec<(u64, Registers)> {
    timer_clocks(events)
        .into_iter()
        .zip(timer_registers(events))
        .collect()
}

#[test]
fn a_signal_at_an_rt_sigreturn_timer_event_matches_ptrace_where_precise() {
    if bounded("a_signal_at_an_rt_sigreturn_timer_event_matches_ptrace_where_precise") {
        return;
    }
    // The guest of `a_signal_pending_at_an_rt_sigreturn_timer_event_follows_it`:
    // SIGSEGV's callback sends SIGUSR1 to the thread, which its handler's
    // mask blocks, and requests 1 RCB, which the handler's one branch, right
    // before its rt_sigreturn, reaches; the mask rt_sigreturn restores
    // unblocks SIGUSR1, which is delivered at its return with the registers
    // it restores. SIGUSR1's callback requests 1 RCB in turn, which the main
    // loop's first branch reaches, right before the guest writes its record.
    //
    // A precise request lands on both backends at the boundary after that
    // branch, in the handler, before rt_sigreturn, and SIGUSR1 comes at
    // rt_sigreturn's return; the second lands after the main loop's branch,
    // at the record write's first instruction. All six precise runs must
    // agree: the same events, clocks and registers, and the same frame but
    // for one bit. The fault's frame saves RF, which a fault sets in the
    // flags the CPU pushes; rt_sigreturn restores it (its FIX_EFLAGS include
    // RF:
    // https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/signal_64.c#L84,
    // https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/include/asm/sighandling.h#L11-L14),
    // and an untraced Linux thread saves it again in SIGUSR1's frame, as this
    // backend does, while the frame under reverie-ptrace lacks it, after the
    // tracer handled the fault's stop, where this Tool injects a syscall.
    //
    // An imprecise request differs, as documented. This backend delivers
    // the first at rt_sigreturn's exit, before the signal selected there.
    // Under reverie-ptrace the PMU notification (SIGSTKFLT, 16) is taken
    // after the handler's branch, during or after rt_sigreturn, where
    // SIGUSR1 (10) is pending too, and Linux dequeues the lower number
    // first: SIGUSR1's callback, an event of another kind, then cancels the
    // request; should the notification be taken right after the branch,
    // before rt_sigreturn, the event comes where a precise one comes. The
    // second imprecise request is decided, on both backends, by whichever
    // comes first after its target: a kick, which stops the guest between
    // two of the record write's instructions and delivers it there, or the
    // write's own callback, an event of another kind, which cancels it. Both
    // are host timing, so imprecise runs are compared with each other up to
    // that request, and what follows it must be nothing, or one event at its
    // target (clock 2) at one of the record write's five instruction starts,
    // with exactly the registers the instructions before it leave: those of
    // the precise event at the record write's first instruction, but for rdi
    // 1 after `mov $1,%edi`, rsi `record` after the lea, rdx 72 after
    // `mov $72,%edx` and rax 1 after `mov $1,%eax`.
    let program = Program::new(&format!(
        "lea 9f(%rip),%r12\nmov $11,%edi\nlea segv_action(%rip),%rsi\nxor %edx,%edx\n\
         mov $8,%r10d\nmov $13,%eax\nsyscall\nmov $10,%edi\nlea usr1_action(%rip),%rsi\n\
         xor %edx,%edx\nmov $8,%r10d\nmov $13,%eax\nsyscall\nmovq 0x10,%rax\n\
         9: mov ${SPINS},%rcx\n1: cmpb $0,flag(%rip)\njne 2f\ndec %rcx\njnz 1b\n2:\n\
         record_write: mov $1,%edi\nrw1: lea record(%rip),%rsi\nrw2: mov $72,%edx\n\
         rw3: mov $1,%eax\nrecord_syscall: syscall\nxor %edi,%edi\nmov $231,%eax\nsyscall\nud2\n\
         segv: addq $8,168(%rdx)\nadd $8,%rsp\nmov $15,%eax\nxor %ecx,%ecx\njz 7f\n\
         7:\nsegv_return: syscall\nud2\n{}",
        signal_record(
            HANDLER_FLAGS,
            &format!("segv_action: .quad segv, {HANDLER_FLAGS:#x}, restorer, 0x200\n")
        )
    ));
    const RF: u64 = 1 << 16;
    // At SIGSEGV's handler's rt_sigreturn, where the precise event comes,
    // rsi and rdx are the handler's arguments, which point into its frame,
    // whose size each backend's floating-point state decides. The other
    // events before the record write see the context rt_sigreturn restored
    // (restore_sigcontext,
    // https://github.com/gregkh/linux/blob/v7.1.3/arch/x86/kernel/signal_64.c#L64-L65):
    // rsi still the address of usr1_action and rdx 0, as the guest's last
    // rt_sigaction left them before the fault.
    let segv_return = program.symbol("segv_return");
    let usr1_action = program.symbol("usr1_action");
    let record_write = program.symbol("record_write");
    // The record write's instruction starts, in order.
    let record_write_starts =
        ["record_write", "rw1", "rw2", "rw3", "record_syscall"].map(|name| program.symbol(name));
    let record_address = program.symbol("record");
    // Where the precise event came: the handler's rt_sigreturn.
    let precise_timer_rip = std::cell::Cell::new(None);
    // The registers of the precise runs' event at the record write's first
    // instruction, as the backends compare them.
    let precise_at_record_write: std::cell::RefCell<Option<Registers>> = Default::default();
    for precise in [true, false] {
        let plan = Plan {
            requests: vec![],
            rearm_at_signal: Some(1),
            registers: true,
            deliver: true,
            self_signal_at_fault: true,
            precise,
            ..Plan::default()
        };
        let mut seen: Vec<(&str, Vec<Event>, Record)> = vec![];
        let precise_rip = precise_timer_rip.get();
        for backend in ["ptrace", "kvm"] {
            for run in 0..COMPARED_RUNS {
                let (events, ending) = match backend {
                    "ptrace" => run_on_ptrace(&program, plan.clone()),
                    _ => run_ending(&program, plan.clone()),
                };
                let context = format!("{backend} run {run}, precise {precise}: {events:?}");
                let (code, stdout, stderr) =
                    ending.unwrap_or_else(|failure| panic!("{failure}: {context}"));
                assert_eq!((code, stderr), (0, vec![]), "{context}");
                let record = Record::read(&stdout);
                assert_eq!(record.count, 1, "{context}");
                // SIGUSR1's frame saves the context rt_sigreturn restored.
                assert_eq!(
                    (record.rip, record.r12, record.rax),
                    (record.r12, record.r12, 0),
                    "{context}"
                );
                assert_eq!(
                    record.eflags & RF,
                    if backend == "kvm" { RF } else { 0 },
                    "{context}: {record:x?}"
                );
                // The events up to the second request, which precise and
                // imprecise runs both compare, and the rest.
                let second = events
                    .iter()
                    .rposition(|event| matches!(event, Event::Requested { .. }))
                    .expect("SIGUSR1's request");
                let (compared, after) = events.split_at(second + 1);
                for (clock, registers) in timer_events_with_registers(compared) {
                    if registers.rip != segv_return {
                        assert_eq!(
                            (registers.rsi, registers.rdx),
                            (usr1_action, 0),
                            "restored rsi and rdx at clock {clock}: {context}"
                        );
                    }
                }
                if precise {
                    let timers = timer_events_with_registers(&events);
                    let at: Vec<u64> = timers.iter().map(|(_, r)| r.rip).collect();
                    assert_eq!(
                        at,
                        [segv_return, record_write],
                        "the precise events: at the handler's rt_sigreturn, then at the \
                         record write: {context}"
                    );
                    assert_eq!(
                        (timers[1].1.rsi, timers[1].1.rdx),
                        (usr1_action, 0),
                        "restored rsi and rdx at the record write: {context}"
                    );
                    assert_eq!(timers[1].1.orig_rax, u64::MAX, "{context}");
                    precise_at_record_write
                        .borrow_mut()
                        .get_or_insert_with(|| comparable_timer_registers(&timers[1].1));
                } else {
                    // What follows the second request: nothing, or its event
                    // at its target, at one of the record write's instruction
                    // starts, with the registers the instructions before that
                    // start leave (see above).
                    let first = precise_at_record_write
                        .borrow()
                        .clone()
                        .expect("the precise runs' event at the record write");
                    let mut allowed = vec![vec![]];
                    for (index, &start) in record_write_starts.iter().enumerate() {
                        let mut expected = first.clone();
                        expected.rip = start;
                        if index >= 1 {
                            expected.rdi = 1;
                        }
                        if index >= 2 {
                            expected.rsi = record_address;
                        }
                        if index >= 3 {
                            expected.rdx = 72;
                        }
                        if index >= 4 {
                            expected.rax = 1;
                        }
                        allowed.push(vec![Event::Timer { clock: 2 }, Event::Registers(expected)]);
                    }
                    let tail = comparable_events(after);
                    assert!(
                        allowed.contains(&tail),
                        "after the second request {tail:x?}, where only one of {allowed:x?} \
                         may come: {context}"
                    );
                }
                // The precise event comes in SIGSEGV's handler, whose rsi and
                // rdx point into its frame (see above).
                let comparable_registers = |events: &[Event]| -> Vec<Event> {
                    comparable_events(events)
                        .into_iter()
                        .map(|event| match event {
                            Event::Registers(registers) if registers.rip == segv_return => {
                                Event::Registers(Registers {
                                    rsi: 0,
                                    rdx: 0,
                                    ..registers
                                })
                            }
                            event => event,
                        })
                        .collect()
                };
                // Imprecise runs compare with each other up to the second
                // request; what follows it was compared above with the only
                // events it may hold.
                let kept = if precise {
                    comparable_registers(&events)
                } else {
                    comparable_registers(compared)
                };
                seen.push((backend, kept, record));
            }
        }
        let (kvm_events, kvm_record) = (&seen.last().unwrap().1, seen.last().unwrap().2);
        for (backend, events, record) in &seen {
            assert_eq!(
                Record {
                    eflags: record.eflags & !RF,
                    ..*record
                },
                Record {
                    eflags: kvm_record.eflags & !RF,
                    ..kvm_record
                },
                "{backend}, precise {precise}"
            );
            let context = format!("{backend}, precise {precise}: {events:?}, KVM {kvm_events:?}");
            if precise || *backend == "kvm" {
                assert_eq!(events, kvm_events, "{context}");
            } else {
                // Without the timer event and its registers, the events are
                // KVM's: the fault, the request, SIGUSR1 at the request's
                // target and the next request. Should the notification be
                // taken right after the handler's branch, before its
                // rt_sigreturn, the event comes there, where a precise one
                // comes, and SIGUSR1 then cancels nothing.
                let without_timer = |events: &[Event]| -> Vec<Event> {
                    events
                        .iter()
                        .filter(|event| !matches!(event, Event::Timer { .. } | Event::Registers(_)))
                        .cloned()
                        .collect()
                };
                assert_eq!(
                    without_timer(events),
                    without_timer(kvm_events),
                    "{context}"
                );
                if events
                    .iter()
                    .any(|event| matches!(event, Event::Timer { .. }))
                {
                    assert_eq!(timer_clocks(events), [1], "{context}");
                    assert_eq!(Some(registers_of(events).rip), precise_rip, "{context}");
                }
            }
        }
        // On KVM the first event comes at its target, at rt_sigreturn's
        // return (imprecise) or before it, at the handler's rt_sigreturn
        // (precise), and SIGUSR1's hook at the same clock.
        let (_, timer_clock) = first_timer(kvm_events);
        let (requested_at, _) = last_request(
            &kvm_events
                .iter()
                .take_while(|event| !matches!(event, Event::Timer { .. }))
                .cloned()
                .collect::<Vec<_>>(),
        );
        assert_eq!(timer_clock, requested_at + 1, "{kvm_events:?}");
        assert_eq!(
            sigusr1_clocks(kvm_events)[0].1,
            timer_clock,
            "{kvm_events:?}"
        );
        let r = registers_of(kvm_events);
        if precise {
            assert_eq!(r.rax, 15, "at the handler's rt_sigreturn: {r:x?}");
            precise_timer_rip.set(Some(r.rip));
        } else {
            assert_eq!(
                (r.rip, r.orig_rax),
                (r.r12, u64::MAX),
                "at rt_sigreturn's return: {r:x?}"
            );
        }
        println!(
            "precise {precise}: KVM {kvm_events:x?}, ptrace {:x?}",
            seen[0].1
        );
    }
}
