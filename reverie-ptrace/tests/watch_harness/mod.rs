/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The Tool and guest accesses the watchpoint tests share (`watchpoints.rs`,
//! with the precise timer's overflow records, `watchpoints_without_records.rs`
//! and `watchpoints_partial_records.rs`). Each binary uses part of it.
//!
//! The guest's accesses are made by the two instructions below, whose next
//! instructions are global symbols, so the test process, from which the
//! guest is forked, knows the address each hit must report.

#![allow(dead_code)]

use std::sync::Mutex;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::WatchHit;
use reverie::WatchKind;
use reverie::WatchSpec;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::check_fn_with_config;
use serde::Deserialize;
use serde::Serialize;

core::arch::global_asm!(
    ".pushsection .text.watch_test_access,\"ax\",@progbits",
    // Unwind information, so that a hit's stack goes past these leaves.
    ".globl watch_test_store",
    ".type watch_test_store, @function",
    "watch_test_store:",
    ".cfi_startproc",
    "mov qword ptr [rdi], rsi",
    ".globl watch_test_after_store",
    "watch_test_after_store:",
    "ret",
    ".cfi_endproc",
    ".size watch_test_store, . - watch_test_store",
    ".globl watch_test_load",
    ".type watch_test_load, @function",
    "watch_test_load:",
    ".cfi_startproc",
    "mov rax, qword ptr [rdi]",
    ".globl watch_test_after_load",
    "watch_test_after_load:",
    "ret",
    ".cfi_endproc",
    ".size watch_test_load, . - watch_test_load",
    ".popsection",
);

// Two `popfq` instructions, the first setting the trap flag and the second
// clearing it as it reads the 8 bytes it pops. Setting the trap flag with
// `popfq` delays the step trap by one instruction, so the trap comes after
// the second `popfq`: a real single-step trap at an instruction that read a
// watched word. The watch is armed on that word from here, once its address
// (the stack slot of the first `pushfq`) is known.
core::arch::global_asm!(
    ".pushsection .text.watch_test_popfq,\"ax\",@progbits",
    ".globl watch_test_popfq",
    ".type watch_test_popfq, @function",
    "watch_test_popfq:",
    ".cfi_startproc",
    "pushfq",
    ".cfi_adjust_cfa_offset 8",
    // Ask the Tool for a read/write watch on this slot, with no stacks.
    "mov rsi, rsp",
    "mov edi, {arm_at}",
    "mov edx, {read_write}",
    "mov r10d, 0",
    "mov eax, {clock_getres}",
    "syscall",
    // The flags the first `popfq` pops, with the trap flag set, below it.
    "pushfq",
    ".cfi_adjust_cfa_offset 8",
    "or qword ptr [rsp], 0x100",
    "popfq",
    ".cfi_adjust_cfa_offset -8",
    // Reads the watched slot and clears the trap flag; the step trap of the
    // `popfq` above arrives after it.
    "popfq",
    ".cfi_adjust_cfa_offset -8",
    ".globl watch_test_after_popfq",
    "watch_test_after_popfq:",
    // Disarm, so that the caller's own use of the slot is not watched.
    "mov edi, {arm_at}",
    "xor esi, esi",
    "xor edx, edx",
    "xor r10d, r10d",
    "mov eax, {clock_getres}",
    "syscall",
    "ret",
    ".cfi_endproc",
    ".size watch_test_popfq, . - watch_test_popfq",
    ".popsection",
    arm_at = const ARM_AT,
    read_write = const 1,
    clock_getres = const libc::SYS_clock_getres,
);

unsafe extern "C" {
    fn watch_test_store(at: *mut u64, value: u64);
    fn watch_test_load(at: *const u64) -> u64;
    /// Arms a read/write watch on a stack slot and reads it with a `popfq`
    /// that a real single step traps on ([`after_popfq`]).
    pub fn watch_test_popfq();
    static watch_test_after_store: u8;
    static watch_test_after_load: u8;
    static watch_test_after_popfq: u8;
}

/// The instruction after the store, where a hit of the store reports.
pub fn after_store() -> u64 {
    (&raw const watch_test_after_store) as u64
}

/// The instruction after the load.
pub fn after_load() -> u64 {
    (&raw const watch_test_after_load) as u64
}

/// The instruction after the `popfq` pair's second `popfq`, where both its
/// step trap and its hit report.
pub fn after_popfq() -> u64 {
    (&raw const watch_test_after_popfq) as u64
}

/// The guest's watched words. The test process allocates nothing between
/// forking guests that would move them: they are a static.
static mut WORDS: [u64; 8] = [0; 8];

pub fn word(n: usize) -> *mut u64 {
    unsafe { (&raw mut WORDS).cast::<u64>().add(n) }
}

pub fn store(n: usize, value: u64) {
    unsafe { watch_test_store(word(n), value) }
}

pub fn load(n: usize) -> u64 {
    unsafe { watch_test_load(word(n)) }
}

pub fn watch(n: usize, kind: WatchKind) -> WatchSpec {
    WatchSpec {
        addr: word(n) as u64,
        len: 8,
        kind,
        backtraces: 0,
    }
}

/// The `clock_getres` clock that asks the Tool to arm the watch set its
/// second argument names; no clock has this ID.
pub const ARM: usize = 0x5741_5443;

/// The `clock_getres` clock that asks the Tool to arm the calling thread
/// with one watch, given by its arguments: the address, the kind (0 writes,
/// 1 reads and writes) and the stacks its hits may carry. A zero address
/// disarms the thread's watches instead.
pub const ARM_AT: usize = 0x5741_5441;

/// Asks the Tool to arm the calling thread with watch set `set`.
pub fn arm(set: usize) {
    let ret = unsafe { libc::syscall(libc::SYS_clock_getres, ARM, set, 0) };
    assert_eq!(ret, 0);
}

/// The set holding SIGTRAP that [`arm_with_sigtrap_blocked`] hands the Tool.
static mut SIGTRAP_SET: libc::sigset_t = unsafe { std::mem::zeroed() };

/// Arms with watch set `set` and asks the Tool to block SIGTRAP in this
/// thread as it does. The Tool injects the `rt_sigprocmask`, which is no
/// event of the guest's, so the thread makes no syscall of its own
/// afterwards and nothing cancels its timer events; every later hit then
/// meets SIGTRAP blocked, and takes the repair that puts it back.
pub fn arm_with_sigtrap_blocked(set: usize) {
    unsafe {
        libc::sigemptyset(&raw mut SIGTRAP_SET);
        libc::sigaddset(&raw mut SIGTRAP_SET, libc::SIGTRAP);
        let ret = libc::syscall(
            libc::SYS_clock_getres,
            ARM,
            set,
            (&raw const SIGTRAP_SET) as usize,
        );
        assert_eq!(ret, 0);
    }
}

/// The `clock_getres` clock that asks the Tool to map no overflow records
/// for the timers of threads made from then on, in this test process
/// (`reverie_ptrace::testing::disable_timer_overflow_records`).
pub const DISABLE_RECORDS: usize = 0x4e4f_5245;

/// Asks the Tool to map no overflow records for later threads' timers.
pub fn disable_records_for_new_threads() {
    let ret = unsafe { libc::syscall(libc::SYS_clock_getres, DISABLE_RECORDS, 0) };
    assert_eq!(ret, 0);
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    /// The watch sets a guest's `arm` calls name.
    pub sets: Vec<Vec<WatchSpec>>,
    /// The set every thread arms as it starts, if any: at the end of its
    /// first `rt_sigprocmask`. A thread glibc starts runs with every signal
    /// blocked until its start code restores its mask with that call, and
    /// arming is refused while SIGTRAP is blocked; the thread runs no code
    /// of the program before it.
    pub at_start: Option<usize>,
    /// Keep the conditions under which Reverie records a thread's signal
    /// state (`GlobalState::keeps_signal_records`): declare serialized
    /// execution, observe sigreturns and trace every syscall. Not rdtsc or
    /// cpuid, whose SIGSEGV records would serve the watches too.
    pub records: bool,
    /// A precise timer of this many RCBs, requested at each arming, and
    /// again at each of its events until `timer_events` have been delivered.
    pub timer: Option<u64>,
    pub timer_events: usize,
    /// And this many instructions after the RCBs
    /// (`TimerSchedule::RcbsAndInstructions`).
    pub timer_instructions: Option<u64>,
}

impl Config {
    fn schedule(&self) -> Option<TimerSchedule> {
        let rcbs = self.timer?;
        Some(match self.timer_instructions {
            Some(instructions) => TimerSchedule::RcbsAndInstructions(rcbs, instructions),
            None => TimerSchedule::Rcbs(rcbs),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Report {
    /// A thread's arming, and whether its hits keep its timer events.
    Armed {
        set: usize,
        result: Result<(), String>,
        keeps_timer_events: bool,
    },
    /// A timer event: the clock since the request and the instruction.
    TimerEvent { clock: u64, ip: u64 },
}

#[derive(Debug, Default)]
pub struct Watched {
    hits: Mutex<Vec<WatchHit>>,
    reports: Mutex<Vec<(Pid, Report)>>,
}

impl Watched {
    pub fn hits(&self) -> Vec<WatchHit> {
        self.hits.lock().unwrap().clone()
    }

    pub fn armings(&self) -> Vec<(Pid, usize, Result<(), String>, bool)> {
        self.reports
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(tid, report)| match report {
                Report::Armed {
                    set,
                    result,
                    keeps_timer_events,
                } => Some((*tid, *set, result.clone(), *keeps_timer_events)),
                _ => None,
            })
            .collect()
    }

    pub fn timer_events(&self) -> Vec<(u64, u64)> {
        self.reports
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(_, report)| match report {
                Report::TimerEvent { clock, ip } => Some((*clock, *ip)),
                _ => None,
            })
            .collect()
    }
}

#[reverie::global_tool]
impl GlobalTool for Watched {
    type Request = Report;
    type Response = ();
    type Config = Config;

    async fn receive_rpc(&self, from: Pid, report: Report) {
        self.reports.lock().unwrap().push((from, report));
    }

    fn on_watchpoint_hit(&self, hit: &WatchHit) {
        self.hits.lock().unwrap().push(hit.clone());
    }
}

#[derive(Debug, Default, Clone)]
pub struct WatchTool;

/// A thread's clock at its timer request, the events it has had, and
/// whether it is still to arm as it starts.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TimerState {
    requested_at: u64,
    events: usize,
    to_arm: bool,
}

impl WatchTool {
    /// Arms watch set `set`; with `block` the address of a signal set, also
    /// injects an `rt_sigprocmask` that blocks it in the thread.
    async fn arm<T: Guest<Self>>(guest: &mut T, cfg: &Config, set: usize, block: usize) {
        let result = guest
            .set_watchpoints(&cfg.sets[set])
            .map_err(|error| format!("{error:?}"));
        if result.is_ok() && block != 0 {
            let blocked = guest
                .inject(
                    reverie::syscalls::RtSigprocmask::new()
                        .with_how(libc::SIG_BLOCK)
                        .with_set(reverie::syscalls::Addr::from_raw(block))
                        .with_oldset(None)
                        .with_sigsetsize(std::mem::size_of::<u64>()),
                )
                .await;
            assert_eq!(blocked, Ok(0));
        }
        let keeps_timer_events = guest.watch_hits_keep_timer_events();
        guest
            .send_rpc(Report::Armed {
                set,
                result,
                keeps_timer_events,
            })
            .await;
        if let Some(schedule) = cfg.schedule() {
            guest.thread_state_mut().requested_at = guest.read_clock().unwrap();
            guest.set_timer_precise(schedule).unwrap();
        }
    }
}

#[reverie::tool]
impl Tool for WatchTool {
    type GlobalState = Watched;
    type ThreadState = TimerState;

    fn subscriptions(cfg: &Config) -> Subscription {
        if cfg.records {
            return Subscription::all_syscalls();
        }
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres]);
        // Only to arm threads as they start: a syscall the Tool observes ends
        // a timer event, as any event it observes does.
        if cfg.at_start.is_some() {
            s.syscalls([Sysno::rt_sigprocmask]);
        }
        s
    }

    fn observes_sigreturns(cfg: &Config) -> bool {
        cfg.records
    }

    fn enforces_serialized_execution(cfg: &Config) -> bool {
        cfg.records
    }

    async fn handle_thread_start<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Error> {
        guest.thread_state_mut().to_arm = guest.config().at_start.is_some();
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        if nr == Sysno::clock_getres && args.arg0 == ARM {
            let cfg = guest.config().clone();
            Self::arm(guest, &cfg, args.arg1, args.arg2).await;
            return Ok(0);
        }
        if nr == Sysno::clock_getres && args.arg0 == ARM_AT && args.arg1 == 0 {
            let result = guest
                .set_watchpoints(&[])
                .map_err(|error| format!("{error:?}"));
            assert_eq!(result, Ok(()));
            return Ok(0);
        }
        if nr == Sysno::clock_getres && args.arg0 == ARM_AT {
            let spec = WatchSpec {
                addr: args.arg1 as u64,
                len: 8,
                kind: if args.arg2 == 0 {
                    WatchKind::Write
                } else {
                    WatchKind::ReadWrite
                },
                backtraces: args.arg3 as u32,
            };
            let result = guest
                .set_watchpoints(&[spec])
                .map_err(|error| format!("{error:?}"));
            let keeps_timer_events = guest.watch_hits_keep_timer_events();
            guest
                .send_rpc(Report::Armed {
                    set: usize::MAX,
                    result,
                    keeps_timer_events,
                })
                .await;
            return Ok(0);
        }
        if nr == Sysno::clock_getres && args.arg0 == DISABLE_RECORDS {
            reverie_ptrace::testing::disable_timer_overflow_records();
            return Ok(0);
        }
        if nr == Sysno::rt_sigprocmask && std::mem::take(&mut guest.thread_state_mut().to_arm) {
            let ret = guest.inject(syscall).await;
            let cfg = guest.config().clone();
            if let Some(set) = cfg.at_start {
                Self::arm(guest, &cfg, set, 0).await;
            }
            return Ok(ret?);
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_timer_event<T: Guest<Self>>(&self, guest: &mut T) {
        let cfg = guest.config().clone();
        let clock = guest.read_clock().unwrap() - guest.thread_state().requested_at;
        let ip = guest.regs().await.rip;
        guest.send_rpc(Report::TimerEvent { clock, ip }).await;
        let state = guest.thread_state_mut();
        state.events += 1;
        if state.events < cfg.timer_events
            && let Some(schedule) = cfg.schedule()
        {
            guest.thread_state_mut().requested_at = guest.read_clock().unwrap();
            guest.set_timer_precise(schedule).unwrap();
        }
    }
}

pub fn run(cfg: Config, guest: impl FnOnce() + Send + 'static) -> Watched {
    check_fn_with_config::<WatchTool, _>(guest, cfg, true)
}

/// The guest of the timer tests: `writes` watched stores, each followed by
/// a few conditional branches, so that the timer's single steps toward each
/// target run some of them.
pub fn timer_guest(writes: u64) -> impl FnOnce() + Send + 'static {
    move || {
        arm(0);
        for i in 0..writes {
            store(0, i);
            reverie::perf::do_branches(3);
        }
    }
}

pub fn timer_config(rcbs: u64, events: usize, armed: bool) -> Config {
    Config {
        sets: vec![if armed {
            vec![watch(0, WatchKind::Write)]
        } else {
            vec![]
        }],
        timer: Some(rcbs),
        timer_events: events,
        ..Config::default()
    }
}

/// [`timer_guest`], with SIGTRAP blocked from the arming on, so that every
/// hit takes the repair of the guest's SIGTRAP state.
pub fn blocked_timer_guest(writes: u64) -> impl FnOnce() + Send + 'static {
    move || {
        arm_with_sigtrap_blocked(0);
        for i in 0..writes {
            store(0, i);
            reverie::perf::do_branches(3);
        }
    }
}

/// Blocks or unblocks the precise timer's signal with a raw
/// `rt_sigprocmask`, which the Tool does not observe, to hold its
/// notification back.
pub fn mask_timer_signal(how: libc::c_int) {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, reverie::PERF_EVENT_SIGNAL as libc::c_int);
        assert_eq!(
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                how,
                &set as *const libc::sigset_t,
                std::ptr::null_mut::<libc::sigset_t>(),
                std::mem::size_of::<libc::c_ulong>(),
            ),
            0
        );
    }
}

/// Above the largest skid margin in Reverie's PMU table, so the request
/// programs a real PMU notification on every host in the table.
pub const PERF_RCBS: u64 = 30_000;

/// A guest whose one watched store comes `before` conditional branches short
/// of a precise timer's target, with the timer's notification held back, so
/// that the hit's stop falls between the programming's period and the
/// target, where only the overflow records tell that the notification is
/// still to come.
pub fn store_near_the_target(before: u64) -> impl FnOnce() + Send + 'static {
    move || {
        mask_timer_signal(libc::SIG_BLOCK);
        arm(0);
        reverie::perf::do_branches(PERF_RCBS - before);
        store(0, 1);
        mask_timer_signal(libc::SIG_UNBLOCK);
        reverie::perf::do_branches(PERF_RCBS);
    }
}

/// How far short of the target `store_near_the_target` stores: half the keep
/// margin, inside it on every processor in Reverie's PMU table and far from
/// the target.
pub fn half_the_keep_margin() -> u64 {
    let margin = reverie_ptrace::PmuConfig::new()
        .expect("this host has a PMU profile")
        .keep_margin();
    assert!(margin / 2 > 200, "keep margin {margin}");
    margin / 2
}
