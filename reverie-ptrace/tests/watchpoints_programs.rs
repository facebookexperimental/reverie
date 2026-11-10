/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Hardware watchpoints on programs Reverie executes, built from
//! `tests/fixtures/watch_entry_push.c` and `watch_sigtrap_state.c`:
//!
//! - a watch armed in the post-exec callback catches the image's first
//!   instruction, which Reverie single-steps, and an exec disarms it;
//! - a forked child and a new thread start with none;
//! - arming is refused while a pending restore's temporary mask blocks
//!   SIGTRAP, at the delivery of a signal that ended a guest's `ppoll`;
//! - a hit's forced SIGTRAP: where the Tool keeps the contract that lets
//!   Reverie record the thread's signal state, a SIGTRAP the guest blocked is
//!   blocked again (in a handler whose mask blocks it, too), and a reset
//!   action is reported (`WatchHit::sigtrap`). Without the contract, the hit
//!   says that the state is not known, and so it does after a delivery of
//!   SIGTRAP itself, or on a signal-action table a thread Reverie does not
//!   trace may use.

#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Signal;
use reverie::SigtrapAtHit;
use reverie::Subscription;
use reverie::Tool;
use reverie::WatchError;
use reverie::WatchHit;
use reverie::WatchKind;
use reverie::WatchSpec;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::test_cmd_with_config;
use reverie_ptrace::testing::watch_status_reads;
use serde::Deserialize;
use serde::Serialize;

/// The `clock_getres` clock with which the guest asks for a write watch on
/// the 8 bytes at its second argument.
const ARM: usize = 0x5741_5443;

/// The `clock_getres` clock with which the guest asks for the same watch to
/// be armed when SIGUSR1 is next delivered to it.
const ARM_AT_SIGUSR1: usize = 0x5553_5231;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Config {
    /// Arm, in the first exec's post-exec callback, a write watch on the 8
    /// bytes below the new image's initial stack pointer.
    arm_at_first_exec: bool,
    /// Keep the contract under which Reverie records a thread's signal
    /// state: declare serialized execution (a one-thread guest keeps it),
    /// observe sigreturns, and trace every syscall. Not rdtsc or cpuid, so
    /// that Reverie keeps no SIGSEGV state, whose records would serve the
    /// watches too.
    contract: bool,
    /// Subscribe to `rt_sigaction`, which alone makes Reverie remember
    /// SIGTRAP's disposition (`GlobalState::caches_sigtrap_disposition`)
    /// without the rest of the contract.
    sigaction: bool,
}

/// An arming's result, and what the thread said of its hits and timer
/// events (`Guest::watch_hits_keep_timer_events`).
type Arming = (Result<(), String>, bool);

/// An arming and its thread.
type Armed = (Pid, Result<(), String>, bool);

#[derive(Debug, Default)]
struct Seen {
    hits: Mutex<Vec<WatchHit>>,
    armings: Mutex<Vec<Armed>>,
}

impl Seen {
    fn hits(&self) -> Vec<WatchHit> {
        self.hits.lock().unwrap().clone()
    }

    fn armings(&self) -> Vec<Armed> {
        self.armings.lock().unwrap().clone()
    }
}

#[reverie::global_tool]
impl GlobalTool for Seen {
    type Request = Arming;
    type Response = ();
    type Config = Config;

    async fn receive_rpc(&self, from: Pid, (result, keeps): Arming) {
        self.armings.lock().unwrap().push((from, result, keeps));
    }

    fn on_watchpoint_hit(&self, hit: &WatchHit) {
        self.hits.lock().unwrap().push(hit.clone());
    }
}

/// Post-exec callbacks so far in the current test (they take turns).
static EXECS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Default, Clone)]
struct ProgramTool;

impl ProgramTool {
    async fn arm<T: Guest<Self>>(guest: &mut T, addr: u64) {
        let result = guest
            .set_watchpoints(&[WatchSpec {
                addr,
                len: 8,
                kind: WatchKind::Write,
                backtraces: 0,
            }])
            .map_err(|error| format!("{error:?}"));
        let keeps = guest.watch_hits_keep_timer_events();
        guest.send_rpc((result, keeps)).await;
    }
}

#[reverie::tool]
impl Tool for ProgramTool {
    type GlobalState = Seen;
    /// The word to watch at the next SIGUSR1 (`ARM_AT_SIGUSR1`).
    type ThreadState = Option<u64>;

    fn subscriptions(cfg: &Config) -> Subscription {
        if cfg.contract {
            return Subscription::all_syscalls();
        }
        let mut s = Subscription::none();
        s.syscalls([Sysno::clock_getres]);
        if cfg.sigaction {
            s.syscalls([Sysno::rt_sigaction]);
        }
        s
    }

    fn observes_sigreturns(cfg: &Config) -> bool {
        cfg.contract
    }

    fn enforces_serialized_execution(cfg: &Config) -> bool {
        cfg.contract
    }

    async fn handle_post_exec<T: Guest<Self>>(&self, guest: &mut T) -> Result<(), Errno> {
        if EXECS.fetch_add(1, Ordering::SeqCst) == 0 && guest.config().arm_at_first_exec {
            let sp = guest
                .initial_stack_pointer()
                .expect("the exec stop recorded the stack pointer");
            Self::arm(guest, sp - 8).await;
        }
        Ok(())
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let (nr, args) = syscall.into_parts();
        if nr == Sysno::clock_getres && args.arg0 == ARM {
            Self::arm(guest, args.arg1 as u64).await;
            return Ok(0);
        }
        if nr == Sysno::clock_getres && args.arg0 == ARM_AT_SIGUSR1 {
            *guest.thread_state_mut() = Some(args.arg1 as u64);
            return Ok(0);
        }
        guest.tail_inject(syscall).await
    }

    async fn handle_signal_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        if signal == Signal::SIGUSR1
            && let Some(addr) = guest.thread_state_mut().take()
        {
            Self::arm(guest, addr).await;
        }
        Ok(Some(signal))
    }
}

/// `ProgramTool` run as a child tool, through `Guest::into_guest`, as a tool
/// that wraps another forwards its callbacks.
#[derive(Debug, Default, Clone)]
struct WrappingTool(ProgramTool);

impl AsMut<ProgramTool> for WrappingTool {
    fn as_mut(&mut self) -> &mut ProgramTool {
        &mut self.0
    }
}

/// The thread state of `WrappingTool`, which holds the child's.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct WrappingThread(Option<u64>);

impl AsRef<Option<u64>> for WrappingThread {
    fn as_ref(&self) -> &Option<u64> {
        &self.0
    }
}

impl AsMut<Option<u64>> for WrappingThread {
    fn as_mut(&mut self) -> &mut Option<u64> {
        &mut self.0
    }
}

#[reverie::tool]
impl Tool for WrappingTool {
    type GlobalState = Seen;
    type ThreadState = WrappingThread;

    fn subscriptions(cfg: &Config) -> Subscription {
        ProgramTool::subscriptions(cfg)
    }

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        self.0
            .handle_syscall_event(&mut guest.into_guest(), syscall)
            .await
    }
}

/// The tests here count Reverie's process-wide watch counters and share
/// `EXECS`, so they take turns.
static TURN: Mutex<()> = Mutex::new(());

fn turn() -> std::sync::MutexGuard<'static, ()> {
    let turn = TURN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    EXECS.store(0, Ordering::SeqCst);
    turn
}

/// Compiles `tests/fixtures/<fixture>.c` with `cc -O0 -g -no-pie` and the
/// extra `args`, beside the test binary, and returns its path and the
/// addresses of `symbols`.
fn build(fixture: &str, args: &[&str], symbols: &[&str]) -> (PathBuf, Vec<u64>) {
    // Prefer the run-time CARGO_MANIFEST_DIR: the compile-time value is a
    // directory on the build host, missing on a test host the binary was
    // copied to.
    let source = std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join(format!("tests/fixtures/{fixture}.c"));
    let directory = std::env::current_exe()
        .expect("locate the test binary")
        .parent()
        .expect("the test binary has a directory")
        .to_path_buf();
    let name = format!("reverie-{}", fixture.replace('_', "-"));
    let path = directory.join(&name);
    let staging = directory.join(format!("{name}.{}.tmp", std::process::id()));
    let status = std::process::Command::new("cc")
        .args(["-O0", "-g", "-no-pie"])
        .args(args)
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
    let addresses = symbols
        .iter()
        .map(|name| {
            elf.syms
                .iter()
                .find(|sym| elf.strtab.get_at(sym.st_name) == Some(name))
                .unwrap_or_else(|| panic!("the guest has no symbol {name}"))
                .st_value
        })
        .collect();
    (path, addresses)
}

/// `watch_entry_push` and the address after its first instruction.
static ENTRY_PUSH: LazyLock<(PathBuf, u64)> = LazyLock::new(|| {
    let (path, addresses) = build(
        "watch_entry_push",
        &["-static", "-nostdlib"],
        &["reverie_after_push"],
    );
    (path, addresses[0])
});

static SIGTRAP_STATE: LazyLock<PathBuf> =
    LazyLock::new(|| build("watch_sigtrap_state", &["-pthread"], &[]).0);

/// Runs `watch_sigtrap_state` in `mode` under `config`, checks that it
/// exits 0, and returns its output line and what the Tool saw.
fn run_state(mode: &str, config: Config) -> (String, Seen) {
    run_state_under::<ProgramTool>(mode, config)
}

/// `run_state` under Tool `T`.
fn run_state_under<T: Tool<GlobalState = Seen> + 'static>(
    mode: &str,
    config: Config,
) -> (String, Seen) {
    let path = SIGTRAP_STATE.to_str().unwrap().to_owned();
    let (output, seen) =
        test_cmd_with_config::<T>(&path, &[mode], config).expect("run the guest under Reverie");
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "{mode}: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (stdout, seen)
}

/// Whether this host reports a trap that is only a watch hit as
/// `TRAP_HWBKPT`, which Reverie claims and whose SIGTRAP it repairs. A host
/// that sets the debug status's single-step bit for a hit alone (an AMD
/// EPYC VM does) gives it `TRAP_TRACE`, which may be a step the guest asked
/// for itself and is never claimed; the repair never runs there, so the
/// tests of what it puts back do not apply. Measured once, by watching one
/// store.
fn hits_are_claimed() -> bool {
    static CLAIMED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CLAIMED.get_or_init(|| {
        let claimed = reverie_ptrace::testing::watch_traps_claimed();
        let (_, seen) = run_state("mask", Config::default());
        assert_eq!(seen.hits().len(), 1);
        let claimed = reverie_ptrace::testing::watch_traps_claimed() > claimed;
        if !claimed {
            eprintln!(
                "this host reports a watch hit's own trap as TRAP_TRACE; the SIGTRAP repair \
                 does not run, and the tests of it are skipped"
            );
        }
        claimed
    })
}

fn contract() -> Config {
    Config {
        contract: true,
        ..Config::default()
    }
}

/// A watch armed in post-exec on the word the image's first instruction
/// pushes catches that instruction, which Reverie single-steps after the
/// callback; the hit comes with the step's trap, and is reported at the
/// instruction after it. The image then executes itself again: the exec
/// disarms the watch, so the second image's push is not reported, and no stop
/// after the exec reads the debug status.
#[test]
fn a_watch_armed_in_post_exec_catches_the_first_instruction_and_exec_disarms_it() {
    let _turn = turn();
    let (path, after_push) = &*ENTRY_PUSH;
    let (output, seen) = test_cmd_with_config::<ProgramTool>(
        path.to_str().unwrap(),
        &["again"],
        Config {
            arm_at_first_exec: true,
            ..Config::default()
        },
    )
    .expect("run the guest under Reverie");
    assert_eq!(output.status, ExitStatus::Exited(0));
    let armings = seen.armings();
    assert_eq!(armings.len(), 1, "{armings:?}");
    assert_eq!(armings[0].1, Ok(()));
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].tid, armings[0].0);
    assert_eq!(hits[0].ip, *after_push);
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Unchanged);
    assert_eq!(
        watch_status_reads(armings[0].0),
        1,
        "only the first instruction's step stop reads the status"
    );
}

/// A forked child and a new thread start with no watch: each runs an `int3`,
/// whose SIGTRAP stop reads the debug status only on a thread with a watch
/// armed, and neither's does. (The contract keeps the guest's SIGTRAP
/// handler across Reverie's own steps, which `pthread_create` runs with
/// every signal blocked; without it, a step's trap there resets the handler,
/// as at base.)
#[test]
fn a_forked_child_and_a_new_thread_start_without_watches() {
    let _turn = turn();
    let (stdout, seen) = run_state("children", contract());
    let ids: Vec<i32> = stdout
        .strip_prefix("child=1 ")
        .unwrap_or_else(|| panic!("{stdout}"))
        .split(' ')
        .map(|id| id.parse().unwrap())
        .collect();
    let armings = seen.armings();
    assert_eq!(armings.len(), 1, "{armings:?}");
    assert_eq!(armings[0].1, Ok(()));
    assert_eq!(seen.hits().len(), 0);
    for id in ids {
        assert_ne!(Pid::from_raw(id), armings[0].0);
        assert_eq!(
            watch_status_reads(Pid::from_raw(id)),
            0,
            "the trap of {id} read the status"
        );
    }
}

/// While a temporary mask's restore is pending, here at the delivery of the
/// signal that ended a guest's `ppoll`, the mask the thread runs under
/// (procfs `SigBlk`) is the temporary one, which blocks SIGTRAP, although
/// the mask the restore puts back, which `PTRACE_GETSIGMASK` reports, does
/// not. Arming is refused, and the guest's call ends as it would have: EINTR
/// after the handler.
#[test]
fn arming_is_refused_while_a_pending_restores_temporary_mask_blocks_sigtrap() {
    let _turn = turn();
    let (stdout, seen) = run_state("pending", Config::default());
    assert_eq!(stdout, "ret=-1 eintr=1 ran=1 after=unblocked");
    let armings = seen.armings();
    assert_eq!(armings.len(), 1, "{armings:?}");
    assert_eq!(
        armings[0].1,
        Err(format!("{:?}", WatchError::SigtrapBlocked))
    );
    assert_eq!(seen.hits().len(), 0);
}

/// Under the contract, a hit while the guest blocks SIGTRAP is followed by
/// SIGTRAP blocked again: the guest finds it blocked, as natively.
#[test]
fn a_blocked_sigtrap_is_blocked_again_after_a_hit() {
    let _turn = turn();
    if !hits_are_claimed() {
        return;
    }
    let (stdout, seen) = run_state("mask", contract());
    assert_eq!(stdout, "after=blocked");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Reblocked);
}

/// The same in a signal handler whose mask blocks SIGTRAP: the resume that
/// entered the handler is recorded, and the handler's mask is read at the hit.
#[test]
fn a_sigtrap_a_handlers_mask_blocks_is_blocked_again_after_a_hit() {
    let _turn = turn();
    if !hits_are_claimed() {
        return;
    }
    let (stdout, seen) = run_state("handler", contract());
    assert_eq!(stdout, "ran=1 in-handler=blocked after=unblocked");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Reblocked);
}

/// A caught SIGTRAP that the guest blocks has its action reset to `SIG_DFL`
/// by the hit, which Reverie does not put back and reports; the mask bit is
/// put back.
#[test]
fn a_hit_that_resets_sigtraps_action_says_so() {
    let _turn = turn();
    if !hits_are_claimed() {
        return;
    }
    let (stdout, seen) = run_state("action", contract());
    assert_eq!(stdout, "after=blocked action=default");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::ActionReset);
    assert!(hits[0].sigtrap.may_have_changed_guest());
}

/// Without the contract Reverie does not record the thread's signal state:
/// the hit unblocks SIGTRAP, as Linux's forced SIGTRAP does, and the hit
/// says that SIGTRAP's state is not known.
#[test]
fn without_the_contract_a_hit_says_sigtraps_state_is_not_known() {
    let _turn = turn();
    let (stdout, seen) = run_state("mask", Config::default());
    assert_eq!(stdout, "after=unblocked");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Unknown);
    assert!(hits[0].sigtrap.may_have_changed_guest());
}

/// `IntoGuest` forwards `set_watchpoints` and `watch_hits_keep_timer_events`
/// to the backend's guest: through a wrapping tool, the watch arms and
/// reports its hit, and the thread says what it says directly. Without the
/// forwarding, the provided methods would refuse (`Unsupported`) and say
/// `false`.
#[test]
fn a_wrapping_tool_arms_and_asks_through_into_guest() {
    let _turn = turn();
    let (stdout, direct) = run_state("mask", Config::default());
    let (wrapped_stdout, wrapped) = run_state_under::<WrappingTool>("mask", Config::default());
    assert_eq!(wrapped_stdout, stdout);
    let (direct_armings, wrapped_armings) = (direct.armings(), wrapped.armings());
    assert_eq!(wrapped_armings.len(), 1, "{wrapped_armings:?}");
    assert_eq!(wrapped_armings[0].1, Ok(()));
    assert!(
        direct_armings[0].2,
        "this host's timers keep their events across a hit"
    );
    assert_eq!(wrapped_armings[0].2, direct_armings[0].2);
    assert_eq!(wrapped.hits().len(), 1);
}

/// A SIGTRAP delivered to the guest runs its handler, which `SA_RESETHAND`
/// resets and whose mask the kernel installs, neither of which Reverie
/// reads. A hit inside that handler therefore says the state is not known,
/// rather than taking what was remembered before the delivery, which would
/// say that nothing changed. (What the guest itself then reads of SIGTRAP's
/// state is Reverie's existing repair of its own steps, not this change's:
/// the guest's own `int3` is delivered, and its handler runs.)
#[test]
fn a_hit_after_a_sigtrap_delivery_says_the_state_is_not_known() {
    let _turn = turn();
    let (stdout, seen) = run_state("resethand", contract());
    assert!(stdout.starts_with("ran=1 "), "{stdout}");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Unknown);
}

/// On a signal-action table that a thread Reverie does not trace may use
/// (here a `CLONE_UNTRACED` thread that shares it), an action read at a hit
/// is no evidence of what the hit reset, so the hit says the state is not
/// known. The thread's own mask bit is still put back.
#[test]
fn a_hit_on_a_table_an_untraced_thread_shares_says_the_state_is_not_known() {
    let _turn = turn();
    if !hits_are_claimed() {
        return;
    }
    let (stdout, seen) = run_state("untraced", contract());
    assert_eq!(stdout, "after=blocked");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Unknown);
}

/// A Tool that subscribes to `rt_sigaction` alone has Reverie remember
/// SIGTRAP's disposition, but keeps none of the records a hit's repair
/// needs: it declares no serialized execution, so another thread could
/// change the mask or the action between the hit and the read. The hit
/// says Unknown and nothing is put back, as without the subscription.
///
/// The `action` guest is the one the remembered disposition would mislead
/// the repair about: SIGTRAP is caught and blocked, so a repair that
/// trusted the disposition would read the action, find `SIG_DFL`, take
/// the hit for the reset's cause and block SIGTRAP again, leaving the
/// guest blocked where Linux left it unblocked, and reporting
/// ActionReset.
#[test]
fn a_hit_under_a_partial_subscription_says_the_state_is_not_known() {
    let _turn = turn();
    let config = || Config {
        sigaction: true,
        ..Config::default()
    };
    let (stdout, seen) = run_state("mask", config());
    assert_eq!(stdout, "after=unblocked");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Unknown);

    let (stdout, seen) = run_state("action", config());
    assert_eq!(stdout, "after=unblocked action=default");
    let hits = seen.hits();
    assert_eq!(hits.len(), 1, "{hits:#?}");
    assert_eq!(hits[0].sigtrap, SigtrapAtHit::Unknown);
}
