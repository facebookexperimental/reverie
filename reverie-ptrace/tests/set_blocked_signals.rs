/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! `Guest::set_blocked_signals` changes a stopped thread's mask without
//! running guest code, so no pending signal is dequeued: every one is still
//! queued afterwards and the kernel delivers them in its own order. It refuses,
//! changing nothing, while a mask-swapping syscall's restore is pending, and it
//! never adds or clears SIGTRAP or the timer signal
//! (<https://github.com/rrnewton/hermit/issues/4273>).

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::MaskChangeRefused;
use reverie::Pid;
use reverie::Signal;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Getpid;
use reverie::syscalls::Ppoll;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::Syscall;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::test_fn;

/// A zero-length write to `OP_FD + op`, whose buffer is an `OpArgs`, is
/// replaced by the tool's operation `op`.
const OP_FD: i32 = 904;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    /// Unblock `unblock` with an injected `rt_sigprocmask`, so its pending
    /// signals are admitted and still queued; block every signal with
    /// `set_blocked_signals`; inject `getpid`; put the old mask back.
    BlockInjectRestore = 0,
    /// Only the unblocking injection of `BlockInjectRestore`: the control,
    /// whose delivery order is the kernel's.
    UnblockOnly = 1,
    /// Inject a 50 ms `ppoll` under the temporary mask `mask`, which admits a
    /// signal the thread blocks, so the call ends with ERESTARTNOHAND and its
    /// restore pending; then ask `set_blocked_signals` for the full mask.
    MaskedWaitThenSet = 2,
    /// Block every signal with `set_blocked_signals`, then put the old mask
    /// back, with no injection in between; then pass the write on, to a
    /// descriptor that is not open (EBADF). Passing it on, rather than
    /// returning a value, keeps this row off the emulation path, which loses
    /// a guest-blocked pending SIGTRAP on its own (a separate defect).
    BlockRestore = 3,
}

impl Op {
    fn from_fd(fd: i32) -> Option<Self> {
        Some(match fd - OP_FD {
            0 => Op::BlockInjectRestore,
            1 => Op::UnblockOnly,
            2 => Op::MaskedWaitThenSet,
            3 => Op::BlockRestore,
            _ => return None,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OpArgs {
    /// The kernel signal mask the thread unblocks first.
    unblock: u64,
    /// The temporary mask of `MaskedWaitThenSet`'s `ppoll`.
    mask: u64,
    timeout: libc::timespec,
}

/// What the tool saw, in order.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
enum Seen {
    /// An injection's result.
    Injected(Result<i64, i32>),
    /// A `set_blocked_signals` answer.
    Set(Result<u64, MaskChangeRefused>),
    /// The thread's procfs `SigBlk` and `SigPnd` at that point.
    Proc { blocked: u64, pending: u64 },
    /// Not recorded: asks whether this is the first interception of
    /// `MaskedWaitThenSet`, so a restarted write is answered differently.
    Claim,
}

#[derive(Default)]
struct Log {
    seen: Mutex<Vec<Seen>>,
    claimed: AtomicBool,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Seen;
    type Response = bool;
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, seen: Seen) -> bool {
        if seen == Seen::Claim {
            return !self.claimed.swap(true, Ordering::SeqCst);
        }
        self.seen.lock().unwrap().push(seen);
        false
    }
}

/// The signals `set_blocked_signals` never adds or clears: SIGTRAP and the
/// timer signal, and SIGKILL and SIGSTOP, which cannot be blocked.
fn never_shielded() -> u64 {
    [
        libc::SIGTRAP,
        reverie::PERF_EVENT_SIGNAL as i32,
        libc::SIGKILL,
        libc::SIGSTOP,
    ]
    .iter()
    .fold(0, |set, &signal| set | bit(signal))
}

/// The whole mask a full request writes over `old`.
fn full_over(old: u64) -> u64 {
    !never_shielded() | (old & never_shielded())
}

/// The procfs `SigBlk` and `SigPnd` of the stopped thread `tid`.
fn proc_masks(tid: Pid) -> Seen {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).unwrap();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(|value| u64::from_str_radix(value.trim(), 16).unwrap())
            .unwrap()
    };
    Seen::Proc {
        blocked: field("SigBlk:"),
        pending: field("SigPnd:"),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MaskTool;

#[reverie::tool]
impl Tool for MaskTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
    }

    async fn handle_signal_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        signal: Signal,
    ) -> Result<Option<Signal>, Errno> {
        // Refused in a signal callback, changing nothing.
        if signal == Signal::SIGURG {
            let tid = guest.tid();
            guest.send_rpc(proc_masks(tid)).await;
            let answer = guest.set_blocked_signals(!0).await;
            guest.send_rpc(Seen::Set(answer)).await;
            guest.send_rpc(proc_masks(tid)).await;
        }
        Ok(Some(signal))
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        let Syscall::Write(write) = syscall else {
            guest.tail_inject(syscall).await
        };
        let base = write.buf().map(|buf| buf.as_raw());
        let (Some(op), 0, Some(base)) = (Op::from_fd(write.fd()), write.len(), base) else {
            guest.tail_inject(syscall).await
        };
        let field = move |offset: usize| base + offset;
        let tid = guest.tid();
        match op {
            Op::BlockInjectRestore | Op::UnblockOnly => {
                let unblocked = guest
                    .inject(
                        RtSigprocmask::new()
                            .with_how(libc::SIG_UNBLOCK)
                            .with_set(Addr::from_raw(field(std::mem::offset_of!(OpArgs, unblock))))
                            .with_oldset(None)
                            .with_sigsetsize(8),
                    )
                    .await;
                guest
                    .send_rpc(Seen::Injected(unblocked.map_err(Errno::into_raw)))
                    .await;
                if op == Op::UnblockOnly {
                    return Ok(0);
                }
                let old = guest.set_blocked_signals(!0).await;
                guest.send_rpc(Seen::Set(old)).await;
                guest.send_rpc(proc_masks(tid)).await;
                let pid = guest.inject(Getpid::new()).await;
                guest
                    .send_rpc(Seen::Injected(
                        pid.map(|pid| (pid > 0) as i64).map_err(Errno::into_raw),
                    ))
                    .await;
                if let Ok(old) = old {
                    let restored = guest.set_blocked_signals(old).await;
                    guest.send_rpc(Seen::Set(restored)).await;
                }
                guest.send_rpc(proc_masks(tid)).await;
                Ok(0)
            }
            Op::MaskedWaitThenSet => {
                // Acts on the first interception only. A restart of the write,
                // which a discarded restore would cause, gets 77, which the
                // guest's assertion rejects at once.
                if !guest.send_rpc(Seen::Claim).await {
                    return Ok(77);
                }
                let result = guest
                    .inject(
                        Ppoll::new()
                            .with_fds(None)
                            .with_nfds(0)
                            .with_timeout(AddrMut::from_raw(field(std::mem::offset_of!(
                                OpArgs, timeout
                            ))))
                            .with_sigmask(Addr::from_raw(field(std::mem::offset_of!(OpArgs, mask))))
                            .with_sigsetsize(8),
                    )
                    .await;
                guest
                    .send_rpc(Seen::Injected(result.map_err(Errno::into_raw)))
                    .await;
                guest.send_rpc(proc_masks(tid)).await;
                let answer = guest.set_blocked_signals(!0).await;
                guest.send_rpc(Seen::Set(answer)).await;
                guest.send_rpc(proc_masks(tid)).await;
                Ok(result?)
            }
            Op::BlockRestore => {
                guest.send_rpc(proc_masks(tid)).await;
                let old = guest.set_blocked_signals(!0).await;
                guest.send_rpc(Seen::Set(old)).await;
                if let Ok(old) = old {
                    let restored = guest.set_blocked_signals(old).await;
                    guest.send_rpc(Seen::Set(restored)).await;
                }
                guest.send_rpc(proc_masks(tid)).await;
                guest.tail_inject(syscall).await
            }
        }
    }
}

static DELIVERIES: AtomicUsize = AtomicUsize::new(0);

/// Signal numbers in the order the handlers started.
static RECORDS: [AtomicI64; 4] = [const { AtomicI64::new(0) }; 4];

extern "C" fn record_signal(signal: libc::c_int) {
    let slot = DELIVERIES.fetch_add(1, Ordering::SeqCst);
    if let Some(slot) = RECORDS.get(slot) {
        slot.store(signal as i64, Ordering::SeqCst);
    }
}

fn records() -> Vec<i64> {
    let count = DELIVERIES.load(Ordering::SeqCst).min(RECORDS.len());
    RECORDS[..count]
        .iter()
        .map(|value| value.load(Ordering::SeqCst))
        .collect()
}

fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}

/// Installs a recording handler for `signal` and blocks it.
fn catch_and_block(signal: i32) {
    // SAFETY: the action and set are fully initialized before use; the
    // handler touches only atomics.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_signal as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
        block(signal);
    }
}

fn block(signal: i32) {
    // SAFETY: the set is fully initialized before use.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
            0
        );
    }
}

/// Sends `signal` to the calling thread.
fn send_self(signal: i32) {
    // SAFETY: tgkill takes plain values.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_tgkill,
            libc::getpid(),
            libc::syscall(libc::SYS_gettid),
            signal,
        )
    };
    assert_eq!(ret, 0);
}

/// The calling thread's mask.
fn current_mask() -> u64 {
    // SAFETY: a NULL set only reads the mask into `old`.
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut old),
            0
        );
        *(&old as *const libc::sigset_t as *const u64)
    }
}

/// The calling thread's pending signals.
fn pending() -> u64 {
    // SAFETY: sigpending fills the set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        assert_eq!(libc::sigpending(&mut set), 0);
        *(&set as *const libc::sigset_t as *const u64)
    }
}

/// Replaced by the tool: runs `op` with `unblock` and `mask`. Returns the
/// guest-visible result.
fn run_op(op: Op, unblock: u64, mask: u64) -> (isize, Option<i32>) {
    let mut args = OpArgs {
        unblock,
        mask,
        timeout: libc::timespec {
            tv_sec: 0,
            tv_nsec: 50_000_000,
        },
    };
    // SAFETY: the tool replaces this zero-length write.
    let ret = unsafe {
        libc::write(
            OP_FD + op as i32,
            &mut args as *mut OpArgs as *const libc::c_void,
            0,
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error();
    (ret, if ret < 0 { errno } else { None })
}

/// Pins the tracer's log level to warnings. `test_fn` installs a TRACE-level
/// collector unless one is set first, and a looping guest then writes
/// gigabytes.
fn quiet_logs() {
    let collector = tracing_subscriber::fmt().with_env_filter("warn").finish();
    let _ = tracing::subscriber::set_global_default(collector);
}

fn run_guest(name: &str, guest: fn()) -> Vec<Seen> {
    run_guest_under::<MaskTool>(name, guest)
}

fn run_guest_under<T: Tool<GlobalState = Log> + 'static>(name: &str, guest: fn()) -> Vec<Seen> {
    quiet_logs();
    let (output, log) = test_fn::<T, _>(guest).expect(name);
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "{name}: stderr: {}; stdout: {}; tool saw: {:?}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout),
        log.seen.lock().unwrap()
    );
    log.seen.lock().unwrap().clone()
}

/// The three signals of the queue rows: two standard ones and a realtime one.
const QUEUED: [i32; 3] = [libc::SIGUSR1, libc::SIGUSR2, 40];

fn queue_three() -> u64 {
    DELIVERIES.store(0, Ordering::SeqCst);
    let mut set = 0;
    for signal in QUEUED {
        catch_and_block(signal);
        send_self(signal);
        set |= bit(signal);
    }
    set
}

/// Control: the three signals, unblocked by an injection, are delivered by
/// the kernel in its order when the guest resumes.
fn kernel_order() -> Vec<i64> {
    let set = queue_three();
    assert_eq!(run_op(Op::UnblockOnly, set, 0), (0, None));
    records()
}

/// Two pending standard signals and a realtime one, admitted by the thread's
/// mask, survive `set_blocked_signals(full)`, an injection under that mask,
/// and the restore, and are then delivered in the kernel's order, the
/// control's. Without the block, the injection's step would have taken one of
/// them before its `syscall` instruction.
#[test]
fn pending_signals_survive_a_block_an_injection_and_the_restore() {
    let seen = run_guest("block, inject, restore", || {
        let set = queue_three();
        let before = current_mask();
        assert_eq!(run_op(Op::BlockInjectRestore, set, 0), (0, None));
        // The kernel's order: highest-numbered handler first, as the kernel
        // dequeues the lowest first and stacks a frame for each.
        assert_eq!(
            records(),
            vec![40, libc::SIGUSR2 as i64, libc::SIGUSR1 as i64]
        );
        // The tool's first injection unblocked the three; nothing else changed.
        assert_eq!(current_mask(), before & !set);
    });
    let Seen::Set(Ok(old)) = seen[1].clone() else {
        panic!("set_blocked_signals refused: {seen:?}");
    };
    let all = QUEUED.iter().fold(0, |set, &signal| set | bit(signal));
    assert_eq!(old & all, 0, "the three were admitted before the block");
    let Seen::Proc { blocked, pending } = seen[2] else {
        panic!("{seen:?}");
    };
    assert_eq!(blocked & all, all, "the block took effect");
    assert_eq!(
        pending & all,
        all,
        "all three still pending under the block"
    );
    assert_eq!(seen[3], Seen::Injected(Ok(1)), "the injection ran");
    assert!(matches!(seen[4], Seen::Set(Ok(_))), "{seen:?}");
    let Seen::Proc { blocked, pending } = seen[5] else {
        panic!("{seen:?}");
    };
    assert_eq!(blocked, old, "the restore is exact");
    assert_eq!(
        pending & all,
        all,
        "all three still pending after the restore"
    );
}

/// The control matches the kernel order the row above asserts.
#[test]
fn the_kernel_delivers_the_three_highest_numbered_first() {
    run_guest("kernel order", || {
        assert_eq!(
            kernel_order(),
            vec![40, libc::SIGUSR2 as i64, libc::SIGUSR1 as i64]
        );
    });
}

/// Codex's state: the thread blocks SIGUSR1, which is pending; an injected
/// `ppoll` whose temporary mask admits it ends with ERESTARTNOHAND and leaves
/// the temporary mask installed with its restore pending. `set_blocked_signals`
/// refuses with `RestorePending` and changes nothing: procfs `SigBlk` is still
/// the temporary mask, and SIGUSR1 is delivered under it as the guest resumes,
/// so the guest's call returns EINTR after the handler, and the thread's own
/// mask, blocking SIGUSR1, comes back.
#[test]
fn a_pending_mask_restore_is_refused_without_a_change() {
    let seen = run_guest("pending restore", || {
        DELIVERIES.store(0, Ordering::SeqCst);
        catch_and_block(libc::SIGUSR1);
        send_self(libc::SIGUSR1);
        let before = current_mask();
        assert_eq!(run_op(Op::MaskedWaitThenSet, 0, 0), (-1, Some(libc::EINTR)));
        assert_eq!(records(), vec![libc::SIGUSR1 as i64]);
        assert_eq!(current_mask(), before);
    });
    assert_eq!(
        seen[0],
        Seen::Injected(Err(Errno::ERESTARTNOHAND.into_raw())),
        "{seen:?}"
    );
    let Seen::Proc { blocked, .. } = seen[1] else {
        panic!("{seen:?}");
    };
    assert_eq!(
        blocked & bit(libc::SIGUSR1),
        0,
        "the temporary mask is in effect"
    );
    let Seen::Set(Err(MaskChangeRefused::RestorePending { saved, effective })) = seen[2].clone()
    else {
        panic!("not refused as RestorePending: {seen:?}");
    };
    assert_eq!(effective, blocked);
    assert_ne!(
        saved & bit(libc::SIGUSR1),
        0,
        "the saved mask blocks SIGUSR1"
    );
    assert_eq!(seen[3], seen[1], "nothing changed");
}

/// SIGTRAP and the timer signal, blocked by the guest itself and both
/// pending, keep their bits through `set_blocked_signals(full)` and its
/// restore, which is exact; both are still pending afterwards.
#[test]
fn guest_blocked_sigtrap_and_timer_bits_are_kept_and_restored_exactly() {
    let seen = run_guest("never-shielded bits", || {
        let timer = reverie::PERF_EVENT_SIGNAL as i32;
        block(libc::SIGTRAP);
        block(timer);
        send_self(libc::SIGTRAP);
        send_self(timer);
        let before = current_mask();
        let result = run_op(Op::BlockRestore, 0, 0);
        let after = current_mask();
        let pend = pending();
        // Take both pending signals, so that nothing delivers them later.
        let take = |signal: i32| {
            // SAFETY: the set and timeout are fully initialized.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, signal);
                let zero = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                libc::sigtimedwait(&set, std::ptr::null_mut(), &zero)
            }
        };
        let taken = (take(libc::SIGTRAP), take(timer));
        assert_eq!(result, (-1, Some(libc::EBADF)));
        assert_eq!(after, before);
        assert_ne!(pend & bit(libc::SIGTRAP), 0, "SIGTRAP is still pending");
        assert_ne!(pend & bit(timer), 0, "the timer signal is still pending");
        assert_eq!(taken, (libc::SIGTRAP, timer));
    });
    let kept = bit(libc::SIGTRAP) | bit(reverie::PERF_EVENT_SIGNAL as i32);
    let Seen::Proc {
        blocked: first,
        pending: first_pending,
    } = seen[0]
    else {
        panic!("{seen:?}");
    };
    assert_eq!(first & kept, kept);
    assert_eq!(first_pending & kept, kept, "both pending before");
    assert_eq!(seen[1], Seen::Set(Ok(first)), "the old mask is returned");
    let Seen::Set(Ok(written)) = seen[2].clone() else {
        panic!("{seen:?}");
    };
    assert_eq!(written & kept, kept, "the block kept the guest's own bits");
    assert_eq!(written, full_over(first), "the whole written mask");
    assert_eq!(
        seen[3], seen[0],
        "the restore is exact and SIGTRAP still pending"
    );
}

/// Over a mask that blocks neither, the full request adds neither SIGTRAP nor
/// the timer signal.
#[test]
fn a_full_request_adds_neither_sigtrap_nor_the_timer_signal() {
    let seen = run_guest("nothing added", || {
        assert_eq!(run_op(Op::BlockRestore, 0, 0), (-1, Some(libc::EBADF)));
    });
    let Seen::Proc { blocked: first, .. } = seen[0] else {
        panic!("{seen:?}");
    };
    let Seen::Set(Ok(written)) = seen[2].clone() else {
        panic!("{seen:?}");
    };
    let never = bit(libc::SIGTRAP) | bit(reverie::PERF_EVENT_SIGNAL as i32);
    assert_eq!(first & never, 0, "the guest blocks neither");
    assert_eq!(written & never, 0, "{seen:?}");
    assert_eq!(written, full_over(first), "the whole written mask");
}

/// In a signal callback the call is refused and changes nothing.
#[test]
fn a_signal_callback_is_refused() {
    let seen = run_guest("signal callback", || {
        // SAFETY: SIGURG's default action is to ignore it; raising it only
        // makes the tool's signal callback run.
        unsafe {
            libc::raise(libc::SIGURG);
        }
    });
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[1], Seen::Set(Err(MaskChangeRefused::Unsupported)));
    assert_eq!(seen[2], seen[0], "nothing changed");
}

/// A tool whose only callback is `handle_thread_start`, where it asks for the
/// full mask.
#[derive(Clone, Copy, Debug, Default)]
struct ThreadStartTool;

#[reverie::tool]
impl Tool for ThreadStartTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        Subscription::none()
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        let tid = guest.tid();
        guest.send_rpc(proc_masks(tid)).await;
        let answer = guest.set_blocked_signals(!0).await;
        guest.send_rpc(Seen::Set(answer)).await;
        guest.send_rpc(proc_masks(tid)).await;
        Ok(())
    }
}

/// Outside a syscall callback, here at a thread's start, the call is refused
/// and changes nothing. This binds the only-in-a-syscall-callback rule
/// through the backend's own wiring.
#[test]
fn a_thread_start_callback_is_refused() {
    let seen = run_guest_under::<ThreadStartTool>("thread start", || {
        std::thread::spawn(|| {}).join().unwrap();
    });
    assert!(!seen.is_empty(), "no thread start was seen");
    assert_eq!(seen.len() % 3, 0, "{seen:?}");
    for start in seen.chunks(3) {
        assert_eq!(start[1], Seen::Set(Err(MaskChangeRefused::Unsupported)));
        assert_eq!(start[2], start[0], "nothing changed");
    }
}

/// What both exec tools do in `handle_post_exec`: ask for the full mask,
/// with the replacement image's SigBlk before and after.
async fn post_exec_request<T: Tool<GlobalState = Log>, G: Guest<T>>(guest: &mut G) {
    let tid = guest.tid();
    guest.send_rpc(proc_masks(tid)).await;
    let answer = guest.set_blocked_signals(!0).await;
    guest.send_rpc(Seen::Set(answer)).await;
    guest.send_rpc(proc_masks(tid)).await;
}

/// Injects the guest's `execve` from its syscall callback. A successful exec
/// never returns there, and the replacement image gets `handle_post_exec`.
#[derive(Clone, Copy, Debug, Default)]
struct InjectedExecTool;

#[reverie::tool]
impl Tool for InjectedExecTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::execve);
        subscription
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        post_exec_request::<Self, G>(guest).await;
        Ok(())
    }
}

/// The control: the `execve` is passed on with the default tail injection.
#[derive(Clone, Copy, Debug, Default)]
struct TailExecTool;

#[reverie::tool]
impl Tool for TailExecTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::execve);
        subscription
    }

    async fn handle_post_exec<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Errno> {
        post_exec_request::<Self, G>(guest).await;
        Ok(())
    }
}

fn exec_true() {
    // SAFETY: execl with NUL-terminated strings and a NULL terminator.
    unsafe {
        libc::execl(
            c"/bin/true".as_ptr(),
            c"true".as_ptr(),
            std::ptr::null::<libc::c_char>(),
        );
    }
    panic!("exec failed: {}", std::io::Error::last_os_error());
}

fn assert_post_exec_refused(seen: &[Seen]) {
    assert_eq!(seen.len(), 3, "one post-exec request: {seen:?}");
    assert_eq!(seen[1], Seen::Set(Err(MaskChangeRefused::Unsupported)));
    assert_eq!(seen[2], seen[0], "nothing changed");
}

/// A syscall callback that injected a successful exec never resumes, so the
/// replacement image's post-exec callback is outside it, and the call is
/// refused there with nothing changed (Codex review of
/// https://github.com/rrnewton/reverie/pull/1083, P2).
#[test]
fn an_injected_exec_refuses_in_post_exec() {
    assert_post_exec_refused(&run_guest_under::<InjectedExecTool>(
        "injected exec",
        exec_true,
    ));
}

/// The control: after a tail-injected exec, the post-exec callback is refused.
#[test]
fn a_tail_injected_exec_refuses_in_post_exec() {
    assert_post_exec_refused(&run_guest_under::<TailExecTool>("tail exec", exec_true));
}
