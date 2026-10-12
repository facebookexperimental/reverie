/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! An injected mask-swapping syscall waits under its own temporary mask, as
//! the guest's own call would. A pending signal that the thread's mask admits
//! and the call's mask blocks stays pending through the call
//! (<https://github.com/rrnewton/hermit/issues/4149>).

use std::sync::Mutex;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Errno;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::EpollPwait;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::Ppoll;
use reverie::syscalls::Pselect6;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::Sysno;
use reverie_ptrace::testing::test_fn;

/// A zero-length write to this descriptor, whose buffer is a `WaitArgs`, is
/// replaced with an injected `rt_sigprocmask(SIG_UNBLOCK, &unblock, NULL)` and
/// then an injected 50 ms wait (`Wait`, the descriptor's offset from this
/// one) under the temporary mask `mask`. The tool returns the wait's result.
const UNBLOCK_THEN_WAIT_FD: i32 = 902;

/// The injected wait, by its offset from `UNBLOCK_THEN_WAIT_FD`.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Wait {
    /// `ppoll(NULL, 0, &timeout, &mask, 8)`.
    Ppoll = 0,
    /// `ppoll(NULL, 0, &timeout, NULL, 8)`: no temporary mask.
    UnmaskedPpoll = 1,
    /// `pselect6(0, NULL, NULL, NULL, &timeout, &wrapper)`, where `wrapper`
    /// is `{ &mask, 8 }`.
    Pselect6 = 2,
    /// `epoll_pwait(epfd, NULL, 1, 50, &mask, 8)` on an empty epoll set.
    EpollPwait = 3,
    /// `epoll_pwait2(epfd, NULL, 1, &timeout, &mask, 8)` on an empty epoll set.
    EpollPwait2 = 4,
    /// `rt_sigsuspend(&mask, 8)`.
    RtSigsuspend = 5,
}

impl Wait {
    fn from_fd(fd: i32) -> Option<Self> {
        Some(match fd - UNBLOCK_THEN_WAIT_FD {
            0 => Wait::Ppoll,
            1 => Wait::UnmaskedPpoll,
            2 => Wait::Pselect6,
            3 => Wait::EpollPwait,
            4 => Wait::EpollPwait2,
            5 => Wait::RtSigsuspend,
            _ => return None,
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WaitArgs {
    /// The kernel signal mask the thread unblocks first.
    unblock: u64,
    /// The wait's temporary mask.
    mask: u64,
    /// pselect6's `{ const sigset_t *ss; size_t ss_len; }` wrapper.
    wrapper: [u64; 2],
    epfd: i64,
    timeout: libc::timespec,
    /// Where the wait's mask is, when not at `mask` (0: at `mask`).
    mask_at: u64,
    /// Where pselect6's wrapper is, when not at `wrapper` (0: at `wrapper`).
    wrapper_at: u64,
}

#[derive(Default)]
struct Log {
    injected: Mutex<Vec<Result<i64, i32>>>,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Request = Result<i64, i32>;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Pid, result: Result<i64, i32>) {
        self.injected.lock().unwrap().push(result);
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct MaskSwapTool;

#[reverie::tool]
impl Tool for MaskSwapTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        let mut subscription = Subscription::none();
        subscription.syscall(Sysno::write);
        subscription
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
        let (Some(wait), 0, Some(base)) = (Wait::from_fd(write.fd()), write.len(), base) else {
            guest.tail_inject(syscall).await
        };
        let field = move |offset: usize| base + offset;
        let args: WaitArgs = guest
            .memory()
            .read_value(Addr::<WaitArgs>::from_raw(base).ok_or(Errno::EFAULT)?)?;
        let unblocked = guest
            .inject(
                RtSigprocmask::new()
                    .with_how(libc::SIG_UNBLOCK)
                    .with_set(Addr::from_raw(field(std::mem::offset_of!(
                        WaitArgs, unblock
                    ))))
                    .with_oldset(None)
                    .with_sigsetsize(8),
            )
            .await;
        guest.send_rpc(unblocked.map_err(Errno::into_raw)).await;
        let mask = Addr::from_raw(if args.mask_at != 0 {
            args.mask_at as usize
        } else {
            field(std::mem::offset_of!(WaitArgs, mask))
        });
        let wrapper = Addr::from_raw(if args.wrapper_at != 0 {
            args.wrapper_at as usize
        } else {
            field(std::mem::offset_of!(WaitArgs, wrapper))
        });
        let timeout = AddrMut::from_raw(field(std::mem::offset_of!(WaitArgs, timeout)));
        let result = match wait {
            Wait::Ppoll | Wait::UnmaskedPpoll => {
                guest
                    .inject(
                        Ppoll::new()
                            .with_fds(None)
                            .with_nfds(0)
                            .with_timeout(timeout)
                            .with_sigmask(if wait == Wait::Ppoll { mask } else { None })
                            .with_sigsetsize(8),
                    )
                    .await
            }
            Wait::Pselect6 => {
                guest
                    .inject(
                        Pselect6::new()
                            .with_nfds(0)
                            .with_readfds(None)
                            .with_writefds(None)
                            .with_exceptfds(None)
                            .with_timeout(timeout)
                            .with_sigmask(wrapper),
                    )
                    .await
            }
            Wait::EpollPwait => {
                guest
                    .inject(
                        EpollPwait::new()
                            .with_epfd(args.epfd as i32)
                            .with_events(None)
                            .with_maxevents(1)
                            .with_timeout(50)
                            .with_sigmask(mask)
                            .with_sigsetsize(8),
                    )
                    .await
            }
            Wait::EpollPwait2 => {
                let args = SyscallArgs::new(
                    args.epfd as usize,
                    0,
                    1,
                    field(std::mem::offset_of!(WaitArgs, timeout)),
                    field(std::mem::offset_of!(WaitArgs, mask)),
                    8,
                );
                guest
                    .inject(Syscall::Other(Sysno::epoll_pwait2, args))
                    .await
            }
            Wait::RtSigsuspend => {
                let args =
                    SyscallArgs::new(field(std::mem::offset_of!(WaitArgs, mask)), 8, 0, 0, 0, 0);
                guest
                    .inject(Syscall::Other(Sysno::rt_sigsuspend, args))
                    .await
            }
        };
        guest.send_rpc(result.map_err(Errno::into_raw)).await;
        Ok(result?)
    }
}

static DELIVERIES: AtomicUsize = AtomicUsize::new(0);

/// Signal numbers, or `sigqueue` values, in the order the handlers saw them.
static RECORDS: [AtomicI64; 4] = [const { AtomicI64::new(0) }; 4];

fn record(value: i64) {
    let slot = DELIVERIES.fetch_add(1, Ordering::SeqCst);
    if let Some(slot) = RECORDS.get(slot) {
        slot.store(value, Ordering::SeqCst);
    }
}

extern "C" fn record_signal(signal: libc::c_int) {
    record(signal as i64);
}

extern "C" fn record_value(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    // SAFETY: an SA_SIGINFO handler gets the kernel's siginfo.
    record(unsafe { (*info).si_value().sival_ptr } as i64);
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

/// Installs a handler for `signal` (an `SA_SIGINFO` one that records
/// `sigqueue` values with `siginfo`, else one that records the number) and
/// blocks it; without `siginfo`, also sends it to the calling thread.
fn catch_and_block(signal: i32, siginfo: bool) {
    // SAFETY: the action and set are fully initialized before use; the
    // handlers touch only atomics; tgkill takes plain values.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        if siginfo {
            action.sa_sigaction = record_value as *const () as usize;
            action.sa_flags = libc::SA_SIGINFO;
        } else {
            action.sa_sigaction = record_signal as *const () as usize;
        }
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(libc::sigaction(signal, &action, std::ptr::null_mut()), 0);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
            0
        );
        if !siginfo {
            let ret = libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                signal,
            );
            assert_eq!(ret, 0);
        }
    }
}

/// Catches SIGALRM and arms a one-shot ITIMER_REAL for `ms` milliseconds.
fn alarm_in(ms: i64) {
    // SAFETY: the action and timer value are fully initialized; the handler
    // touches only atomics.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = record_signal as *const () as usize;
        libc::sigemptyset(&mut action.sa_mask);
        assert_eq!(
            libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()),
            0
        );
        let timer = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: 0,
                tv_usec: ms * 1000,
            },
        };
        assert_eq!(
            libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()),
            0
        );
    }
}

/// The calling thread's signal mask.
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

/// Replaced by the tool: unblocks `unblock`, then waits 50 ms in `wait` under
/// the temporary mask `mask`. Returns the guest-visible result.
fn unblock_then_wait(wait: Wait, unblock: u64, mask: u64) -> (isize, Option<i32>) {
    unblock_then_wait_for(wait, unblock, mask, 50)
}

/// `unblock_then_wait` with a `timeout_ms` millisecond wait.
fn unblock_then_wait_for(
    wait: Wait,
    unblock: u64,
    mask: u64,
    timeout_ms: i64,
) -> (isize, Option<i32>) {
    unblock_then_wait_placed(wait, unblock, mask, timeout_ms, None)
}

/// `unblock_then_wait_for`, with the mask, and pselect6's wrapper after it,
/// on a page of their own protected with `protection` when it is given.
fn unblock_then_wait_placed(
    wait: Wait,
    unblock: u64,
    mask: u64,
    timeout_ms: i64,
    protection: Option<libc::c_int>,
) -> (isize, Option<i32>) {
    let page = protection.map(|protection| {
        // SAFETY: a fresh private anonymous page, written before it is
        // protected and unmapped below.
        unsafe {
            let page = libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(page, libc::MAP_FAILED);
            let words = page as *mut u64;
            *words = mask;
            *words.add(2) = page as u64;
            *words.add(3) = 8;
            assert_eq!(libc::mprotect(page, 4096, protection), 0);
            page as u64
        }
    });
    // SAFETY: plain syscall; the descriptor is closed below.
    let epfd = unsafe { libc::epoll_create1(0) };
    assert!(epfd >= 0);
    // The kernel writes the remaining time back to `timeout`.
    let mut args = WaitArgs {
        unblock,
        mask,
        wrapper: [0, 8],
        epfd: epfd as i64,
        timeout: libc::timespec {
            tv_sec: 0,
            tv_nsec: timeout_ms * 1_000_000,
        },
        mask_at: page.unwrap_or(0),
        wrapper_at: page.map_or(0, |page| page + 16),
    };
    args.wrapper[0] = &args.mask as *const u64 as u64;
    // SAFETY: the tool replaces this zero-length write.
    let ret = unsafe {
        libc::write(
            UNBLOCK_THEN_WAIT_FD + wait as i32,
            &mut args as *mut WaitArgs as *const libc::c_void,
            0,
        )
    };
    let errno = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: closes the descriptor and unmaps the page opened above.
    unsafe {
        libc::close(epfd);
        if let Some(page) = page {
            libc::munmap(page as *mut libc::c_void, 4096);
        }
    }
    (ret, if ret < 0 { errno } else { None })
}

/// Runs `guest` under the tool and returns the injections' results.
fn run_guest(name: &str, guest: fn()) -> Vec<Result<i64, i32>> {
    let (output, log) = test_fn::<MaskSwapTool, _>(guest).expect(name);
    assert_eq!(
        output.status,
        ExitStatus::Exited(0),
        "{name}: stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    log.injected.lock().unwrap().clone()
}

/// The thread blocks SIGUSR1 and sends it to itself. The tool unblocks it
/// with an injected `rt_sigprocmask`, so it is pending and admitted, and then
/// injects a 50 ms wait whose temporary mask blocks it. Linux keeps the
/// signal pending through the guest's own such call, which times out, and
/// runs the handler when the call returns. Before, the injection left the
/// private page under the thread's own mask, the signal stopped it before
/// its `syscall`, the injection reported ERESTARTSYS, and the guest's call
/// returned EINTR without waiting.
fn a_blocked_signal_stays_pending(wait: Wait) {
    DELIVERIES.store(0, Ordering::SeqCst);
    catch_and_block(libc::SIGUSR1, false);
    let usr1 = bit(libc::SIGUSR1);
    assert_eq!(
        unblock_then_wait(wait, usr1, usr1),
        (0, None),
        "the injected {wait:?} must time out with the signal pending"
    );
    assert_eq!(records(), vec![libc::SIGUSR1 as i64]);
}

#[test]
fn a_signal_the_temporary_mask_blocks_stays_pending_through_an_injected_ppoll() {
    let injected = run_guest("ppoll", || a_blocked_signal_stays_pending(Wait::Ppoll));
    assert_eq!(injected, vec![Ok(0), Ok(0)]);
}

#[test]
fn a_signal_the_temporary_mask_blocks_stays_pending_through_an_injected_pselect6() {
    let injected = run_guest("pselect6", || {
        a_blocked_signal_stays_pending(Wait::Pselect6)
    });
    assert_eq!(injected, vec![Ok(0), Ok(0)]);
}

#[test]
fn a_signal_the_temporary_mask_blocks_stays_pending_through_an_injected_epoll_pwait() {
    let injected = run_guest("epoll_pwait", || {
        a_blocked_signal_stays_pending(Wait::EpollPwait)
    });
    assert_eq!(injected, vec![Ok(0), Ok(0)]);
}

/// Two queued instances of a real-time signal, pending and admitted, stay
/// queued in order through an injected `ppoll` whose mask blocks them, and
/// reach the handler in `sigqueue` order after it. Requeuing an instance
/// after it stopped the step would re-send it behind the second
/// (https://github.com/rrnewton/reverie/pull/995 review); blocked, neither
/// leaves the queue.
#[test]
fn real_time_instances_keep_their_order_through_an_injected_ppoll() {
    let injected = run_guest("real-time ppoll", || {
        DELIVERIES.store(0, Ordering::SeqCst);
        let signal = libc::SIGRTMIN() + 2;
        catch_and_block(signal, true);
        for value in [2usize, 3] {
            let value = libc::sigval {
                sival_ptr: value as *mut libc::c_void,
            };
            // SAFETY: sigqueue takes plain values.
            assert_eq!(unsafe { libc::sigqueue(libc::getpid(), signal, value) }, 0);
        }
        assert_eq!(
            unblock_then_wait(Wait::Ppoll, bit(signal), bit(signal)),
            (0, None),
            "the injected ppoll must time out with both instances pending"
        );
        assert_eq!(records(), vec![2, 3]);
    });
    assert_eq!(injected, vec![Ok(0), Ok(0)]);
}

/// An injected `ppoll` that names no mask installs none, so a pending signal
/// the thread admits ends it, as it would end the guest's own call. Nothing is
/// shielded: the signal stops the step before its `syscall` as before, the
/// injection reports that the call did not run (ERESTARTSYS), and the signal
/// is delivered when the guest resumes. Shielding every ppoll by its number
/// let the call run and return ERESTARTNOHAND with the signal still queued,
/// which a tool that identifies the stop by the signal it took (Hermit's
/// absorbing waits) cannot name.
#[test]
fn an_unmasked_injected_ppoll_still_reports_a_pending_signal_as_not_run() {
    let injected = run_guest("unmasked ppoll", || {
        DELIVERIES.store(0, Ordering::SeqCst);
        catch_and_block(libc::SIGUSR1, false);
        let usr1 = bit(libc::SIGUSR1);
        assert_eq!(
            unblock_then_wait(Wait::UnmaskedPpoll, usr1, usr1),
            (-1, Some(libc::EINTR))
        );
        assert_eq!(records(), vec![libc::SIGUSR1 as i64]);
    });
    assert_eq!(injected, vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())]);
}

/// SIGUSR1 and SIGUSR2 are pending and admitted; the injected `ppoll`'s
/// temporary mask blocks SIGUSR1 only. SIGUSR1 is shielded and stays queued;
/// SIGUSR2, which both masks admit and which would interrupt the guest's own
/// call, stops the step before its `syscall` as before: the injection
/// reports that the call did not run, and the guest's call returns EINTR.
/// Both handlers run once when the guest resumes.
#[test]
fn a_signal_both_masks_admit_still_stops_a_partly_shielded_ppoll() {
    let injected = run_guest("partly shielded ppoll", || {
        DELIVERIES.store(0, Ordering::SeqCst);
        catch_and_block(libc::SIGUSR1, false);
        catch_and_block(libc::SIGUSR2, false);
        let both = bit(libc::SIGUSR1) | bit(libc::SIGUSR2);
        assert_eq!(
            unblock_then_wait(Wait::Ppoll, both, bit(libc::SIGUSR1)),
            (-1, Some(libc::EINTR))
        );
        let mut seen = records();
        seen.sort_unstable();
        assert_eq!(
            seen,
            vec![libc::SIGUSR1 as i64, libc::SIGUSR2 as i64],
            "both handlers run once"
        );
    });
    assert_eq!(injected, vec![Ok(0), Err(Errno::ERESTARTSYS.into_raw())]);
}

#[test]
fn a_signal_the_temporary_mask_blocks_stays_pending_through_an_injected_epoll_pwait2() {
    let injected = run_guest("epoll_pwait2", || {
        a_blocked_signal_stays_pending(Wait::EpollPwait2)
    });
    assert_eq!(injected, vec![Ok(0), Ok(0)]);
}

/// A shielded wait that a signal both masks admit interrupts during the wait:
/// SIGUSR1 is pending and blocked by the call's mask, and a SIGALRM arrives
/// 50 ms into a 500 ms wait. Linux ends the call with EINTR, runs SIGALRM's
/// handler under the temporary mask, then restores the thread's mask, so
/// SIGUSR1's handler runs next. This leaves a mask restore pending when the
/// injection returns, which the shield's restore at the syscall entry must not
/// disturb.
fn a_shielded_wait_interrupted_during_the_wait(wait: Wait) {
    DELIVERIES.store(0, Ordering::SeqCst);
    catch_and_block(libc::SIGUSR1, false);
    alarm_in(50);
    let usr1 = bit(libc::SIGUSR1);
    assert_eq!(
        unblock_then_wait_for(wait, usr1, usr1, 500),
        (-1, Some(libc::EINTR))
    );
    assert_eq!(
        records(),
        vec![libc::SIGALRM as i64, libc::SIGUSR1 as i64],
        "SIGALRM's handler, then SIGUSR1's once the thread's mask is back"
    );
    assert_eq!(current_mask() & usr1, 0, "the thread's mask is restored");
}

#[test]
fn a_shielded_ppoll_interrupted_during_its_wait_restores_the_thread_mask() {
    run_guest("interrupted ppoll", || {
        a_shielded_wait_interrupted_during_the_wait(Wait::Ppoll)
    });
}

#[test]
fn a_shielded_rt_sigsuspend_woken_by_another_signal_restores_the_thread_mask() {
    run_guest("interrupted rt_sigsuspend", || {
        a_shielded_wait_interrupted_during_the_wait(Wait::RtSigsuspend)
    });
}

/// A mask on a write-only page is valid: Linux's copy of it reads an x86
/// write-only mapping, so the guest's own call waits under it. The injected
/// wait is shielded as for a readable mask and times out with the signal
/// pending (Codex review of https://github.com/rrnewton/reverie/pull/996: a
/// `process_vm_readv` read refused the page, nothing was shielded, and the
/// call returned EINTR).
fn a_write_only_mask_is_shielded(wait: Wait) {
    DELIVERIES.store(0, Ordering::SeqCst);
    catch_and_block(libc::SIGUSR1, false);
    let usr1 = bit(libc::SIGUSR1);
    assert_eq!(
        unblock_then_wait_placed(wait, usr1, usr1, 50, Some(libc::PROT_WRITE)),
        (0, None),
        "the injected {wait:?} must time out with the signal pending"
    );
    assert_eq!(records(), vec![libc::SIGUSR1 as i64]);
}

#[test]
fn a_write_only_mask_shields_an_injected_ppoll() {
    let injected = run_guest("write-only ppoll", || {
        a_write_only_mask_is_shielded(Wait::Ppoll)
    });
    assert_eq!(injected, vec![Ok(0), Ok(0)]);
}

#[test]
fn a_write_only_wrapper_and_mask_shield_an_injected_pselect6() {
    let injected = run_guest("write-only pselect6", || {
        a_write_only_mask_is_shielded(Wait::Pselect6)
    });
    assert_eq!(injected, vec![Ok(0), Ok(0)]);
}

/// A mask on a `PROT_NONE` page makes the guest's own ppoll fail with EFAULT
/// at entry, before it would wait; a pending signal it admits is then taken
/// after the call returns. The injected ppoll does the same.
#[test]
fn an_inaccessible_mask_fails_an_injected_ppoll_with_efault() {
    let injected = run_guest("PROT_NONE ppoll", || {
        DELIVERIES.store(0, Ordering::SeqCst);
        catch_and_block(libc::SIGUSR1, false);
        let usr1 = bit(libc::SIGUSR1);
        assert_eq!(
            unblock_then_wait_placed(Wait::Ppoll, usr1, usr1, 50, Some(libc::PROT_NONE)),
            (-1, Some(libc::EFAULT))
        );
        assert_eq!(records(), vec![libc::SIGUSR1 as i64]);
    });
    assert_eq!(injected, vec![Ok(0), Err(libc::EFAULT)]);
}
