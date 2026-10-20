/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The fixture of `launch_late_open_descriptor` and
//! `launch_late_open_descriptor_signal`: a launch whose `pipe2` fails with
//! EMFILE because another thread's transient open, which began during the
//! launch after `launch_window::OPEN_WAIT_LIMIT`, still holds the last free
//! descriptor (<https://github.com/rrnewton/reverie/issues/930>). Each test
//! binary runs it once, so its statics are its own.
//!
//! A user-notification supervisor in this process holds the launcher's
//! `pipe2` until another thread has opened a descriptor late and is closing
//! it; a second supervisor holds that close until the launcher makes another
//! `pipe2`. `RLIMIT_NOFILE` leaves exactly the two descriptors the launch
//! needs, so the first `pipe2` fails, and the launch completes only if it
//! makes a second one, and that one runs after the close. No privilege is
//! needed.
//!
//! The filters wait for an answer without being interrupted by a signal once
//! the supervisor has received the call (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`),
//! and every answer is checked. That alone does not show that a call the
//! supervisor let run ran: some kernels (6.13 among them) discard an answer
//! that arrives after a signal woke the wait and before the waiting thread
//! took the notification lock again, and restart the call, which would then
//! look like a retry. So the supervisor answers only once the launcher waits
//! killably again, and the signal's handler checks the registers the signal
//! saved: the first `pipe2` must have returned EMFILE, not been rewound to
//! restart.
//!
//! The supervisors also hold, until the launch ends, every `futex` call the
//! launcher makes and the `FUTEX_WAKE_PRIVATE` of the other thread's release
//! while the launch is held, and the retried `pipe2` until the other thread has
//! finished. A launch that waited in `futex` for the close, or a release that
//! woke it, could then never end; the supervisors give up after
//! [`FUTEX_HOLD`] so the test reports that instead of hanging.

use std::os::unix::fs::FileExt;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use reverie_process::Command;
use reverie_process::ExitStatus;
use reverie_process::launch_window;

/// `_IOWR('!', 0, struct seccomp_notif)` and `_IOWR('!', 1, struct
/// seccomp_notif_resp)` from `<linux/seccomp.h>`.
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
/// `AUDIT_ARCH_X86_64` from `<linux/audit.h>`.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// How long the test waits for any one step before it reports the step.
const BOUND: Duration = Duration::from_secs(30);
/// How long a supervisor holds a `futex` call made while the launch is held
/// before it gives up and reports it.
const FUTEX_HOLD: Duration = Duration::from_secs(2);
/// `FUTEX_WAKE_PRIVATE`, the operation the other thread's filter matches.
const FUTEX_WAKE_PRIVATE: u32 = (libc::FUTEX_WAKE | libc::FUTEX_PRIVATE_FLAG) as u32;
/// How long the signal's handler sleeps.
const HANDLER_SLEEP: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 30_000_000,
};

static STOP: AtomicBool = AtomicBool::new(false);
/// Set when the helper may make its late open.
static HELPER_GO: AtomicBool = AtomicBool::new(false);
/// Set when the launch may begin.
static LAUNCHER_GO: AtomicBool = AtomicBool::new(false);
/// Set once the helper's open began while a launch held the lock.
static OPENED_DURING_LAUNCH: AtomicBool = AtomicBool::new(false);
/// Set once the close supervisor holds the helper's close.
static CLOSE_HELD: AtomicBool = AtomicBool::new(false);
/// Set once the launcher's spawn returned.
static SPAWN_RETURNED: AtomicBool = AtomicBool::new(false);
/// Set once the launcher's first `pipe2` was let run.
static FIRST_PIPE2_CONTINUED: AtomicBool = AtomicBool::new(false);
/// `pipe2` calls the launcher made after its first one ran.
static LATER_PIPE2: AtomicU32 = AtomicU32::new(0);
/// Whether the launch was still held when the second `pipe2` was notified.
static RETRY_UNDER_LAUNCH: AtomicBool = AtomicBool::new(false);
/// Whether the helper's close ran only once the second `pipe2` was notified.
static CLOSE_AFTER_RETRY: AtomicBool = AtomicBool::new(false);
/// Set while the other thread releases its open.
static RELEASING: AtomicBool = AtomicBool::new(false);
/// Set once the other thread has released its open.
static HELPER_DONE: AtomicBool = AtomicBool::new(false);
/// Whether the retried `pipe2` was let run only after the other thread
/// finished.
static RETRY_AFTER_HELPER: AtomicBool = AtomicBool::new(false);
/// Answers to a notification that the kernel refused.
static ANSWERS_REFUSED: AtomicU32 = AtomicU32::new(0);
/// `futex` calls the launcher made while the launch was held.
static LAUNCHER_FUTEX_UNDER_LAUNCH: AtomicU32 = AtomicU32::new(0);
/// `FUTEX_WAKE_PRIVATE` calls the other thread made while the launch was held.
static HELPER_WAKE_UNDER_LAUNCH: AtomicU32 = AtomicU32::new(0);
/// Set once the signal was sent; it is sent only once.
static SIGNAL_SENT: AtomicBool = AtomicBool::new(false);
/// Times the signal's handler ran to completion.
static HANDLER_RUNS: AtomicU32 = AtomicU32::new(0);
/// The `rax` the signal saved: the interrupted `pipe2`'s return value, or its
/// system call number if the kernel rewound it to restart.
static HANDLER_SAVED_RAX: AtomicI64 = AtomicI64::new(i64::MIN);
/// Whether the launcher waited killably for the answer after the signal.
static KILLABLE_AFTER_SIGNAL: AtomicBool = AtomicBool::new(false);
/// The listeners, published without a `futex` call: a filtered thread's
/// channel send could wait for a supervisor that does not exist yet.
static PIPE2_LISTENER: AtomicI32 = AtomicI32::new(-1);
static CLOSE_LISTENER: AtomicI32 = AtomicI32::new(-1);
static LAUNCHER_TID: AtomicI32 = AtomicI32::new(-1);

/// Installs, on the calling thread only, a filter that hands every call of
/// system call `nr`, and every `futex` call (only those whose operation is
/// `futex_op`, if given), to a user-notification listener, and returns the
/// listener.
fn notify_on_this_thread(nr: libc::c_long, futex_op: Option<u32>) -> libc::c_int {
    let arch = std::mem::offset_of!(libc::seccomp_data, arch) as u32;
    let nr_offset = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
    // The low word of the second argument, on this little-endian target.
    let op_offset = (std::mem::offset_of!(libc::seccomp_data, args) + 8) as u32;
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let notify = stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_USER_NOTIF);
    let allow = stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW);
    let mut filter = vec![
        stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, arch),
        jeq(AUDIT_ARCH_X86_64, 0, 0), // jf patched below, to `allow`
        stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, nr_offset),
        jeq(nr as u32, 0, 1),
        notify,
    ];
    match futex_op {
        None => filter.extend([jeq(libc::SYS_futex as u32, 0, 1), notify]),
        Some(op) => filter.extend([
            jeq(libc::SYS_futex as u32, 0, 3),
            stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, op_offset),
            jeq(op, 0, 1),
            notify,
        ]),
    }
    filter.push(allow);
    filter[1].jf = (filter.len() - 3) as u8;
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points at `filter`, which outlives both calls; neither
    // flag synchronizes other threads, so only this thread is filtered.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        let listener = libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER | libc::SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
            &prog as *const libc::sock_fprog,
        );
        assert!(
            listener >= 0,
            "seccomp listener (Linux 5.19 or later): {}",
            std::io::Error::last_os_error()
        );
        listener as libc::c_int
    }
}

/// Receives the next notification on `listener`, or `None` once `STOP` is
/// set. Opens no descriptor.
fn receive(listener: libc::c_int) -> Option<libc::seccomp_notif> {
    while !STOP.load(Ordering::SeqCst) {
        let mut ready = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polls one descriptor this test owns.
        if unsafe { libc::poll(&mut ready, 1, 10) } != 1 {
            continue;
        }
        // SAFETY: zeroed is a valid `seccomp_notif`, which RECV fills.
        let mut request: libc::seccomp_notif = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, &mut request) } == 0 {
            return Some(request);
        }
    }
    None
}

/// Lets the notified system call `id` run. Returns whether the kernel took
/// the answer; if it did not, counts that in [`ANSWERS_REFUSED`].
fn continue_call(listener: libc::c_int, id: u64) -> bool {
    let response = libc::seccomp_notif_resp {
        id,
        val: 0,
        error: 0,
        flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
    };
    // SAFETY: answers a notification just received.
    let taken = unsafe { libc::ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, &response) } == 0;
    if !taken {
        ANSWERS_REFUSED.fetch_add(1, Ordering::SeqCst);
    }
    taken
}

/// Waits until `flag` is set, for at most [`BOUND`]. Returns whether it was.
fn wait_for(flag: &AtomicBool) -> bool {
    wait_for_at_most(flag, BOUND)
}

/// Waits until `flag` is set, for at most `bound`. Returns whether it was.
fn wait_for_at_most(flag: &AtomicBool, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    while !flag.load(Ordering::SeqCst) {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    true
}

/// Holds a `futex` call made while the launch is held until the launch ends,
/// for at most [`FUTEX_HOLD`], and counts it in `under_launch`.
fn hold_futex_under_launch(under_launch: &AtomicU32) {
    if launch_window::launching() {
        under_launch.fetch_add(1, Ordering::SeqCst);
        let give_up_at = Instant::now() + FUTEX_HOLD;
        while launch_window::launching() && Instant::now() < give_up_at {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Records the `rax` the signal saved, then sleeps in a real system call, as a
/// handler that does work would.
extern "C" fn sleep_in_handler(
    _signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: with SA_SIGINFO, `context` points at the `ucontext_t` the
    // kernel saved for this handler.
    let saved = unsafe { (*context.cast::<libc::ucontext_t>()).uc_mcontext.gregs };
    HANDLER_SAVED_RAX.store(saved[libc::REG_RAX as usize], Ordering::SeqCst);
    // SAFETY: nanosleep is async-signal-safe; the timespec is valid.
    unsafe { libc::nanosleep(&HANDLER_SLEEP, std::ptr::null_mut()) };
    HANDLER_RUNS.fetch_add(1, Ordering::SeqCst);
}

/// Waits until the launcher, whose `/proc/.../stat` is `stat`, waits
/// killably (state `D`), for at most [`FUTEX_HOLD`]. Returns whether it did.
/// Reads through the descriptor opened before the table was filled.
fn wait_until_killable(stat: &std::fs::File) -> bool {
    let give_up_at = Instant::now() + FUTEX_HOLD;
    let mut buf = [0u8; 512];
    while Instant::now() < give_up_at {
        let len = stat.read_at(&mut buf, 0).unwrap_or(0);
        let text = &buf[..len];
        // The state follows the command name, which ends at the last ')'.
        if let Some(end) = text.iter().rposition(|&b| b == b')')
            && text.get(end + 2) == Some(&b'D')
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    false
}

/// Supervises the launcher. Holds its first `pipe2` until the helper has
/// opened a descriptor during the launch and its close is held, and then, if
/// `signal`, sends it a handled `SIGUSR1` once and waits until it waits
/// killably again before letting the `pipe2` run. A `pipe2` the kernel
/// refused to let run counts as not yet run, so a call a signal cancelled and
/// restarted is held again.
/// Holds a later `pipe2` until the helper has finished, and its `futex` calls
/// as [`hold_futex_under_launch`] does.
fn supervise_launcher(listener: libc::c_int, signal: bool, stat: std::fs::File) {
    while let Some(request) = receive(listener) {
        if request.data.nr == libc::SYS_futex as i32 {
            hold_futex_under_launch(&LAUNCHER_FUTEX_UNDER_LAUNCH);
            continue_call(listener, request.id);
        } else if !FIRST_PIPE2_CONTINUED.load(Ordering::SeqCst) {
            HELPER_GO.store(true, Ordering::SeqCst);
            wait_for(&CLOSE_HELD);
            if signal && !SIGNAL_SENT.swap(true, Ordering::SeqCst) {
                // SAFETY: signals a thread of this process whose handler is
                // installed.
                unsafe {
                    libc::syscall(
                        libc::SYS_tgkill,
                        libc::getpid(),
                        LAUNCHER_TID.load(Ordering::SeqCst),
                        libc::SIGUSR1,
                    )
                };
                // The signal wakes the wait; the filter's flag makes it wait
                // again, killably, rather than cancel the call. An answer
                // sent before then can be discarded (see the module doc).
                KILLABLE_AFTER_SIGNAL.store(wait_until_killable(&stat), Ordering::SeqCst);
            }
            if continue_call(listener, request.id) {
                FIRST_PIPE2_CONTINUED.store(true, Ordering::SeqCst);
            }
        } else {
            LATER_PIPE2.fetch_add(1, Ordering::SeqCst);
            RETRY_UNDER_LAUNCH.store(launch_window::launching(), Ordering::SeqCst);
            RETRY_AFTER_HELPER.store(wait_for_at_most(&HELPER_DONE, FUTEX_HOLD), Ordering::SeqCst);
            continue_call(listener, request.id);
        }
    }
}

/// Supervises the helper. Holds its close until the launcher has made another
/// `pipe2` after the first ran, or its spawn has returned, then lets it run;
/// holds its wakes as [`hold_futex_under_launch`] does.
fn supervise_helper(listener: libc::c_int) {
    while let Some(request) = receive(listener) {
        if request.data.nr == libc::SYS_futex as i32 {
            // Only the release's wake; the thread's other wakes are not the
            // lock's.
            if RELEASING.load(Ordering::SeqCst) && !HELPER_DONE.load(Ordering::SeqCst) {
                hold_futex_under_launch(&HELPER_WAKE_UNDER_LAUNCH);
            }
        } else if !CLOSE_HELD.swap(true, Ordering::SeqCst) {
            let deadline = Instant::now() + BOUND;
            while LATER_PIPE2.load(Ordering::SeqCst) == 0
                && !SPAWN_RETURNED.load(Ordering::SeqCst)
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            CLOSE_AFTER_RETRY.store(LATER_PIPE2.load(Ordering::SeqCst) > 0, Ordering::SeqCst);
        }
        continue_call(listener, request.id);
    }
}

/// Lowers the soft `RLIMIT_NOFILE` and fills every free descriptor below it
/// but two, and returns the fillers and the old limit.
fn leave_two_descriptors() -> (Vec<std::fs::File>, libc::rlimit) {
    let highest = std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u64>().ok())
        .max()
        .unwrap();
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain getrlimit/setrlimit on valid structs.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut old), 0);
        let limit = libc::rlimit {
            rlim_cur: (highest + 64).min(old.rlim_max),
            rlim_max: old.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
    let mut fillers = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => fillers.push(file),
            Err(err) if err.raw_os_error() == Some(libc::EMFILE) => break,
            Err(err) => panic!("filling the descriptor table: {err}"),
        }
    }
    assert!(fillers.len() >= 2, "no descriptor was free to fill");
    fillers.truncate(fillers.len() - 2);
    (fillers, old)
}

/// Runs the case once, if `signal` with a handled, restarting `SIGUSR1` sent
/// to the launcher while its first `pipe2` is held, and asserts that the
/// launch completed by retrying that `pipe2` after the late open closed.
pub fn launch_retries_a_pipe_after_a_late_open_releases_its_descriptor(signal: bool) {
    if signal {
        // SAFETY: installs a handler that only sleeps and counts.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = sleep_in_handler
                as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void)
                as usize;
            action.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
            assert_eq!(
                libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()),
                0
            );
        }
    }
    let (done_tx, done_rx) = mpsc::channel();
    // Detached: if the launch hangs, its thread can never be joined.
    std::thread::spawn(move || {
        // SAFETY: gettid has no preconditions.
        LAUNCHER_TID.store(unsafe { libc::gettid() }, Ordering::SeqCst);
        PIPE2_LISTENER.store(
            notify_on_this_thread(libc::SYS_pipe2, None),
            Ordering::SeqCst,
        );
        wait_for(&LAUNCHER_GO);
        let status = Command::new("/bin/true")
            .spawn()
            .map_err(|e| e.to_string())
            .and_then(|mut child| child.wait_blocking().map_err(|e| e.to_string()));
        SPAWN_RETURNED.store(true, Ordering::SeqCst);
        done_tx.send(status).unwrap();
    });
    std::thread::spawn(move || {
        CLOSE_LISTENER.store(
            notify_on_this_thread(libc::SYS_close, Some(FUTEX_WAKE_PRIVATE)),
            Ordering::SeqCst,
        );
        wait_for(&HELPER_GO);
        let open = launch_window::TransientOpen::begin();
        OPENED_DURING_LAUNCH.store(launch_window::launching(), Ordering::SeqCst);
        // Takes one of the launch's two descriptors; its close is held.
        drop(std::fs::File::open("/dev/null").unwrap());
        RELEASING.store(true, Ordering::SeqCst);
        drop(open);
        HELPER_DONE.store(true, Ordering::SeqCst);
    });
    let published = |listener: &AtomicI32| {
        let deadline = Instant::now() + BOUND;
        while listener.load(Ordering::SeqCst) < 0 {
            assert!(Instant::now() < deadline, "a filter was not installed");
            std::thread::sleep(Duration::from_millis(1));
        }
        listener.load(Ordering::SeqCst)
    };
    let pipe2_listener = published(&PIPE2_LISTENER);
    let close_listener = published(&CLOSE_LISTENER);
    // Opened now: once the table is filled, an open would take a descriptor
    // the launch needs. The launcher stored its id before its listener.
    let launcher_stat = std::fs::File::open(format!(
        "/proc/self/task/{}/stat",
        LAUNCHER_TID.load(Ordering::SeqCst)
    ))
    .unwrap();
    std::thread::spawn(move || supervise_launcher(pipe2_listener, signal, launcher_stat));
    std::thread::spawn(move || supervise_helper(close_listener));

    let (fillers, old_limit) = leave_two_descriptors();
    LAUNCHER_GO.store(true, Ordering::SeqCst);
    let status = done_rx.recv_timeout(BOUND);
    STOP.store(true, Ordering::SeqCst);
    drop(fillers);
    // SAFETY: restores the limit read above.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &old_limit) };

    let status = status.unwrap_or_else(|_| panic!("the launch did not return within {BOUND:?}"));
    eprintln!(
        "launch_late_open_descriptor (signal {signal}): status {status:?}; open during launch \
         {}; close held {}; first pipe2 ran {}; later pipe2 calls {}; retry under the launch \
         {}; close only after the retry {}; retry after helper {}; answers refused {}; \
         launcher futex calls under launch {}; helper wakes under launch {}; handler runs {}; \
         killable after the signal {}; rax the signal saved {}",
        OPENED_DURING_LAUNCH.load(Ordering::SeqCst),
        CLOSE_HELD.load(Ordering::SeqCst),
        FIRST_PIPE2_CONTINUED.load(Ordering::SeqCst),
        LATER_PIPE2.load(Ordering::SeqCst),
        RETRY_UNDER_LAUNCH.load(Ordering::SeqCst),
        CLOSE_AFTER_RETRY.load(Ordering::SeqCst),
        RETRY_AFTER_HELPER.load(Ordering::SeqCst),
        ANSWERS_REFUSED.load(Ordering::SeqCst),
        LAUNCHER_FUTEX_UNDER_LAUNCH.load(Ordering::SeqCst),
        HELPER_WAKE_UNDER_LAUNCH.load(Ordering::SeqCst),
        HANDLER_RUNS.load(Ordering::SeqCst),
        KILLABLE_AFTER_SIGNAL.load(Ordering::SeqCst),
        HANDLER_SAVED_RAX.load(Ordering::SeqCst),
    );
    assert!(
        OPENED_DURING_LAUNCH.load(Ordering::SeqCst) && CLOSE_HELD.load(Ordering::SeqCst),
        "the helper's open did not begin during the launch with its close held; the case was \
         not exercised"
    );
    assert_eq!(
        ANSWERS_REFUSED.load(Ordering::SeqCst),
        0,
        "the kernel refused an answer, so a held call did not run as the supervisor let it; \
         the case was not exercised as intended"
    );
    assert!(
        FIRST_PIPE2_CONTINUED.load(Ordering::SeqCst),
        "the launcher's first pipe2 was never let run"
    );
    assert_eq!(
        HANDLER_RUNS.load(Ordering::SeqCst),
        u32::from(signal),
        "the signal's handler did not run exactly as often as it was sent"
    );
    if signal {
        assert!(
            KILLABLE_AFTER_SIGNAL.load(Ordering::SeqCst),
            "the launcher did not wait killably for the answer after the signal woke its wait"
        );
        assert_eq!(
            HANDLER_SAVED_RAX.load(Ordering::SeqCst),
            -i64::from(libc::EMFILE),
            "the signal did not find the first pipe2 returned with EMFILE ({} is pipe2's number, \
             saved when the kernel rewinds a call to restart it); a later pipe2 would not be a \
             retry",
            libc::SYS_pipe2
        );
    }
    assert_eq!(
        LAUNCHER_FUTEX_UNDER_LAUNCH.load(Ordering::SeqCst),
        0,
        "the launcher made a futex call while the launch was held, which a supervisor could \
         hold until the launch ends"
    );
    assert_eq!(
        HELPER_WAKE_UNDER_LAUNCH.load(Ordering::SeqCst),
        0,
        "a release woke the lock while the launch was held, which a supervisor could hold \
         until the launch ends"
    );
    assert_eq!(
        status,
        Ok(ExitStatus::Exited(0)),
        "the launch failed while an open that began during it held a descriptor it needed"
    );
    assert!(
        LATER_PIPE2.load(Ordering::SeqCst) == 1
            && RETRY_UNDER_LAUNCH.load(Ordering::SeqCst)
            && CLOSE_AFTER_RETRY.load(Ordering::SeqCst)
            && RETRY_AFTER_HELPER.load(Ordering::SeqCst),
        "the launch did not complete by retrying its pipe2 once, under the launch, after the \
         helper's close"
    );
}
