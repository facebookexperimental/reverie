/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Regression coverage for a tracer thread's transient descriptor leaking into
//! a guest launch on another host thread
//! (https://github.com/rrnewton/reverie/issues/912, rows 25 and 26 of
//! https://github.com/rrnewton/reverie/issues/845).
//!
//! Tracer A runs a guest that takes a signal. At its signal-delivery stop the
//! tracer reads `/proc/thread-self/status` (`thread_may_be_seccomp_filtered`).
//! This binary interposes `open64` and holds that one descriptor open while
//! tracer B launches a guest with `spawn_fn_with_config`. Descriptors 3 to 255
//! are filled first, so the status descriptor is numbered 256 or above, which
//! the no-exec guest does not close. Without mutual exclusion between the two:
//!
//! - F-1: B's guest inherits the status descriptor and keeps it for its run.
//! - F-2: under a soft `RLIMIT_NOFILE` that fits exactly the launch's four pipe
//!   descriptors, the status descriptor takes one of their numbers and the
//!   launch fails with EMFILE.
//!
//! With the exclusion, B's launch waits until A closes the descriptor. The
//! test releases A only when B's launch has returned (which, while A is held,
//! is the defect) or when B's thread is seen waiting for the launch lock before
//! its first pipe: asleep in `FUTEX_WAIT_PRIVATE` on the lock's own futex word,
//! whose address comes from this executable's symbol table, in two samples
//! `WAIT_CONFIRM` apart. If neither happens within `BOUND`, the overlap was not
//! exercised and the test fails. On the waiting path it also checks that B's
//! first pipe came after the release, so a launch that merely ran late cannot
//! pass.
//!
//! A third test covers a launch through `TracerBuilder::spawn` whose child's
//! `pre_exec` waits for tracer A's guest to handle a signal. The launch must
//! not hold the lock while it waits for its child to start, or A's
//! signal-delivery stop (a transient open) waits for B's launch. Since an open
//! proceeds after `OPEN_WAIT_LIMIT`, a lock held there would now delay A's
//! stop rather than deadlock the two, so this test checks that B's spawn
//! returns, not where the lock is released; the source releases it before
//! the startup wait.
//!
//! A fourth test covers `pthread_atfork` handlers around a
//! `spawn_fn_with_config` launch, which forks through libc. Its prepare
//! handler waits for another tracer's transient open, so the launch must not
//! hold the lock across `fork`, or that open waits for the launch. As above,
//! a lock held there would now delay the open by `OPEN_WAIT_LIMIT` rather
//! than make the handler time out, so the test does not establish where the
//! lock is released; the source releases it before `fork`. The
//! descriptors the handlers make on purpose, a replacement for one the launch
//! inherits (prepare) and a new eventfd (child), must reach the guest; the
//! eventfd's number must be free before the launch, and the guest also checks
//! a flag that only the child handler sets, in the child. That
//! transient open itself, begun after the launch's guard ended, still reaches
//! the guest, as before the lock
//! (<https://github.com/rrnewton/reverie/issues/927>); the test does not
//! check it.
//!
//! A fifth test counts the allocator calls a thread makes while it holds the
//! launch lock, through this binary's global allocator, and requires none: an
//! allocator can hold its own lock, or wait for a transient open, while
//! another thread waits for the launch to end.

#![cfg(all(target_os = "linux", target_env = "gnu"))]

use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::sync::Condvar;
use std::sync::Mutex;
use std::sync::Once;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

use reverie::ExitStatus;
use reverie::syscalls::Errno;
use reverie_ptrace::TracerBuilder;
use reverie_ptrace::spawn_fn_with_config;
use reverie_ptrace::testing::run_tokio_test;

/// The path tracer A opens at a signal-delivery stop.
const STATUS_PATH: &CStr = c"/proc/thread-self/status";

/// Bound on the test's waits for the launches and for A's status read, so a
/// launch that never reaches the overlap reports as a failure.
const BOUND: Duration = Duration::from_secs(120);

/// Interval between the two samples that must both find B waiting for the
/// launch lock.
const WAIT_CONFIRM: Duration = Duration::from_millis(100);

/// Exit code of B's guest when it finds A's status descriptor open.
const INHERITED: i32 = 73;

/// The tests share the process's descriptor table and limits.
static SERIAL: Mutex<()> = Mutex::new(());

/// Set to hold the next open of `STATUS_PATH`.
static HOLD_NEXT_STATUS_OPEN: AtomicBool = AtomicBool::new(false);
/// The held status descriptor, or -1.
static HELD_FD: AtomicI32 = AtomicI32::new(-1);
/// What the held descriptor resolves to (`/proc/self/fd/N`).
static HELD_TARGET: Mutex<Option<CString>> = Mutex::new(None);

#[derive(Default)]
struct Hold {
    opened: bool,
    released: bool,
}

static HOLD: Mutex<Hold> = Mutex::new(Hold {
    opened: false,
    released: false,
});
static HOLD_CHANGED: Condvar = Condvar::new();

/// Set just before the controller releases A.
static RELEASED: AtomicBool = AtomicBool::new(false);
/// When B's first pipe ran: `PIPE_NOT_YET`, or before or after A's release.
static FIRST_PIPE: AtomicU8 = AtomicU8::new(PIPE_NOT_YET);
const PIPE_NOT_YET: u8 = 0;
const PIPE_BEFORE_RELEASE: u8 = 1;
const PIPE_AFTER_RELEASE: u8 = 2;

thread_local! {
    /// Set on B's launching thread to record its first pipe in `FIRST_PIPE`.
    static RECORD_FIRST_PIPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Set on B's launching thread to tighten `RLIMIT_NOFILE` at its first
    /// pipe (F-2).
    static TIGHTEN_AT_PIPE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Pipes seen since tightening, and the limit to restore.
    static TIGHTENED: std::cell::Cell<Option<(u32, libc::rlimit)>> =
        const { std::cell::Cell::new(None) };
}

static REAL_OPEN64: AtomicUsize = AtomicUsize::new(0);
static REAL_PIPE: AtomicUsize = AtomicUsize::new(0);

fn real(cache: &AtomicUsize, name: &CStr) -> usize {
    let mut addr = cache.load(Ordering::Relaxed);
    if addr == 0 {
        // SAFETY: `name` is a valid C string; RTLD_NEXT finds libc's symbol.
        addr = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) } as usize;
        assert_ne!(addr, 0, "dlsym({name:?}) failed");
        cache.store(addr, Ordering::Relaxed);
    }
    addr
}

/// Interposes libc's `open64`, which `std::fs::File::open` calls. The mode is
/// taken as a fixed third argument, which the x86-64 and AArch64 Linux calling
/// conventions pass where a variadic one goes.
///
/// # Safety
///
/// As libc's `open64`: `path` is a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open64(path: *const c_char, flags: c_int, mode: libc::mode_t) -> c_int {
    let real_open64: unsafe extern "C" fn(*const c_char, c_int, libc::mode_t) -> c_int =
        // SAFETY: `real` returns libc's `open64`.
        unsafe { std::mem::transmute(real(&REAL_OPEN64, c"open64")) };
    // SAFETY: the caller's arguments, passed through.
    let fd = unsafe { real_open64(path, flags, mode) };
    // SAFETY: `path` is the caller's C string.
    if fd >= 0
        && unsafe { CStr::from_ptr(path) } == STATUS_PATH
        && HOLD_NEXT_STATUS_OPEN.swap(false, Ordering::SeqCst)
    {
        hold(fd);
    }
    fd
}

/// Interposes libc's `pipe`, which `nix::unistd::pipe` calls.
///
/// # Safety
///
/// As libc's `pipe`: `fds` is writable for two descriptors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe(fds: *mut c_int) -> c_int {
    let real_pipe: unsafe extern "C" fn(*mut c_int) -> c_int =
        // SAFETY: `real` returns libc's `pipe`.
        unsafe { std::mem::transmute(real(&REAL_PIPE, c"pipe")) };
    if RECORD_FIRST_PIPE
        .try_with(|r| r.replace(false))
        .unwrap_or(false)
    {
        let when = if RELEASED.load(Ordering::SeqCst) {
            PIPE_AFTER_RELEASE
        } else {
            PIPE_BEFORE_RELEASE
        };
        FIRST_PIPE.store(when, Ordering::SeqCst);
    }
    if TIGHTEN_AT_PIPE
        .try_with(|t| t.replace(false))
        .unwrap_or(false)
    {
        TIGHTENED.with(|t| t.set(Some((0, tighten_nofile()))));
    }
    // SAFETY: the caller's argument, passed through.
    let rc = unsafe { real_pipe(fds) };
    if let Ok(Some((seen, saved))) = TIGHTENED.try_with(|t| t.get()) {
        if rc != 0 || seen + 1 == 2 {
            TIGHTENED.with(|t| t.set(None));
            // SAFETY: `saved` is the limit read before tightening.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &saved) }, 0);
        } else {
            TIGHTENED.with(|t| t.set(Some((seen + 1, saved))));
        }
    }
    rc
}

/// Records `fd` as held and blocks until the test releases it.
fn hold(fd: c_int) {
    HELD_FD.store(fd, Ordering::SeqCst);
    *HELD_TARGET.lock().unwrap() = Some(fd_target(fd).expect("held descriptor has no target"));
    let mut hold = HOLD.lock().unwrap();
    hold.opened = true;
    HOLD_CHANGED.notify_all();
    let (_hold, timeout) = HOLD_CHANGED
        .wait_timeout_while(hold, BOUND, |h| !h.released)
        .unwrap();
    assert!(
        !timeout.timed_out(),
        "the status descriptor was never released"
    );
}

/// What `/proc/self/fd/<fd>` links to, `None` if `fd` is not open.
fn fd_target(fd: c_int) -> Option<CString> {
    let link = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let mut buf = [0u8; 4096];
    // SAFETY: `link` is a C string and `buf` is writable for its length.
    let n = unsafe { libc::readlink(link.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    (n > 0).then(|| CString::new(&buf[..n as usize]).unwrap())
}

/// Whether A's held status descriptor is open in this process.
fn held_fd_open() -> bool {
    let fd = HELD_FD.load(Ordering::SeqCst);
    let held = HELD_TARGET
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    fd >= 0 && held.is_some() && fd_target(fd) == held
}

fn fd_free(fd: c_int) -> bool {
    // SAFETY: F_GETFD only reads the descriptor table.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    flags == -1
}

/// Sets the soft `RLIMIT_NOFILE` to fit exactly the four lowest descriptor
/// numbers that would be free if A's status descriptor were closed, and
/// returns the previous limit.
fn tighten_nofile() -> libc::rlimit {
    let mut saved = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `saved` is writable.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved) },
        0
    );
    let held = held_fd_open().then(|| HELD_FD.load(Ordering::SeqCst));
    let mut available = 0;
    let mut fd = 0;
    loop {
        if fd_free(fd) || Some(fd) == held {
            available += 1;
            if available == 4 {
                break;
            }
        }
        fd += 1;
    }
    let tight = libc::rlimit {
        rlim_cur: fd as libc::rlim_t + 1,
        rlim_max: saved.rlim_max,
    };
    // SAFETY: `tight` is a valid limit no higher than the hard limit.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &tight) }, 0);
    saved
}

/// Fills every free descriptor from 3 to 255 and closes them on drop.
struct LowDescriptorsFilled(Vec<c_int>);

impl LowDescriptorsFilled {
    fn new() -> Self {
        // SAFETY: plain open of a constant path.
        let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(null >= 0);
        let mut filled = Vec::new();
        for fd in 3..256 {
            if fd != null && fd_free(fd) {
                // SAFETY: `fd` is free and `null` is open.
                assert_eq!(unsafe { libc::dup3(null, fd, libc::O_CLOEXEC) }, fd);
                filled.push(fd);
            }
        }
        if null >= 256 {
            // SAFETY: our own descriptor.
            unsafe { libc::close(null) };
        } else {
            filled.push(null);
        }
        Self(filled)
    }
}

impl Drop for LowDescriptorsFilled {
    fn drop(&mut self) {
        for &fd in &self.0 {
            // SAFETY: descriptors this guard opened.
            unsafe { libc::close(fd) };
        }
    }
}

/// Guest of tracer A: takes one handled SIGUSR1.
fn take_a_signal() {
    extern "C" fn on_usr1(_: c_int) {}
    // SAFETY: installs a no-op handler, then raises the signal at itself.
    unsafe {
        libc::signal(libc::SIGUSR1, on_usr1 as *const () as libc::sighandler_t);
        libc::raise(libc::SIGUSR1);
    }
}

/// Guest of tracer B for F-1: exits `INHERITED` if A's status descriptor is
/// open in it. The guest is a fork of this process, so it reads the held
/// descriptor's number and target from the copied statics.
fn check_not_inherited() {
    if held_fd_open() {
        // SAFETY: ends the guest without running the test process's exit
        // handlers.
        unsafe { libc::_exit(INHERITED) };
    }
}

/// Mangled-name fragment of the launch lock's futex word,
/// `reverie_process::launch_window::STATE`, in both the legacy and the v0
/// symbol mangling.
const LOCK_SYMBOL: &[u8] = b"15reverie_process13launch_window5STATE";

/// ELF section type of a symbol table.
const SHT_SYMTAB: u32 = 2;

/// The run-time address of the launch lock's futex word, from this
/// executable's symbol table, or `None` if it has no such symbol (a build
/// without the lock).
fn launch_lock_address() -> Option<u64> {
    static ADDRESS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    *ADDRESS.get_or_init(|| {
        let elf = std::fs::read("/proc/self/exe").ok()?;
        let u16_at = |at: usize| Some(u16::from_le_bytes(elf.get(at..at + 2)?.try_into().ok()?));
        let u32_at = |at: usize| Some(u32::from_le_bytes(elf.get(at..at + 4)?.try_into().ok()?));
        let u64_at = |at: usize| Some(u64::from_le_bytes(elf.get(at..at + 8)?.try_into().ok()?));
        if elf.get(..5)? != b"\x7fELF\x02" {
            return None;
        }
        // Load bias: where the program headers are mapped, less the address
        // PT_PHDR gives them in the file.
        let (phoff, phentsize, phnum) = (u64_at(0x20)?, u16_at(0x36)?, u16_at(0x38)?);
        let phdr_vaddr = (0..phnum as u64).find_map(|i| {
            let at = (phoff + i * phentsize as u64) as usize;
            (u32_at(at)? == libc::PT_PHDR).then(|| u64_at(at + 0x10))?
        })?;
        // SAFETY: getauxval has no preconditions.
        let bias = unsafe { libc::getauxval(libc::AT_PHDR) }.checked_sub(phdr_vaddr)?;
        let (shoff, shentsize, shnum) = (u64_at(0x28)?, u16_at(0x3a)?, u16_at(0x3c)?);
        let section = |i: u64| (shoff + i * shentsize as u64) as usize;
        let symtab = (0..shnum as u64)
            .map(section)
            .find(|&at| u32_at(at + 4) == Some(SHT_SYMTAB))?;
        let (offset, size, entsize) = (
            u64_at(symtab + 0x18)?,
            u64_at(symtab + 0x20)?,
            u64_at(symtab + 0x38)?,
        );
        let strtab = u64_at(section(u32_at(symtab + 0x28)? as u64) + 0x18)? as usize;
        let mut found = None;
        for at in (offset..offset + size).step_by(entsize.max(1) as usize) {
            let at = at as usize;
            let name_at = strtab + u32_at(at)? as usize;
            let name = elf.get(name_at..)?;
            let name = &name[..name.iter().position(|&b| b == 0)?];
            if name.windows(LOCK_SYMBOL.len()).any(|w| w == LOCK_SYMBOL) {
                let value = u64_at(at + 8)? + bias;
                if found.is_some_and(|other| other != value) {
                    return None;
                }
                found = Some(value);
            }
        }
        found
    })
}

/// Whether thread `tid` of this process is blocked in the launch lock's wait:
/// `FUTEX_WAIT_PRIVATE` on the lock's own futex word (found by
/// [`launch_lock_address`]), on a value counting transient opens with no
/// launch in progress.
fn waiting_for_launch_lock(tid: libc::pid_t) -> bool {
    let Some(lock) = launch_lock_address() else {
        return false;
    };
    let Ok(text) = std::fs::read_to_string(format!("/proc/self/task/{tid}/syscall")) else {
        return false;
    };
    let fields: Vec<&str> = text.split_whitespace().collect();
    let hex = |i: usize| {
        fields
            .get(i)
            .and_then(|f| f.strip_prefix("0x"))
            .and_then(|f| u64::from_str_radix(f, 16).ok())
    };
    let op = (libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG) as u64;
    fields.first() == Some(&libc::SYS_futex.to_string().as_str())
        && hex(1) == Some(lock)
        && hex(2) == Some(op)
        && hex(3).is_some_and(|val| val != 0 && val < 1 << 31)
}

/// What the controller saw before it released A.
#[derive(Debug, PartialEq)]
enum Release {
    /// B's thread was waiting for the launch lock before its first pipe, in
    /// two samples `WAIT_CONFIRM` apart.
    LaunchWaiting,
    /// B's launch returned while A was held.
    LaunchReturned,
    /// Neither within `BOUND`: the overlap was not exercised.
    Neither,
}

/// How B's launch ended, what released A, and when B's first pipe ran.
struct Outcome {
    launch: Result<ExitStatus, String>,
    release: Release,
    first_pipe: u8,
}

impl Outcome {
    /// Asserts the launch overlapped A's open and waited for its close.
    fn assert_launch_waited(&self) {
        assert_eq!(
            self.release,
            Release::LaunchWaiting,
            "B's launch did not wait for A's transient descriptor (Neither means the overlap \
             was not exercised)"
        );
        assert_eq!(
            self.first_pipe, PIPE_AFTER_RELEASE,
            "B's first pipe must come after A's release (1 = before, 0 = never)"
        );
    }
}

/// Holds A's next status read open, runs B's launch of `guest` meanwhile, and
/// releases A once B's launch has returned or is seen waiting for the lock.
fn launch_during_status_read(guest: fn(), tighten_nofile: bool) -> Outcome {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _filled = LowDescriptorsFilled::new();
    *HOLD.lock().unwrap() = Hold::default();
    HELD_FD.store(-1, Ordering::SeqCst);
    *HELD_TARGET.lock().unwrap() = None;
    RELEASED.store(false, Ordering::SeqCst);
    FIRST_PIPE.store(PIPE_NOT_YET, Ordering::SeqCst);
    HOLD_NEXT_STATUS_OPEN.store(true, Ordering::SeqCst);

    let tracer_a = std::thread::spawn(|| {
        run_tokio_test(async {
            let tracer = spawn_fn_with_config::<(), _>(take_a_signal, (), false).await?;
            tracer.wait().await
        })
    });

    {
        let hold = HOLD.lock().unwrap();
        let (_hold, timeout) = HOLD_CHANGED
            .wait_timeout_while(hold, BOUND, |h| !h.opened)
            .unwrap();
        assert!(
            !timeout.timed_out(),
            "tracer A never opened {STATUS_PATH:?}; the test reached no overlap"
        );
    }
    assert!(held_fd_open());
    assert!(
        HELD_FD.load(Ordering::SeqCst) >= 256,
        "the held descriptor must be one the guest does not close"
    );

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (returned_tx, returned_rx) = std::sync::mpsc::channel();
    let tracer_b = std::thread::spawn(move || {
        // `block_on` polls this future on this thread, so the launch's
        // synchronous part (lock, pipes, fork) runs here.
        run_tokio_test(async move {
            // SAFETY: gettid has no preconditions.
            entered_tx.send(unsafe { libc::gettid() }).unwrap();
            RECORD_FIRST_PIPE.with(|r| r.set(true));
            TIGHTEN_AT_PIPE.with(|t| t.set(tighten_nofile));
            let launched = spawn_fn_with_config::<(), _>(guest, (), false).await;
            TIGHTEN_AT_PIPE.with(|t| t.set(false));
            RECORD_FIRST_PIPE.with(|r| r.set(false));
            returned_tx.send(()).unwrap();
            match launched {
                Ok(tracer) => tracer
                    .wait()
                    .await
                    .map(|(status, ())| status)
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    });

    let b_tid = entered_rx.recv_timeout(BOUND).unwrap();
    let entered = Instant::now();
    let not_piped = || FIRST_PIPE.load(Ordering::SeqCst) == PIPE_NOT_YET;
    let release = loop {
        if returned_rx.try_recv().is_ok() {
            break Release::LaunchReturned;
        }
        if waiting_for_launch_lock(b_tid) && not_piped() {
            std::thread::sleep(WAIT_CONFIRM);
            if waiting_for_launch_lock(b_tid) && not_piped() {
                break Release::LaunchWaiting;
            }
            continue;
        }
        if entered.elapsed() > BOUND {
            break Release::Neither;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    eprintln!(
        "launch_descriptor_window: A held descriptor {} ({:?}), released {:?} after B \
         entered its launch: {release:?} (launch lock at {:x?})",
        HELD_FD.load(Ordering::SeqCst),
        HELD_TARGET.lock().unwrap().as_deref().unwrap_or_default(),
        entered.elapsed(),
        launch_lock_address(),
    );
    RELEASED.store(true, Ordering::SeqCst);
    {
        let mut hold = HOLD.lock().unwrap();
        hold.released = true;
        HOLD_CHANGED.notify_all();
    }

    let launch = tracer_b.join().unwrap();
    let a = tracer_a.join().unwrap();
    assert_eq!(a.map(|(status, ())| status).unwrap(), ExitStatus::Exited(0));
    Outcome {
        launch,
        release,
        first_pipe: FIRST_PIPE.load(Ordering::SeqCst),
    }
}

/// F-1: B's guest must not inherit A's transient descriptor.
#[test]
fn a_launch_does_not_inherit_another_threads_transient_descriptor() {
    let outcome = launch_during_status_read(check_not_inherited, false);
    assert_eq!(
        outcome.launch,
        Ok(ExitStatus::Exited(0)),
        "B's guest exited {INHERITED} if it inherited A's status descriptor"
    );
    outcome.assert_launch_waited();
}

/// F-2: B's launch must not lose a pipe descriptor to A's transient one.
#[test]
fn a_launch_does_not_run_out_of_descriptors_to_another_threads_transient_one() {
    let outcome = launch_during_status_read(|| {}, true);
    assert_eq!(outcome.launch, Ok(ExitStatus::Exited(0)));
    outcome.assert_launch_waited();
}

/// Descriptors for the third test, above the 3 to 255 a no-exec guest closes:
/// B's child reads A's reply on `REPLY_READ`; A's guest writes it on
/// `REPLY_WRITE` and announces its PID on `READY_WRITE`.
const REPLY_READ: c_int = 300;
const REPLY_WRITE: c_int = 301;
const READY_READ: c_int = 302;
const READY_WRITE: c_int = 303;

/// How long B's spawn may take before the test rescues it and fails.
const SPAWN_BOUND: Duration = Duration::from_secs(60);

/// Guest of tracer A for the third test: announces its PID, then waits for
/// one SIGUSR1, whose handler writes the reply B's child waits for.
fn reply_on_signal() {
    extern "C" fn on_usr1(_: c_int) {
        // SAFETY: write is async-signal-safe; the buffer is a local.
        unsafe { libc::write(REPLY_WRITE, [1u8].as_ptr().cast(), 1) };
    }
    // SAFETY: signal-mask and handler setup on this single-threaded guest; the
    // buffers are locals.
    unsafe {
        let mut usr1: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut usr1);
        libc::sigaddset(&mut usr1, libc::SIGUSR1);
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, &usr1, &mut old);
        libc::signal(libc::SIGUSR1, on_usr1 as *const () as libc::sighandler_t);
        let pid = libc::getpid().to_ne_bytes();
        libc::write(READY_WRITE, pid.as_ptr().cast(), pid.len());
        libc::sigdelset(&mut old, libc::SIGUSR1);
        libc::sigsuspend(&old);
    }
}

/// Creates a pipe at the two given descriptor numbers, close-on-exec.
fn pipe_at(read: c_int, write: c_int) {
    let mut fds = [0; 2];
    // SAFETY: `fds` is writable for two descriptors.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    for (from, to) in [(fds[0], read), (fds[1], write)] {
        assert!(fd_free(to), "descriptor {to} is in use");
        // SAFETY: `from` is ours and `to` is free.
        assert_eq!(unsafe { libc::dup3(from, to, libc::O_CLOEXEC) }, to);
        // SAFETY: our own descriptor.
        unsafe { libc::close(from) };
    }
}

/// A launch through `TracerBuilder::spawn` must not hold the launch lock
/// while its child's `pre_exec` waits on another tracer's guest.
#[test]
fn a_command_launch_does_not_hold_the_lock_while_its_child_starts() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    pipe_at(REPLY_READ, REPLY_WRITE);
    pipe_at(READY_READ, READY_WRITE);

    let tracer_a = std::thread::spawn(|| {
        run_tokio_test(async {
            let tracer = spawn_fn_with_config::<(), _>(reply_on_signal, (), false).await?;
            tracer.wait().await
        })
    });
    let mut ready = libc::pollfd {
        fd: READY_READ,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: polls one descriptor this test opened.
    let polled = unsafe { libc::poll(&mut ready, 1, BOUND.as_millis() as c_int) };
    assert_eq!(polled, 1, "tracer A's guest did not announce its PID");
    let mut pid = [0u8; 4];
    // SAFETY: reads into a local buffer; A's guest writes its PID in one write.
    let n = unsafe { libc::read(READY_READ, pid.as_mut_ptr().cast(), pid.len()) };
    assert_eq!(n, 4, "tracer A's guest did not announce its PID");
    let a_guest = libc::pid_t::from_ne_bytes(pid);

    let (spawned_tx, spawned_rx) = std::sync::mpsc::channel();
    let tracer_b = std::thread::spawn(move || {
        run_tokio_test(async move {
            let mut command = reverie::process::Command::new("/bin/true");
            // SAFETY: the callback makes only async-signal-safe calls. It
            // signals A's guest, whose handler runs only after tracer A has
            // handled the signal-delivery stop, then waits for the reply.
            unsafe {
                command.pre_exec(move || {
                    if libc::kill(a_guest, libc::SIGUSR1) != 0 {
                        return Err(Errno::last());
                    }
                    // Fail the spawn unless the reply really arrived, so the
                    // test cannot pass without the cross-tracer wait.
                    let mut byte = 0u8;
                    loop {
                        match libc::read(REPLY_READ, (&mut byte as *mut u8).cast(), 1) {
                            1 => return Ok(()),
                            0 => return Err(Errno::EPIPE),
                            _ if Errno::last() == Errno::EINTR => {}
                            _ => return Err(Errno::last()),
                        }
                    }
                });
            }
            let spawned = TracerBuilder::<()>::new(command).spawn().await;
            spawned_tx.send(()).unwrap();
            match spawned {
                Ok(tracer) => tracer
                    .wait()
                    .await
                    .map(|(status, ())| status)
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    });

    let started = Instant::now();
    let spawned_in_time = spawned_rx.recv_timeout(SPAWN_BOUND).is_ok();
    eprintln!(
        "launch_descriptor_window: B's spawn {} after {:?}",
        if spawned_in_time {
            "returned"
        } else {
            "had not returned"
        },
        started.elapsed()
    );
    if !spawned_in_time {
        // Rescue the deadlock so both tracers end: B's child gets its reply
        // and execs, B's launch ends, and A's stop can proceed.
        // SAFETY: writes one byte from a local.
        unsafe { libc::write(REPLY_WRITE, [1u8].as_ptr().cast(), 1) };
    }
    let b = tracer_b.join().unwrap();
    let a = tracer_a.join().unwrap();
    for fd in [REPLY_READ, REPLY_WRITE, READY_READ, READY_WRITE] {
        // SAFETY: descriptors this test opened.
        unsafe { libc::close(fd) };
    }
    assert!(
        spawned_in_time,
        "B's spawn did not return within {SPAWN_BOUND:?}: it waited on its child's pre_exec \
         while holding the launch lock A's signal-delivery stop needed"
    );
    assert_eq!(b, Ok(ExitStatus::Exited(0)));
    assert_eq!(a.map(|(status, ())| status).unwrap(), ExitStatus::Exited(0));
}

/// How long the prepare handler of the fourth test waits for A's status read
/// to open.
const PREPARE_BOUND: Duration = Duration::from_secs(20);

/// What the fourth test's prepare handler saw: not run yet, A's status
/// descriptor open in this process at the `fork`, or no open within
/// `PREPARE_BOUND`.
static PREPARE_OUTCOME: AtomicU8 = AtomicU8::new(PREPARE_NOT_RUN);
const PREPARE_NOT_RUN: u8 = 0;
const PREPARE_HELD_OPEN: u8 = 1;
const PREPARE_TIMED_OUT: u8 = 2;
/// A's guest, which the prepare handler signals.
static A_GUEST: AtomicI32 = AtomicI32::new(0);
/// The inode of the pipe the prepare handler puts at `READY_READ`.
static PREPARED_INODE: AtomicUsize = AtomicUsize::new(0);

/// Where the child handler puts its eventfd, and the count it holds. The test
/// requires the number to be free before the launch.
const CHILD_EVENTFD: c_int = 304;
const CHILD_EVENTFD_COUNT: u64 = 42;
/// Set by the child handler, in B's forked child only; the test process never
/// sets it.
static CHILD_HANDLER_RAN: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// Set on B's launching thread for the prepare handler's one run.
    static SIGNAL_A_AT_FORK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Set by that run for the child handler, in B's forked child.
    static MAKE_CHILD_EVENTFD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// `pthread_atfork` prepare handler for the fourth test. On B's launching
/// thread only, it makes A's guest take a signal, waits until A's
/// signal-delivery stop holds its status read open, and replaces
/// `READY_READ`, open since before the launch, with a new pipe.
extern "C" fn signal_a_and_wait_for_its_open() {
    if !SIGNAL_A_AT_FORK
        .try_with(|s| s.replace(false))
        .unwrap_or(false)
    {
        return;
    }
    HOLD_NEXT_STATUS_OPEN.store(true, Ordering::SeqCst);
    // SAFETY: signals A's guest, a process this test started.
    unsafe { libc::kill(A_GUEST.load(Ordering::SeqCst), libc::SIGUSR1) };
    let hold = HOLD.lock().unwrap();
    let (hold, _) = HOLD_CHANGED
        .wait_timeout_while(hold, PREPARE_BOUND, |h| !h.opened)
        .unwrap();
    let outcome = if hold.opened && held_fd_open() {
        PREPARE_HELD_OPEN
    } else {
        PREPARE_TIMED_OUT
    };
    PREPARE_OUTCOME.store(outcome, Ordering::SeqCst);
    drop(hold);
    let mut fds = [0; 2];
    // SAFETY: `fds` is writable for two descriptors, and `stat` for one
    // `fstat`; the rest moves this test's own descriptors.
    unsafe {
        assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC), 0);
        assert_eq!(libc::dup3(fds[0], READY_READ, libc::O_CLOEXEC), READY_READ);
        libc::close(fds[0]);
        libc::close(fds[1]);
        let mut stat: libc::stat = std::mem::zeroed();
        assert_eq!(libc::fstat(READY_READ, &mut stat), 0);
        PREPARED_INODE.store(stat.st_ino as usize, Ordering::SeqCst);
    }
    MAKE_CHILD_EVENTFD.with(|m| m.set(true));
}

/// `pthread_atfork` child handler for the fourth test: in B's child only, puts
/// an eventfd holding `CHILD_EVENTFD_COUNT` at `CHILD_EVENTFD`.
extern "C" fn make_an_eventfd_in_the_child() {
    if !MAKE_CHILD_EVENTFD
        .try_with(|m| m.replace(false))
        .unwrap_or(false)
    {
        return;
    }
    // SAFETY: async-signal-safe calls on descriptors this handler makes.
    unsafe {
        let fd = libc::eventfd(CHILD_EVENTFD_COUNT as libc::c_uint, 0);
        if fd >= 0 && libc::dup3(fd, CHILD_EVENTFD, 0) == CHILD_EVENTFD {
            libc::close(fd);
        }
    }
    CHILD_HANDLER_RAN.store(true, Ordering::SeqCst);
}

/// Exit code of B's guest when the pipe the prepare handler made is not at
/// `READY_READ`.
const LOST_PREPARED: i32 = 75;
/// Exit code of B's guest when the child handler's eventfd is not at
/// `CHILD_EVENTFD` with its count.
const LOST_CHILD_MADE: i32 = 76;
/// Exit code of B's guest when the child handler did not run in its process.
const CHILD_HANDLER_NOT_RUN: i32 = 77;

/// Guest of tracer B for the fourth test: exits `CHILD_HANDLER_NOT_RUN`,
/// `LOST_PREPARED` or `LOST_CHILD_MADE` unless the child handler ran in this
/// process and both handlers' descriptors reached it.
fn check_atfork_descriptors_kept() {
    // SAFETY: reads this process's descriptors into locals, then ends the
    // guest without running the test process's exit handlers on failure.
    unsafe {
        if !CHILD_HANDLER_RAN.load(Ordering::SeqCst) {
            libc::_exit(CHILD_HANDLER_NOT_RUN);
        }
        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(READY_READ, &mut stat) != 0
            || stat.st_ino as usize != PREPARED_INODE.load(Ordering::SeqCst)
        {
            libc::_exit(LOST_PREPARED);
        }
        let mut count = 0u64;
        if libc::read(CHILD_EVENTFD, (&mut count as *mut u64).cast(), 8) != 8
            || count != CHILD_EVENTFD_COUNT
        {
            libc::_exit(LOST_CHILD_MADE);
        }
    }
}

/// A `spawn_fn_with_config` launch's `pthread_atfork` prepare handler may wait
/// for another tracer's transient open without a deadlock, and the descriptors
/// its prepare and child handlers make reach the guest.
#[test]
fn a_forked_launch_runs_atfork_handlers_outside_the_lock_and_keeps_their_descriptors() {
    static REGISTER: Once = Once::new();
    REGISTER.call_once(|| {
        // SAFETY: registers handlers that do nothing off B's thread and B's
        // child.
        let rc = unsafe {
            libc::pthread_atfork(
                Some(signal_a_and_wait_for_its_open),
                None,
                Some(make_an_eventfd_in_the_child),
            )
        };
        assert_eq!(rc, 0);
    });
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    pipe_at(REPLY_READ, REPLY_WRITE);
    pipe_at(READY_READ, READY_WRITE);
    *HOLD.lock().unwrap() = Hold::default();
    HELD_FD.store(-1, Ordering::SeqCst);
    *HELD_TARGET.lock().unwrap() = None;
    PREPARE_OUTCOME.store(PREPARE_NOT_RUN, Ordering::SeqCst);
    PREPARED_INODE.store(0, Ordering::SeqCst);
    // SAFETY: only queries a descriptor number.
    let child_eventfd_free = unsafe { libc::fcntl(CHILD_EVENTFD, libc::F_GETFD) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    assert!(
        child_eventfd_free,
        "descriptor {CHILD_EVENTFD} must be free before the launch"
    );
    assert!(!CHILD_HANDLER_RAN.load(Ordering::SeqCst));

    let tracer_a = std::thread::spawn(|| {
        run_tokio_test(async {
            let tracer = spawn_fn_with_config::<(), _>(reply_on_signal, (), false).await?;
            tracer.wait().await
        })
    });
    let mut ready = libc::pollfd {
        fd: READY_READ,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: polls one descriptor this test opened.
    let polled = unsafe { libc::poll(&mut ready, 1, BOUND.as_millis() as c_int) };
    assert_eq!(polled, 1, "tracer A's guest did not announce its PID");
    let mut pid = [0u8; 4];
    // SAFETY: reads into a local buffer; A's guest writes its PID in one write.
    let n = unsafe { libc::read(READY_READ, pid.as_mut_ptr().cast(), pid.len()) };
    assert_eq!(n, 4, "tracer A's guest did not announce its PID");
    A_GUEST.store(libc::pid_t::from_ne_bytes(pid), Ordering::SeqCst);

    let (returned_tx, returned_rx) = std::sync::mpsc::channel();
    let tracer_b = std::thread::spawn(move || {
        run_tokio_test(async move {
            SIGNAL_A_AT_FORK.with(|s| s.set(true));
            let launched =
                spawn_fn_with_config::<(), _>(check_atfork_descriptors_kept, (), false).await;
            SIGNAL_A_AT_FORK.with(|s| s.set(false));
            returned_tx.send(()).unwrap();
            match launched {
                Ok(tracer) => tracer
                    .wait()
                    .await
                    .map(|(status, ())| status)
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
        })
    });

    let returned = returned_rx.recv_timeout(BOUND).is_ok();
    let prepare = PREPARE_OUTCOME.load(Ordering::SeqCst);
    eprintln!(
        "launch_descriptor_window: atfork prepare outcome {prepare} (1 = A's descriptor held \
         open at the fork, 2 = timed out), B's launch returned: {returned}"
    );
    {
        let mut hold = HOLD.lock().unwrap();
        hold.released = true;
        HOLD_CHANGED.notify_all();
    }
    let b = tracer_b.join().unwrap();
    let a = tracer_a.join().unwrap();
    for fd in [REPLY_READ, REPLY_WRITE, READY_READ, READY_WRITE] {
        // SAFETY: descriptors this test opened.
        unsafe { libc::close(fd) };
    }
    assert!(returned, "B's launch did not return within {BOUND:?}");
    assert_eq!(
        prepare, PREPARE_HELD_OPEN,
        "the prepare handler must see A's status descriptor open (2 = A's open waited for B's \
         launch, which waited for the handler)"
    );
    assert!(
        !CHILD_HANDLER_RAN.load(Ordering::SeqCst),
        "the child handler ran in the test process"
    );
    assert_eq!(
        b,
        Ok(ExitStatus::Exited(0)),
        "B's guest exited {CHILD_HANDLER_NOT_RUN} if the child handler did not run in it, \
         {LOST_PREPARED} if it lost the prepare handler's pipe, {LOST_CHILD_MADE} if it lost \
         the child handler's eventfd"
    );
    assert_eq!(a.map(|(status, ())| status).unwrap(), ExitStatus::Exited(0));
}

/// Allocator calls made by a thread while it held the launch lock.
static ALLOCATOR_CALLS_UNDER_LAUNCH: AtomicUsize = AtomicUsize::new(0);

fn note_allocator_call() {
    if reverie::process::launch_window::held_by_this_thread() {
        ALLOCATOR_CALLS_UNDER_LAUNCH.fetch_add(1, Ordering::SeqCst);
    }
}

/// The system allocator, counting the calls made under the launch lock.
struct CountingUnderLaunch;

// SAFETY: every call is forwarded unchanged to the system allocator.
unsafe impl std::alloc::GlobalAlloc for CountingUnderLaunch {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        note_allocator_call();
        // SAFETY: the caller's contract, forwarded.
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
        note_allocator_call();
        // SAFETY: the caller's contract, forwarded.
        unsafe { std::alloc::System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        note_allocator_call();
        // SAFETY: the caller's contract, forwarded.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
        note_allocator_call();
        // SAFETY: the caller's contract, forwarded.
        unsafe { std::alloc::System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingUnderLaunch = CountingUnderLaunch;

/// Neither launch path allocates or frees memory while it holds the launch
/// lock: `TracerBuilder::spawn` (reverie-process's `Command::spawn`) and
/// `spawn_fn_with_config`.
#[test]
fn a_launch_makes_no_allocator_call_while_it_holds_the_lock() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let before = ALLOCATOR_CALLS_UNDER_LAUNCH.load(Ordering::SeqCst);
    let command = run_tokio_test(async {
        let mut command = reverie::process::Command::new("/bin/true");
        command.env("LAUNCH_DESCRIPTOR_WINDOW", "an environment entry to copy");
        let tracer = TracerBuilder::<()>::new(command)
            .spawn()
            .await
            .map_err(|e| e.to_string())?;
        tracer
            .wait()
            .await
            .map(|(status, ())| status)
            .map_err(|e| e.to_string())
    });
    let forked = run_tokio_test(async {
        let tracer = spawn_fn_with_config::<(), _>(|| {}, (), false).await?;
        tracer.wait().await
    });
    let under_launch = ALLOCATOR_CALLS_UNDER_LAUNCH.load(Ordering::SeqCst) - before;
    assert_eq!(command, Ok(ExitStatus::Exited(0)));
    assert_eq!(
        forked.map(|(status, ())| status).unwrap(),
        ExitStatus::Exited(0)
    );
    assert_eq!(
        under_launch, 0,
        "a launching thread called the allocator {under_launch} times while it held the lock"
    );
}
