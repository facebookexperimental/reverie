//! The runtime's own mask under a Tool that takes the in-guest backend's
//! signal delivery (`Tool::in_guest_signal_delivery` true), on the shared
//! runtime with no patcher (`TrapHost`), so every syscall reaches the Tool
//! through the fallback continuation.
//!
//! Each scenario prints lines that a test compares with the same scenario
//! run natively (`native`), with no runtime: what the guest observes of its
//! own mask and pending set must be Linux's. The kernel's own view is read
//! from guest code through the runtime's trusted gate, which no Tool sees:
//! after a completion it is the mask the guest runs under.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io::Write;
use std::path::Path;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

const fn bit(signal: i32) -> u64 {
    1 << (signal - 1)
}

/// The `getppid` argument that asks the Tool for `Guest::resume_signal_mask`
/// (stored in [`RESUME_MASKS`] at the index in the second argument); with a
/// third argument of 1 it first prepares a SIGALRM delivery for this return.
const RESUME_MASK_MARKER: usize = 0x5160;

/// A signal the Tool sends the calling thread itself, through an injected
/// `tgkill`, before it runs the next `rt_sigprocmask` or `rt_sigtimedwait`:
/// an arrival while the thread is in its runtime. 0 for none; taken once.
static SEND_BEFORE_MASK_CALL: AtomicI32 = AtomicI32::new(0);

/// The `getppid` argument that asks the Tool to make, with its own private
/// mask buffer, an `rt_sigsuspend` through `Guest::inject` (second argument 0)
/// or `Guest::tail_inject` (1): a call the runtime must refuse under the gate
/// whatever the guest's protection keys.
const PRIVATE_SIGSUSPEND_MARKER: usize = 0x5161;

/// The `getppid` arguments around the counted calls (`run_count`), which a
/// tracing test finds by their first argument.
pub(super) const COUNT_START_MARKER: usize = 0x5162;
pub(super) const COUNT_END_MARKER: usize = 0x5163;
/// `Guest::resume_signal_mask` as the Tool saw it (`u64::MAX` for `None`).
static RESUME_MASKS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static HANDLER_RAN: AtomicBool = AtomicBool::new(false);
static PREPARE_RESULT: AtomicI64 = AtomicI64::new(1);

async fn handle<T: Tool, G: Guest<T>>(guest: &mut G, syscall: Syscall) -> Result<i64, Error> {
    let args = syscall.into_parts().1;
    if syscall.number() == Sysno::getppid && args.arg0 == RESUME_MASK_MARKER {
        let record = |slot: usize, mask: Option<u64>| {
            RESUME_MASKS[slot].store(mask.unwrap_or(u64::MAX), Ordering::SeqCst);
        };
        if args.arg2 == 1 {
            record(args.arg1, guest.resume_signal_mask());
            let mut info = [0_u8; 128];
            info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
            info[8..12].copy_from_slice(&0x80_i32.to_ne_bytes());
            let event = reverie::SignalEvent::new(
                libc::SIGALRM,
                info,
                reverie::SignalTarget::Process { pid: guest.pid() },
            )
            .unwrap();
            let prepared = match guest.defer_signal_delivery(event).await {
                Ok(()) => 0,
                Err(Error::Errno(errno)) => -i64::from(errno.into_raw()),
                Err(_) => -i64::from(libc::EIO),
            };
            PREPARE_RESULT.store(prepared, Ordering::SeqCst);
            record(args.arg1 + 1, guest.resume_signal_mask());
        } else {
            record(args.arg1, guest.resume_signal_mask());
        }
        return Ok(0);
    }
    if syscall.number() == Sysno::getppid && args.arg0 == PRIVATE_SIGSUSPEND_MARKER {
        // The Tool's own buffer, which the guest's keys do not cover.
        let mask = Box::new(bit(libc::SIGUSR1));
        let call = reverie::syscalls::RtSigsuspend::new()
            .with_mask(Some(
                reverie::syscalls::Addr::from_raw(&*mask as *const u64 as usize).unwrap(),
            ))
            .with_sigsetsize(8);
        if args.arg1 == 1 {
            guest.tail_inject(call).await;
        }
        return Ok(guest.inject(call).await?);
    }
    if syscall.number() == Sysno::getpid {
        // The Tool's view of the calling process, which the runtime caches
        // under the gate: a fork child must see its own.
        return Ok(i64::from(guest.pid().as_raw()));
    }
    if matches!(
        syscall.number(),
        Sysno::rt_sigprocmask | Sysno::rt_sigtimedwait
    ) {
        let signal = SEND_BEFORE_MASK_CALL.swap(0, Ordering::SeqCst);
        if signal != 0 {
            let sent = guest
                .inject(
                    reverie::syscalls::Tgkill::new()
                        .with_tgid(guest.pid().as_raw())
                        .with_tid(guest.tid().as_raw())
                        .with_sig(signal),
                )
                .await?;
            assert_eq!(sent, 0);
        }
    }
    Ok(guest.inject(syscall).await?)
}

macro_rules! gate_tool {
    ($name:ident, $delivers:expr, $subscriptions:expr) => {
        #[derive(Default)]
        struct $name;

        #[reverie::tool]
        impl Tool for $name {
            type GlobalState = super::CounterGlobal;
            type ThreadState = ();

            fn subscriptions(_cfg: &()) -> Subscription {
                $subscriptions
            }

            fn in_guest_signal_delivery(_cfg: &()) -> bool {
                $delivers
            }

            async fn handle_syscall_event<G: Guest<Self>>(
                &self,
                guest: &mut G,
                syscall: Syscall,
            ) -> Result<i64, Error> {
                handle::<Self, G>(guest, syscall).await
            }
        }
    };
}

gate_tool!(GateTool, true, Subscription::all_syscalls());
gate_tool!(UngatedTool, false, Subscription::all_syscalls());
gate_tool!(
    UnsubscribedGateTool,
    true,
    [Sysno::getppid, Sysno::getpid].into_iter().collect()
);

fn install(path: &Path, tool: &str, sigalrm_handlers: bool) {
    let mut options = reverie_inguest::guest::tool_install::TrapOptions {
        sigalrm_handlers,
        ..Default::default()
    };
    options.config.use_alt_stack = reverie_liteinst::alt_stack_from_env_value(
        std::env::var_os(reverie_liteinst::ALT_STACK_ENV).as_deref(),
    )
    .expect("alternate-stack selector");
    let host = reverie_inguest::guest::tool_install::TrapHost::new(options);
    let installed = unsafe {
        match tool {
            "gated" => reverie_inguest::guest::tool_install::install_tool_with::<GateTool, _>(
                path, true, host,
            ),
            "ungated" => reverie_inguest::guest::tool_install::install_tool_with::<UngatedTool, _>(
                path, true, host,
            ),
            "unsubscribed" => reverie_inguest::guest::tool_install::install_tool_with::<
                UnsubscribedGateTool,
                _,
            >(path, true, host),
            other => panic!("unknown Tool {other:?}"),
        }
    };
    installed.expect("install the gate Tool");
}

/// `rt_sigprocmask(how, set, old, size)` through the guest's own (trapped)
/// syscall, its raw result (a value or a negated errno).
fn mask_call(how: i32, set: *const u64, old: *mut u64, size: usize) -> i64 {
    let result = unsafe { libc::syscall(libc::SYS_rt_sigprocmask, how, set, old, size) };
    errno_result(result)
}

fn errno_result(result: libc::c_long) -> i64 {
    if result < 0 {
        -i64::from(std::io::Error::last_os_error().raw_os_error().unwrap())
    } else {
        result
    }
}

/// The guest's mask, through its own query.
fn guest_mask() -> u64 {
    let mut old = 0_u64;
    assert_eq!(
        mask_call(libc::SIG_BLOCK, core::ptr::null(), &mut old, 8),
        0
    );
    old
}

/// The kernel's mask for this thread, read through the runtime's trusted
/// gate from guest code (no Tool sees it): the mask the guest runs under.
fn kernel_mask() -> u64 {
    let mut mask = 0;
    unsafe { reverie_inguest::signal::raw_sigprocmask(libc::SIG_BLOCK, None, Some(&mut mask)) }
        .unwrap();
    mask
}

fn pending_call(set: *mut u8, size: usize) -> i64 {
    errno_result(unsafe { libc::syscall(libc::SYS_rt_sigpending, set, size) })
}

fn pending() -> u64 {
    let mut set = 0_u64;
    assert_eq!(pending_call((&raw mut set).cast(), 8), 0);
    set
}

fn raise(signal: i32) {
    let result = unsafe {
        libc::syscall(
            libc::SYS_tgkill,
            libc::getpid(),
            libc::syscall(libc::SYS_gettid),
            signal,
        )
    };
    assert_eq!(result, 0);
}

/// Takes one pending `signal` with a zero-timeout `rt_sigtimedwait`, the
/// guest's own call; its result.
fn take(signal: i32) -> i64 {
    let set = bit(signal);
    let zero = [0_i64; 2];
    errno_result(unsafe {
        libc::syscall(
            libc::SYS_rt_sigtimedwait,
            &set as *const u64,
            core::ptr::null_mut::<u8>(),
            zero.as_ptr(),
            8,
        )
    })
}

/// A page with protection `protection`, for unreadable and unwritable sets.
fn page(protection: i32) -> *mut u64 {
    let mapping = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            protection,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    mapping.cast()
}

const SENTINEL: u64 = 0x5a5a_5a5a_5a5a_5a5a;

/// The calls on the blocked set, row by row, in Linux's order; also run
/// natively. The kernel's mask is printed after each change that returns to
/// guest code.
fn mask_rows(out: &mut impl Write) {
    let usr1 = bit(libc::SIGUSR1);
    let usr2 = bit(libc::SIGUSR2);
    let hup = bit(libc::SIGHUP);
    let term = bit(libc::SIGTERM);
    let kill_stop = bit(libc::SIGKILL) | bit(libc::SIGSTOP);
    let unreadable = page(libc::PROT_NONE);
    let read_only = page(libc::PROT_READ);
    let initial = guest_mask();
    writeln!(out, "initial mask={initial:#x} kernel={:#x}", kernel_mask()).unwrap();
    fn row(
        out: &mut impl Write,
        name: &str,
        how: i32,
        set: Option<u64>,
        old: *mut u64,
        size: usize,
    ) {
        let set_value = set.unwrap_or(0);
        let set_pointer = if set.is_some() {
            &set_value as *const u64
        } else {
            core::ptr::null()
        };
        let result = mask_call(how, set_pointer, old, size);
        writeln!(
            out,
            "{name} result={result} mask={:#x} kernel={:#x}",
            guest_mask(),
            kernel_mask()
        )
        .unwrap();
    }
    let mut old = SENTINEL;
    row(
        out,
        "setmask-usr1",
        libc::SIG_SETMASK,
        Some(usr1),
        &mut old,
        8,
    );
    writeln!(out, "  old={old:#x}").unwrap();
    row(out, "block-usr2", libc::SIG_BLOCK, Some(usr2), &mut old, 8);
    writeln!(out, "  old={old:#x}").unwrap();
    row(
        out,
        "unblock-usr1",
        libc::SIG_UNBLOCK,
        Some(usr1),
        &mut old,
        8,
    );
    writeln!(out, "  old={old:#x}").unwrap();
    row(
        out,
        "block-kill-stop-term",
        libc::SIG_BLOCK,
        Some(kill_stop | term),
        &mut old,
        8,
    );
    old = SENTINEL;
    row(out, "invalid-how-with-set", 99, Some(hup), &mut old, 8);
    writeln!(out, "  old={old:#x}").unwrap();
    old = SENTINEL;
    row(out, "invalid-how-null-set", 99, None, &mut old, 8);
    writeln!(out, "  old={old:#x}").unwrap();
    old = SENTINEL;
    let result = mask_call(99, unreadable, &mut old, 8);
    writeln!(
        out,
        "invalid-how-unreadable-set result={result} mask={:#x} old={old:#x}",
        guest_mask()
    )
    .unwrap();
    old = SENTINEL;
    row(out, "size-4", libc::SIG_BLOCK, Some(hup), &mut old, 4);
    writeln!(out, "  old={old:#x}").unwrap();
    row(
        out,
        "unwritable-old",
        libc::SIG_BLOCK,
        Some(hup),
        read_only,
        8,
    );
    row(
        out,
        "query-null-old",
        libc::SIG_BLOCK,
        None,
        core::ptr::null_mut(),
        8,
    );

    // rt_sigpending: the pending set within the guest's mask.
    row(
        out,
        "setmask-usr1-usr2",
        libc::SIG_SETMASK,
        Some(usr1 | usr2),
        &mut old,
        8,
    );
    raise(libc::SIGUSR1);
    let mut set = SENTINEL;
    let result = pending_call((&raw mut set).cast(), 8);
    writeln!(out, "pending-8 result={result} set={set:#x}").unwrap();
    let result = pending_call(unreadable.cast(), 0);
    writeln!(out, "pending-0-unwritable result={result}").unwrap();
    let result = pending_call((&raw mut set).cast(), 9);
    writeln!(out, "pending-9 result={result}").unwrap();
    set = SENTINEL;
    let result = pending_call((&raw mut set).cast(), 4);
    writeln!(out, "pending-4 result={result} set={set:#x}").unwrap();
    let result = pending_call(read_only.cast(), 8);
    writeln!(out, "pending-unwritable result={result}").unwrap();
    // A zero-timeout rt_sigtimedwait of a blocked pending signal runs.
    writeln!(
        out,
        "sigtimedwait-zero taken={} again={} pending={:#x}",
        take(libc::SIGUSR1),
        take(libc::SIGUSR1),
        pending()
    )
    .unwrap();
    // A signalfd read of a blocked pending signal runs.
    raise(libc::SIGUSR2);
    let fd = unsafe {
        libc::syscall(
            libc::SYS_signalfd4,
            -1,
            &usr2 as *const u64,
            8,
            libc::SFD_NONBLOCK | libc::SFD_CLOEXEC,
        )
    };
    assert!(fd >= 0);
    let mut info = [0_u8; 128];
    let read = unsafe { libc::read(fd as i32, info.as_mut_ptr().cast(), info.len()) };
    let signo = u32::from_ne_bytes(info[0..4].try_into().unwrap());
    unsafe { libc::close(fd as i32) };
    writeln!(
        out,
        "signalfd read={read} signo={signo} pending={:#x}",
        pending()
    )
    .unwrap();
    row(
        out,
        "restore",
        libc::SIG_SETMASK,
        Some(initial),
        &mut old,
        8,
    );
}

/// An ignored signal that arrives while the thread is in its runtime, outside
/// the guest's mask, is discarded as Linux discards it at send, even when the
/// next call blocks it; one the guest's mask already blocked stays. Natively
/// the guest sends it itself, just before the call.
fn discard_rows(out: &mut impl Write, gated: bool) {
    let send_then_block = |signal: i32| {
        if gated {
            SEND_BEFORE_MASK_CALL.store(signal, Ordering::SeqCst);
        } else {
            raise(signal);
        }
        let set = bit(signal);
        let result = mask_call(libc::SIG_BLOCK, &set, core::ptr::null_mut(), 8);
        assert_eq!(result, 0);
        assert_eq!(SEND_BEFORE_MASK_CALL.load(Ordering::SeqCst), 0);
    };
    let ignore = |signal: i32, handler: libc::sighandler_t| {
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        action.sa_sigaction = handler;
        assert_eq!(
            unsafe { libc::sigaction(signal, &action, core::ptr::null_mut()) },
            0
        );
    };
    ignore(libc::SIGUSR2, libc::SIG_IGN);
    for (name, signal) in [
        ("sigurg-default", libc::SIGURG),
        ("sigchld-default", libc::SIGCHLD),
        ("sigusr2-ignored", libc::SIGUSR2),
    ] {
        let zero = 0_u64;
        assert_eq!(
            mask_call(libc::SIG_SETMASK, &zero, core::ptr::null_mut(), 8),
            0
        );
        send_then_block(signal);
        writeln!(out, "discard {name} pending={:#x}", pending()).unwrap();
        // Already blocked when it arrives: queued, on Linux too.
        send_then_block(signal);
        writeln!(
            out,
            "keep {name} pending={:#x} taken={}",
            pending(),
            take(signal)
        )
        .unwrap();
    }
    // An ignored SIGURG the guest's mask lets in, arriving while the runtime
    // runs, just before a zero-timeout rt_sigtimedwait for it: Linux discarded
    // it at send, so the call finds nothing.
    let zero = 0_u64;
    assert_eq!(
        mask_call(libc::SIG_SETMASK, &zero, core::ptr::null_mut(), 8),
        0
    );
    if gated {
        SEND_BEFORE_MASK_CALL.store(libc::SIGURG, Ordering::SeqCst);
    } else {
        raise(libc::SIGURG);
    }
    let taken = take(libc::SIGURG);
    assert_eq!(SEND_BEFORE_MASK_CALL.load(Ordering::SeqCst), 0);
    writeln!(out, "discard sigurg-before-sigtimedwait taken={taken}").unwrap();
    ignore(libc::SIGUSR2, libc::SIG_DFL);
    assert_eq!(
        mask_call(libc::SIG_SETMASK, &zero, core::ptr::null_mut(), 8),
        0
    );
}

/// A fork child starts with its parent's mask, and its cached identity is
/// its own.
fn fork_rows(out: &mut impl Write) {
    let usr1 = bit(libc::SIGUSR1);
    let shared = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    }
    .cast::<AtomicU64>();
    assert_ne!(shared.cast(), libc::MAP_FAILED);
    let shared = unsafe { core::slice::from_raw_parts(shared, 3) };
    assert_eq!(
        mask_call(libc::SIG_SETMASK, &usr1, core::ptr::null_mut(), 8),
        0
    );
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        // The child's first instructions: the kernel's mask, then its own.
        shared[0].store(kernel_mask(), Ordering::SeqCst);
        shared[1].store(guest_mask(), Ordering::SeqCst);
        shared[2].store(
            unsafe { libc::syscall(libc::SYS_getpid) } as u64,
            Ordering::SeqCst,
        );
        unsafe { libc::_exit(0) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    writeln!(
        out,
        "fork child-kernel={:#x} child-mask={:#x} child-getpid={}",
        shared[0].load(Ordering::SeqCst),
        shared[1].load(Ordering::SeqCst),
        if shared[2].load(Ordering::SeqCst) == child as u64 {
            "child"
        } else {
            "other"
        }
    )
    .unwrap();
    let parent = unsafe { libc::syscall(libc::SYS_getpid) };
    writeln!(
        out,
        "parent-getpid={}",
        if parent == i64::from(std::process::id()) {
            "parent"
        } else {
            "other"
        }
    )
    .unwrap();
    let zero = 0_u64;
    assert_eq!(
        mask_call(libc::SIG_SETMASK, &zero, core::ptr::null_mut(), 8),
        0
    );
}

/// Every scenario, natively (`tool` "native") or under a Tool.
pub(super) fn run(path: &Path, tool: &str) {
    if tool != "native" {
        install(path, tool, false);
    }
    let gated = tool != "native" && tool != "ungated";
    let mut out = std::io::stdout().lock();
    mask_rows(&mut out);
    discard_rows(&mut out, gated && tool == "gated");
    fork_rows(&mut out);
    out.flush().unwrap();
}

unsafe extern "C" fn resume_handler(_signal: libc::c_int) {
    HANDLER_RAN.store(true, Ordering::SeqCst);
    // A call from the handler: the Tool sees the mask the handler runs under.
    unsafe { libc::syscall(libc::SYS_getppid, RESUME_MASK_MARKER, 3, 0) };
}

/// `Guest::resume_signal_mask` under the gate, with signal phase 1's SIGALRM
/// handler: the saved mask, and, once a delivery is prepared for this return,
/// the mask the handler runs under, which is also the one its own calls carry.
pub(super) fn run_resume(path: &Path, tool: &str) {
    install(path, tool, true);
    let usr1 = bit(libc::SIGUSR1);
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = resume_handler as *const () as usize;
    unsafe { libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2) };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGALRM, &action, core::ptr::null_mut()) },
        0
    );
    assert_eq!(
        mask_call(libc::SIG_SETMASK, &usr1, core::ptr::null_mut(), 8),
        0
    );
    unsafe { libc::syscall(libc::SYS_getppid, RESUME_MASK_MARKER, 0, 0) };
    unsafe { libc::syscall(libc::SYS_getppid, RESUME_MASK_MARKER, 1, 1) };
    let show = |slot: usize| match RESUME_MASKS[slot].load(Ordering::SeqCst) {
        u64::MAX => "none".to_owned(),
        mask => format!("{mask:#x}"),
    };
    println!(
        "resume plain={} before-prepare={} after-prepare={} in-handler={} prepared={} handler-ran={} after={:#x}",
        show(0),
        show(1),
        show(2),
        show(3),
        PREPARE_RESULT.load(Ordering::SeqCst),
        HANDLER_RAN.load(Ordering::SeqCst),
        guest_mask(),
    );
}

/// One call that the runtime must refuse to forward raw under the gate when
/// it would install a mask, and must run otherwise.
pub(super) fn run_forward(path: &Path, tool: &str, row: &str) {
    install(path, tool, false);
    let usr1 = bit(libc::SIGUSR1);
    let zero = [0_i64; 2];
    let invalid = [0_i64, 1_000_000_000];
    let result = unsafe {
        match row {
            "sigsuspend" => libc::syscall(libc::SYS_rt_sigsuspend, &usr1 as *const u64, 8),
            "sigtimedwait-null" => libc::syscall(
                libc::SYS_rt_sigtimedwait,
                &usr1 as *const u64,
                core::ptr::null_mut::<u8>(),
                core::ptr::null::<u8>(),
                8,
            ),
            "sigtimedwait-zero" => libc::syscall(
                libc::SYS_rt_sigtimedwait,
                &usr1 as *const u64,
                core::ptr::null_mut::<u8>(),
                zero.as_ptr(),
                8,
            ),
            "ppoll-masked" => libc::syscall(
                libc::SYS_ppoll,
                core::ptr::null_mut::<u8>(),
                0,
                zero.as_ptr(),
                &usr1 as *const u64,
                8,
            ),
            "ppoll-invalid-timeout" => libc::syscall(
                libc::SYS_ppoll,
                core::ptr::null_mut::<u8>(),
                0,
                invalid.as_ptr(),
                &usr1 as *const u64,
                8,
            ),
            "pselect6-masked" => {
                let pack = [&usr1 as *const u64 as u64, 8];
                libc::syscall(
                    libc::SYS_pselect6,
                    0,
                    core::ptr::null_mut::<u8>(),
                    core::ptr::null_mut::<u8>(),
                    core::ptr::null_mut::<u8>(),
                    zero.as_ptr(),
                    pack.as_ptr(),
                )
            }
            "sigtimedwait-pending-1s" | "sigtimedwait-pending-null" => {
                // A waited-for signal already pending, blocked: Linux
                // dequeues it at once, installing nothing.
                assert_eq!(
                    mask_call(libc::SIG_BLOCK, &usr1, core::ptr::null_mut(), 8),
                    0
                );
                raise(libc::SIGUSR1);
                let second = [1_i64, 0];
                let timeout = if row == "sigtimedwait-pending-1s" {
                    second.as_ptr()
                } else {
                    core::ptr::null()
                };
                libc::syscall(
                    libc::SYS_rt_sigtimedwait,
                    &usr1 as *const u64,
                    core::ptr::null_mut::<u8>(),
                    timeout,
                    8,
                )
            }
            "pkru-inject" | "pkru-tail" => {
                // The guest's keys deny key 0 while it asks the Tool for an
                // rt_sigsuspend on the Tool's own buffer.
                let mode = u64::from(row == "pkru-tail");
                match super::syscall_with_key_zero_denied(
                    1,
                    libc::SYS_getppid,
                    [PRIVATE_SIGSUSPEND_MARKER as u64, mode, 0, 0],
                ) {
                    Some(result) => result,
                    None => {
                        println!("forward {row} OSPKE unavailable");
                        return;
                    }
                }
            }
            "signalfd" => {
                let fd = libc::syscall(libc::SYS_signalfd4, -1, &usr1 as *const u64, 8, 0);
                if fd >= 0 {
                    libc::close(fd as i32);
                    0
                } else {
                    fd
                }
            }
            other => panic!("unknown row {other:?}"),
        }
    };
    let result = if row.starts_with("pkru-") {
        result
    } else {
        errno_result(result)
    };
    println!("forward {row} result={result}");
}

/// The `sa_mask` of the runtime's SIGSYS action, read through the trusted
/// gate: the runtime mask under the gate, so the kernel blocks every other
/// guest signal from the trap on; none otherwise.
pub(super) fn run_actions(path: &Path, tool: &str) {
    install(path, tool, false);
    let mut action = reverie_inguest::signal::KernelSigaction::default();
    unsafe { reverie_inguest::signal::raw_sigaction(libc::SIGSYS, None, Some(&mut action)) }
        .unwrap();
    println!("sigsys-action-mask={:#x}", action.mask);
}

/// Between two marker calls a tracing test counts the runtime's host
/// syscalls: `calls` plain `getppid` calls, each one event.
pub(super) fn run_count(path: &Path, tool: &str, calls: u64) {
    install(path, tool, false);
    unsafe { libc::syscall(libc::SYS_getppid, COUNT_START_MARKER) };
    for _ in 0..calls {
        unsafe { libc::syscall(libc::SYS_getppid) };
    }
    unsafe { libc::syscall(libc::SYS_getppid, COUNT_END_MARKER) };
    println!("count {tool} calls={calls}");
}
