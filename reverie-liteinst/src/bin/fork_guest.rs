use core::arch::global_asm;
use std::process;

const CHILD_MESSAGE: &[u8] = b"fork child reached guest code\n";

fn main() {
    let mode = std::env::args_os().nth(1);
    if mode.as_deref() == Some(std::ffi::OsStr::new("--unsafe-clone")) {
        probe_unsafe_clone();
        return;
    }
    if mode.as_deref() == Some(std::ffi::OsStr::new("--unsafe-process")) {
        probe_unsafe_process_creation();
        return;
    }
    let raw_fork = mode.as_deref() == Some(std::ffi::OsStr::new("--raw-fork"));
    let child = unsafe {
        if raw_fork {
            libc::syscall(libc::SYS_fork) as libc::pid_t
        } else {
            libc::fork()
        }
    };
    if child < 0 {
        eprintln!("fork failed: {}", std::io::Error::last_os_error());
        process::exit(1);
    }

    if child == 0 {
        unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                CHILD_MESSAGE.as_ptr().cast(),
                CHILD_MESSAGE.len(),
            );
            libc::_exit(0);
        }
    }

    let mut status = 0;
    if unsafe { libc::waitpid(child, &mut status, 0) } != child {
        eprintln!("waitpid failed: {}", std::io::Error::last_os_error());
        process::exit(1);
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        eprintln!("child status was {status}");
        process::exit(1);
    }

    println!("fork parent observed child {child}");
}

fn probe_unsafe_clone() {
    let flags = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
    let result = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
    if result == 0 {
        unsafe {
            libc::_exit(90);
        }
    }
    if result >= 0 {
        eprintln!("unsafe clone unexpectedly created child {result}");
        process::exit(1);
    }
    println!(
        "unsafe clone rejected: {}",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    );
}

// Two syscall sites that nothing else executes, laid out like
// trap_count_guest's fixed getpid site. Each is called once, so that call
// reaches LiteInst through the SIGSYS trap that first claims the site, not
// through a hook installed by an earlier call; the probe checks the site's
// trap count to confirm it. The probes through libc's `syscall()` site reach
// LiteInst through the hook that the probe's first `getpid` installs there.
global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_fresh_site_vfork
    .hidden reverie_liteinst_fresh_site_vfork
    .type reverie_liteinst_fresh_site_vfork,@function
reverie_liteinst_fresh_site_vfork:
    .cfi_startproc
    mov eax, 58
    .global reverie_liteinst_fresh_site_vfork_syscall
    .hidden reverie_liteinst_fresh_site_vfork_syscall
reverie_liteinst_fresh_site_vfork_syscall:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_fresh_site_vfork, .-reverie_liteinst_fresh_site_vfork

    .p2align 4
    .global reverie_liteinst_fresh_site_clone3
    .hidden reverie_liteinst_fresh_site_clone3
    .type reverie_liteinst_fresh_site_clone3,@function
reverie_liteinst_fresh_site_clone3:
    .cfi_startproc
    mov eax, 435
    .global reverie_liteinst_fresh_site_clone3_syscall
    .hidden reverie_liteinst_fresh_site_clone3_syscall
reverie_liteinst_fresh_site_clone3_syscall:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_fresh_site_clone3, .-reverie_liteinst_fresh_site_clone3
"#
);

unsafe extern "C" {
    /// Raw `vfork` from its own syscall site. Returns the kernel's result:
    /// a pid, 0 in a child, or a negative errno.
    fn reverie_liteinst_fresh_site_vfork() -> i64;
    static reverie_liteinst_fresh_site_vfork_syscall: u8;
    /// Raw `clone3(args, size)` from its own syscall site. Returns the
    /// kernel's result like [`reverie_liteinst_fresh_site_vfork`].
    fn reverie_liteinst_fresh_site_clone3(args: *const u64, size: usize) -> i64;
    static reverie_liteinst_fresh_site_clone3_syscall: u8;
}

/// SIGSYS deliveries LiteInst has counted at the syscall instruction at
/// `site`. Panics if the LiteInst runtime is not loaded.
fn site_trap_count(site: *const u8) -> u64 {
    // SAFETY: RTLD_DEFAULT searches already loaded DSOs and the name is
    // terminated.
    let symbol = unsafe {
        libc::dlsym(
            libc::RTLD_DEFAULT,
            c"reverie_liteinst_site_trap_count".as_ptr(),
        )
    };
    assert!(!symbol.is_null(), "the LiteInst runtime is not loaded");
    // SAFETY: the runtime exports this counter with exactly this C ABI.
    let count: unsafe extern "C" fn(u64) -> u64 = unsafe { core::mem::transmute(symbol) };
    // SAFETY: the counter only looks the address up in the site table.
    unsafe { count(site as usize as u64) }
}

/// Issue raw `vfork` and seven `clone3` shapes through libc's `syscall()`
/// site, then `vfork` and a fork-shaped `clone3` once each from syscall sites
/// of their own. Each must be refused with `ENOTSUP` before the kernel sees it:
/// no task may be created, the kernel's own `EINVAL`/`EPERM` for malformed
/// `clone_args` must not surface, and the parent's stack and TLS canaries must
/// be unchanged afterwards.
fn probe_unsafe_process_creation() {
    std::thread_local! {
        static TLS_CANARY: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    }
    const CANARY: u64 = 0x4c49_5445_464f_524b;
    // `struct clone_args` through `cgroup`: eleven u64 fields.
    const CLONE_ARGS_SIZE_VER2: usize = 88;
    const SIGCHLD: u64 = libc::SIGCHLD as u64;
    let mut stack_canary = CANARY;
    let stack_canary_address = &raw mut stack_canary;
    TLS_CANARY.set(CANARY);
    // The first call traps and installs the hook on libc's `syscall()` site, so
    // every probe through that site reaches the dispatcher through the hook.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    assert!(
        pid > 0 && tid > 0,
        "parent identity must be available before the refusal probes"
    );
    let child_stack = [0_u64; 1024];
    let child_stack_base = child_stack.as_ptr() as u64;
    let child_stack_size = std::mem::size_of_val(&child_stack) as u64;
    let clone_args = |flags: u64, exit_signal: u64, stack: bool, tls: u64| {
        let mut clone_args = [0_u64; CLONE_ARGS_SIZE_VER2 / 8];
        clone_args[0] = flags;
        clone_args[4] = exit_signal;
        if stack {
            clone_args[5] = child_stack_base;
            clone_args[6] = child_stack_size;
        }
        clone_args[7] = tls;
        clone_args
    };
    // Check one probe's libc-style result (-1 and `errno` on failure) and
    // return its report.
    let expect_refused = |name: &str, flags: u64, result: i64, errno: i32| {
        if result == 0 {
            // A faulty admission created a child. A child sharing the
            // parent's memory makes these writes visible to the parent.
            TLS_CANARY.set(0);
            unsafe {
                core::ptr::write_volatile(stack_canary_address, 0);
                libc::_exit(90);
            }
        }
        if result > 0 {
            // A thread cannot be reaped, and signalling it would kill this
            // process too, so fail at once; exiting takes the thread down.
            assert!(
                flags & libc::CLONE_THREAD as u64 == 0,
                "{name} created thread {result}"
            );
            // The refusal failed and created a task. Kill it before reaping it
            // rather than wait for it to exit: a child started on its own stack
            // inside the forwarding code can spin forever, which would hang
            // this probe instead of failing it. SIGKILL cannot be blocked, so
            // the wait below is bounded.
            let child = result as libc::pid_t;
            assert_eq!(
                unsafe { libc::kill(child, libc::SIGKILL) },
                0,
                "failed to kill unexpected {name} child {child}"
            );
            let mut status = 0;
            loop {
                let waited = unsafe { libc::waitpid(child, &mut status, 0) };
                if waited == child {
                    break;
                }
                assert!(
                    waited == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR),
                    "failed to reap unexpected {name} child {child}"
                );
            }
        }
        assert_eq!(result, -1, "{name} created task {result}");
        assert_eq!(
            errno,
            libc::ENOTSUP,
            "{name} was not refused before forwarding"
        );
        assert_eq!(
            unsafe { core::ptr::read_volatile(stack_canary_address) },
            CANARY,
            "{name} changed the parent's stack"
        );
        assert_eq!(TLS_CANARY.get(), CANARY, "{name} changed the parent's TLS");
        assert_eq!(unsafe { libc::syscall(libc::SYS_getpid) }, pid);
        assert_eq!(unsafe { libc::syscall(libc::SYS_gettid) }, tid);
        format!("{name}={errno}")
    };
    let mut results = Vec::new();
    for (name, number, flags, exit_signal, stack, tls, size) in [
        (
            "vfork",
            libc::SYS_vfork,
            0,
            SIGCHLD,
            false,
            0,
            CLONE_ARGS_SIZE_VER2,
        ),
        (
            "clone3",
            libc::SYS_clone3,
            0,
            SIGCHLD,
            false,
            0,
            CLONE_ARGS_SIZE_VER2,
        ),
        (
            "clone3-shared",
            libc::SYS_clone3,
            (libc::CLONE_VM | libc::CLONE_VFORK) as u64,
            SIGCHLD,
            false,
            0,
            CLONE_ARGS_SIZE_VER2,
        ),
        // A thread on its own stack, which the kernel would create: a thread
        // takes no exit signal.
        (
            "clone3-thread",
            libc::SYS_clone3,
            (libc::CLONE_VM | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64,
            0,
            true,
            0,
            CLONE_ARGS_SIZE_VER2,
        ),
        (
            "clone3-stack",
            libc::SYS_clone3,
            0,
            SIGCHLD,
            true,
            0,
            CLONE_ARGS_SIZE_VER2,
        ),
        // The kernel itself would reject the last three with EPERM or EINVAL.
        (
            "clone3-tls",
            libc::SYS_clone3,
            libc::CLONE_SETTLS as u64,
            SIGCHLD,
            false,
            u64::MAX,
            CLONE_ARGS_SIZE_VER2,
        ),
        (
            "clone3-flags",
            libc::SYS_clone3,
            1_u64 << 63,
            SIGCHLD,
            false,
            0,
            CLONE_ARGS_SIZE_VER2,
        ),
        ("clone3-size", libc::SYS_clone3, 0, SIGCHLD, false, 0, 1),
    ] {
        let clone_args = clone_args(flags, exit_signal, stack, tls);
        let result = unsafe { libc::syscall(number, clone_args.as_ptr(), size) };
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        results.push(expect_refused(name, flags, result, errno));
    }
    // The fresh sites return the raw kernel result; convert it to libc's form.
    let libc_style = |result: i64| match result {
        -4095..=-1 => (-1, -result as i32),
        _ => (result, 0),
    };
    // Each fresh site must be unknown before its call and trapped exactly once
    // by it.
    let vfork_site = &raw const reverie_liteinst_fresh_site_vfork_syscall;
    assert_eq!(
        site_trap_count(vfork_site),
        0,
        "fresh vfork site already ran"
    );
    let (result, errno) = libc_style(unsafe { reverie_liteinst_fresh_site_vfork() });
    results.push(expect_refused("fresh-site-vfork", 0, result, errno));
    assert_eq!(
        site_trap_count(vfork_site),
        1,
        "fresh vfork site did not trap"
    );
    let clone3_site = &raw const reverie_liteinst_fresh_site_clone3_syscall;
    assert_eq!(
        site_trap_count(clone3_site),
        0,
        "fresh clone3 site already ran"
    );
    let fork_shaped = clone_args(0, SIGCHLD, false, 0);
    let (result, errno) = libc_style(unsafe {
        reverie_liteinst_fresh_site_clone3(fork_shaped.as_ptr(), CLONE_ARGS_SIZE_VER2)
    });
    results.push(expect_refused("fresh-site-clone3", 0, result, errno));
    assert_eq!(
        site_trap_count(clone3_site),
        1,
        "fresh clone3 site did not trap"
    );
    // Later hooked syscalls must still return into this parent's frames.
    for _ in 0..4 {
        assert_eq!(unsafe { libc::syscall(libc::SYS_getpid) }, pid);
    }
    println!(
        "unsafe process creation rejected: {} parent-canaries=unchanged",
        results.join(" ")
    );
}
