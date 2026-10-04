/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use core::arch::global_asm;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Errno;
use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

const FAST_CALLS: u64 = 8;
const RPC_GETPID: u64 = 1;
const RPC_CLOCK_GETTIME: u64 = 2;
const RPC_GETTIMEOFDAY: u64 = 3;
const RPC_FORK: u64 = 4;
static FORCE_WAIT_RESTART: AtomicBool = AtomicBool::new(true);
static READ_CALLS: AtomicUsize = AtomicUsize::new(0);

global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_lifecycle_getpid
    .hidden reverie_liteinst_lifecycle_getpid
    .type reverie_liteinst_lifecycle_getpid,@function
reverie_liteinst_lifecycle_getpid:
    .cfi_startproc
    mov eax, 39
    .global reverie_liteinst_lifecycle_getpid_site
    .hidden reverie_liteinst_lifecycle_getpid_site
reverie_liteinst_lifecycle_getpid_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_lifecycle_getpid, .-reverie_liteinst_lifecycle_getpid

    .p2align 4
    .global reverie_liteinst_lifecycle_read
    .hidden reverie_liteinst_lifecycle_read
    .type reverie_liteinst_lifecycle_read,@function
reverie_liteinst_lifecycle_read:
    .cfi_startproc
    xor eax, eax
    mov edi, -1
    xor esi, esi
    xor edx, edx
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_lifecycle_read, .-reverie_liteinst_lifecycle_read
"#
);

unsafe extern "C" {
    fn reverie_liteinst_lifecycle_getpid() -> i64;
    fn reverie_liteinst_lifecycle_read() -> i64;
    static reverie_liteinst_lifecycle_getpid_site: u8;
}

#[derive(Default)]
struct LifecycleGlobal {
    total: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for LifecycleGlobal {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, event: u64) {
        self.total.fetch_add(event, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct LifecycleTool;

#[reverie::tool]
impl Tool for LifecycleTool {
    type GlobalState = LifecycleGlobal;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [
            Sysno::getpid,
            Sysno::clock_gettime,
            Sysno::gettimeofday,
            Sysno::fork,
            Sysno::clone,
            Sysno::wait4,
            Sysno::read,
            Sysno::exit,
            Sysno::exit_group,
        ]
        .into_iter()
        .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::wait4 {
            if FORCE_WAIT_RESTART.swap(false, Ordering::Relaxed) {
                return Err(Errno::ERESTARTSYS.into());
            }
            return Ok(4242);
        }
        if syscall.number() == Sysno::read {
            if READ_CALLS.fetch_add(1, Ordering::Relaxed) < 2 {
                return Err(Errno::ERESTARTSYS.into());
            }
            return Ok(4243);
        }
        let event = match syscall.number() {
            Sysno::getpid => RPC_GETPID,
            Sysno::clock_gettime => RPC_CLOCK_GETTIME,
            Sysno::gettimeofday => RPC_GETTIMEOFDAY,
            Sysno::fork | Sysno::clone => RPC_FORK,
            Sysno::wait4 => unreachable!("wait4 is handled before event classification"),
            Sysno::exit | Sysno::exit_group => 0,
            number => panic!("unexpected lifecycle fixture syscall {number}"),
        };
        if event != 0 {
            guest.send_rpc(event).await;
        }
        match syscall.number() {
            // The fixture only proves that ptrace syscallized the vDSO call
            // and the in-guest Tool received it. Zeroed outputs are sufficient.
            Sysno::clock_gettime | Sysno::gettimeofday => Ok(0),
            _ => Ok(guest.inject(syscall).await?),
        }
    }
}

fn install_tool() {
    let coordinator = std::env::var_os(reverie_liteinst::COORDINATOR_ENV)
        .expect("lifecycle fixture requires a LiteInst coordinator");
    // SAFETY: main starts before application-created threads and installs once.
    unsafe { reverie_liteinst::install_tool_quiescent::<LifecycleTool>(coordinator) }.unwrap();
}

fn fork_or_panic() -> libc::pid_t {
    let child = unsafe { libc::fork() };
    assert_ne!(
        child,
        -1,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    child
}

fn root_exits_first(marker: &Path) -> ! {
    if fork_or_panic() == 0 {
        std::thread::sleep(Duration::from_millis(150));
        std::fs::write(marker, b"descendant-finished\n").unwrap();
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::_exit(23) }
}

fn signaled_descendant(pid_file: &Path) -> ! {
    if fork_or_panic() == 0 {
        std::fs::write(pid_file, format!("{}\n", std::process::id())).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        unsafe {
            libc::raise(libc::SIGTERM);
            libc::_exit(127);
        }
    }
    unsafe { libc::_exit(29) }
}

fn fast_path() {
    let mut expected = None;
    for _ in 0..FAST_CALLS {
        let observed = unsafe { reverie_liteinst_lifecycle_getpid() };
        assert_eq!(*expected.get_or_insert(observed), observed);
    }
    let address = core::ptr::addr_of!(reverie_liteinst_lifecycle_getpid_site) as usize as u64;
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(address);
    let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(address);
    println!("calls={FAST_CALLS} traps={traps} hooks={hooks}");
    assert_eq!(traps, 1);
    assert_eq!(hooks, FAST_CALLS);
}

fn restart_wait4() {
    let waited = unsafe { libc::waitpid(-1, core::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(waited, 4242, "wait4 callback was not restarted");
    println!("wait4-restart-ok");
}

fn restart_read() {
    let result = unsafe { reverie_liteinst_lifecycle_read() };
    let calls = READ_CALLS.load(Ordering::Relaxed);
    println!("read-result={result} calls={calls}");
    assert_eq!(result, 4243, "read callback was not restarted");
    assert_eq!(calls, 3, "read callback did not restart repeatedly");
}

fn fallback_fork_stats() {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    // mov eax, SYS_fork; syscall; ret, with the syscall at the page end.
    let entry = unsafe { mapping.cast::<u8>().add(page - 8) };
    unsafe {
        std::ptr::copy_nonoverlapping([0xb8, 57, 0, 0, 0, 0x0f, 0x05, 0xc3].as_ptr(), entry, 8)
    };
    assert_eq!(
        unsafe { libc::mprotect(mapping, page, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    let site = unsafe { entry.add(5) } as u64;
    let fork: unsafe extern "C" fn() -> i64 = unsafe { std::mem::transmute(entry) };
    install_tool();
    let child = unsafe { fork() };
    assert!(child >= 0, "fork failed: {child}");
    assert_eq!(reverie_liteinst::reverie_liteinst_site_hook_count(site), 0);
    assert_eq!(reverie_liteinst::reverie_liteinst_site_trap_count(site), 1);
    assert_eq!(
        reverie_liteinst::reverie_liteinst_fallback_syscall_count(libc::SYS_fork),
        1
    );
    if child == 0 {
        unsafe { libc::_exit(0) };
    }
    // The wait4 callback deliberately returns a fixture value in other modes.
    // Use the trusted gate here to observe this actual child's completion.
    let mut status = -1i32;
    loop {
        let waited = unsafe {
            reverie_preload::trap::raw_syscall6(
                libc::SYS_wait4,
                [child as u64, (&mut status as *mut i32) as u64, 0, 0, 0, 0],
            )
        };
        if waited == -i64::from(libc::EINTR) {
            continue;
        }
        assert_eq!(waited, child);
        break;
    }
    assert_eq!(status, 0);
    println!("fallback fork stats: child=finished");
}

fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next().expect("missing lifecycle fixture mode");
    if mode == "fallback-fork-stats" {
        fallback_fork_stats();
        return;
    }
    install_tool();

    match mode.to_str() {
        Some("root-exits-first") => {
            root_exits_first(Path::new(&arguments.next().expect("missing marker path")))
        }
        Some("signaled-descendant") => signaled_descendant(Path::new(
            &arguments.next().expect("missing child pid path"),
        )),
        Some("fast-path") => fast_path(),
        Some("restart-wait4") => restart_wait4(),
        Some("restart-read") => restart_read(),
        _ => panic!("unknown lifecycle fixture mode {mode:?}"),
    }
}
