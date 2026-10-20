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
use std::sync::atomic::AtomicI64;
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
use reverie::TimerSchedule;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

const FAST_CALLS: u64 = 8;
const RPC_GETPID: u64 = 1;
const RPC_CLOCK_GETTIME: u64 = 2;
const RPC_GETTIMEOFDAY: u64 = 3;
const RPC_FORK: u64 = 4;
/// Tags the one RPC a process sends at `exit_group` with its count of Tool
/// callbacks, so the host can compare the backend's dispatch counts with the
/// callbacks the Tool actually made.
const RPC_CALLBACK_COUNT: u64 = 1 << 32;
static FORCE_WAIT_RESTART: AtomicBool = AtomicBool::new(true);
static READ_CALLS: AtomicUsize = AtomicUsize::new(0);
/// This process's Tool callbacks, one per guest entry: a callback that asks
/// for a restart is re-run for the same entry and is not counted again.
/// Counted in memory, because a counting syscall would itself be trapped and
/// change what is being measured. The fixture's processes are single-threaded.
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
/// Makes the next `getpid` callback call the `getppid` stub, a Tool syscall
/// that reaches a site an earlier guest call patched.
static NESTED_GETPPID: AtomicBool = AtomicBool::new(false);
const TIMER_ACCEPTED: i64 = 0;
const TIMER_NOT_ERRNO: i64 = -1;
const TIMER_NOT_PROBED: i64 = -2;
static PROBE_TIMERS: AtomicBool = AtomicBool::new(false);
static SET_TIMER_OUTCOME: AtomicI64 = AtomicI64::new(TIMER_NOT_PROBED);
static SET_TIMER_PRECISE_OUTCOME: AtomicI64 = AtomicI64::new(TIMER_NOT_PROBED);

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

    .p2align 4
    .global reverie_liteinst_lifecycle_getppid
    .hidden reverie_liteinst_lifecycle_getppid
    .type reverie_liteinst_lifecycle_getppid,@function
reverie_liteinst_lifecycle_getppid:
    .cfi_startproc
    mov eax, 110
    .global reverie_liteinst_lifecycle_getppid_site
    .hidden reverie_liteinst_lifecycle_getppid_site
reverie_liteinst_lifecycle_getppid_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_lifecycle_getppid, .-reverie_liteinst_lifecycle_getppid

    .p2align 4
    .global reverie_liteinst_lifecycle_fork
    .hidden reverie_liteinst_lifecycle_fork
    .type reverie_liteinst_lifecycle_fork,@function
reverie_liteinst_lifecycle_fork:
    .cfi_startproc
    mov eax, 57
    .global reverie_liteinst_lifecycle_fork_site
    .hidden reverie_liteinst_lifecycle_fork_site
reverie_liteinst_lifecycle_fork_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_lifecycle_fork, .-reverie_liteinst_lifecycle_fork
"#
);

unsafe extern "C" {
    fn reverie_liteinst_lifecycle_getpid() -> i64;
    fn reverie_liteinst_lifecycle_read() -> i64;
    fn reverie_liteinst_lifecycle_getppid() -> i64;
    fn reverie_liteinst_lifecycle_fork() -> i64;
    static reverie_liteinst_lifecycle_getpid_site: u8;
    static reverie_liteinst_lifecycle_getppid_site: u8;
    static reverie_liteinst_lifecycle_fork_site: u8;
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
            Sysno::getppid,
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
        CALLBACKS.fetch_add(1, Ordering::Relaxed);
        if syscall.number() == Sysno::wait4 {
            if FORCE_WAIT_RESTART.swap(false, Ordering::Relaxed) {
                return Err(restart_same_entry());
            }
            return Ok(4242);
        }
        if syscall.number() == Sysno::getpid && PROBE_TIMERS.swap(false, Ordering::Relaxed) {
            let outcome = timer_outcome(guest.set_timer(TimerSchedule::Rcbs(1)));
            SET_TIMER_OUTCOME.store(outcome, Ordering::Relaxed);
            let outcome = timer_outcome(guest.set_timer_precise(TimerSchedule::Rcbs(1)));
            SET_TIMER_PRECISE_OUTCOME.store(outcome, Ordering::Relaxed);
        }
        if syscall.number() == Sysno::read {
            if READ_CALLS.fetch_add(1, Ordering::Relaxed) < 2 {
                return Err(restart_same_entry());
            }
            return Ok(4243);
        }
        let event = match syscall.number() {
            Sysno::getpid => RPC_GETPID,
            Sysno::clock_gettime => RPC_CLOCK_GETTIME,
            Sysno::gettimeofday => RPC_GETTIMEOFDAY,
            Sysno::fork | Sysno::clone => RPC_FORK,
            Sysno::wait4 => unreachable!("wait4 is handled before event classification"),
            Sysno::getppid | Sysno::exit | Sysno::exit_group => 0,
            number => panic!("unexpected lifecycle fixture syscall {number}"),
        };
        if event != 0 {
            guest.send_rpc(event).await;
        }
        if event == RPC_GETPID && NESTED_GETPPID.swap(false, Ordering::Relaxed) {
            unsafe { reverie_liteinst_lifecycle_getppid() };
        }
        if syscall.number() == Sysno::exit_group {
            guest
                .send_rpc(RPC_CALLBACK_COUNT | CALLBACKS.load(Ordering::Relaxed))
                .await;
        }
        match syscall {
            // The fixture only proves that ptrace syscallized the vDSO call
            // and the in-guest Tool received it. Zeroed outputs are sufficient.
            Syscall::ClockGettime(_) | Syscall::Gettimeofday(_) => Ok(0),
            Syscall::Fork(_) => Ok(inject_fork(guest, syscall).await?),
            Syscall::Clone(clone) if clone.flags().bits() & libc::CLONE_VM == 0 => {
                Ok(inject_fork(guest, syscall).await?)
            }
            _ => Ok(guest.inject(syscall).await?),
        }
    }
}

/// Asks the driver to re-run this callback for the same guest entry, which the
/// re-run counts again.
fn restart_same_entry() -> Error {
    CALLBACKS.fetch_sub(1, Ordering::Relaxed);
    Errno::ERESTARTSYS.into()
}

/// A new process's callback count starts with the one callback it returns
/// from, which the backend also counts as the child's own first event.
async fn inject_fork<G: Guest<LifecycleTool>>(
    guest: &mut G,
    syscall: Syscall,
) -> Result<i64, Error> {
    let result = guest.inject(syscall).await?;
    if result == 0 {
        CALLBACKS.store(1, Ordering::Relaxed);
    }
    Ok(result)
}

/// Encodes a timer request's result so the guest can report it after the hook.
fn timer_outcome(result: Result<(), Error>) -> i64 {
    match result {
        Ok(()) => TIMER_ACCEPTED,
        Err(error) => error
            .into_errno()
            .map_or(TIMER_NOT_ERRNO, |errno| i64::from(errno.into_raw())),
    }
}

fn timer_label(outcome: i64) -> String {
    match outcome {
        TIMER_ACCEPTED => "accepted".to_owned(),
        TIMER_NOT_ERRNO => "non-errno-error".to_owned(),
        TIMER_NOT_PROBED => "not-probed".to_owned(),
        errno if errno == i64::from(libc::ENOSYS) => "ENOSYS".to_owned(),
        errno => format!("errno-{errno}"),
    }
}

/// Bootstrap bytes the lifecycle tests pass to `*_preload_data` launches.
const LIFECYCLE_TOOL_DATA: &[u8] = b"lifecycle";
/// Set by the tests of the `*_preload_data` launchers. It makes the fixture
/// fail unless it received its coordinator through the bootstrap descriptor,
/// so those tests cannot pass through the environment branch.
const EXPECT_BOOTSTRAP_ENV: &str = "REVERIE_LITEINST_LIFECYCLE_EXPECT_BOOTSTRAP";

fn install_tool() {
    if std::env::var_os(EXPECT_BOOTSTRAP_ENV).is_some() {
        let environ = std::fs::read("/proc/self/environ").unwrap();
        let entry = format!("{}=", reverie_liteinst::COORDINATOR_ENV);
        assert!(
            !environ
                .split(|byte| *byte == 0)
                .any(|variable| variable.starts_with(entry.as_bytes())),
            "a bootstrap launch put {} in the initial environment",
            reverie_liteinst::COORDINATOR_ENV
        );
    }
    let coordinator = match std::env::var_os(reverie_liteinst::COORDINATOR_ENV) {
        Some(coordinator) => std::path::PathBuf::from(coordinator),
        // A `*_preload_data` launch passes the coordinator in an inherited
        // bootstrap descriptor instead of the environment.
        None => {
            // SAFETY: main starts before application-created threads.
            let bootstrap = unsafe { reverie_liteinst::take_preload_bootstrap() }
                .unwrap()
                .expect("lifecycle fixture requires a LiteInst coordinator");
            assert_eq!(bootstrap.tool_data, LIFECYCLE_TOOL_DATA);
            bootstrap.coordinator
        }
    };
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

/// Returns this process's `TracerPid` from procfs; zero means no ptrace attach.
///
/// Reads with `pread`: the fixture Tool answers `read` itself.
fn tracer_pid() -> u64 {
    let fd = unsafe { libc::open(c"/proc/self/status".as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open: {}", std::io::Error::last_os_error());
    let mut status = vec![0u8; 64 * 1024];
    let mut len = 0;
    loop {
        let read = unsafe {
            libc::pread(
                fd,
                status[len..].as_mut_ptr().cast(),
                status.len() - len,
                len as libc::off_t,
            )
        };
        assert!(read >= 0, "pread: {}", std::io::Error::last_os_error());
        if read == 0 {
            break;
        }
        len += read as usize;
        assert!(len < status.len(), "procfs status filled the buffer");
    }
    assert_eq!(unsafe { libc::close(fd) }, 0);
    std::str::from_utf8(&status[..len])
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix("TracerPid:"))
        .expect("procfs status has a TracerPid line")
        .trim()
        .parse()
        .unwrap()
}

fn patching_off() {
    let mut expected = None;
    for _ in 0..FAST_CALLS {
        let observed = unsafe { reverie_liteinst_lifecycle_getpid() };
        assert_eq!(*expected.get_or_insert(observed), observed);
    }
    // The vDSO fast paths must trap too. The fixture Tool answers both calls
    // with 0 and writes nothing, so the sentinels survive only if the Tool,
    // not the kernel or an unpatched vDSO, ran every call.
    assert_ne!(
        unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) },
        0,
        "the fixture needs a vDSO"
    );
    for _ in 0..FAST_CALLS {
        let mut time = libc::timespec {
            tv_sec: -1,
            tv_nsec: -1,
        };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) },
            0
        );
        assert_eq!((time.tv_sec, time.tv_nsec), (-1, -1));
        let mut day = libc::timeval {
            tv_sec: -1,
            tv_usec: -1,
        };
        assert_eq!(
            unsafe { libc::gettimeofday(&mut day, core::ptr::null_mut()) },
            0
        );
        assert_eq!((day.tv_sec, day.tv_usec), (-1, -1));
    }
    let address = core::ptr::addr_of!(reverie_liteinst_lifecycle_getpid_site) as usize as u64;
    // Read every counter before procfs and stdout add their own syscalls.
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(address);
    let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(address);
    let fallback_getpid =
        reverie_liteinst::reverie_liteinst_fallback_syscall_count(libc::SYS_getpid);
    let fallback_clock_gettime =
        reverie_liteinst::reverie_liteinst_fallback_syscall_count(libc::SYS_clock_gettime);
    let fallback_gettimeofday =
        reverie_liteinst::reverie_liteinst_fallback_syscall_count(libc::SYS_gettimeofday);
    let tracer = tracer_pid();
    println!(
        "calls={FAST_CALLS} traps={traps} hooks={hooks} fallback_getpid={fallback_getpid} \
         fallback_clock_gettime={fallback_clock_gettime} \
         fallback_gettimeofday={fallback_gettimeofday} tracer_pid={tracer}"
    );
}

fn timer_refused() {
    PROBE_TIMERS.store(true, Ordering::Relaxed);
    unsafe { reverie_liteinst_lifecycle_getpid() };
    println!(
        "set_timer={} set_timer_precise={}",
        timer_label(SET_TIMER_OUTCOME.load(Ordering::Relaxed)),
        timer_label(SET_TIMER_PRECISE_OUTCOME.load(Ordering::Relaxed)),
    );
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

fn site_counts(site: *const u8) -> (u64, u64) {
    let address = site as usize as u64;
    (
        reverie_liteinst::reverie_liteinst_site_trap_count(address),
        reverie_liteinst::reverie_liteinst_site_hook_count(address),
    )
}

fn nested_hook() {
    let site = core::ptr::addr_of!(reverie_liteinst_lifecycle_getppid_site);
    // The guest's own call traps once and patches the site.
    unsafe { reverie_liteinst_lifecycle_getppid() };
    NESTED_GETPPID.store(true, Ordering::Relaxed);
    unsafe { reverie_liteinst_lifecycle_getpid() };
    assert!(!NESTED_GETPPID.load(Ordering::Relaxed));
    let (traps, hooks) = site_counts(site);
    println!("nested getppid traps={traps} hooks={hooks}");
    assert_eq!((traps, hooks), (1, 2));
}

fn hooked_fork_stats() {
    let site = core::ptr::addr_of!(reverie_liteinst_lifecycle_fork_site);
    // The first call traps, installs the hook and forks inside it.
    let child = unsafe { reverie_liteinst_lifecycle_fork() };
    assert!(child >= 0, "fork failed: {child}");
    let (traps, hooks) = site_counts(site);
    if child == 0 {
        // The child's counts were reset, then given back the one hook entry
        // it returns from.
        assert_eq!((traps, hooks), (0, 1));
        unsafe { libc::_exit(0) };
    }
    assert_eq!((traps, hooks), (1, 1));
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
    println!("hooked fork stats: child=finished");
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
        Some("patching-off") => patching_off(),
        Some("timer-refused") => timer_refused(),
        Some("restart-wait4") => restart_wait4(),
        Some("restart-read") => restart_read(),
        Some("nested-hook") => nested_hook(),
        Some("hooked-fork-stats") => hooked_fork_stats(),
        _ => panic!("unknown lifecycle fixture mode {mode:?}"),
    }
}
