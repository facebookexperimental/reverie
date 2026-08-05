use core::arch::global_asm;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::ExitGroup;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_rpc_transport::RpcServer;

const CALLS: u64 = 32;
static LAST_TOTAL: AtomicU64 = AtomicU64::new(0);
static LAST_SENDERS: AtomicU64 = AtomicU64::new(0);
static LAST_NESTED_UID: AtomicI64 = AtomicI64::new(-1);
static LAST_MASK_RESULT: AtomicI64 = AtomicI64::new(0);
static LAST_FIRST_USE_EXEC_RESULT: AtomicI64 = AtomicI64::new(0);
static LAST_FIRST_USE_SIGNAL_RESULT: AtomicI64 = AtomicI64::new(0);
static CHILD_RECONSTRUCTED: AtomicBool = AtomicBool::new(false);

#[derive(Default)]
struct CounterGlobal {
    calls: AtomicU64,
    senders: Mutex<BTreeSet<i32>>,
}

#[reverie::global_tool]
impl GlobalTool for CounterGlobal {
    type Request = u64;
    type Response = (u64, u64);
    type Config = ();

    async fn receive_rpc(&self, from: reverie::Tid, amount: u64) -> (u64, u64) {
        let total = self.calls.fetch_add(amount, Ordering::Relaxed) + amount;
        let mut senders = self.senders.lock().unwrap();
        senders.insert(from.as_raw());
        (total, senders.len() as u64)
    }
}

#[derive(Default)]
struct CounterTool;

#[reverie::tool]
impl Tool for CounterTool {
    type GlobalState = CounterGlobal;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            let uid = unsafe { reverie_liteinst_rpc_getuid() };
            LAST_NESTED_UID.store(uid, Ordering::Relaxed);
            let mask = 0_u64;
            let mask_result = unsafe {
                reverie_liteinst_rpc_sigprocmask(
                    libc::SIG_BLOCK as u64,
                    &mask,
                    core::ptr::null_mut(),
                    core::mem::size_of::<u64>(),
                )
            };
            LAST_MASK_RESULT.store(mask_result, Ordering::Relaxed);
            let exec_result = unsafe {
                reverie_liteinst_rpc_execve(core::ptr::null(), core::ptr::null(), core::ptr::null())
            };
            LAST_FIRST_USE_EXEC_RESULT.store(exec_result, Ordering::Relaxed);
            let signal_result = unsafe { reverie_liteinst_rpc_sigaltstack() };
            LAST_FIRST_USE_SIGNAL_RESULT.store(signal_result, Ordering::Relaxed);
        }
        *guest.thread_state_mut() += 1;
        let (total, senders) = guest.send_rpc(1).await;
        LAST_TOTAL.store(total, Ordering::Relaxed);
        LAST_SENDERS.store(senders, Ordering::Relaxed);
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct UnsubscribedLifecycleTool;

#[reverie::tool]
impl Tool for UnsubscribedLifecycleTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Tid,
        _global_state: &G,
        _thread_state: Self::ThreadState,
        status: ExitStatus,
    ) -> Result<(), Error> {
        eprintln!("unsubscribed-thread={status:?}");
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        _global_state: &G,
        status: ExitStatus,
    ) -> Result<(), Error> {
        eprintln!("unsubscribed-process={status:?}");
        Ok(())
    }
}

#[derive(Default)]
struct InjectExitTool;

#[reverie::tool]
impl Tool for InjectExitTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            return Ok(guest.inject(ExitGroup::new().with_status(0x1234)).await?);
        }
        Ok(guest.inject(syscall).await?)
    }

    async fn on_exit_thread<G: GlobalRPC<Self::GlobalState>>(
        &self,
        _tid: Tid,
        _global_state: &G,
        _thread_state: Self::ThreadState,
        status: ExitStatus,
    ) -> Result<(), Error> {
        eprintln!("injected-thread={status:?}");
        Ok(())
    }

    async fn on_exit_process<G: GlobalRPC<Self::GlobalState>>(
        self,
        _pid: Pid,
        _global_state: &G,
        status: ExitStatus,
    ) -> Result<(), Error> {
        eprintln!("injected-process={status:?}");
        Ok(())
    }
}

#[derive(Default)]
struct UnsubscribedForkTool;

#[reverie::tool]
impl Tool for UnsubscribedForkTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        Subscription::none()
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        if guest.ppid().is_some() {
            CHILD_RECONSTRUCTED.store(true, Ordering::Release);
        }
        Ok(())
    }
}

#[derive(Default)]
struct TailForkTool;

#[reverie::tool]
impl Tool for TailForkTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        [Sysno::clone, Sysno::fork].into_iter().collect()
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        if guest.ppid().is_some() {
            CHILD_RECONSTRUCTED.store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.tail_inject(syscall).await
    }
}

global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_liteinst_rpc_getpid
    .hidden reverie_liteinst_rpc_getpid
    .type reverie_liteinst_rpc_getpid,@function
reverie_liteinst_rpc_getpid:
    mov eax, 39
    .global reverie_liteinst_rpc_getpid_site
    .hidden reverie_liteinst_rpc_getpid_site
reverie_liteinst_rpc_getpid_site:
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_getpid, .-reverie_liteinst_rpc_getpid

    .p2align 4
    .global reverie_liteinst_rpc_getuid
    .hidden reverie_liteinst_rpc_getuid
    .type reverie_liteinst_rpc_getuid,@function
reverie_liteinst_rpc_getuid:
    mov eax, 102
    .global reverie_liteinst_rpc_getuid_site
    .hidden reverie_liteinst_rpc_getuid_site
reverie_liteinst_rpc_getuid_site:
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_getuid, .-reverie_liteinst_rpc_getuid

    .p2align 4
    .global reverie_liteinst_rpc_sigprocmask
    .hidden reverie_liteinst_rpc_sigprocmask
    .type reverie_liteinst_rpc_sigprocmask,@function
reverie_liteinst_rpc_sigprocmask:
    mov r10, rcx
    mov eax, 14
    .global reverie_liteinst_rpc_sigprocmask_site
    .hidden reverie_liteinst_rpc_sigprocmask_site
reverie_liteinst_rpc_sigprocmask_site:
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_sigprocmask, .-reverie_liteinst_rpc_sigprocmask

    .p2align 4
    .global reverie_liteinst_rpc_wait4
    .hidden reverie_liteinst_rpc_wait4
    .type reverie_liteinst_rpc_wait4,@function
reverie_liteinst_rpc_wait4:
    mov r10, rcx
    mov eax, 61
    .global reverie_liteinst_rpc_wait4_site
    .hidden reverie_liteinst_rpc_wait4_site
reverie_liteinst_rpc_wait4_site:
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_wait4, .-reverie_liteinst_rpc_wait4

    .p2align 4
    .global reverie_liteinst_rpc_execve
    .hidden reverie_liteinst_rpc_execve
    .type reverie_liteinst_rpc_execve,@function
reverie_liteinst_rpc_execve:
    mov eax, 59
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_execve, .-reverie_liteinst_rpc_execve

    .p2align 4
    .global reverie_liteinst_rpc_sigaltstack
    .hidden reverie_liteinst_rpc_sigaltstack
    .type reverie_liteinst_rpc_sigaltstack,@function
reverie_liteinst_rpc_sigaltstack:
    mov eax, 131
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_sigaltstack, .-reverie_liteinst_rpc_sigaltstack

    .p2align 4
    .global reverie_liteinst_rpc_raise_sigsys
    .hidden reverie_liteinst_rpc_raise_sigsys
    .type reverie_liteinst_rpc_raise_sigsys,@function
reverie_liteinst_rpc_raise_sigsys:
    mov eax, 39
    syscall
    mov rdi, rax
    .p2align 4
    mov eax, 186
    syscall
    mov rsi, rax
    mov edx, 31
    .p2align 4
    mov eax, 234
    syscall
    ret
    .size reverie_liteinst_rpc_raise_sigsys, .-reverie_liteinst_rpc_raise_sigsys

    # A raw `SYS_fork` (x86-64 __NR_fork = 57) that never enters libc, so no
    # `pthread_atfork` child handler can run. This is the shape Go's runtime and
    # hand-written `syscall(2)` call sites produce; the tool host must still
    # notice the child inherited the parent's coordinator connection.
    .p2align 4
    .global reverie_liteinst_rpc_raw_fork
    .hidden reverie_liteinst_rpc_raw_fork
    .type reverie_liteinst_rpc_raw_fork,@function
reverie_liteinst_rpc_raw_fork:
    mov eax, 57
    .global reverie_liteinst_rpc_raw_fork_site
    .hidden reverie_liteinst_rpc_raw_fork_site
reverie_liteinst_rpc_raw_fork_site:
    syscall
    nop
    nop
    nop
    ret
    .size reverie_liteinst_rpc_raw_fork, .-reverie_liteinst_rpc_raw_fork
"#
);

unsafe extern "C" {
    fn reverie_liteinst_rpc_getpid() -> i64;
    fn reverie_liteinst_rpc_getuid() -> i64;
    fn reverie_liteinst_rpc_execve(
        path: *const u8,
        argv: *const *const u8,
        envp: *const *const u8,
    ) -> i64;
    fn reverie_liteinst_rpc_sigaltstack() -> i64;
    fn reverie_liteinst_rpc_raise_sigsys() -> i64;
    fn reverie_liteinst_rpc_raw_fork() -> i64;
    fn reverie_liteinst_rpc_sigprocmask(
        how: u64,
        set: *const u64,
        old_set: *mut u64,
        size: usize,
    ) -> i64;
    fn reverie_liteinst_rpc_wait4(
        pid: libc::pid_t,
        status: *mut libc::c_int,
        options: libc::c_int,
        rusage: *mut libc::rusage,
    ) -> i64;
    static reverie_liteinst_rpc_getpid_site: u8;
    static reverie_liteinst_rpc_getuid_site: u8;
    static reverie_liteinst_rpc_sigprocmask_site: u8;
    static reverie_liteinst_rpc_wait4_site: u8;
}

fn coordinator(path: &Path) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();
    runtime.block_on(async {
        let server = RpcServer::bind(path, Arc::new(CounterGlobal::default()), ()).unwrap();
        println!("ready");
        std::io::stdout().flush().unwrap();
        server.serve().await.unwrap();
    });
}

unsafe extern "C" fn forbidden_signal_handler(_signal: libc::c_int) {}

fn guest(path: &Path) {
    let mut expected_mask = 0_u64;
    let mask_query = unsafe {
        reverie_liteinst_rpc_sigprocmask(
            libc::SIG_BLOCK as u64,
            core::ptr::null(),
            &mut expected_mask,
            core::mem::size_of::<u64>(),
        )
    };
    assert_eq!(mask_query, 0);
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let ignored = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    assert_ne!(ignored, libc::SIG_ERR);
    let defaulted = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    assert_eq!(defaulted, libc::SIG_IGN);
    let rpc_baseline = LAST_TOTAL.load(Ordering::Relaxed);
    let signal_result = unsafe {
        libc::signal(
            libc::SIGUSR1,
            forbidden_signal_handler as *const () as libc::sighandler_t,
        )
    };
    assert_eq!(signal_result, libc::SIG_ERR);
    let expected_uid = unsafe { reverie_liteinst_rpc_getuid() };
    let mut initial_mask = 0_u64;
    let mask_query = unsafe {
        reverie_liteinst_rpc_sigprocmask(
            libc::SIG_BLOCK as u64,
            core::ptr::null(),
            &mut initial_mask,
            core::mem::size_of::<u64>(),
        )
    };
    assert_eq!(mask_query, 0);
    assert_eq!(initial_mask, expected_mask);
    let mut pid = None;
    for _ in 0..CALLS {
        let observed = unsafe { reverie_liteinst_rpc_getpid() };
        assert_eq!(*pid.get_or_insert(observed), observed);
    }
    let address = core::ptr::addr_of!(reverie_liteinst_rpc_getpid_site) as usize as u64;
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(address);
    let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(address);
    let nested_address = core::ptr::addr_of!(reverie_liteinst_rpc_getuid_site) as usize as u64;
    let nested_traps = reverie_liteinst::reverie_liteinst_site_trap_count(nested_address);
    let nested_hooks = reverie_liteinst::reverie_liteinst_site_hook_count(nested_address);
    let mask_address = core::ptr::addr_of!(reverie_liteinst_rpc_sigprocmask_site) as usize as u64;
    let mask_traps = reverie_liteinst::reverie_liteinst_site_trap_count(mask_address);
    let mask_hooks = reverie_liteinst::reverie_liteinst_site_hook_count(mask_address);
    let rpc = LAST_TOTAL.load(Ordering::Relaxed);
    let rpc_delta = rpc - rpc_baseline;
    let first_use_exec_result = LAST_FIRST_USE_EXEC_RESULT.load(Ordering::Relaxed);
    let first_use_signal_result = LAST_FIRST_USE_SIGNAL_RESULT.load(Ordering::Relaxed);
    let mask_result = LAST_MASK_RESULT.load(Ordering::Relaxed);
    let nested_uid = LAST_NESTED_UID.load(Ordering::Relaxed);
    println!(
        "calls={CALLS} traps={traps} hooks={hooks} rpc_delta={rpc_delta} nested_traps={nested_traps} nested_hooks={nested_hooks} mask_traps={mask_traps} mask_hooks={mask_hooks} mask_result={mask_result} first_use_exec_result={first_use_exec_result} first_use_signal_result={first_use_signal_result} nested_uid={nested_uid} expected_uid={expected_uid}"
    );
    assert_eq!(traps, 1);
    assert_eq!(hooks, CALLS);
    assert_eq!(rpc_delta, CALLS + 2);
    assert_eq!(nested_traps, 1);
    assert_eq!(nested_hooks, CALLS + 1);
    assert_eq!(mask_traps, 1);
    assert_eq!(mask_hooks, CALLS + 1);
    assert_eq!(mask_result, -i64::from(libc::EPERM));
    assert_eq!(first_use_exec_result, -i64::from(libc::ENOTSUP));
    assert_eq!(first_use_signal_result, -i64::from(libc::EPERM));
    assert_eq!(nested_uid, expected_uid);
}

fn preinstalled_handler_guest(path: &Path) {
    let previous = unsafe {
        libc::signal(
            libc::SIGUSR1,
            forbidden_signal_handler as *const () as libc::sighandler_t,
        )
    };
    assert_ne!(previous, libc::SIG_ERR);
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let previous = unsafe { libc::signal(libc::SIGUSR1, libc::SIG_IGN) };
    assert_eq!(previous, libc::SIG_DFL);
    println!("preinstalled-handler-reset");
}

unsafe extern "C" fn stale_sigsys_handler(_signal: libc::c_int) {
    unsafe { libc::_exit(77) };
}

fn pending_sigsys_guest(path: &Path) -> ! {
    let previous = unsafe {
        libc::signal(
            libc::SIGSYS,
            stale_sigsys_handler as *const () as libc::sighandler_t,
        )
    };
    assert_ne!(previous, libc::SIG_ERR);
    let sigsys = 1_u64 << (libc::SIGSYS - 1);
    let block = unsafe {
        reverie_liteinst_rpc_sigprocmask(
            libc::SIG_BLOCK as u64,
            &sigsys,
            core::ptr::null_mut(),
            core::mem::size_of::<u64>(),
        )
    };
    assert_eq!(block, 0);
    assert_eq!(unsafe { libc::raise(libc::SIGSYS) }, 0);
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    panic!("pending guest SIGSYS was not delivered");
}

fn preblocked_sigsys_guest(path: &Path) {
    let sigsys = 1_u64 << (libc::SIGSYS - 1);
    let block = unsafe {
        reverie_liteinst_rpc_sigprocmask(
            libc::SIG_BLOCK as u64,
            &sigsys,
            core::ptr::null_mut(),
            core::mem::size_of::<u64>(),
        )
    };
    assert_eq!(block, 0);
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let mut current = 0_u64;
    let query = unsafe {
        reverie_liteinst_rpc_sigprocmask(
            libc::SIG_BLOCK as u64,
            core::ptr::null(),
            &mut current,
            core::mem::size_of::<u64>(),
        )
    };
    assert_eq!(query, 0);
    assert_eq!(current & sigsys, 0);
    println!("inherited-sigsys-unblocked");
}

fn spoof_sigsys_guest(path: &Path) -> ! {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    unsafe { reverie_liteinst_rpc_raise_sigsys() };
    panic!("guest-generated SIGSYS returned");
}

fn unsubscribed_lifecycle_guest(path: &Path) -> ! {
    unsafe { reverie_liteinst::install_tool::<UnsubscribedLifecycleTool>(path) }.unwrap();
    let flags = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
    let result = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOTSUP)
    );
    println!("unsubscribed-clone-rejected");
    unsafe { libc::syscall(libc::SYS_exit_group, 0x1234) };
    panic!("exit_group returned");
}

fn injected_exit_guest(path: &Path) -> ! {
    unsafe { reverie_liteinst::install_tool::<InjectExitTool>(path) }.unwrap();
    unsafe { reverie_liteinst_rpc_getpid() };
    panic!("injected exit returned");
}

fn wait_for_child(child: libc::pid_t) {
    let mut status = 0;
    let waited =
        unsafe { reverie_liteinst_rpc_wait4(child, &mut status, 0, core::ptr::null_mut()) };
    assert_eq!(waited, i64::from(child));
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

fn fork_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let parent = unsafe { reverie_liteinst_rpc_getpid() };
    assert_eq!(parent, i64::from(unsafe { libc::getpid() }));
    let senders_before_fork = LAST_SENDERS.load(Ordering::Relaxed);
    let child = unsafe { libc::fork() };
    assert!(
        child >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        let observed = unsafe { reverie_liteinst_rpc_getpid() };
        assert_eq!(observed, i64::from(unsafe { libc::getpid() }));
        unsafe { libc::_exit(0) };
    }

    wait_for_child(child);
    let wait_address = core::ptr::addr_of!(reverie_liteinst_rpc_wait4_site) as usize as u64;
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(wait_address),
        1
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(wait_address),
        1
    );
    let observed = unsafe { reverie_liteinst_rpc_getpid() };
    assert_eq!(observed, i64::from(unsafe { libc::getpid() }));
    let sender_delta = LAST_SENDERS.load(Ordering::Relaxed) - senders_before_fork;
    println!(
        "fork-rpc-total={} fork-rpc-sender-delta={sender_delta}",
        LAST_TOTAL.load(Ordering::Relaxed)
    );
}

/// Same shape as [`fork_guest`], but the fork is a bare `SYS_fork` instruction
/// that never enters libc, so no `pthread_atfork` child handler can run.
///
/// The child must still be recognized as a fresh child and reconnect under its
/// own identity. `CounterGlobal` keys its sender set on the RPC's `from` tid and
/// `BlockingRpcClient::connect` stamps the connect-time tid, so a child that
/// wrongly reuses the parent's inherited connection reports the PARENT's tid and
/// leaves the sender count unchanged (delta 0). A correctly reconnected child
/// adds exactly one new sender (delta 1).
fn raw_fork_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let parent = unsafe { reverie_liteinst_rpc_getpid() };
    assert_eq!(parent, i64::from(unsafe { libc::getpid() }));
    let senders_before_fork = LAST_SENDERS.load(Ordering::Relaxed);

    let child = unsafe { reverie_liteinst_rpc_raw_fork() };
    assert!(child >= 0, "raw SYS_fork failed: {child}");
    if child == 0 {
        // In the child: this RPC must be attributed to the child, not the parent.
        let observed = unsafe { reverie_liteinst_rpc_getpid() };
        assert_eq!(observed, i64::from(unsafe { libc::getpid() }));
        assert_ne!(observed, parent, "child must not report the parent pid");
        unsafe { libc::_exit(0) };
    }

    wait_for_child(child as libc::pid_t);
    let observed = unsafe { reverie_liteinst_rpc_getpid() };
    assert_eq!(observed, i64::from(unsafe { libc::getpid() }));
    let sender_delta = LAST_SENDERS.load(Ordering::Relaxed) - senders_before_fork;
    println!(
        "raw-fork-rpc-total={} raw-fork-rpc-sender-delta={sender_delta}",
        LAST_TOTAL.load(Ordering::Relaxed)
    );
}

fn check_reconstructed_fork(label: &str) {
    CHILD_RECONSTRUCTED.store(false, Ordering::Release);
    let child = unsafe { libc::fork() };
    assert!(
        child >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        assert!(CHILD_RECONSTRUCTED.load(Ordering::Acquire));
        unsafe { libc::_exit(0) };
    }
    wait_for_child(child);
    println!("{label}-fork-reconstructed");
}

fn unsubscribed_fork_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<UnsubscribedForkTool>(path) }.unwrap();
    check_reconstructed_fork("unsubscribed");
}

fn tail_fork_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<TailForkTool>(path) }.unwrap();
    check_reconstructed_fork("tail");
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let mode = args.next().expect("mode");
    let path = args.next().expect("socket path");
    match mode.to_str() {
        Some("coordinator") => coordinator(Path::new(&path)),
        Some("guest") => guest(Path::new(&path)),
        Some("preinstalled-handler") => preinstalled_handler_guest(Path::new(&path)),
        Some("pending-sigsys") => pending_sigsys_guest(Path::new(&path)),
        Some("preblocked-sigsys") => preblocked_sigsys_guest(Path::new(&path)),
        Some("spoof-sigsys") => spoof_sigsys_guest(Path::new(&path)),
        Some("unsubscribed-lifecycle") => unsubscribed_lifecycle_guest(Path::new(&path)),
        Some("injected-exit") => injected_exit_guest(Path::new(&path)),
        Some("fork-guest") => fork_guest(Path::new(&path)),
        Some("raw-fork-guest") => raw_fork_guest(Path::new(&path)),
        Some("unsubscribed-fork") => unsubscribed_fork_guest(Path::new(&path)),
        Some("tail-fork") => tail_fork_guest(Path::new(&path)),
        _ => panic!("expected coordinator or guest"),
    }
}
