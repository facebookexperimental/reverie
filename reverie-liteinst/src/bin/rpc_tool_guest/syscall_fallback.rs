use core::arch::global_asm;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::path::Path;

use reverie::Error;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Errno;
use reverie::syscalls::Getpid;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

static SITE: AtomicUsize = AtomicUsize::new(0);
static EXPECTED_RSP: AtomicUsize = AtomicUsize::new(0);
#[path = "syscall_fallback/xstate.rs"]
mod xstate;

static NATIVE_PID: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct FallbackTool;

#[reverie::tool]
impl Tool for FallbackTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = u32;

    fn subscriptions(_config: &()) -> Subscription {
        [
            Sysno::getpid,
            Sysno::getuid,
            Sysno::getgid,
            Sysno::getppid,
            Sysno::fork,
        ]
        .into_iter()
        .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        xstate::check_callback_environment();
        let (number, args) = syscall.into_parts();
        assert_eq!(
            [
                args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5
            ],
            [11, 22, 33, 44, 55, 66],
        );
        let registers = guest.regs().await;
        assert_eq!(registers.rip, SITE.load(Ordering::Relaxed) as u64);
        let expected_rsp = EXPECTED_RSP.load(Ordering::Relaxed);
        assert_eq!(registers.rsp, expected_rsp as u64);
        let nested = unsafe { fallback_test_call(SITE.load(Ordering::Relaxed), libc::SYS_getpid) };
        assert_eq!(nested, NATIVE_PID.load(Ordering::Relaxed) as i64);
        EXPECTED_RSP.store(expected_rsp, Ordering::Relaxed);
        let (total, senders) = guest.send_rpc(1).await;
        super::LAST_TOTAL.store(total, Ordering::Relaxed);
        super::LAST_SENDERS.store(senders, Ordering::Relaxed);
        unsafe { *libc::__errno_location() = libc::EINVAL };
        unsafe {
            core::arch::asm!("pxor xmm0, xmm0", out("xmm0") _, options(nostack, preserves_flags))
        };
        xstate::clobber_callback_state();
        match number {
            Sysno::fork => guest.tail_inject(reverie::syscalls::Fork::new()).await,
            Sysno::getpid => Ok(424_242),
            Sysno::getuid => Err(Errno::EPERM.into()),
            Sysno::getgid => guest.tail_inject(Getpid::new()).await,
            Sysno::getppid => {
                *guest.thread_state_mut() += 1;
                if *guest.thread_state() == 1 {
                    Err(Errno::ERESTARTSYS.into())
                } else {
                    Ok(777_777)
                }
            }
            _ => unreachable!(),
        }
    }
}

fn prepare_site() -> (*mut u8, i32) {
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
    let site = unsafe { mapping.cast::<u8>().add(page - 3) };
    unsafe { std::ptr::copy_nonoverlapping([0x0f, 0x05, 0xc3].as_ptr(), site, 3) };
    assert_eq!(
        unsafe { libc::mprotect(mapping, page, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    let native_pid = unsafe { libc::getpid() };
    assert_ne!(native_pid, 424_242);
    SITE.store(site as usize, Ordering::Relaxed);
    NATIVE_PID.store(native_pid as usize, Ordering::Relaxed);
    (site, native_pid)
}

pub(super) fn run(path: &Path) {
    let (site, native_pid) = prepare_site();
    unsafe { reverie_liteinst::install_tool::<FallbackTool>(path) }.unwrap();
    unsafe { *libc::__errno_location() = libc::E2BIG };
    for _ in 0..3 {
        assert_eq!(
            unsafe { fallback_test_call(site as usize, libc::SYS_getpid) },
            424_242
        );
    }
    assert_eq!(
        unsafe { fallback_test_call(site as usize, libc::SYS_getuid) },
        -i64::from(libc::EPERM)
    );
    assert_eq!(
        unsafe { fallback_test_call(site as usize, libc::SYS_getgid) },
        i64::from(native_pid)
    );
    assert_eq!(
        unsafe { fallback_test_call(site as usize, libc::SYS_getppid) },
        777_777
    );
    assert_eq!(unsafe { *libc::__errno_location() }, libc::E2BIG);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(site, 3) },
        [0x0f, 0x05, 0xc3]
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(site as u64),
        0
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(site as u64),
        6
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_fallback_refusal_count(),
        0
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_fallback_syscall_refusal_count(libc::SYS_getuid),
        0
    );
    assert_eq!(super::LAST_TOTAL.load(Ordering::Relaxed), 7);
    assert_eq!(super::LAST_SENDERS.load(Ordering::Relaxed), 1);
    println!("fallback: calls=6 rpc=7 hooks=0 bytes=unchanged abi=preserved");
}

unsafe extern "C" {
    fn fallback_test_call(site: usize, number: i64) -> i64;
    static fallback_installed_site: u8;
}

global_asm!(
    r#"
    .text
    .p2align 6
    .global fallback_installed_site
    .hidden fallback_installed_site
    .type fallback_installed_site,@function
fallback_installed_site:
    .cfi_startproc
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size fallback_installed_site, .-fallback_installed_site
"#
);

global_asm!(
    r#"
    .text
    .global fallback_test_call
    .hidden fallback_test_call
    .type fallback_test_call,@function
fallback_test_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r12, rdi
    mov [rsp + 24], r12
    mov rax, rsi
    mov rbx, 71
    mov rbp, 72
    mov r13, 73
    mov r14, 74
    mov r15, 75
    mov rdi, 11
    mov rsi, 22
    mov rdx, 33
    mov r10, 44
    mov r8, 55
    mov r9, 66
    mov qword ptr [rsp - 16], 123456
    pcmpeqd xmm0, xmm0
    lea r11, [rsp - 8]
    mov [rip + {expected_rsp}], r11
    stc
    pushfq
    pop qword ptr [rsp]
    call r12
    mov [rsp + 16], r11
    pushfq
    pop r11
    cmp r11, [rsp]
    jne 9f
    cmp r11, [rsp + 16]
    jne 9f
    lea r11, [r12 + 2]
    cmp rcx, r11
    jne 9f
    cmp qword ptr [rsp - 16], 123456
    jne 9f
    cmp r12, [rsp + 24]
    jne 9f
    cmp rbx, 71
    jne 9f
    cmp rbp, 72
    jne 9f
    cmp r13, 73
    jne 9f
    cmp r14, 74
    jne 9f
    cmp r15, 75
    jne 9f
    cmp rdi, 11
    jne 9f
    cmp rsi, 22
    jne 9f
    cmp rdx, 33
    jne 9f
    cmp r10, 44
    jne 9f
    cmp r8, 55
    jne 9f
    cmp r9, 66
    jne 9f
    pmovmskb r11d, xmm0
    cmp r11d, 65535
    jne 9f
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
9:
    ud2
    .size fallback_test_call, .-fallback_test_call
"#,
    expected_rsp = sym EXPECTED_RSP,
);

pub(super) fn run_xstate(path: &Path) {
    xstate::run(path);
}

pub(super) fn run_pkey(path: &Path) {
    xstate::run_pkey(path);
}

pub(super) fn run_fork(path: &Path, installed: bool) {
    let (site, _) = if installed {
        // The site is in this executable's own text, with an unwind-table
        // entry, because LiteInst patches a syscall only where its entry
        // census proves that nothing branches into the displaced bytes.
        let site = core::ptr::addr_of!(fallback_installed_site).cast_mut();
        let pid = unsafe { libc::getpid() };
        SITE.store(site as usize, Ordering::Relaxed);
        NATIVE_PID.store(pid as usize, Ordering::Relaxed);
        (site, pid)
    } else {
        prepare_site()
    };
    unsafe { reverie_liteinst::install_tool::<FallbackTool>(path) }.unwrap();
    let child = unsafe { fallback_test_call(site as usize, libc::SYS_fork) };
    assert!(child >= 0, "fork failed: {child}");
    let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(site as u64);
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(site as u64);
    let fallback = reverie_liteinst::reverie_liteinst_fallback_dispatch_count();
    let syscall = reverie_liteinst::reverie_liteinst_fallback_syscall_count(libc::SYS_fork);
    // The parent also enters the installed site once for the nested native
    // getpid control. Child counters are reset after that parent-only work.
    assert_eq!(
        hooks,
        if installed {
            if child == 0 { 1 } else { 2 }
        } else {
            0
        }
    );
    assert_eq!(traps, u64::from(!installed || child != 0));
    assert_eq!(fallback, u64::from(!installed));
    assert_eq!(syscall, u64::from(!installed));
    // The child's original entry and callback physically happened before
    // fork in the parent. It receives only its own completion signal.
    if !installed {
        unsafe extern "C" {
            fn reverie_liteinst_owned_fallback_observation(selector: u32) -> u64;
        }
        assert_eq!(
            unsafe { reverie_liteinst_owned_fallback_observation(0) },
            u64::from(child != 0)
        );
        assert_eq!(
            unsafe { reverie_liteinst_owned_fallback_observation(1) },
            u64::from(child != 0)
        );
        assert_eq!(unsafe { reverie_liteinst_owned_fallback_observation(2) }, 1);
    }
    let label = if installed { "installed" } else { "fallback" };
    if !installed {
        assert_eq!(
            unsafe { std::slice::from_raw_parts(site, 3) },
            [0x0f, 0x05, 0xc3]
        );
    } else {
        assert_ne!(
            unsafe { std::slice::from_raw_parts(site, 5) },
            [0x0f, 0x05, 0x90, 0x90, 0x90]
        );
    }
    if child == 0 {
        println!(
            "{label} fork child: hooks={hooks} traps={traps} fallback={fallback} syscall={syscall}"
        );
        unsafe { libc::_exit(0) };
    }
    super::wait_for_child(child as libc::pid_t);
    println!(
        "{label} fork parent: hooks={hooks} traps={traps} fallback={fallback} syscall={syscall}"
    );
}

/// A `syscall` site long enough to patch, in an anonymous executable mapping
/// made before LiteInst initializes, beside the text control site
/// (<https://github.com/rrnewton/reverie/issues/812>). LiteInst records an
/// arena for the mapping, so only the entry census can refuse the site: no
/// object owns the bytes, the census has nothing to decode, and the site must
/// stay on the fallback path while the control is patched.
pub(super) fn run_anonymous(path: &Path) {
    const CODE: [u8; 6] = [0x0f, 0x05, 0x90, 0x90, 0x90, 0xc3];
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
    let anonymous = unsafe { mapping.cast::<u8>().add(64) };
    unsafe { std::ptr::copy_nonoverlapping(CODE.as_ptr(), anonymous, CODE.len()) };
    assert_eq!(
        unsafe { libc::mprotect(mapping, page, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    let control = core::ptr::addr_of!(fallback_installed_site).cast_mut();
    assert_eq!(
        unsafe { std::slice::from_raw_parts(control, 5) },
        &CODE[..5]
    );
    let native_pid = unsafe { libc::getpid() };
    assert_ne!(native_pid, 424_242);
    NATIVE_PID.store(native_pid as usize, Ordering::Relaxed);
    unsafe { reverie_liteinst::install_tool::<FallbackTool>(path) }.unwrap();
    let mut counts = [(0, 0, 0); 2];
    for (site, count) in [anonymous, control].into_iter().zip(&mut counts) {
        SITE.store(site as usize, Ordering::Relaxed);
        let fallback = reverie_liteinst::reverie_liteinst_fallback_dispatch_count();
        for _ in 0..3 {
            assert_eq!(
                unsafe { fallback_test_call(site as usize, libc::SYS_getpid) },
                424_242
            );
        }
        *count = (
            reverie_liteinst::reverie_liteinst_site_trap_count(site as u64),
            reverie_liteinst::reverie_liteinst_site_hook_count(site as u64),
            reverie_liteinst::reverie_liteinst_fallback_dispatch_count() - fallback,
        );
    }
    let bytes = |site: *mut u8| {
        if unsafe { std::slice::from_raw_parts(site, 5) } == &CODE[..5] {
            "unchanged"
        } else {
            "patched"
        }
    };
    let [
        (traps, hooks, fallback),
        (control_traps, control_hooks, control_fallback),
    ] = counts;
    println!(
        "anonymous: calls=3 traps={traps} hooks={hooks} fallback={fallback} bytes={} \
         control: calls=3 traps={control_traps} hooks={control_hooks} \
         fallback={control_fallback} bytes={}",
        bytes(anonymous),
        bytes(control)
    );
}

pub(super) fn run_refusal() {
    let (site, _) = prepare_site();
    unsafe {
        std::env::set_var("REVERIE_LITEINST_TOOL", "compat");
        reverie_liteinst::reverie_liteinst_initialize();
    }
    let result = unsafe { fallback_test_call(site as usize, libc::SYS_getpid) };
    assert_eq!(result, -i64::from(libc::EOPNOTSUPP));
    assert_eq!(
        reverie_liteinst::reverie_liteinst_fallback_dispatch_count(),
        1
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_fallback_refusal_count(),
        1
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_fallback_syscall_refusal_count(libc::SYS_getpid),
        1
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(site as u64),
        0
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(site, 3) },
        [0x0f, 0x05, 0xc3]
    );
    println!("fallback refusal: result=-95 attempts=1 refused=1 syscall=1 hooks=0 bytes=unchanged");
}
