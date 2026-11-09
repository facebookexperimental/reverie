//! One Tool, reached three ways: LiteInst with site patching on (the binary's
//! syscall site is patched, while a site in an anonymous executable page,
//! which has no arena, is declined), LiteInst with site patching off (every
//! site declined, as in-guest-trap runs it), and the shared runtime with no
//! patcher at all (`TrapHost`). The first output line holds only what the
//! Tool and the guest observe and must be identical in all three; the second
//! reports both sites' LiteInst accounting, which shows which route ran.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::io::Write;
use std::path::Path;

use reverie::CpuIdResult;
use reverie::Error;
use reverie::Guest;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

const GETPIDS: u64 = 8;
const TOOL_TSC: u64 = 0x5a3e_0000_0000_1234;

static TOOL_GETPIDS: AtomicU64 = AtomicU64::new(0);
static TOOL_CLOCKS: AtomicU64 = AtomicU64::new(0);
static TOOL_CPUIDS: AtomicU64 = AtomicU64::new(0);
static TOOL_RDTSCS: AtomicU64 = AtomicU64::new(0);

#[derive(Default)]
struct SameTool;

#[reverie::tool]
impl Tool for SameTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut subscriptions: Subscription =
            [Sysno::getpid, Sysno::clock_gettime].into_iter().collect();
        subscriptions.cpuid().rdtsc();
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            TOOL_GETPIDS.fetch_add(1, Ordering::Relaxed);
            let (total, _) = guest.send_rpc(1).await;
            super::LAST_TOTAL.store(total, Ordering::Relaxed);
        } else if syscall.number() == Sysno::clock_gettime {
            TOOL_CLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        Ok(guest.inject(syscall).await?)
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        _eax: u32,
        _ecx: u32,
    ) -> Result<CpuIdResult, reverie::Errno> {
        TOOL_CPUIDS.fetch_add(1, Ordering::Relaxed);
        Ok(CpuIdResult {
            eax: super::TOOL_CPUID_EAX,
            ebx: super::TOOL_CPUID_EBX,
            ecx: super::TOOL_CPUID_ECX,
            edx: super::TOOL_CPUID_EDX,
        })
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, reverie::Errno> {
        TOOL_RDTSCS.fetch_add(1, Ordering::Relaxed);
        Ok(RdtscResult {
            tsc: TOOL_TSC,
            aux: (request == Rdtsc::Tscp).then_some(0x2468_ace0),
        })
    }
}

/// Installs [`SameTool`] with LiteInst (`liteinst`; the caller selects site
/// patching through its environment) or with the shared runtime and no
/// patcher (`no-patcher`), then exercises one syscall site, the vDSO clock,
/// CPUID and RDTSC.
pub(super) fn run(path: &Path, installer: &str) {
    // Read before any Tool exists, so the comparison below is not itself a
    // trapped getpid.
    let pid = i64::from(std::process::id());
    // mov eax, SYS_getpid; syscall; ret -- in an anonymous page, which no
    // arena covers, so LiteInst can never patch it.
    const CODE: [u8; 8] = [0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3];
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
    let stub = unsafe { mapping.cast::<u8>().add(64) };
    unsafe { std::ptr::copy_nonoverlapping(CODE.as_ptr(), stub, CODE.len()) };
    assert_eq!(
        unsafe { libc::mprotect(mapping, page, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    // SAFETY: the page now holds exactly this function, and stays mapped.
    let anonymous_getpid: extern "C" fn() -> i64 = unsafe { core::mem::transmute(stub) };
    let anonymous_site = stub as u64 + 5;
    let installed = match installer {
        "liteinst" => unsafe { reverie_liteinst::install_tool::<SameTool>(path) },
        "no-patcher" => {
            // The same alternate-stack selector the LiteInst runs read, so each
            // test case runs both installers with one stack choice.
            let mut options = reverie_inguest::guest::tool_install::TrapOptions::default();
            options.config.use_alt_stack = reverie_liteinst::alt_stack_from_env_value(
                std::env::var_os(reverie_liteinst::ALT_STACK_ENV).as_deref(),
            )
            .expect("alternate-stack selector");
            unsafe {
                reverie_inguest::guest::tool_install::install_tool_with::<SameTool, _>(
                    path,
                    true,
                    reverie_inguest::guest::tool_install::TrapHost::new(options),
                )
            }
        }
        other => panic!("unknown installer {other:?}"),
    };
    if let Err(error) = installed {
        super::fail_instruction_install(error);
    }
    let mut same_pid = true;
    for _ in 0..GETPIDS {
        same_pid &= unsafe { super::reverie_liteinst_rpc_getpid() } == pid;
        same_pid &= anonymous_getpid() == pid;
    }
    let mut time = core::mem::MaybeUninit::<libc::timespec>::uninit();
    let clock = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) };
    let cpuid = core::arch::x86_64::__cpuid_count(0, 0);
    let cpuid_from_tool = (cpuid.eax, cpuid.ebx, cpuid.ecx, cpuid.edx)
        == (
            super::TOOL_CPUID_EAX,
            super::TOOL_CPUID_EBX,
            super::TOOL_CPUID_ECX,
            super::TOOL_CPUID_EDX,
        );
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let site = core::ptr::addr_of!(super::reverie_liteinst_rpc_getpid_site) as usize as u64;
    println!(
        "same-tool getpid={} tool-getpid={} rpc={} clock={} tool-clock={} cpuid={} tool-cpuid={} rdtsc={} tool-rdtsc={}",
        if same_pid { "pid" } else { "other" },
        TOOL_GETPIDS.load(Ordering::Relaxed),
        super::LAST_TOTAL.load(Ordering::Relaxed),
        clock,
        TOOL_CLOCKS.load(Ordering::Relaxed),
        if cpuid_from_tool { "tool" } else { "native" },
        TOOL_CPUIDS.load(Ordering::Relaxed),
        if tsc == TOOL_TSC { "tool" } else { "native" },
        TOOL_RDTSCS.load(Ordering::Relaxed),
    );
    println!(
        "binary-site traps={} hooks={} anonymous-site traps={} hooks={}",
        reverie_liteinst::reverie_liteinst_site_trap_count(site),
        reverie_liteinst::reverie_liteinst_site_hook_count(site),
        reverie_liteinst::reverie_liteinst_site_trap_count(anonymous_site),
        reverie_liteinst::reverie_liteinst_site_hook_count(anonymous_site),
    );
    std::io::stdout().flush().unwrap();
}
