// Legacy embedded Tool root: intentionally retains scoped allocation behavior.
reverie_liteinst::declare_legacy_scoped_tool_allocator!();

use core::arch::global_asm;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI64;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::ffi::CString;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

use reverie::CpuIdResult;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalRPC;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Pid;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::ExitGroup;
use reverie::syscalls::RtSigprocmask;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_rpc_transport::RpcServer;

#[path = "rpc_tool_guest/syscall_fallback.rs"]
mod syscall_fallback_guest;

#[path = "rpc_tool_guest/memory_access.rs"]
mod memory_access_guest;

#[path = "rpc_tool_guest/owned_frame.rs"]
mod owned_frame_guest;

#[path = "rpc_tool_guest/vdso_getrandom.rs"]
mod vdso_getrandom_guest;

#[path = "rpc_tool_guest/vdso_fail_closed.rs"]
mod vdso_fail_closed_guest;

#[path = "rpc_tool_guest/late_code.rs"]
mod late_code_guest;

#[path = "rpc_tool_guest/fixed_gates.rs"]
mod fixed_gates_guest;

const CALLS: u64 = 32;
const TOOL_CPUID_EAX: u32 = 0x1111_1111;
const TOOL_CPUID_EBX: u32 = 0x2222_2222;
const TOOL_CPUID_ECX: u32 = 0;
const TOOL_CPUID_EDX: u32 = 0x4444_4444;
const INSTRUCTION_CONTROL_UNAVAILABLE_STATUS: i32 = 77;
static LAST_TOTAL: AtomicU64 = AtomicU64::new(0);
static LAST_SENDERS: AtomicU64 = AtomicU64::new(0);
static LAST_NESTED_UID: AtomicI64 = AtomicI64::new(-1);
static LAST_MASK_RESULT: AtomicI64 = AtomicI64::new(0);
static LAST_FIRST_USE_EXEC_RESULT: AtomicI64 = AtomicI64::new(0);
static LAST_FIRST_USE_SIGNAL_RESULT: AtomicI64 = AtomicI64::new(0);
static CHILD_RECONSTRUCTED: AtomicBool = AtomicBool::new(false);
static MASK_DURING_WAIT: AtomicU64 = AtomicU64::new(0);
static MASK_PROBE_READABLE: AtomicI64 = AtomicI64::new(0);
static MASK_PROBE_UNREADABLE: AtomicI64 = AtomicI64::new(0);
static MASK_INSTRUCTION_CALLBACKS: AtomicU64 = AtomicU64::new(0);
static RCB_BEFORE: AtomicU64 = AtomicU64::new(0);
static RCB_AFTER: AtomicU64 = AtomicU64::new(0);
static RCB_CALLBACKS: AtomicU64 = AtomicU64::new(0);
static RCB_ENTRIES: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static RCB_AVAILABLE: AtomicBool = AtomicBool::new(false);
static VDSO_CLOCK_CALLS: AtomicU64 = AtomicU64::new(0);
static CHILD_NESTED_CPUID_NATIVE: AtomicBool = AtomicBool::new(false);
static CHILD_NESTED_RDTSC_NATIVE: AtomicBool = AtomicBool::new(false);
static CHILD_NESTED_RDTSCP_NATIVE: AtomicBool = AtomicBool::new(false);
static INSTRUCTION_TOOL_CALLBACKS: AtomicU64 = AtomicU64::new(0);
static INSTRUCTION_HANDLER_RPC_CALLS: AtomicU64 = AtomicU64::new(0);
static INSTRUCTION_PATCHED_CPUID_NATIVE: AtomicBool = AtomicBool::new(false);
static INSTRUCTION_FIRST_USE_RDTSC_NATIVE: AtomicBool = AtomicBool::new(false);
static INSTRUCTION_NESTED_SYSCALL_NATIVE: AtomicBool = AtomicBool::new(false);
static INSTRUCTION_EXPECTED_UID: AtomicI64 = AtomicI64::new(-1);

#[derive(Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct CpuidWords {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

fn tool_cpuid_words() -> CpuidWords {
    CpuidWords {
        eax: TOOL_CPUID_EAX,
        ebx: TOOL_CPUID_EBX,
        ecx: TOOL_CPUID_ECX,
        edx: TOOL_CPUID_EDX,
    }
}

#[inline(never)]
fn retire_conditional_branches(iterations: u64) {
    let mut remaining = iterations;
    unsafe {
        core::arch::asm!(
            "2:",
            "dec {remaining}",
            "jnz 2b",
            remaining = inout(reg) remaining,
            options(nostack),
        );
    }
    std::hint::black_box(remaining);
}

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

/// The `getppid` argument that asks [`CounterTool`] for a private mask query
/// on its own buffer.
const PRIVATE_MASK_QUERY_MARKER: usize = 0x5157;

/// The `getppid` argument that asks [`CounterTool`] to deliver a SIGALRM as
/// the call completes (`Guest::defer_signal_delivery`).
const DELIVER_SIGALRM_MARKER: usize = 0x5158;

/// The `getppid` argument that asks [`CounterTool`] to request two SIGALRM
/// deliveries in one call; it returns the second request's result.
const DELIVER_SIGALRM_TWICE_MARKER: usize = 0x5159;

/// The `getppid` argument that, while [`ENTRY_DELIVERY_ARMED`] is set, asks
/// [`CounterTool`] to deliver a SIGALRM at the call's entry, without running
/// it (`Guest::defer_signal_delivery_before_syscall`); the call then runs
/// from the start. Disarmed by that first sighting.
const DELIVER_SIGALRM_BEFORE_MARKER: usize = 0x515a;
static ENTRY_DELIVERY_ARMED: AtomicBool = AtomicBool::new(false);
/// How many times [`CounterTool`] ran the marked call (injected it).
static BEFORE_MARKER_RUNS: AtomicU64 = AtomicU64::new(0);
/// The entry delivery's result, as the Tool saw it (0 or a negative errno).
static ENTRY_DELIVERY_RESULT: AtomicI64 = AtomicI64::new(1);

/// [`CounterTool`]'s exit status if a guest `rt_sigreturn` ever reaches it.
const TOOL_SAW_SIGRETURN_STATUS: i32 = 118;

#[reverie::tool]
impl Tool for CounterTool {
    type GlobalState = CounterGlobal;
    type ThreadState = u64;

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::rt_sigreturn {
            // The runtime refuses the guest's own rt_sigreturn before any
            // Tool sees it (tool-sigreturn-trap, tool-sigreturn-hook).
            unsafe { reverie_inguest::guest::support::exit_now(TOOL_SAW_SIGRETURN_STATUS) };
        }
        let marker = syscall.into_parts().1.arg0;
        if syscall.number() == Sysno::getppid && marker == DELIVER_SIGALRM_BEFORE_MARKER {
            if ENTRY_DELIVERY_ARMED.swap(false, Ordering::SeqCst) {
                let mut info = [0_u8; 128];
                info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
                info[8..12].copy_from_slice(&0x80_i32.to_ne_bytes());
                let event = reverie::SignalEvent::new(
                    libc::SIGALRM,
                    info,
                    reverie::SignalTarget::Process {
                        pid: reverie::Pid::from_raw(unsafe { libc::getpid() }),
                    },
                )
                .unwrap();
                let result = match guest.defer_signal_delivery_before_syscall(event).await {
                    Ok(()) => 0,
                    Err(reverie::Error::Errno(errno)) => -i64::from(errno.into_raw()),
                    Err(_) => -i64::from(libc::EIO),
                };
                ENTRY_DELIVERY_RESULT.store(result, Ordering::SeqCst);
                if result == 0 {
                    // Discarded: the call starts again after the handler.
                    return Ok(-i64::from(libc::EHWPOISON));
                }
            }
            BEFORE_MARKER_RUNS.fetch_add(1, Ordering::SeqCst);
            return Ok(guest.inject(syscall).await?);
        }
        if syscall.number() == Sysno::getppid
            && (marker == DELIVER_SIGALRM_MARKER || marker == DELIVER_SIGALRM_TWICE_MARKER)
        {
            // A Tool-committed SIGALRM, delivered as this call completes.
            let mut info = [0_u8; 128];
            info[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
            info[8..12].copy_from_slice(&0x80_i32.to_ne_bytes());
            let event = reverie::SignalEvent::new(
                libc::SIGALRM,
                info,
                reverie::SignalTarget::Process {
                    pid: reverie::Pid::from_raw(unsafe { libc::getpid() }),
                },
            )
            .unwrap();
            if marker == DELIVER_SIGALRM_TWICE_MARKER {
                assert!(guest.defer_signal_delivery(event).await.is_ok());
            }
            return Ok(match guest.defer_signal_delivery(event).await {
                Ok(()) => 0,
                Err(reverie::Error::Errno(errno)) => -i64::from(errno.into_raw()),
                Err(_) => -i64::from(libc::EIO),
            });
        }
        if syscall.number() == Sysno::getppid
            && syscall.into_parts().1.arg0 == PRIVATE_MASK_QUERY_MARKER
        {
            // A private call on the Tool's own buffer: the guest's rights
            // never apply to it.
            let mut old = 0_u64;
            let query = signal_mask_call(libc::SIG_BLOCK, 0, (&raw mut old) as usize);
            return Ok(errno_result(guest.inject(query).await));
        }
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
struct InstructionTool;

#[reverie::tool]
impl Tool for InstructionTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut subscriptions: Subscription = [Sysno::getuid].into_iter().collect();
        subscriptions.cpuid().rdtsc();
        subscriptions
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        _eax: u32,
        _ecx: u32,
    ) -> Result<CpuIdResult, reverie::Errno> {
        let callback = INSTRUCTION_TOOL_CALLBACKS.fetch_add(1, Ordering::Relaxed) + 1;
        if callback == 1 {
            INSTRUCTION_PATCHED_CPUID_NATIVE
                .store(nested_cpuid(0, 0) != tool_cpuid_words(), Ordering::Relaxed);
            INSTRUCTION_FIRST_USE_RDTSC_NATIVE.store(
                unsafe { reverie_liteinst_rpc_first_use_rdtsc() } != 0x1234_5678_9abc_def0,
                Ordering::Relaxed,
            );
            let uid = unsafe { reverie_liteinst_rpc_getuid() };
            INSTRUCTION_NESTED_SYSCALL_NATIVE.store(
                uid == INSTRUCTION_EXPECTED_UID.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            let _ = guest.send_rpc(1).await;
            INSTRUCTION_HANDLER_RPC_CALLS.fetch_add(1, Ordering::Relaxed);
        }
        Ok(CpuIdResult {
            eax: TOOL_CPUID_EAX,
            ebx: TOOL_CPUID_EBX,
            ecx: TOOL_CPUID_ECX,
            edx: TOOL_CPUID_EDX,
        })
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, reverie::Errno> {
        INSTRUCTION_TOOL_CALLBACKS.fetch_add(1, Ordering::Relaxed);
        Ok(RdtscResult {
            tsc: match request {
                Rdtsc::Tsc => 0x1234_5678_9abc_def0,
                Rdtsc::Tscp => 0x0fed_cba9_8765_4321,
            },
            aux: (request == Rdtsc::Tscp).then_some(0x2468_ace0),
        })
    }
}

#[derive(Default)]
struct NestedInstructionForkTool;

#[reverie::tool]
impl Tool for NestedInstructionForkTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut subscriptions: Subscription = [Sysno::fork, Sysno::getpid, Sysno::wait4]
            .into_iter()
            .collect();
        subscriptions.cpuid().rdtsc();
        subscriptions
    }

    async fn handle_thread_start<G: Guest<Self>>(&self, guest: &mut G) -> Result<(), Error> {
        if guest.ppid().is_some() {
            let observed = nested_cpuid(0, 0);
            CHILD_NESTED_CPUID_NATIVE.store(observed != tool_cpuid_words(), Ordering::Release);
            CHILD_NESTED_RDTSC_NATIVE.store(
                unsafe { reverie_liteinst_rpc_nested_rdtsc() } != 0x1234_5678_9abc_def0,
                Ordering::Release,
            );
            let (tsc, _) = nested_rdtscp();
            CHILD_NESTED_RDTSCP_NATIVE.store(tsc != 0x0fed_cba9_8765_4321, Ordering::Release);
        }
        Ok(())
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        _eax: u32,
        _ecx: u32,
    ) -> Result<CpuIdResult, reverie::Errno> {
        Ok(CpuIdResult {
            eax: TOOL_CPUID_EAX,
            ebx: TOOL_CPUID_EBX,
            ecx: TOOL_CPUID_ECX,
            edx: TOOL_CPUID_EDX,
        })
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, reverie::Errno> {
        Ok(RdtscResult {
            tsc: match request {
                Rdtsc::Tsc => 0x1234_5678_9abc_def0,
                Rdtsc::Tscp => 0x0fed_cba9_8765_4321,
            },
            aux: (request == Rdtsc::Tscp).then_some(0x2468_ace0),
        })
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct ClockAndVdsoTool;

#[reverie::tool]
impl Tool for ClockAndVdsoTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        [Sysno::getpid, Sysno::clock_gettime].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() == Sysno::getpid {
            let callback = RCB_CALLBACKS.fetch_add(1, Ordering::Relaxed);
            match guest.read_clock() {
                Ok(before) => {
                    if let Some(entry) = RCB_ENTRIES.get(callback as usize) {
                        entry.store(before, Ordering::Relaxed);
                    }
                    if callback == 0 {
                        // This is deliberately much more handler work than the
                        // guest performs between either pair of clock samples.
                        // If handler RCBs leak, the first interval dominates.
                        retire_conditional_branches(65_536);
                        let after = guest.read_clock()?;
                        RCB_BEFORE.store(before, Ordering::Relaxed);
                        RCB_AFTER.store(after, Ordering::Relaxed);
                    }
                    RCB_AVAILABLE.store(true, Ordering::Release);
                }
                Err(_) => RCB_AVAILABLE.store(false, Ordering::Release),
            }
        } else if syscall.number() == Sysno::clock_gettime {
            VDSO_CLOCK_CALLS.fetch_add(1, Ordering::Relaxed);
        }
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

const SIGSET_SIZE: usize = core::mem::size_of::<u64>();

const fn signal_bit(signal: libc::c_int) -> u64 {
    1 << (signal - 1)
}

/// The mask left by blocking every signal under Mode A: Linux never blocks
/// SIGKILL or SIGSTOP, and the runtime keeps SIGSYS unblocked.
const FULL_MASK_UNDER_MODE_A: u64 =
    !(signal_bit(libc::SIGKILL) | signal_bit(libc::SIGSTOP) | signal_bit(libc::SIGSYS));

/// The same mask while CPUID or RDTSC is subscribed: those instructions trap
/// with SIGSEGV, so the runtime keeps SIGSEGV unblocked too.
const FULL_MASK_UNDER_INSTRUCTIONS: u64 = FULL_MASK_UNDER_MODE_A & !signal_bit(libc::SIGSEGV);

/// The value [`MaskInstructionTool`] returns for RDTSC.
const MASK_TOOL_TSC: u64 = 0x1234_5678_9abc_def0;

fn errno_result(result: Result<i64, reverie::Errno>) -> i64 {
    result.unwrap_or_else(|error| -i64::from(error.into_raw()))
}

/// An `rt_sigprocmask` call on the Tool's own sets; 0 passes no set.
fn signal_mask_call(how: libc::c_int, set: usize, old_set: usize) -> RtSigprocmask {
    RtSigprocmask::new()
        .with_how(how)
        .with_set(Addr::from_raw(set))
        .with_oldset(AddrMut::from_raw(old_set))
        .with_sigsetsize(SIGSET_SIZE)
}

/// Blocks every signal around a guest `wait4`, as Detcore's blocking wait does.
#[derive(Default)]
struct BlockingWaitTool;

#[reverie::tool]
impl Tool for BlockingWaitTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        [Sysno::rt_sigprocmask, Sysno::wait4].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if syscall.number() != Sysno::wait4 {
            return Ok(guest.inject(syscall).await?);
        }
        // Addresses, not raw pointers, keep the future `Send`; the sets live
        // in the pinned future, so they stay put across each await.
        let all = u64::MAX;
        let mut previous = 0_u64;
        let mut during = 0_u64;
        let all_addr = (&raw const all) as usize;
        let previous_addr = (&raw mut previous) as usize;
        let during_addr = (&raw mut during) as usize;
        // Detcore checks that a guest set is readable with an invalid `how`,
        // which Linux rejects only after it has read the set.
        let readable = guest.inject(signal_mask_call(-1, all_addr, 0)).await;
        MASK_PROBE_READABLE.store(errno_result(readable), Ordering::Release);
        let unreadable = guest.inject(signal_mask_call(-1, 0x10, 0)).await;
        MASK_PROBE_UNREADABLE.store(errno_result(unreadable), Ordering::Release);
        guest
            .inject(signal_mask_call(libc::SIG_SETMASK, all_addr, previous_addr))
            .await?;
        guest
            .inject(signal_mask_call(libc::SIG_SETMASK, 0, during_addr))
            .await?;
        let during = unsafe { (during_addr as *const u64).read_volatile() };
        MASK_DURING_WAIT.store(during, Ordering::Release);
        let waited = guest.inject(syscall).await;
        guest
            .inject(signal_mask_call(libc::SIG_SETMASK, previous_addr, 0))
            .await?;
        Ok(waited?)
    }
}

/// Subscribes CPUID and RDTSC, so the runtime reserves SIGSEGV, and injects the
/// guest's own `rt_sigprocmask` calls, as Detcore does. The instruction set is
/// [`InstructionTool`]'s, so the test's capability result from the instruction
/// modes decides whether this install succeeds or refuses.
#[derive(Default)]
struct MaskInstructionTool;

#[reverie::tool]
impl Tool for MaskInstructionTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut subscriptions: Subscription = [Sysno::rt_sigprocmask].into_iter().collect();
        subscriptions.cpuid().rdtsc();
        subscriptions
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        Ok(guest.inject(syscall).await?)
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, reverie::Errno> {
        MASK_INSTRUCTION_CALLBACKS.fetch_add(1, Ordering::Relaxed);
        assert_eq!(request, Rdtsc::Tsc);
        Ok(RdtscResult {
            tsc: MASK_TOOL_TSC,
            aux: None,
        })
    }
}

#[derive(Default)]
struct TailMaskTool;

#[reverie::tool]
impl Tool for TailMaskTool {
    type GlobalState = CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        [Sysno::rt_sigprocmask].into_iter().collect()
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
    .cfi_startproc
    mov eax, 39
    .global reverie_liteinst_rpc_getpid_site
    .hidden reverie_liteinst_rpc_getpid_site
reverie_liteinst_rpc_getpid_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_getpid, .-reverie_liteinst_rpc_getpid

    .p2align 4
    .global reverie_liteinst_rpc_getuid
    .hidden reverie_liteinst_rpc_getuid
    .type reverie_liteinst_rpc_getuid,@function
reverie_liteinst_rpc_getuid:
    .cfi_startproc
    mov eax, 102
    .global reverie_liteinst_rpc_getuid_site
    .hidden reverie_liteinst_rpc_getuid_site
reverie_liteinst_rpc_getuid_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_getuid, .-reverie_liteinst_rpc_getuid

    # One syscall site for any number (the first argument), like glibc's
    # syscall() wrapper: patched for one number, its hook carries the next.
    .p2align 4
    .global reverie_liteinst_rpc_numbered
    .hidden reverie_liteinst_rpc_numbered
    .type reverie_liteinst_rpc_numbered,@function
reverie_liteinst_rpc_numbered:
    .cfi_startproc
    mov rax, rdi
    .global reverie_liteinst_rpc_numbered_site
    .hidden reverie_liteinst_rpc_numbered_site
reverie_liteinst_rpc_numbered_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_numbered, .-reverie_liteinst_rpc_numbered

    # The same for a site no other syscall reaches, so its first call traps.
    .p2align 4
    .global reverie_liteinst_rpc_fresh_numbered
    .hidden reverie_liteinst_rpc_fresh_numbered
    .type reverie_liteinst_rpc_fresh_numbered,@function
reverie_liteinst_rpc_fresh_numbered:
    .cfi_startproc
    mov rax, rdi
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_fresh_numbered, .-reverie_liteinst_rpc_fresh_numbered

    # A site reached only by the guest's own rt_sigreturn, so it traps.
    .p2align 4
    .global reverie_liteinst_rpc_sigreturn
    .hidden reverie_liteinst_rpc_sigreturn
    .type reverie_liteinst_rpc_sigreturn,@function
reverie_liteinst_rpc_sigreturn:
    .cfi_startproc
    mov eax, 15
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_sigreturn, .-reverie_liteinst_rpc_sigreturn

    .p2align 4
    .global reverie_liteinst_rpc_sigprocmask
    .hidden reverie_liteinst_rpc_sigprocmask
    .type reverie_liteinst_rpc_sigprocmask,@function
reverie_liteinst_rpc_sigprocmask:
    .cfi_startproc
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
    .cfi_endproc
    .size reverie_liteinst_rpc_sigprocmask, .-reverie_liteinst_rpc_sigprocmask

    # A second rt_sigprocmask site whose first call carries a set: that call
    # traps once, the runtime installs the site's hook, and the call then
    # completes through that hook.
    .p2align 4
    .global reverie_liteinst_rpc_sigprocmask_first
    .hidden reverie_liteinst_rpc_sigprocmask_first
    .type reverie_liteinst_rpc_sigprocmask_first,@function
reverie_liteinst_rpc_sigprocmask_first:
    .cfi_startproc
    mov r10, rcx
    mov eax, 14
    .global reverie_liteinst_rpc_sigprocmask_first_site
    .hidden reverie_liteinst_rpc_sigprocmask_first_site
reverie_liteinst_rpc_sigprocmask_first_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_sigprocmask_first, .-reverie_liteinst_rpc_sigprocmask_first

    # An RDTSC site first reached after every signal has been blocked.
    .p2align 4
    .global reverie_liteinst_rpc_mask_rdtsc
    .hidden reverie_liteinst_rpc_mask_rdtsc
    .type reverie_liteinst_rpc_mask_rdtsc,@function
reverie_liteinst_rpc_mask_rdtsc:
    .global reverie_liteinst_rpc_mask_rdtsc_site
    .hidden reverie_liteinst_rpc_mask_rdtsc_site
reverie_liteinst_rpc_mask_rdtsc_site:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
    .size reverie_liteinst_rpc_mask_rdtsc, .-reverie_liteinst_rpc_mask_rdtsc

    # rt_sigprocmask(rsi, rdx, rcx, r8) through the `syscall` at rdi.
    .p2align 4
    .global reverie_liteinst_rpc_mask_at
    .hidden reverie_liteinst_rpc_mask_at
    .type reverie_liteinst_rpc_mask_at,@function
reverie_liteinst_rpc_mask_at:
    .cfi_startproc
    mov r11, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov eax, 14
    call r11
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_mask_at, .-reverie_liteinst_rpc_mask_at

    .p2align 4
    .global reverie_liteinst_rpc_wait4
    .hidden reverie_liteinst_rpc_wait4
    .type reverie_liteinst_rpc_wait4,@function
reverie_liteinst_rpc_wait4:
    .cfi_startproc
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
    .cfi_endproc
    .size reverie_liteinst_rpc_wait4, .-reverie_liteinst_rpc_wait4

    .p2align 4
    .global reverie_liteinst_rpc_execve
    .hidden reverie_liteinst_rpc_execve
    .type reverie_liteinst_rpc_execve,@function
reverie_liteinst_rpc_execve:
    .cfi_startproc
    mov eax, 59
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_execve, .-reverie_liteinst_rpc_execve

    .p2align 4
    .global reverie_liteinst_rpc_sigaltstack
    .hidden reverie_liteinst_rpc_sigaltstack
    .type reverie_liteinst_rpc_sigaltstack,@function
reverie_liteinst_rpc_sigaltstack:
    .cfi_startproc
    mov eax, 131
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_sigaltstack, .-reverie_liteinst_rpc_sigaltstack

    .p2align 4
    .global reverie_liteinst_rpc_raise_sigsys
    .hidden reverie_liteinst_rpc_raise_sigsys
    .type reverie_liteinst_rpc_raise_sigsys,@function
reverie_liteinst_rpc_raise_sigsys:
    .cfi_startproc
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
    .cfi_endproc
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
    .cfi_startproc
    mov eax, 57
    .global reverie_liteinst_rpc_raw_fork_site
    .hidden reverie_liteinst_rpc_raw_fork_site
reverie_liteinst_rpc_raw_fork_site:
    syscall
    nop
    nop
    nop
    ret
    .cfi_endproc
    .size reverie_liteinst_rpc_raw_fork, .-reverie_liteinst_rpc_raw_fork

    # One stable CPUID site is deliberately used both outside and inside a Tool
    # callback. The former must be Tool-virtualized; the latter must execute
    # natively rather than recursively acquiring the Tool lock.
    .p2align 4
    .global reverie_liteinst_rpc_nested_cpuid
    .hidden reverie_liteinst_rpc_nested_cpuid
    .type reverie_liteinst_rpc_nested_cpuid,@function
reverie_liteinst_rpc_nested_cpuid:
    push rbx
    mov r8, rdx
    mov eax, edi
    mov ecx, esi
    .global reverie_liteinst_rpc_nested_cpuid_site
    .hidden reverie_liteinst_rpc_nested_cpuid_site
reverie_liteinst_rpc_nested_cpuid_site:
    cpuid
    mov dword ptr [r8], eax
    mov dword ptr [r8 + 4], ebx
    mov dword ptr [r8 + 8], ecx
    mov dword ptr [r8 + 12], edx
    pop rbx
    ret
    .size reverie_liteinst_rpc_nested_cpuid, .-reverie_liteinst_rpc_nested_cpuid

    # This RDTSC site is first reached from an active CPUID Tool callback.
    # CPUID is temporarily native for the outer hook, but TSC faulting remains
    # enabled, so this exercises the active-Tool SIGSEGV first-use path.
    # It must execute natively without publishing a hook; its later application
    # use must still enter the Tool.
    .p2align 4
    .global reverie_liteinst_rpc_first_use_rdtsc
    .hidden reverie_liteinst_rpc_first_use_rdtsc
    .type reverie_liteinst_rpc_first_use_rdtsc,@function
reverie_liteinst_rpc_first_use_rdtsc:
    .global reverie_liteinst_rpc_first_use_rdtsc_site
    .hidden reverie_liteinst_rpc_first_use_rdtsc_site
reverie_liteinst_rpc_first_use_rdtsc_site:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
    .size reverie_liteinst_rpc_first_use_rdtsc, .-reverie_liteinst_rpc_first_use_rdtsc

    .p2align 4
    .global reverie_liteinst_rpc_nested_rdtsc
    .hidden reverie_liteinst_rpc_nested_rdtsc
    .type reverie_liteinst_rpc_nested_rdtsc,@function
reverie_liteinst_rpc_nested_rdtsc:
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
    .size reverie_liteinst_rpc_nested_rdtsc, .-reverie_liteinst_rpc_nested_rdtsc

    .p2align 4
    .global reverie_liteinst_rpc_nested_rdtscp
    .hidden reverie_liteinst_rpc_nested_rdtscp
    .type reverie_liteinst_rpc_nested_rdtscp,@function
reverie_liteinst_rpc_nested_rdtscp:
    mov r8, rdi
    rdtscp
    mov dword ptr [r8], ecx
    shl rdx, 32
    or rax, rdx
    ret
    .size reverie_liteinst_rpc_nested_rdtscp, .-reverie_liteinst_rpc_nested_rdtscp

    # Force the instruction to begin at byte 61 of a cache line. The eight-byte
    # LiteInst publication word therefore straddles the boundary and exercises
    # both guarded Concurrent publication and calibration-free Quiescent
    # publication in their respective fixture processes.
    .p2align 6
    .global reverie_liteinst_straddling_cpuid
    .hidden reverie_liteinst_straddling_cpuid
    .type reverie_liteinst_straddling_cpuid,@function
reverie_liteinst_straddling_cpuid:
    push rbx
    .fill 60, 1, 0x90
    cpuid
    pop rbx
    ret
    .size reverie_liteinst_straddling_cpuid, .-reverie_liteinst_straddling_cpuid

    .p2align 6
    .global reverie_liteinst_straddling_rdtsc
    .hidden reverie_liteinst_straddling_rdtsc
    .type reverie_liteinst_straddling_rdtsc,@function
reverie_liteinst_straddling_rdtsc:
    .fill 61, 1, 0x90
    rdtsc
    shl rdx, 32
    or rax, rdx
    ret
    .size reverie_liteinst_straddling_rdtsc, .-reverie_liteinst_straddling_rdtsc
"#
);

unsafe extern "C" {
    fn reverie_liteinst_rpc_getpid() -> i64;
    fn reverie_liteinst_rpc_getuid() -> i64;
    fn reverie_liteinst_rpc_numbered(number: i64) -> i64;
    fn reverie_liteinst_rpc_fresh_numbered(number: i64) -> i64;
    fn reverie_liteinst_rpc_sigreturn() -> i64;
    fn reverie_liteinst_rpc_execve(
        path: *const u8,
        argv: *const *const u8,
        envp: *const *const u8,
    ) -> i64;
    fn reverie_liteinst_rpc_sigaltstack() -> i64;
    fn reverie_liteinst_rpc_raise_sigsys() -> i64;
    fn reverie_liteinst_rpc_raw_fork() -> i64;
    fn reverie_liteinst_rpc_nested_cpuid(eax: u32, ecx: u32, result: *mut CpuidWords);
    fn reverie_liteinst_rpc_first_use_rdtsc() -> u64;
    fn reverie_liteinst_rpc_nested_rdtsc() -> u64;
    fn reverie_liteinst_rpc_nested_rdtscp(aux: *mut u32) -> u64;
    fn reverie_liteinst_straddling_cpuid() -> u64;
    fn reverie_liteinst_straddling_rdtsc() -> u64;
    fn reverie_liteinst_rpc_sigprocmask(
        how: u64,
        set: *const u64,
        old_set: *mut u64,
        size: usize,
    ) -> i64;
    fn reverie_liteinst_rpc_sigprocmask_first(
        how: u64,
        set: *const u64,
        old_set: *mut u64,
        size: usize,
    ) -> i64;
    fn reverie_liteinst_rpc_mask_rdtsc() -> u64;
    fn reverie_liteinst_rpc_mask_at(
        site: u64,
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
    static reverie_liteinst_rpc_numbered_site: u8;
    static reverie_liteinst_rpc_sigprocmask_site: u8;
    static reverie_liteinst_rpc_sigprocmask_first_site: u8;
    static reverie_liteinst_rpc_mask_rdtsc_site: u8;
    static reverie_liteinst_rpc_wait4_site: u8;
    static reverie_liteinst_rpc_nested_cpuid_site: u8;
    static reverie_liteinst_rpc_first_use_rdtsc_site: u8;
}

fn nested_cpuid(eax: u32, ecx: u32) -> CpuidWords {
    let mut result = CpuidWords::default();
    unsafe { reverie_liteinst_rpc_nested_cpuid(eax, ecx, &mut result) };
    result
}

fn nested_rdtscp() -> (u64, u32) {
    let mut aux = 0;
    let tsc = unsafe { reverie_liteinst_rpc_nested_rdtscp(&mut aux) };
    (tsc, aux)
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

/// Signal phase 1 in the Tool mode: the runtime's SIGSYS handler and the
/// LiteInst2 guard's SIGTRAP handler return through the private restorer, the
/// filter admits `rt_sigreturn` there alone, and a guest's new SIGKILL or
/// SIGSTOP action reaches Linux, which refuses it with EINVAL.
fn tool_signal_runtime_guest(path: &Path) {
    use reverie_inguest::signal::KernelSigaction;
    use reverie_inguest::signal::SA_RESTORER;
    use reverie_inguest::signal::raw_sigaction;
    use reverie_inguest::signal::signal_restorer;

    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    assert!(reverie_inguest::trap::signal_return_restricted());
    for signal in [libc::SIGSYS, libc::SIGTRAP] {
        let mut action = KernelSigaction::default();
        unsafe { raw_sigaction(signal, None, Some(&mut action)) }.unwrap();
        assert_ne!(action.handler, libc::SIG_DFL as u64, "signal {signal}");
        assert_ne!(action.flags & SA_RESTORER as u64, 0, "signal {signal}");
        assert_eq!(action.restorer, signal_restorer(), "signal {signal}");
    }
    for signal in [libc::SIGKILL, libc::SIGSTOP] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = forbidden_signal_handler as *const () as usize;
        let result = unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
        assert_eq!(result, -1, "signal {signal}");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL),
            "signal {signal}"
        );
    }
    println!("tool-signal-runtime-ok");
}

/// The guest's own `rt_sigreturn` in the Tool mode ends the process, whether
/// it traps at a fresh site or reaches a site's hook installed for another
/// syscall, and whether its number register holds 15 or an alias with high
/// bits set (Linux reads the low 32 bits).
fn tool_guest_sigreturn_guest(path: &Path, through_hook: bool, alias: bool) -> ! {
    let number = if alias {
        0x1_0000_0000 | libc::SYS_rt_sigreturn
    } else {
        libc::SYS_rt_sigreturn
    };
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    if through_hook {
        let parent = unsafe { libc::getppid() };
        for _ in 0..2 {
            assert_eq!(
                unsafe { reverie_liteinst_rpc_numbered(libc::SYS_getppid) },
                i64::from(parent)
            );
        }
        let site = core::ptr::addr_of!(reverie_liteinst_rpc_numbered_site) as usize as u64;
        assert!(reverie_liteinst::reverie_liteinst_site_hook_count(site) >= 1);
        println!("numbered-site-hooked");
        unsafe { reverie_liteinst_rpc_numbered(number) };
    } else if alias {
        println!("sigreturn-site-fresh");
        unsafe { reverie_liteinst_rpc_fresh_numbered(number) };
    } else {
        println!("sigreturn-site-fresh");
        unsafe { reverie_liteinst_rpc_sigreturn() };
    }
    panic!("the guest's rt_sigreturn returned");
}

/// A SIGTRAP that is not a guard trap is passed by LiteInst2's router to the
/// prior default action through the runtime's raw callback: the process dies
/// of SIGTRAP after the router returns through the private restorer.
fn tool_sigtrap_default_guest(path: &Path) -> ! {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    // Non-dumpable, so the default action writes no core.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
    println!("raising-sigtrap");
    unsafe { reverie_inguest::signal::raw_raise(libc::SIGTRAP) }.unwrap();
    panic!("a non-guard SIGTRAP did not take the default action");
}

unsafe extern "C" fn guest_sigalrm_handler(_signal: libc::c_int) {}

unsafe extern "C" fn other_guest_sigalrm_handler(_signal: libc::c_int) {}

/// An allow-everything classic BPF program for a seccomp filter.
fn allow_all_filter() -> ([libc::sock_filter; 1], libc::sock_fprog) {
    let program = [libc::sock_filter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k: libc::SECCOMP_RET_ALLOW,
    }];
    let fprog = libc::sock_fprog {
        len: 1,
        filter: core::ptr::null_mut(),
    };
    (program, fprog)
}

/// A raw `rt_sigaction(SIGALRM, NULL, &old)` made while the guest's PKRU
/// denies writes to key 0 (all of this process's memory), restoring the PKRU
/// right after; `None` when the processor has no protection keys enabled.
/// Linux answers EFAULT: it cannot copy the old action out.
fn sigalrm_query_with_key_zero_write_denied() -> Option<i64> {
    let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
    if leaf7.ecx & (1 << 4) == 0 {
        return None;
    }
    let mut old = reverie_inguest::signal::KernelSigaction::default();
    let result: i64;
    unsafe {
        core::arch::asm!(
            "xor ecx, ecx",
            "rdpkru",
            "mov r13d, eax",
            "xor ecx, ecx",
            "xor edx, edx",
            "mov eax, r13d",
            "or eax, 2",
            "wrpkru",
            "mov eax, 13",
            "mov edi, 14",
            "xor esi, esi",
            "mov rdx, r9",
            "mov r10d, 8",
            "syscall",
            "mov r12, rax",
            "xor ecx, ecx",
            "xor edx, edx",
            "mov eax, r13d",
            "wrpkru",
            in("r9") &raw mut old,
            out("r12") result,
            out("r13") _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("rdi") _,
            out("rsi") _,
            out("r10") _,
            out("r11") _,
        );
    }
    Some(result)
}

/// A raw syscall `number(arg0, arg1, arg2, arg3)` made while the guest's PKRU
/// adds `bits` for key 0 (1 access-disable, 2 write-disable), restoring the
/// PKRU right after; `None` when the processor has no protection keys
/// enabled. The asm touches no memory between the two PKRU writes.
fn syscall_with_key_zero_denied(bits: u32, number: i64, arguments: [u64; 4]) -> Option<i64> {
    let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
    if leaf7.ecx & (1 << 4) == 0 {
        return None;
    }
    let result: i64;
    unsafe {
        core::arch::asm!(
            "xor ecx, ecx",
            "rdpkru",
            "mov r13d, eax",
            "xor ecx, ecx",
            "xor edx, edx",
            "mov eax, r13d",
            "or eax, r14d",
            "wrpkru",
            "mov rax, r15",
            "mov rdx, r12",
            "syscall",
            "mov r12, rax",
            "xor ecx, ecx",
            "xor edx, edx",
            "mov eax, r13d",
            "wrpkru",
            in("r14") bits,
            in("r15") number,
            in("rdi") arguments[0],
            in("rsi") arguments[1],
            inout("r12") arguments[2] => result,
            in("r10") arguments[3],
            out("r13") _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r11") _,
        );
    }
    Some(result)
}

fn alternate_stack_is_disabled() -> bool {
    // Every byte, padding included, must be Linux's image of a disabled
    // stack; the buffer starts as all ones so an unwritten byte shows.
    let mut stack = [0xff_u8; 24];
    let queried = unsafe { libc::sigaltstack(core::ptr::null(), stack.as_mut_ptr().cast()) };
    queried == 0 && stack == reverie_inguest::guest::sigalrm::disabled_stack_bytes()
}

fn sigalrm_sigaction(action: &libc::sigaction) -> Result<(), i32> {
    if unsafe { libc::sigaction(libc::SIGALRM, action, core::ptr::null_mut()) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap())
    }
}

fn guest_handler_action(flags: libc::c_int) -> libc::sigaction {
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = guest_sigalrm_handler as *const () as usize;
    action.sa_flags = flags;
    action
}

fn physical_sigalrm_action() -> reverie_inguest::signal::KernelSigaction {
    let mut action = reverie_inguest::signal::KernelSigaction::default();
    unsafe { reverie_inguest::signal::raw_sigaction(libc::SIGALRM, None, Some(&mut action)) }
        .unwrap();
    action
}

fn physical_mask() -> u64 {
    let mut mask = 0;
    unsafe { reverie_inguest::signal::raw_sigprocmask(libc::SIG_BLOCK, None, Some(&mut mask)) }
        .unwrap();
    mask
}

fn guest_mask_call(how: libc::c_int, set: Option<u64>) -> u64 {
    let mut old = 0_u64;
    let set_pointer = set
        .as_ref()
        .map_or(core::ptr::null(), |set| set as *const u64);
    let result = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            how,
            set_pointer,
            &mut old as *mut u64,
            8,
        )
    };
    assert_eq!(result, 0);
    old
}

/// Signal phase 1, step I3b, in the Tool mode with handlers admitted: the
/// guest's SIGALRM action, signal mask, pending set and alternate stack are
/// virtual, the physical state is the runtime's, refusals change nothing,
/// and the accepted restorer's page is protected.
fn sigalrm_virtual_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let alarm = 1_u64 << (libc::SIGALRM - 1);
    let usr1 = 1_u64 << (libc::SIGUSR1 - 1);

    // Refusals first: each EPERM, nothing installed.
    assert_eq!(
        sigalrm_sigaction(&guest_handler_action(libc::SA_RESETHAND)),
        Err(libc::EPERM)
    );
    assert_eq!(
        sigalrm_sigaction(&guest_handler_action(libc::SA_NODEFER)),
        Err(libc::EPERM)
    );
    // A hand-written restorer: glibc's bytes in a heap copy.
    let copy = Box::new(reverie_inguest::guest::restorer::GLIBC_RESTORER_BYTES);
    let forged = reverie_inguest::signal::KernelSigaction {
        handler: guest_sigalrm_handler as *const () as u64,
        flags: reverie_inguest::signal::SA_RESTORER as u64,
        restorer: copy.as_ptr() as u64,
        mask: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            libc::SIGALRM,
            &forged as *const _,
            core::ptr::null_mut::<u8>(),
            8,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    // No SA_RESTORER at all.
    let bare = reverie_inguest::signal::KernelSigaction {
        flags: 0,
        restorer: 0,
        ..forged
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            libc::SIGALRM,
            &bare as *const _,
            core::ptr::null_mut::<u8>(),
            8,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(physical_sigalrm_action().handler, libc::SIG_DFL as u64);

    // With handlers admitted the alternate stack is always virtual and
    // disabled, before any handler too; and the guest cannot add a seccomp
    // filter (one could fake the runtime's own calls).
    assert!(alternate_stack_is_disabled());
    let (mut program, mut fprog) = allow_all_filter();
    fprog.filter = program.as_mut_ptr();
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    let added = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const libc::sock_fprog,
        )
    };
    assert_eq!(added, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EOPNOTSUPP)
    );

    // No protection key can be allocated while handlers are admitted (the
    // runtime's virtual calls copy guest memory with every key open).
    let key = unsafe { libc::syscall(libc::SYS_pkey_alloc, 0, 0) };
    assert_eq!(key, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOSPC)
    );

    // Admission: the guest's action is virtual, the physical one the runtime's.
    let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
    unsafe { libc::sigaddset(&mut blocked, libc::SIGUSR2) };
    let mut action = guest_handler_action(libc::SA_RESTART | libc::SA_ONSTACK);
    action.sa_mask = blocked;
    sigalrm_sigaction(&action).unwrap();
    let mut queried: libc::sigaction = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGALRM, core::ptr::null(), &mut queried) },
        0
    );
    assert_eq!(
        queried.sa_sigaction,
        guest_sigalrm_handler as *const () as usize
    );
    assert_eq!(queried.sa_flags & libc::SA_ONSTACK, libc::SA_ONSTACK);
    let glibc_restorer = queried.sa_restorer.unwrap() as usize as u64;
    let physical = physical_sigalrm_action();
    assert_ne!(physical.handler, guest_sigalrm_handler as *const () as u64);
    assert_eq!(
        physical.restorer,
        reverie_inguest::signal::signal_restorer()
    );
    assert_eq!(physical.flags & libc::SA_ONSTACK as u64, 0);
    assert_ne!(physical.flags & libc::SA_RESTART as u64, 0);
    assert_eq!(physical.mask, (1 << (libc::SIGUSR2 - 1)) | alarm);

    // The mask: the guest sees its own; the physical one always blocks SIGALRM.
    let old = guest_mask_call(libc::SIG_BLOCK, Some(usr1));
    assert_eq!(old & alarm, 0);
    assert_eq!(guest_mask_call(libc::SIG_BLOCK, None), usr1);
    assert_eq!(physical_mask() & (usr1 | alarm), usr1 | alarm);
    guest_mask_call(libc::SIG_SETMASK, Some(0));
    assert_eq!(guest_mask_call(libc::SIG_BLOCK, None), 0);
    assert_eq!(physical_mask() & (usr1 | alarm), alarm);
    let bad_how = unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            99,
            &usr1 as *const u64,
            core::ptr::null_mut::<u64>(),
            8,
        )
    };
    assert_eq!(bad_how, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINVAL)
    );

    // A physical SIGALRM stays blocked and hidden from rt_sigpending, even
    // while the guest blocks SIGALRM itself; another blocked pending signal
    // stays visible.
    guest_mask_call(libc::SIG_SETMASK, Some(usr1 | alarm));
    unsafe { reverie_inguest::signal::raw_raise(libc::SIGALRM) }.unwrap();
    unsafe { reverie_inguest::signal::raw_raise(libc::SIGUSR1) }.unwrap();
    let mut pending: libc::sigset_t = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { libc::sigpending(&mut pending) }, 0);
    assert_eq!(unsafe { libc::sigismember(&pending, libc::SIGALRM) }, 0);
    assert_eq!(unsafe { libc::sigismember(&pending, libc::SIGUSR1) }, 1);
    // Linux's sizes: 0 copies nothing (even to NULL), 4 copies a prefix, 9
    // is EINVAL.
    let raw_pending =
        |set: *mut u64, size: usize| unsafe { libc::syscall(libc::SYS_rt_sigpending, set, size) };
    assert_eq!(raw_pending(core::ptr::null_mut(), 0), 0);
    let mut prefix = u64::MAX;
    assert_eq!(raw_pending(&mut prefix, 4), 0);
    assert_eq!(prefix, 0xffff_ffff_0000_0000 | usr1);
    assert_eq!(raw_pending(&mut prefix, 9), -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINVAL)
    );
    guest_mask_call(libc::SIG_SETMASK, Some(usr1));

    // The signal argument is a C int: 0x1_0000_000e is SIGALRM, and its query
    // is the virtual action.
    let mut aliased = reverie_inguest::signal::KernelSigaction::default();
    let result = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            0x1_0000_0000_i64 | libc::SIGALRM as i64,
            core::ptr::null::<u8>(),
            &mut aliased as *mut _,
            8,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(aliased.handler, guest_sigalrm_handler as *const () as u64);

    // Linux clears flag bits it does not know (here SA_UNSUPPORTED, 0x400),
    // so a guest can probe for one; and the old action is copied out after
    // the change, so an unwritable old pointer is EFAULT with the new action
    // in place.
    let probing = reverie_inguest::signal::KernelSigaction {
        handler: other_guest_sigalrm_handler as *const () as u64,
        flags: 0x400 | reverie_inguest::signal::SA_RESTORER as u64,
        restorer: glibc_restorer,
        mask: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            libc::SIGALRM,
            &probing as *const _,
            8_usize as *mut u8,
            8,
        )
    };
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EFAULT)
    );
    let mut probed: libc::sigaction = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGALRM, core::ptr::null(), &mut probed) },
        0
    );
    // The new handler is in place although copying the old action out
    // failed: Linux changes the action first.
    assert_eq!(probed.sa_flags & 0x400, 0);
    assert_eq!(
        probed.sa_sigaction,
        other_guest_sigalrm_handler as *const () as usize
    );
    sigalrm_sigaction(&action).unwrap();

    // A fork child inherits the virtual action and mask.
    let child = unsafe { libc::fork() };
    if child == 0 {
        let mut inherited: libc::sigaction = unsafe { core::mem::zeroed() };
        let ok = unsafe { libc::sigaction(libc::SIGALRM, core::ptr::null(), &mut inherited) } == 0
            && inherited.sa_sigaction == guest_sigalrm_handler as *const () as usize
            && guest_mask_call(libc::SIG_BLOCK, None) == usr1
            && physical_sigalrm_action().handler != guest_sigalrm_handler as *const () as u64
            && physical_mask() & alarm != 0;
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "{status:#x}"
    );

    // The guest's own protection-key rights apply to the runtime's copies of
    // the guest's buffers: with key 0 write-denied the query cannot copy the
    // old action out, while a new action is still read and installed (Linux
    // only reads it). A Tool's private call on its own buffer, made while the
    // guest denies key 0 writes, keeps the Tool's rights. (Access-disable
    // cannot be exercised here: the kernel cannot deliver the SIGSYS that
    // traps such a call, and the process dies of SIGSEGV.)
    if let Some(result) = sigalrm_query_with_key_zero_write_denied() {
        assert_eq!(result, -i64::from(libc::EFAULT));
        let replacement = reverie_inguest::signal::KernelSigaction {
            handler: other_guest_sigalrm_handler as *const () as u64,
            flags: reverie_inguest::signal::SA_RESTORER as u64,
            restorer: glibc_restorer,
            mask: 0,
        };
        let installed = syscall_with_key_zero_denied(
            2,
            libc::SYS_rt_sigaction,
            [libc::SIGALRM as u64, (&raw const replacement) as u64, 0, 8],
        );
        assert_eq!(installed, Some(0));
        let mut current: libc::sigaction = unsafe { core::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGALRM, core::ptr::null(), &mut current) },
            0
        );
        assert_eq!(
            current.sa_sigaction,
            other_guest_sigalrm_handler as *const () as usize
        );
        sigalrm_sigaction(&action).unwrap();
        let private = syscall_with_key_zero_denied(
            2,
            libc::SYS_getppid,
            [PRIVATE_MASK_QUERY_MARKER as u64, 0, 0, 0],
        );
        assert_eq!(private, Some(0));
    }
    // No protection key but 0 can be given to memory.
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    let assigned = unsafe {
        libc::syscall(
            libc::SYS_pkey_mprotect,
            page,
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            1,
        )
    };
    assert_eq!(assigned, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
    assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);
    // No execute-only mapping (it would carry a protection key of its own).
    let execute_only = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_eq!(execute_only, libc::MAP_FAILED);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );

    // A disabled alternate stack, never the runtime's.
    let mut stack: libc::stack_t = unsafe { core::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaltstack(core::ptr::null(), &mut stack) },
        0
    );
    assert_eq!(stack.ss_flags, libc::SS_DISABLE);
    assert!(stack.ss_sp.is_null());

    // The accepted restorer's page is protected.
    let page = glibc_restorer & !4095;
    let errno_of = |result: libc::c_int| {
        (result == -1).then(|| std::io::Error::last_os_error().raw_os_error())
    };
    assert_eq!(
        errno_of(unsafe {
            libc::mprotect(
                page as *mut libc::c_void,
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        }),
        Some(Some(libc::EPERM))
    );
    assert_eq!(
        errno_of(unsafe { libc::madvise(page as *mut libc::c_void, 4096, libc::MADV_NORMAL) }),
        Some(Some(libc::EPERM))
    );

    // SIG_IGN: physical too, and the pending physical SIGALRM is discarded.
    let mut ignore: libc::sigaction = unsafe { core::mem::zeroed() };
    ignore.sa_sigaction = libc::SIG_IGN;
    sigalrm_sigaction(&ignore).unwrap();
    assert_eq!(physical_sigalrm_action().handler, libc::SIG_IGN as u64);
    assert_eq!(physical_mask() & alarm, 0);
    // The alternate stack stays disabled after the handler is gone.
    assert!(alternate_stack_is_disabled());
    // The page stays protected after the handler is gone.
    assert_eq!(
        unsafe { libc::madvise(page as *mut libc::c_void, 4096, libc::MADV_NORMAL) },
        -1
    );
    println!("sigalrm-virtual-ok");
}

/// A SIGALRM the runtime did not prepare that reaches the trampoline ends
/// the process before any guest code runs.
fn sigalrm_unprepared_guest(path: &Path) -> ! {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    sigalrm_sigaction(&guest_handler_action(0)).unwrap();
    println!("sigalrm-handler-installed");
    unsafe { reverie_inguest::signal::raw_raise(libc::SIGALRM) }.unwrap();
    // Unblock it physically, behind the runtime's back.
    let alarm = 1_u64 << (libc::SIGALRM - 1);
    unsafe { reverie_inguest::signal::raw_sigprocmask(libc::SIG_UNBLOCK, Some(&alarm), None) }
        .unwrap();
    panic!("an unprepared SIGALRM reached guest code");
}

/// Installing a handler while SIGALRM is physically pending is refused, and
/// so is any handler while handlers are not admitted.
fn sigalrm_refused_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let mut blocked: libc::sigset_t = unsafe { core::mem::zeroed() };
    unsafe { libc::sigaddset(&mut blocked, libc::SIGALRM) };
    assert_eq!(
        unsafe { libc::sigprocmask(libc::SIG_BLOCK, &blocked, core::ptr::null_mut()) },
        0
    );
    assert_eq!(unsafe { libc::raise(libc::SIGALRM) }, 0);
    assert_eq!(
        sigalrm_sigaction(&guest_handler_action(0)),
        Err(libc::EPERM)
    );
    assert_eq!(physical_sigalrm_action().handler, libc::SIG_DFL as u64);
    println!("sigalrm-refused-ok");
}

/// A seccomp filter the runtime did not install (here added through the
/// runtime's own gate, behind its back) keeps any handler from being admitted:
/// it could fabricate the result of the runtime's own signal calls.
fn sigalrm_extra_filter_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let (mut program, mut fprog) = allow_all_filter();
    fprog.filter = program.as_mut_ptr();
    let added = unsafe {
        reverie_inguest::trap::raw_syscall6(
            libc::SYS_seccomp,
            [
                libc::SECCOMP_SET_MODE_FILTER as u64,
                0,
                (&fprog as *const libc::sock_fprog) as u64,
                0,
                0,
                0,
            ],
        )
    };
    assert_eq!(added, 0);
    assert_eq!(
        sigalrm_sigaction(&guest_handler_action(0)),
        Err(libc::EPERM)
    );
    assert_eq!(physical_sigalrm_action().handler, libc::SIG_DFL as u64);
    println!("sigalrm-extra-filter-ok");
}

/// A seccomp filter present before the runtime starts (inherited, here
/// installed first) keeps handlers from being admitted at all.
fn sigalrm_inherited_filter_guest(path: &Path) {
    let (mut program, mut fprog) = allow_all_filter();
    fprog.filter = program.as_mut_ptr();
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    let added = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &fprog as *const libc::sock_fprog,
        )
    };
    assert_eq!(added, 0);
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    assert!(!reverie_inguest::guest::sigalrm::admitted());
    assert_eq!(
        sigalrm_sigaction(&guest_handler_action(0)),
        Err(libc::EPERM)
    );
    println!("sigalrm-inherited-filter-ok");
}

/// Memory with a protection key other than 0 before the runtime starts keeps
/// handlers from being admitted at all (the runtime applies only key 0's
/// rights to the guest's buffers).
fn sigalrm_pkey_before_install_guest(path: &Path) {
    let leaf7 = core::arch::x86_64::__cpuid_count(7, 0);
    let pkeys = leaf7.ecx & (1 << 4) != 0;
    if pkeys {
        let key = unsafe { libc::syscall(libc::SYS_pkey_alloc, 0, 0) };
        assert!(key > 0, "pkey_alloc: {}", std::io::Error::last_os_error());
        let page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let assigned = unsafe {
            libc::syscall(
                libc::SYS_pkey_mprotect,
                page,
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                key,
            )
        };
        assert_eq!(assigned, 0);
    }
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    if pkeys {
        assert!(!reverie_inguest::guest::sigalrm::admitted());
        assert_eq!(
            sigalrm_sigaction(&guest_handler_action(0)),
            Err(libc::EPERM)
        );
    }
    println!("sigalrm-pkey-before-install-ok");
}

static DELIVERED: AtomicU64 = AtomicU64::new(0);
static DELIVERED_CODE: AtomicI64 = AtomicI64::new(0);
static DELIVERED_SAVED_MASK: AtomicU64 = AtomicU64::new(0);
static DELIVERED_ACTIVE_MASK: AtomicU64 = AtomicU64::new(0);
/// The handler frame's `uc_mcontext.gregs[REG_OLDMASK]`.
static DELIVERED_OLDMASK: AtomicU64 = AtomicU64::new(0);
/// Whether the delivered siginfo was SIGALRM, errno 0, SI_KERNEL and zero
/// everywhere else (no runtime pid, uid or nonce left in it).
static DELIVERED_INFO_SCRUBBED: AtomicBool = AtomicBool::new(false);
/// When nonzero, the handler stores it in its frame's uc_sigmask.
static EDITED_RETURN_MASK: AtomicU64 = AtomicU64::new(0);
/// When set, the handler writes an enabled stack into its frame's uc_stack.
static EDIT_RETURN_STACK: AtomicBool = AtomicBool::new(false);
/// When set, the handler writes only the padding bytes of its frame's
/// uc_stack, which Linux ignores.
static EDIT_RETURN_STACK_PADDING: AtomicBool = AtomicBool::new(false);
static ONE_ARGUMENT_DELIVERED: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" fn recording_sigalrm_handler(
    _signal: libc::c_int,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    DELIVERED.fetch_add(1, Ordering::SeqCst);
    DELIVERED_CODE.store(i64::from(unsafe { (*info).si_code }), Ordering::SeqCst);
    let bytes = unsafe { core::slice::from_raw_parts(info.cast::<u8>(), 128) };
    let mut expected = [0_u8; 128];
    expected[0..4].copy_from_slice(&libc::SIGALRM.to_ne_bytes());
    expected[8..12].copy_from_slice(&0x80_i32.to_ne_bytes());
    DELIVERED_INFO_SCRUBBED.store(bytes == expected, Ordering::SeqCst);
    let saved = unsafe { context.cast::<u8>().add(296).cast::<u64>().read_unaligned() };
    DELIVERED_SAVED_MASK.store(saved, Ordering::SeqCst);
    let oldmask = unsafe {
        (*context.cast::<libc::ucontext_t>()).uc_mcontext.gregs[libc::REG_OLDMASK as usize]
    };
    DELIVERED_OLDMASK.store(oldmask as u64, Ordering::SeqCst);
    let edited = EDITED_RETURN_MASK.load(Ordering::SeqCst);
    if edited != 0 {
        unsafe {
            context
                .cast::<u8>()
                .add(296)
                .cast::<u64>()
                .write_unaligned(edited)
        };
    }
    if EDIT_RETURN_STACK_PADDING.load(Ordering::SeqCst) {
        unsafe {
            core::ptr::write_unaligned(
                context.cast::<u8>().add(16 + 12).cast::<[u8; 4]>(),
                [0xff; 4],
            )
        };
    }
    if EDIT_RETURN_STACK.load(Ordering::SeqCst) {
        let stack = Box::leak(vec![0_u8; 64 * 1024].into_boxed_slice());
        let mut image = [0_u8; 24];
        image[0..8].copy_from_slice(&(stack.as_ptr() as u64).to_ne_bytes());
        image[16..24].copy_from_slice(&(stack.len() as u64).to_ne_bytes());
        unsafe {
            core::ptr::write_unaligned(context.cast::<u8>().add(16).cast::<[u8; 24]>(), image)
        };
    }
    // The guest's mask inside its handler, as it queries it.
    let mut active = 0_u64;
    unsafe {
        libc::syscall(
            libc::SYS_rt_sigprocmask,
            libc::SIG_BLOCK,
            core::ptr::null::<u64>(),
            &mut active as *mut u64,
            8,
        )
    };
    DELIVERED_ACTIVE_MASK.store(active, Ordering::SeqCst);
}

static RUNS_SEEN_BY_HANDLER: AtomicU64 = AtomicU64::new(u64::MAX);

unsafe extern "C" fn entry_sigalrm_handler(_signal: libc::c_int) {
    RUNS_SEEN_BY_HANDLER.store(BEFORE_MARKER_RUNS.load(Ordering::SeqCst), Ordering::SeqCst);
}

/// Signal phase 1, the I4 addendum's point c: a SIGALRM the Tool commits at a
/// call's entry runs the guest's handler before the call, which then runs
/// once from the start with its own number and arguments and returns its own
/// result. With no handler installed the Tool's request is refused and the
/// call runs as usual.
fn sigalrm_entry_delivery_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let ppid = i64::from(unsafe { libc::getppid() });
    let marked = || unsafe { libc::syscall(libc::SYS_getppid, DELIVER_SIGALRM_BEFORE_MARKER) };
    // No handler: refused, and the call runs once.
    ENTRY_DELIVERY_ARMED.store(true, Ordering::SeqCst);
    assert_eq!(marked(), ppid);
    assert_eq!(
        ENTRY_DELIVERY_RESULT.load(Ordering::SeqCst),
        -i64::from(libc::ENOSYS)
    );
    assert_eq!(BEFORE_MARKER_RUNS.load(Ordering::SeqCst), 1);
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = entry_sigalrm_handler as *const () as usize;
    sigalrm_sigaction(&action).unwrap();
    ENTRY_DELIVERY_ARMED.store(true, Ordering::SeqCst);
    assert_eq!(marked(), ppid);
    assert_eq!(ENTRY_DELIVERY_RESULT.load(Ordering::SeqCst), 0);
    // The handler ran before the call, which then ran exactly once.
    assert_eq!(RUNS_SEEN_BY_HANDLER.load(Ordering::SeqCst), 1);
    assert_eq!(BEFORE_MARKER_RUNS.load(Ordering::SeqCst), 2);
    assert_eq!(guest_mask_call(libc::SIG_BLOCK, None), 0);
    assert_eq!(physical_mask(), 1_u64 << (libc::SIGALRM - 1));
    println!("sigalrm-entry-delivery-ok");
}

unsafe extern "C" fn one_argument_sigalrm_handler(_signal: libc::c_int) {
    ONE_ARGUMENT_DELIVERED.fetch_add(1, Ordering::SeqCst);
}

/// Signal phase 1, step I4: a SIGALRM the Tool commits is delivered to the
/// guest's handler as the committing call completes, as Linux would show it:
/// SI_KERNEL siginfo with nothing else in it, the pre-delivery mask in
/// uc_sigmask, the activation mask (saved, sa_mask, SIGALRM) inside the
/// handler; afterwards the guest's mask is back and the physical mask is
/// exactly the derived one. A second delivery works the same way. A handler
/// that edits uc_sigmask returns to that mask (SIGKILL dropped). A
/// one-argument handler runs. With no handler installed the Tool's request is
/// refused; a second request in one call is refused (EINVAL), and with a
/// physical SIGALRM already pending the request fails (EIO) and nothing runs.
fn sigalrm_delivery_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let alarm = 1_u64 << (libc::SIGALRM - 1);
    let usr1 = 1_u64 << (libc::SIGUSR1 - 1);
    let usr2 = 1_u64 << (libc::SIGUSR2 - 1);
    let deliver = || unsafe { libc::syscall(libc::SYS_getppid, DELIVER_SIGALRM_MARKER) };
    // No handler: nothing to deliver to.
    assert_eq!(deliver(), -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ENOSYS)
    );
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = recording_sigalrm_handler as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    unsafe { libc::sigaddset(&mut action.sa_mask, libc::SIGUSR2) };
    sigalrm_sigaction(&action).unwrap();
    guest_mask_call(libc::SIG_SETMASK, Some(usr1));
    for round in 1..=2_u64 {
        assert_eq!(deliver(), 0);
        assert_eq!(DELIVERED.load(Ordering::SeqCst), round);
        assert_eq!(DELIVERED_CODE.load(Ordering::SeqCst), 0x80);
        assert_eq!(DELIVERED_SAVED_MASK.load(Ordering::SeqCst), usr1);
        // Linux stores the saved mask in sigcontext.oldmask as well.
        assert_eq!(DELIVERED_OLDMASK.load(Ordering::SeqCst), usr1);
        assert_eq!(
            DELIVERED_ACTIVE_MASK.load(Ordering::SeqCst),
            usr1 | usr2 | alarm
        );
        assert!(DELIVERED_INFO_SCRUBBED.load(Ordering::SeqCst));
        assert_eq!(guest_mask_call(libc::SIG_BLOCK, None), usr1);
        assert_eq!(physical_mask(), usr1 | alarm);
    }
    // With a runtime-reserved signal (SIGSYS) in the guest's mask, the
    // physical window lacks it, but both saved masks the handler sees carry
    // it, as on Linux.
    let sys = 1_u64 << (libc::SIGSYS - 1);
    guest_mask_call(libc::SIG_SETMASK, Some(usr1 | sys));
    assert_eq!(deliver(), 0);
    assert_eq!(DELIVERED_SAVED_MASK.load(Ordering::SeqCst), usr1 | sys);
    assert_eq!(DELIVERED_OLDMASK.load(Ordering::SeqCst), usr1 | sys);
    assert_eq!(guest_mask_call(libc::SIG_SETMASK, Some(usr1)), usr1 | sys);
    // An edited return mask is taken, normalized as Linux does.
    let kill = 1_u64 << (libc::SIGKILL - 1);
    EDITED_RETURN_MASK.store(usr1 | usr2 | kill, Ordering::SeqCst);
    assert_eq!(deliver(), 0);
    EDITED_RETURN_MASK.store(0, Ordering::SeqCst);
    assert_eq!(DELIVERED.load(Ordering::SeqCst), 4);
    assert_eq!(guest_mask_call(libc::SIG_SETMASK, Some(usr1)), usr1 | usr2);
    assert_eq!(physical_mask(), usr1 | alarm);
    // A padding-only edit of uc_stack is no stack request: the return works.
    EDIT_RETURN_STACK_PADDING.store(true, Ordering::SeqCst);
    assert_eq!(deliver(), 0);
    EDIT_RETURN_STACK_PADDING.store(false, Ordering::SeqCst);
    assert_eq!(DELIVERED.load(Ordering::SeqCst), 5);
    assert_eq!(guest_mask_call(libc::SIG_BLOCK, None), usr1);
    // Two requests in one call: the second is refused, one delivery runs.
    let twice = unsafe { libc::syscall(libc::SYS_getppid, DELIVER_SIGALRM_TWICE_MARKER) };
    assert_eq!(twice, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINVAL)
    );
    assert_eq!(DELIVERED.load(Ordering::SeqCst), 6);
    // A one-argument handler.
    let mut plain: libc::sigaction = unsafe { core::mem::zeroed() };
    plain.sa_sigaction = one_argument_sigalrm_handler as *const () as usize;
    sigalrm_sigaction(&plain).unwrap();
    assert_eq!(deliver(), 0);
    assert_eq!(ONE_ARGUMENT_DELIVERED.load(Ordering::SeqCst), 1);
    assert_eq!(guest_mask_call(libc::SIG_BLOCK, None), usr1);
    assert_eq!(physical_mask(), usr1 | alarm);
    // A physical SIGALRM already pending: the request fails, nothing runs.
    let tid = unsafe { reverie_inguest::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { reverie_inguest::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let sent = unsafe {
        reverie_inguest::trap::raw_syscall6(
            libc::SYS_tgkill,
            [pid as u64, tid as u64, libc::SIGALRM as u64, 0, 0, 0],
        )
    };
    assert_eq!(sent, 0);
    assert_eq!(deliver(), -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EIO)
    );
    assert_eq!(ONE_ARGUMENT_DELIVERED.load(Ordering::SeqCst), 1);
    println!("sigalrm-delivery-ok");
}

/// Signal phase 1, step I4: a handler that changes uc_stack in its frame
/// ends the process (phase 1 supports no guest stack).
fn sigalrm_stack_edit_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = recording_sigalrm_handler as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    sigalrm_sigaction(&action).unwrap();
    EDIT_RETURN_STACK.store(true, Ordering::SeqCst);
    println!("sigalrm-stack-edit-armed");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    unsafe { libc::syscall(libc::SYS_getppid, DELIVER_SIGALRM_MARKER) };
    println!("sigalrm-stack-edit-returned");
}

/// Signal phase 1, the frame invariant: once a physical mask or alternate
/// stack the runtime did not set shows in a guest call's frame, that call
/// ends the process.
fn sigalrm_entry_frame_guest(path: &Path, stack: bool) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = recording_sigalrm_handler as *const () as usize;
    action.sa_flags = libc::SA_SIGINFO;
    sigalrm_sigaction(&action).unwrap();
    // The control: an ordinary call passes the check.
    assert!(unsafe { libc::getppid() } > 0);
    println!("sigalrm-entry-frame-armed");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    if stack {
        let other = Box::leak(vec![0_u8; 64 * 1024].into_boxed_slice());
        let mut image = [0_u8; 24];
        image[0..8].copy_from_slice(&(other.as_ptr() as u64).to_ne_bytes());
        image[16..24].copy_from_slice(&(other.len() as u64).to_ne_bytes());
        let changed = unsafe {
            reverie_inguest::trap::raw_syscall6(
                libc::SYS_sigaltstack,
                [image.as_ptr() as u64, 0, 0, 0, 0, 0],
            )
        };
        assert_eq!(changed, 0);
    } else {
        let usr2 = 1_u64 << (libc::SIGUSR2 - 1);
        unsafe { reverie_inguest::signal::raw_sigprocmask(libc::SIG_BLOCK, Some(&usr2), None) }
            .unwrap();
    }
    unsafe { libc::getppid() };
    println!("sigalrm-entry-frame-passed");
}

static PKRU_HANDLER_RAN: AtomicU64 = AtomicU64::new(0);

// A SIGALRM handler that denies writes to key 0 (PKRU bit 1) and returns,
// as a guest may: Linux's restorer writes no memory before rt_sigreturn
// restores the frame's PKRU.
global_asm!(
    r#"
    .text
    .p2align 4
    .type rpc_tool_write_denying_sigalrm_handler, @function
rpc_tool_write_denying_sigalrm_handler:
    mov qword ptr [rip + {ran}], 1
    xor ecx, ecx
    rdpkru
    or eax, 2
    xor edx, edx
    wrpkru
    ret
    .size rpc_tool_write_denying_sigalrm_handler, .-rpc_tool_write_denying_sigalrm_handler
"#,
    ran = sym PKRU_HANDLER_RAN,
);

unsafe extern "C" {
    fn rpc_tool_write_denying_sigalrm_handler(signal: libc::c_int);
}

fn current_pkru() -> u32 {
    let rights: u32;
    unsafe {
        core::arch::asm!(
            "rdpkru",
            in("ecx") 0_u32,
            out("eax") rights,
            out("edx") _,
            options(nomem, nostack, preserves_flags),
        )
    };
    rights
}

/// Signal phase 1, step I4: a handler that leaves key 0 write-denied returns
/// like any other, and the guest resumes with its own rights (the frame's).
fn sigalrm_handler_pkru_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    if !reverie_inguest::trap::pkru_present() {
        println!("sigalrm-handler-pkru: OSPKE unavailable");
        return;
    }
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = rpc_tool_write_denying_sigalrm_handler as *const () as usize;
    sigalrm_sigaction(&action).unwrap();
    let before = current_pkru();
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_getppid, DELIVER_SIGALRM_MARKER) },
        0
    );
    assert_eq!(PKRU_HANDLER_RAN.load(Ordering::SeqCst), 1);
    assert_eq!(current_pkru(), before);
    println!("sigalrm-handler-pkru-ok");
}

fn spoof_sigsys_guest(path: &Path) -> ! {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    unsafe { reverie_liteinst_rpc_raise_sigsys() };
    panic!("guest-generated SIGSYS returned");
}

#[derive(Clone, Copy)]
enum InstructionPublication {
    Concurrent,
    Quiescent,
}

fn instruction_guest(path: &Path, publication: InstructionPublication) {
    INSTRUCTION_EXPECTED_UID.store(i64::from(unsafe { libc::getuid() }), Ordering::Relaxed);
    let install = match publication {
        // Exercise the public production default, including guarded
        // instruction-site publication.
        InstructionPublication::Concurrent => unsafe {
            reverie_liteinst::install_tool::<InstructionTool>(path)
        },
        // Retain the stopped-tracee/Hermit single-thread contract as a
        // separate bracket that does not require WordPatch++ calibration.
        InstructionPublication::Quiescent => unsafe {
            reverie_liteinst::install_tool_quiescent::<InstructionTool>(path)
        },
    };
    if let Err(error) = install {
        fail_instruction_install(error);
    }
    assert_eq!(nested_cpuid(0, 0), tool_cpuid_words());
    let patched_cpuid_address =
        core::ptr::addr_of!(reverie_liteinst_rpc_nested_cpuid_site) as usize as u64;
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(patched_cpuid_address),
        1
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(patched_cpuid_address),
        2,
        "the planted nested call must traverse the existing hook exactly once"
    );
    let first_use_rdtsc_address =
        core::ptr::addr_of!(reverie_liteinst_rpc_first_use_rdtsc_site) as usize as u64;
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(first_use_rdtsc_address),
        0,
        "an instruction first reached inside the Tool must not claim a site"
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(first_use_rdtsc_address),
        0,
        "an instruction first reached inside the Tool must not publish a hook"
    );
    assert_eq!(
        unsafe { reverie_liteinst_rpc_first_use_rdtsc() },
        0x1234_5678_9abc_def0,
        "a first-use RDTSC reached inside the Tool must remain unpublished"
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(first_use_rdtsc_address),
        1
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(first_use_rdtsc_address),
        1
    );
    assert_eq!(
        unsafe { reverie_liteinst_straddling_cpuid() } as u32,
        0x1111_1111
    );
    assert_eq!(
        unsafe { reverie_liteinst_straddling_rdtsc() },
        0x1234_5678_9abc_def0
    );
    let cpuid = core::arch::x86_64::__cpuid_count(0, 0);
    let feature_leaf = core::arch::x86_64::__cpuid_count(1, 0);
    let extended_feature_leaf = core::arch::x86_64::__cpuid_count(7, 0);
    let tsc = unsafe { core::arch::x86_64::_rdtsc() };
    let mut aux = 0;
    let tscp = unsafe { core::arch::x86_64::__rdtscp(&mut aux) };
    assert_eq!(cpuid.eax, 0x1111_1111);
    assert_eq!(cpuid.ebx, 0x2222_2222);
    assert_eq!(cpuid.ecx, 0);
    assert_eq!(cpuid.edx, 0x4444_4444);
    assert_eq!(feature_leaf.ecx & (1 << 30), 0, "RDRAND must be masked");
    assert_eq!(
        extended_feature_leaf.ebx & (1 << 18),
        0,
        "RDSEED must be masked"
    );
    assert_eq!(tsc, 0x1234_5678_9abc_def0);
    assert_eq!(tscp, 0x0fed_cba9_8765_4321);
    assert_eq!(aux, 0x2468_ace0);
    assert!(
        INSTRUCTION_PATCHED_CPUID_NATIVE.load(Ordering::Relaxed),
        "a patched CPUID reached inside its Tool callback must execute natively"
    );
    assert!(
        INSTRUCTION_FIRST_USE_RDTSC_NATIVE.load(Ordering::Relaxed),
        "a first-use RDTSC reached inside a CPUID Tool callback must execute natively"
    );
    assert!(
        INSTRUCTION_NESTED_SYSCALL_NATIVE.load(Ordering::Relaxed),
        "a subscribed syscall reached inside an instruction callback must execute natively"
    );
    assert_eq!(INSTRUCTION_HANDLER_RPC_CALLS.load(Ordering::Relaxed), 1);
    assert_eq!(INSTRUCTION_TOOL_CALLBACKS.load(Ordering::Relaxed), 9);
    println!(
        "cpuid=tool rdtsc=tool rdtscp=tool rdrand=masked rdseed=masked instruction-handler-rpc=1 patched-native=1 first-use-native=1 nested-syscall-native=1 tool-callbacks=9"
    );
    std::io::stdout().flush().unwrap();
}

fn clock_and_vdso_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<ClockAndVdsoTool>(path) }.unwrap();
    assert!(unsafe { reverie_liteinst_rpc_getpid() } > 0);
    retire_conditional_branches(128);
    assert!(unsafe { reverie_liteinst_rpc_getpid() } > 0);
    retire_conditional_branches(4_096);
    assert!(unsafe { reverie_liteinst_rpc_getpid() } > 0);

    let mut time = core::mem::MaybeUninit::<libc::timespec>::uninit();
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) },
        0
    );
    assert_eq!(VDSO_CLOCK_CALLS.load(Ordering::Relaxed), 1);

    if RCB_AVAILABLE.load(Ordering::Acquire) {
        let before = RCB_BEFORE.load(Ordering::Relaxed);
        let after = RCB_AFTER.load(Ordering::Relaxed);
        assert_eq!(
            after, before,
            "branches retired inside the Tool handler must be deducted"
        );
        let first = RCB_ENTRIES[0].load(Ordering::Relaxed);
        let second = RCB_ENTRIES[1].load(Ordering::Relaxed);
        let third = RCB_ENTRIES[2].load(Ordering::Relaxed);
        let small_guest_delta = second.checked_sub(first).unwrap();
        let large_guest_delta = third.checked_sub(second).unwrap();
        assert!(
            small_guest_delta > 0,
            "known guest branches must advance the RCB clock: {first} -> {second}"
        );
        assert!(
            large_guest_delta > small_guest_delta,
            "4,096 guest branches must advance the guest-only clock more than 128 guest branches; the 65,536 Tool branches before the first interval must be excluded: small={small_guest_delta} large={large_guest_delta}"
        );
        println!(
            "rcb=measured before={before} after={after} small-guest-delta={small_guest_delta} large-guest-delta={large_guest_delta} vdso-calls=1"
        );
    } else {
        println!("rcb=unmeasured vdso-calls=1");
    }
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

fn nested_instruction_fork_guest(path: &Path) {
    if let Err(error) =
        unsafe { reverie_liteinst::install_tool_quiescent::<NestedInstructionForkTool>(path) }
    {
        fail_instruction_install(error);
    }
    assert_eq!(nested_cpuid(0, 0), tool_cpuid_words());
    assert_eq!(
        unsafe { reverie_liteinst_rpc_nested_rdtsc() },
        0x1234_5678_9abc_def0
    );
    assert_eq!(nested_rdtscp(), (0x0fed_cba9_8765_4321, 0x2468_ace0));

    let child = unsafe { libc::fork() };
    assert!(
        child >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        assert!(
            CHILD_NESTED_CPUID_NATIVE.load(Ordering::Acquire),
            "Tool-internal CPUID must execute natively"
        );
        assert!(
            CHILD_NESTED_RDTSC_NATIVE.load(Ordering::Acquire),
            "Tool-internal RDTSC must execute natively"
        );
        assert!(
            CHILD_NESTED_RDTSCP_NATIVE.load(Ordering::Acquire),
            "Tool-internal RDTSCP must execute natively"
        );
        assert_eq!(
            nested_cpuid(0, 0),
            tool_cpuid_words(),
            "the same CPUID site must remain Tool-virtualized in guest code"
        );
        assert_eq!(
            unsafe { reverie_liteinst_rpc_nested_rdtsc() },
            0x1234_5678_9abc_def0,
            "the same RDTSC site must remain Tool-virtualized in guest code"
        );
        assert_eq!(
            nested_rdtscp(),
            (0x0fed_cba9_8765_4321, 0x2468_ace0),
            "the same RDTSCP site must remain Tool-virtualized in guest code"
        );
        let observed = unsafe { reverie_liteinst_rpc_getpid() };
        assert_eq!(observed, i64::from(unsafe { libc::getpid() }));
        unsafe { libc::_exit(0) };
    }

    wait_for_child(child);
    println!(
        "nested-cpuid=native nested-rdtsc=native nested-rdtscp=native guest-cpuid=tool guest-rdtsc=tool guest-rdtscp=tool child-getpid=complete child-exit=0"
    );
}

fn fail_instruction_install(error: std::io::Error) -> ! {
    if error.kind() == std::io::ErrorKind::Unsupported {
        eprintln!("instruction-control-unavailable");
        std::process::exit(INSTRUCTION_CONTROL_UNAVAILABLE_STATUS);
    }
    panic!("failed to install instruction Tool: {error}");
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

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

fn clone3_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let parent = unsafe { reverie_liteinst_rpc_getpid() };
    let senders_before_fork = LAST_SENDERS.load(Ordering::Relaxed);
    let args = CloneArgs {
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    let child = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            core::mem::size_of::<CloneArgs>(),
        )
    };
    assert!(
        child >= 0,
        "clone3 failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        let observed = unsafe { reverie_liteinst_rpc_getpid() };
        assert_eq!(observed, i64::from(unsafe { libc::getpid() }));
        assert_ne!(observed, parent);
        unsafe { libc::_exit(0) };
    }
    wait_for_child(child as libc::pid_t);
    let observed = unsafe { reverie_liteinst_rpc_getpid() };
    assert_eq!(observed, parent);
    let sender_delta = LAST_SENDERS.load(Ordering::Relaxed) - senders_before_fork;
    assert_eq!(sender_delta, 1);
    println!("clone3=child-reconstructed sender-delta=1");
}

fn vfork_guest(path: &Path) {
    unsafe { reverie_liteinst::install_tool::<CounterTool>(path) }.unwrap();
    let parent = unsafe { reverie_liteinst_rpc_getpid() };
    let senders_before_fork = LAST_SENDERS.load(Ordering::Relaxed);
    let child = unsafe { libc::syscall(libc::SYS_vfork) };
    assert!(
        child >= 0,
        "vfork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        let observed = unsafe { reverie_liteinst_rpc_getpid() };
        assert_eq!(observed, i64::from(unsafe { libc::getpid() }));
        assert_ne!(observed, parent);
        unsafe { libc::_exit(0) };
    }
    wait_for_child(child as libc::pid_t);
    let observed = unsafe { reverie_liteinst_rpc_getpid() };
    assert_eq!(observed, parent);
    let sender_delta = LAST_SENDERS.load(Ordering::Relaxed) - senders_before_fork;
    assert_eq!(sender_delta, 1);
    println!("vfork=translated-cow-child sender-delta=1");
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

fn guest_signal_mask(how: libc::c_int, set: *const u64, size: usize) -> (i64, u64) {
    let mut old_set = 0_u64;
    let result = unsafe { reverie_liteinst_rpc_sigprocmask(how as u64, set, &mut old_set, size) };
    (result, old_set)
}

fn current_signal_mask() -> u64 {
    let (result, mask) = guest_signal_mask(libc::SIG_BLOCK, core::ptr::null(), SIGSET_SIZE);
    assert_eq!(result, 0);
    mask
}

/// Maps a `syscall; ret` at the end of an anonymous executable page, as the
/// fallback guest does. The runtime cannot patch such a site, so every call
/// through it completes through the SIGSYS fallback; callers check that with
/// its hook count.
fn unpatchable_syscall_site() -> u64 {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mapping = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    let site = unsafe { mapping.cast::<u8>().add(page - 3) };
    unsafe { core::ptr::copy_nonoverlapping([0x0f, 0x05, 0xc3].as_ptr(), site, 3) };
    assert_eq!(
        unsafe { libc::mprotect(mapping, page, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    site as u64
}

/// Checks a guest's own `rt_sigprocmask` calls under Mode A: each installs
/// its set without the reserved signals, whichever path completes it, a later
/// trap still reaches the runtime, and a refused call changes nothing.
fn signal_mask_checks(label: &str, expected_uid: i64, full_mask: u64) -> u64 {
    let initial = current_signal_mask();
    let usr1 = signal_bit(libc::SIGUSR1);

    // Linux reads the set with an ordinary user copy, which can read a
    // write-only page.
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    let write_only = page.cast::<u64>();
    unsafe { write_only.write_volatile(usr1) };
    assert_eq!(
        guest_signal_mask(libc::SIG_BLOCK, write_only, SIGSET_SIZE),
        (0, initial)
    );
    assert_eq!(current_signal_mask(), initial | usr1);
    assert_eq!(
        guest_signal_mask(libc::SIG_UNBLOCK, write_only, SIGSET_SIZE).0,
        0
    );
    assert_eq!(current_signal_mask(), initial);
    assert_eq!(unsafe { libc::munmap(page, 4096) }, 0);

    assert_eq!(guest_signal_mask(libc::SIG_BLOCK, &usr1, SIGSET_SIZE).0, 0);
    assert_eq!(current_signal_mask(), initial | usr1);

    // The first call at a fresh site traps with SIGSYS, installs the site's
    // hook and completes through it after the signal frame has returned, so
    // the mask saved in that frame must not undo the set the call installs.
    let all = u64::MAX;
    let mut old = 0_u64;
    let first = unsafe {
        reverie_liteinst_rpc_sigprocmask_first(
            libc::SIG_SETMASK as u64,
            &all,
            &mut old,
            SIGSET_SIZE,
        )
    };
    assert_eq!((first, old), (0, initial | usr1));
    let first_site =
        core::ptr::addr_of!(reverie_liteinst_rpc_sigprocmask_first_site) as usize as u64;
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(first_site),
        1
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(first_site),
        1
    );
    assert_eq!(current_signal_mask(), full_mask);

    // At a site that cannot be patched, each call completes through the
    // SIGSYS fallback, which returns through a second signal frame.
    let site = unpatchable_syscall_site();
    let fallback = unsafe {
        reverie_liteinst_rpc_mask_at(
            site,
            libc::SIG_SETMASK as u64,
            &initial,
            &mut old,
            SIGSET_SIZE,
        )
    };
    assert_eq!((fallback, old), (0, full_mask));
    assert_eq!(current_signal_mask(), initial);
    let fallback = unsafe {
        reverie_liteinst_rpc_mask_at(site, libc::SIG_SETMASK as u64, &all, &mut old, SIGSET_SIZE)
    };
    assert_eq!((fallback, old), (0, initial));
    assert_eq!(current_signal_mask(), full_mask);
    assert_eq!(reverie_liteinst::reverie_liteinst_site_trap_count(site), 2);
    assert_eq!(reverie_liteinst::reverie_liteinst_site_hook_count(site), 0);

    // The first call at this site traps with SIGSYS. Had SIGSYS been blocked,
    // Linux would reset it to its default action and kill the process here.
    let uid = unsafe { reverie_liteinst_rpc_getuid() };
    assert_eq!(uid, expected_uid);
    let getuid_site = core::ptr::addr_of!(reverie_liteinst_rpc_getuid_site) as usize as u64;
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(getuid_site),
        1
    );
    let unreadable = 0x10 as *const u64;
    assert_eq!(
        guest_signal_mask(libc::SIG_SETMASK, unreadable, SIGSET_SIZE).0,
        -i64::from(libc::EFAULT)
    );
    assert_eq!(
        guest_signal_mask(libc::SIG_SETMASK, &initial, SIGSET_SIZE / 2).0,
        -i64::from(libc::EINVAL)
    );
    assert_eq!(
        guest_signal_mask(99, &initial, SIGSET_SIZE).0,
        -i64::from(libc::EINVAL)
    );
    // Linux checks the size before it reads the set, and reads the set
    // before it checks `how`.
    assert_eq!(
        guest_signal_mask(libc::SIG_SETMASK, unreadable, SIGSET_SIZE / 2).0,
        -i64::from(libc::EINVAL)
    );
    assert_eq!(
        guest_signal_mask(99, unreadable, SIGSET_SIZE).0,
        -i64::from(libc::EFAULT)
    );
    assert_eq!(current_signal_mask(), full_mask);
    assert_eq!(
        guest_signal_mask(libc::SIG_SETMASK, &initial, SIGSET_SIZE).0,
        0
    );
    assert_eq!(current_signal_mask(), initial);
    println!(
        "{label}-mask full={full_mask:#x} write-only-set first-call fallback-site trap-after-full-mask"
    );
    initial
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Runs in the forked child. Waits until the parent is asleep with every
/// signal blocked, which happens only inside the Tool's blocking `wait4`,
/// then sends it SIGUSR2. Returns the child's exit status.
fn signal_parent_in_blocking_wait(
    parent: libc::pid_t,
    status_path: &CStr,
    blocked_line: &[u8],
) -> libc::c_int {
    let mut buffer = [0_u8; 4096];
    for _ in 0..5000 {
        let fd = unsafe { libc::open(status_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return 2;
        }
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        unsafe { libc::close(fd) };
        if read <= 0 {
            return 2;
        }
        let status = &buffer[..read as usize];
        if contains(status, b"State:\tS") && contains(status, blocked_line) {
            return if unsafe { libc::kill(parent, libc::SIGUSR2) } == 0 {
                0
            } else {
                4
            };
        }
        unsafe { libc::usleep(1000) };
    }
    3
}

fn mask_inject_guest(path: &Path) {
    let expected_uid = i64::from(unsafe { libc::getuid() });
    unsafe { reverie_liteinst::install_tool::<BlockingWaitTool>(path) }.unwrap();
    let initial = signal_mask_checks("inject", expected_uid, FULL_MASK_UNDER_MODE_A);
    // An ordinary signal the guest blocks itself, which the Tool's wait must
    // leave blocked once it restores the guest's mask.
    let usr2 = signal_bit(libc::SIGUSR2);
    assert_eq!(guest_signal_mask(libc::SIG_BLOCK, &usr2, SIGSET_SIZE).0, 0);
    let seeded = initial | usr2;
    assert_eq!(current_signal_mask(), seeded);
    let parent = unsafe { libc::getpid() };
    let status_path = CString::new(format!("/proc/{parent}/status")).unwrap();
    let blocked_line = format!("SigBlk:\t{FULL_MASK_UNDER_MODE_A:016x}\n");
    let child = unsafe { libc::fork() };
    assert!(
        child >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        let status = signal_parent_in_blocking_wait(parent, &status_path, blocked_line.as_bytes());
        unsafe { libc::_exit(status) };
    }
    wait_for_child(child);
    let during = MASK_DURING_WAIT.load(Ordering::Acquire);
    assert_eq!(during, FULL_MASK_UNDER_MODE_A);
    assert_eq!(
        MASK_PROBE_READABLE.load(Ordering::Acquire),
        -i64::from(libc::EINVAL)
    );
    assert_eq!(
        MASK_PROBE_UNREADABLE.load(Ordering::Acquire),
        -i64::from(libc::EFAULT)
    );
    assert_eq!(current_signal_mask(), seeded);
    // The child sent SIGUSR2 while the wait blocked every signal. The restored
    // mask still blocks it, so it is pending rather than delivered.
    let mut pending = 0_u64;
    assert_eq!(
        unsafe { libc::syscall(libc::SYS_rt_sigpending, &mut pending, SIGSET_SIZE) },
        0
    );
    assert_eq!(pending, usr2);
    let no_wait = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigtimedwait,
                &usr2,
                core::ptr::null_mut::<libc::siginfo_t>(),
                &no_wait,
                SIGSET_SIZE,
            )
        },
        i64::from(libc::SIGUSR2)
    );
    assert_eq!(
        guest_signal_mask(libc::SIG_SETMASK, &initial, SIGSET_SIZE).0,
        0
    );
    assert_eq!(current_signal_mask(), initial);
    println!(
        "blocking-wait during={during:#x} probe=EINVAL,EFAULT parent-asleep-in-wait seeded-mask-restored blocked-signal-pending"
    );
}

fn mask_unsubscribed_guest(path: &Path) {
    let expected_uid = i64::from(unsafe { libc::getuid() });
    unsafe { reverie_liteinst::install_tool::<UnsubscribedForkTool>(path) }.unwrap();
    signal_mask_checks("unsubscribed", expected_uid, FULL_MASK_UNDER_MODE_A);
}

fn mask_tail_guest(path: &Path) {
    let expected_uid = i64::from(unsafe { libc::getuid() });
    unsafe { reverie_liteinst::install_tool::<TailMaskTool>(path) }.unwrap();
    signal_mask_checks("tail", expected_uid, FULL_MASK_UNDER_MODE_A);
}

fn mask_instruction_guest(path: &Path) {
    let expected_uid = i64::from(unsafe { libc::getuid() });
    if let Err(error) = unsafe { reverie_liteinst::install_tool::<MaskInstructionTool>(path) } {
        fail_instruction_install(error);
    }
    let initial = signal_mask_checks("instruction", expected_uid, FULL_MASK_UNDER_INSTRUCTIONS);
    // With every other signal blocked, an RDTSC at a fresh site must still
    // trap with SIGSEGV and reach the Tool. Had SIGSEGV been blocked, Linux
    // would kill the process here instead.
    let all = u64::MAX;
    assert_eq!(guest_signal_mask(libc::SIG_SETMASK, &all, SIGSET_SIZE).0, 0);
    assert_eq!(current_signal_mask(), FULL_MASK_UNDER_INSTRUCTIONS);
    assert_eq!(unsafe { reverie_liteinst_rpc_mask_rdtsc() }, MASK_TOOL_TSC);
    let rdtsc_site = core::ptr::addr_of!(reverie_liteinst_rpc_mask_rdtsc_site) as usize as u64;
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(rdtsc_site),
        1
    );
    assert_eq!(MASK_INSTRUCTION_CALLBACKS.load(Ordering::Relaxed), 1);
    assert_eq!(
        guest_signal_mask(libc::SIG_SETMASK, &initial, SIGSET_SIZE).0,
        0
    );
    assert_eq!(current_signal_mask(), initial);
    println!("rdtsc-after-full-mask=tool");
}

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let mode = args.next().expect("mode");
    let path = args.next().expect("socket path");
    match mode.to_str() {
        Some("coordinator") => coordinator(Path::new(&path)),
        Some("fixed-gates") => fixed_gates_guest::run(Path::new(&path)),
        Some("fixed-gate-collision") => fixed_gates_guest::collision(Path::new(&path)),
        Some("fixed-gate-inherited-filter") => {
            fixed_gates_guest::inherited_filter(Path::new(&path))
        }
        Some("fixed-gate-install-failure") => fixed_gates_guest::install_failure(Path::new(&path)),
        Some("guest") => guest(Path::new(&path)),
        Some("syscall-fallback") => syscall_fallback_guest::run(Path::new(&path)),
        Some("syscall-fallback-xstate") => syscall_fallback_guest::run_xstate(Path::new(&path)),
        Some("syscall-fallback-refusal") => syscall_fallback_guest::run_refusal(),
        Some("syscall-anonymous-site") => syscall_fallback_guest::run_anonymous(Path::new(&path)),
        Some("syscall-fallback-fork") => syscall_fallback_guest::run_fork(Path::new(&path), false),
        Some("syscall-installed-fork") => syscall_fallback_guest::run_fork(Path::new(&path), true),
        Some("syscall-fallback-pkey") => syscall_fallback_guest::run_pkey(Path::new(&path)),
        Some("memory-access") => memory_access_guest::run(Path::new(&path)),
        Some("owned-frame") => owned_frame_guest::run(Path::new(&path)),
        Some("preinstalled-handler") => preinstalled_handler_guest(Path::new(&path)),
        Some("pending-sigsys") => pending_sigsys_guest(Path::new(&path)),
        Some("preblocked-sigsys") => preblocked_sigsys_guest(Path::new(&path)),
        Some("spoof-sigsys") => spoof_sigsys_guest(Path::new(&path)),
        Some("tool-signal-runtime") => tool_signal_runtime_guest(Path::new(&path)),
        Some("sigalrm-virtual") => sigalrm_virtual_guest(Path::new(&path)),
        Some("sigalrm-unprepared") => sigalrm_unprepared_guest(Path::new(&path)),
        Some("sigalrm-refused") => sigalrm_refused_guest(Path::new(&path)),
        Some("sigalrm-extra-filter") => sigalrm_extra_filter_guest(Path::new(&path)),
        Some("sigalrm-inherited-filter") => sigalrm_inherited_filter_guest(Path::new(&path)),
        Some("sigalrm-pkey-before-install") => sigalrm_pkey_before_install_guest(Path::new(&path)),
        Some("sigalrm-delivery") => sigalrm_delivery_guest(Path::new(&path)),
        Some("sigalrm-stack-edit") => sigalrm_stack_edit_guest(Path::new(&path)),
        Some("sigalrm-entry-delivery") => sigalrm_entry_delivery_guest(Path::new(&path)),
        Some("sigalrm-entry-mask") => sigalrm_entry_frame_guest(Path::new(&path), false),
        Some("sigalrm-entry-stack") => sigalrm_entry_frame_guest(Path::new(&path), true),
        Some("sigalrm-handler-pkru") => sigalrm_handler_pkru_guest(Path::new(&path)),
        Some("tool-sigreturn-trap") => tool_guest_sigreturn_guest(Path::new(&path), false, false),
        Some("tool-sigreturn-hook") => tool_guest_sigreturn_guest(Path::new(&path), true, false),
        Some("tool-sigreturn-trap-alias") => {
            tool_guest_sigreturn_guest(Path::new(&path), false, true)
        }
        Some("tool-sigreturn-hook-alias") => {
            tool_guest_sigreturn_guest(Path::new(&path), true, true)
        }
        Some("tool-sigtrap-default") => tool_sigtrap_default_guest(Path::new(&path)),
        Some("instruction-guest") => {
            instruction_guest(Path::new(&path), InstructionPublication::Concurrent)
        }
        Some("instruction-guest-quiescent") => {
            instruction_guest(Path::new(&path), InstructionPublication::Quiescent)
        }
        Some("clock-and-vdso-guest") => clock_and_vdso_guest(Path::new(&path)),
        Some("vdso-getrandom-guest") => vdso_getrandom_guest::run(Path::new(&path)),
        Some("vdso-fail-closed-guest") => vdso_fail_closed_guest::run(Path::new(&path)),
        Some("unsubscribed-lifecycle") => unsubscribed_lifecycle_guest(Path::new(&path)),
        Some("injected-exit") => injected_exit_guest(Path::new(&path)),
        Some("fork-guest") => fork_guest(Path::new(&path)),
        Some("nested-instruction-fork") => nested_instruction_fork_guest(Path::new(&path)),
        Some("raw-fork-guest") => raw_fork_guest(Path::new(&path)),
        Some("clone3-guest") => clone3_guest(Path::new(&path)),
        Some("vfork-guest") => vfork_guest(Path::new(&path)),
        Some("unsubscribed-fork") => unsubscribed_fork_guest(Path::new(&path)),
        Some("tail-fork") => tail_fork_guest(Path::new(&path)),
        Some("mask-inject") => mask_inject_guest(Path::new(&path)),
        Some("mask-unsubscribed") => mask_unsubscribed_guest(Path::new(&path)),
        Some("mask-tail") => mask_tail_guest(Path::new(&path)),
        Some("mask-instruction") => mask_instruction_guest(Path::new(&path)),
        Some("late-code-instruction") => late_code_guest::run_instruction(Path::new(&path), false),
        Some("late-code-instruction-trap-only") => {
            late_code_guest::run_instruction(Path::new(&path), true)
        }
        Some("late-code-dlopen") => {
            late_code_guest::run_dlopen(Path::new(&path), &args.next().expect("library path"))
        }
        Some("late-code-dlopen-system") => late_code_guest::run_dlopen_system(
            Path::new(&path),
            &args.next().expect("library path"),
        ),
        Some("late-code-gp-fault") => late_code_guest::run_fault(Path::new(&path), false),
        Some("late-code-null-load") => late_code_guest::run_fault(Path::new(&path), true),
        Some("straddler-instruction") => late_code_guest::run_straddler(Path::new(&path)),
        Some("straddler-reclaim-partial") => late_code_guest::run_reclaim_partial(Path::new(&path)),
        Some("straddler-shared-mapping") => late_code_guest::run_shared_mapping(Path::new(&path)),
        Some("straddler-split-mapping") => late_code_guest::run_split_mapping(Path::new(&path)),
        Some("fallback-syscall-then-rdtsc") => {
            late_code_guest::run_syscall_then_rdtsc(Path::new(&path))
        }
        Some("straddler-private-alias") => late_code_guest::run_private_alias(Path::new(&path)),
        Some("straddler-syscall-reservation") => {
            late_code_guest::run_syscall_reservation(Path::new(&path))
        }
        _ => panic!("expected coordinator or guest"),
    }
}
