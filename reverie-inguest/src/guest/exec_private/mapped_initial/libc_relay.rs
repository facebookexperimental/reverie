//! Finite private-libc bootstrap relay. No Tool/Ready or owner publication.
//! Every unsafe entry retains the same actual stopped-generation physical owner.
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::ptr::NonNull;
use core::ptr::{self};
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::Ordering;

use reverie_syscalls::linux_abi::KernelStack;
use reverie_syscalls::linux_abi::KernelStat;

use super::CapturedMappedInitial;
pub(in crate::guest::exec_private) mod frontend;

pub(super) mod tool_init;
use super::NativeControl;
use super::record_registration_result;
use crate::private_runtime::tls::IndexedAux;
use crate::private_runtime::tls::layout::Plan;
use crate::private_runtime::tls::{self};
use crate::signal::KernelSigaction;
use crate::trap::frame::BootstrapPrefix;

fn die(_reason: u32) -> ! {
    // SAFETY: installer and every use retain the actual selected gate/filter and
    // host terminal owner; abort is the real no-TLS naked terminal leaf.
    crate::private_runtime::abort()
}
unsafe fn kernel(nr: i64, a: [u64; 6]) -> i64 {
    // SAFETY: capture adopted the physical gate; caller owns actual operands.
    unsafe { crate::trap::raw_syscall6(nr, a) }
}

/// The four checked local roles; the wire stores numeric discriminators only.
pub use reverie_loader::handoff::Operation;
#[derive(Clone, Copy)]
struct Site {
    syscall_ip: u64,
    return_ip: u64,
    nr: u64,
    operation: Operation,
}
// Pointer/count into initialized fixed storage in the SAME RelayStorage.
// No general handoff parser or record accessor runs on the bootstrap handler.
#[derive(Clone, Copy)]
struct Sites {
    base: NonNull<Site>,
    count: usize,
}
impl Sites {
    fn len(self) -> usize {
        self.count
    }
    fn is_empty(self) -> bool {
        self.count == 0
    }
    fn iter(&self) -> impl ExactSizeIterator<Item = Site> + '_ {
        (0..self.count).map(|i| {
            // SAFETY: only the installer creates Sites, after initializing all
            // count<=128 entries in retained disjoint storage, before publishing
            // the State. These entries are immutable thereafter.
            unsafe { self.base.as_ptr().add(i).read() }
        })
    }
}
#[derive(Clone, Copy)]
struct Extent {
    lo: usize,
    hi: usize,
}
impl Extent {
    fn covers(self, address: usize, length: usize) -> bool {
        address >= self.lo && address.checked_add(length).is_some_and(|e| e <= self.hi)
    }
}
#[derive(Clone, Copy)]
struct Lease {
    fd: i64,
    site: u64,
    identity: FdIdentity,
    closed: bool,
}
struct Progress {
    // Set only after actual libc and complete original-FD restoration, under
    // the same busy exclusion. Not a Ready/publication authority.
    libc_cleaned: bool,
    tool_init: bool,
    // Installed once after real cleanup and complete same-blob decoding.
    // Every access uses the existing busy exclusion, never a readiness token.
    tool_sites: Option<reverie_loader::handoff::View<'static>>,
    frontend: frontend::Frontend,
    fs_set: bool,
    tid_set: bool,
    polled: bool,
    expected_opens: usize,
    opens: [Lease; 3],
    opened: usize,
    // Actual failures remain in fixed storage even when terminal is invoked.
    last_nr: u64,
    last_result: i64,
}
// A non-owning borrow of the SAME physical NativeControl and same owned State
// role; no mapping destructor, ToolRegion owner, readiness bit or second wire.
// Fields remain private; only the unsafe same-owner installer constructs it.
struct RelayState {
    busy: AtomicBool,
    control: NonNull<NativeControl>,
    stack: Extent,
    altstack: Extent,
    sites: Sites,
    restorer: usize,
    startup_mask: u64,
    tid: i64,
    original_fs: u64,
    expected_private_fs: u64, // exact prepared TCB, not merely within TLS band
    thread_list_lock: u64,    // exact final __thread_list_lock, owned RW image
    dev_null: u64,            // exact final RO "/dev/null\0" pointer
    progress: UnsafeCell<Progress>,
    original_fds: [FdIdentity; 3],
    secure: bool,
    input_identity: FdIdentity,
}
// Publication is performed ONLY by the unsafe same-physical-owner installer after
// complete scalar initialization. A null/unpublished handler refuses without
// reading uninitialized Context/NativeControl. No safe setter is exposed.
static INSTALLED: AtomicPtr<RelayState> = AtomicPtr::new(ptr::null_mut());
const INVALID: u32 = 1;
const REENTRY: u32 = 2;
const UNKNOWN_SITE: u32 = 3;
const OPERATION: u32 = 4;
const KERNEL_FAILURE: u32 = 5;

unsafe fn read_fs() -> u64 {
    let mut value = 0_u64;
    // SAFETY: stack scalar in live owned handler stack, queried through gate.
    if unsafe {
        kernel(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut value) as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        die(KERNEL_FAILURE);
    }
    value
}

/// Kernel-only SA_SIGINFO entry. It deliberately performs no FS switch.
/// # Safety
/// Real installed SIGSYS disposition; authentic kernel frame on the owned
/// bootstrap altstack, all bootstrap storage memory-accessible before entry.
/// Final object closure proves no TLS, allocation, unwind, stack-protector,
/// sanitizer/profiling callout or interposable libc helper before private init.
pub unsafe extern "C" fn bootstrap_sigsys(signal: i32, info: *mut c_void, context: *mut c_void) {
    let raw = INSTALLED.load(Ordering::Acquire);
    if raw.is_null() {
        die(INVALID);
    }
    // SAFETY: release publication guarantees initialized live fixed State role;
    // only the atomic is borrowed until the reentrancy guard succeeds.
    let busy = unsafe { &*(&raw const (*raw).busy) };
    if busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        die(REENTRY);
    }
    // SAFETY: private producer lifetime and exclusive guard, same sole leader.
    let s = unsafe { &*raw };
    let p = unsafe { &mut *s.progress.get() };
    let mut current_rsp: usize;
    // No CPUID, feature detection or stack switching in this handler.
    unsafe {
        core::arch::asm!("mov {}, rsp",out(reg) current_rsp,options(nomem,nostack,preserves_flags));
    }
    // Select authenticated immutable frontend facts BEFORE reading the frame.
    // Replacing/Retired terminate; phase-1 retains exactly the bootstrap facts.
    let frontend = frontend::frame_facts(s, p);
    if signal != libc::SIGSYS || !frontend.stack.covers(current_rsp, 1) {
        die(INVALID);
    }
    // SAFETY: actual frame is bounded inside the owned altstack before reads.
    let mut frame = match unsafe {
        BootstrapPrefix::from_bootstrap_raw(
            context,
            info,
            frontend.stack.lo,
            frontend.stack.hi,
            frontend.restorer,
            frontend.mask,
        )
    } {
        Ok(f) => f,
        Err(_) => die(INVALID),
    };
    if !s.stack.covers(frame.rsp() as usize, 1) {
        die(INVALID);
    }
    // Actual leader and actual blocked mask, not constructor/control samples.
    let tid = unsafe { kernel(libc::SYS_gettid, [0; 6]) };
    if tid != s.tid || unsafe { kernel(libc::SYS_getpid, [0; 6]) } != tid {
        die(INVALID);
    }
    let mut mask = 0_u64;
    if unsafe {
        kernel(
            libc::SYS_rt_sigprocmask,
            [libc::SIG_SETMASK as u64, 0, (&raw mut mask) as u64, 8, 0, 0],
        )
    } != 0
        || mask != (frontend.mask | (1_u64 << (libc::SIGSYS - 1)))
    {
        die(INVALID);
    }
    if p.tool_init {
        // SAFETY: same busy guard, genuine bounded frame, same retained owner.
        unsafe { tool_init::forward(s, p, &mut frame) };
        s.busy.store(false, Ordering::Release);
        return;
    }
    let c = s.control.as_ptr();
    // The joint producer retains phase1/CAPTURED and ready0 throughout libc.
    // No existing active/published-control accessor is used before ToolInit.
    if unsafe { (&raw const (*c).phase).read_volatile() } != 1
        || unsafe { (&raw const (*c).native_state).read_volatile() } != 1
        || unsafe { (&raw const (*c).runtime_ready).read_volatile() } != 0
    {
        die(INVALID);
    }
    let expected_fs = if p.fs_set {
        s.expected_private_fs
    } else {
        s.original_fs
    };
    if unsafe { read_fs() } != expected_fs {
        die(INVALID);
    }
    let mut selected = None;
    // Fixed maximum is authenticated before publication; no dynamic inventory.
    if s.sites.is_empty() || s.sites.len() > 128 {
        die(INVALID);
    }
    for site in s.sites.iter() {
        if site.return_ip == frame.rip() && site.nr == frame.rax() {
            selected = Some(site);
            break;
        }
    }
    let site = match selected {
        Some(site) => site,
        None => die(UNKNOWN_SITE),
    };
    // The exact instruction bytes are immutable, source-bound private image.
    if site.syscall_ip.checked_add(2) != Some(site.return_ip)
        || unsafe { (site.syscall_ip as *const u16).read_unaligned() } != 0x050f
    {
        die(UNKNOWN_SITE);
    }
    let a = frame.args();
    // Exact *meaningful* arguments only: unused registers need not be zero.
    match site.operation {
        Operation::SetFs => {
            if site.nr != libc::SYS_arch_prctl as u64
                || p.fs_set
                || p.tid_set
                || a[0] != 0x1002
                || a[1] != s.expected_private_fs
            {
                die(OPERATION);
            }
        }
        Operation::SetTid => {
            if site.nr != libc::SYS_set_tid_address as u64
                || !p.fs_set
                || p.tid_set
                || a[0] != s.thread_list_lock
            {
                die(OPERATION);
            }
        }
        Operation::SecurePoll => {
            if site.nr != libc::SYS_poll as u64
                || !p.fs_set
                || !p.tid_set
                || !s.secure
                || p.polled
                || a[1] != 3
                || a[2] != 0
                || !s.stack.covers(a[0] as usize, 24)
            {
                die(OPERATION);
            }
            let base = a[0] as *const u8;
            let mut i = 0;
            while i < 3 {
                // pollfd: i32 fd, i16 events, i16 revents. Exact final x86-64 ABI.
                if unsafe { base.add(i * 8).cast::<i32>().read_unaligned() } != i as i32
                    || unsafe { base.add(i * 8 + 4).cast::<i16>().read_unaligned() } != 0
                {
                    die(OPERATION);
                }
                i += 1;
            }
        }
        Operation::SecureOpen => {
            if site.nr != libc::SYS_open as u64
                || !p.fs_set
                || !p.tid_set
                || !p.polled
                || p.opened >= 3
                || p.opened >= p.expected_opens
                || a[0] != s.dev_null
                || a[1] != 0x8002
            {
                die(OPERATION);
            }
        }
    }
    p.last_nr = site.nr;
    // SAFETY: exact site/operation, genuine bounded pointers and same sole
    // physical owner. This is a bootstrap transcript, not guest syscall policy.
    let result = unsafe { kernel(site.nr as i64, a) };
    p.last_result = result;
    // Record every successful fresh open BEFORE any fallible query or return.
    if matches!(site.operation, Operation::SecureOpen) && result >= 0 {
        let slot = p.opened;
        p.opens[slot] = Lease {
            fd: result,
            site: site.return_ip,
            identity: EMPTY_FD,
            closed: false,
        };
        p.opened = slot + 1;
        let mut i = 0;
        while i < slot {
            if p.opens[i].fd == result {
                die(INVALID);
            }
            i += 1;
        }
        // The successful open is already journaled; a failed observation is fatal.
        if result < 3 && s.original_fds[result as usize].open {
            die(INVALID);
        }
        p.opens[slot].identity = unsafe { fd_identity(result) };
        if !p.opens[slot].identity.open {
            die(INVALID);
        }
    }
    if result < 0 {
        die(KERNEL_FAILURE);
    } // real result retained; never repaired
    match site.operation {
        Operation::SetFs => {
            // FS was changed in the handler's kernel call. Never restore old FS
            // or enter the existing Tool-FS bridge. Signal return must retain the new
            // actual base, including reconciliation of its selector below.
            p.fs_set = true;
            let selector: u16;
            unsafe {
                core::arch::asm!("mov {0:x}, fs",out(reg) selector,
                options(nomem,nostack,preserves_flags));
            }
            // Qualified fixed TCB is >2GiB; require the actual post-set null
            // selector, then preserve it in the frame. Final kernel test must
            // prove the actual new FS BASE survives the restorer as well.
            if selector != 0 {
                die(INVALID);
            }
            frame.set_post_setfs_selector(selector);
            if result != 0 || unsafe { read_fs() } != s.expected_private_fs {
                die(INVALID);
            }
        }
        Operation::SetTid => {
            if result != s.tid {
                die(INVALID);
            }
            // Successful exact setter is the only clear-tid witness; no getter
            // or guessed value. __init_tp ignores a negative setter result, so
            // this relay terminally refuses failure before libc can continue.
            if unsafe { record_registration_result(s.control, site.nr as i64, a, result) }.is_err()
            {
                die(INVALID);
            }
            p.tid_set = true;
        }
        Operation::SecurePoll => {
            if result > 3 {
                die(INVALID);
            }
            p.polled = true;
            let mut i = 0;
            while i < 3 {
                let revents = unsafe {
                    (a[0] as *const u8)
                        .add(i * 8 + 6)
                        .cast::<i16>()
                        .read_unaligned()
                };
                if revents & 0x20 != 0 {
                    p.expected_opens += 1;
                } // POLLNVAL
                i += 1;
            }
        }
        Operation::SecureOpen => {}
    }
    if unsafe { read_fs() }
        != if p.fs_set {
            s.expected_private_fs
        } else {
            s.original_fs
        }
    {
        die(INVALID);
    }
    // FP/xstate, RIP, RSP, mask and all other registers untouched; only
    // RAX and the successful SET_FS selector change are reflected in the frame.
    frame.set_result(result);
    s.busy.store(false, Ordering::Release);
    // Qualified SA_RESTORER performs exact permitted rt_sigreturn. Neither the
    // Rust handler nor a libc wrapper restores a stale pre-SET_FS base.
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct FdIdentity {
    open: bool,
    descriptor_flags: i64,
    status_flags: i64,
    dev: u64,
    ino: u64,
    rdev: u64,
    mode: u32,
}
const EMPTY_FD: FdIdentity = FdIdentity {
    open: false,
    descriptor_flags: 0,
    status_flags: 0,
    dev: 0,
    ino: 0,
    rdev: 0,
    mode: 0,
};
const EMPTY_LEASE: Lease = Lease {
    fd: -1,
    site: 0,
    identity: EMPTY_FD,
    closed: false,
};

// Fstat supplements the no-destructive-operation custody transcript. Matching
// inode/flags ALONE never authenticates an OFD or ownership of an arbitrary FD.
unsafe fn fd_identity(fd: i64) -> FdIdentity {
    let flags = unsafe {
        kernel(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
        )
    };
    if flags == -i64::from(libc::EBADF) {
        return EMPTY_FD;
    }
    if flags < 0 {
        die(KERNEL_FAILURE);
    }
    let status = unsafe {
        kernel(
            libc::SYS_fcntl,
            [fd as u64, libc::F_GETFL as u64, 0, 0, 0, 0],
        )
    };
    if status < 0 {
        die(KERNEL_FAILURE);
    }
    // SAFETY: generated raw kernel integer-only stat object; successful fstat
    // supplies its field values. No native-libc stat wrapper/layout is used.
    let mut stat = core::mem::MaybeUninit::<KernelStat>::uninit();
    if unsafe {
        kernel(
            libc::SYS_fstat,
            [fd as u64, stat.as_mut_ptr() as u64, 0, 0, 0, 0],
        )
    } != 0
    {
        die(KERNEL_FAILURE);
    }
    let stat = unsafe { stat.assume_init() };
    FdIdentity {
        open: true,
        descriptor_flags: flags,
        status_flags: status,
        dev: stat.st_dev,
        ino: stat.st_ino,
        rdev: stat.st_rdev,
        mode: stat.st_mode,
    }
}

/// Opaque fixed storage; the physical producer reserves and retains its exact
/// size/alignment in the SAME guarded State role. No safe constructor/owner.
#[repr(C, align(64))]
pub struct RelayStorage {
    state: core::mem::MaybeUninit<RelayState>,
    // Kept OUTSIDE state: state.write below must not overwrite initialized
    // entries referenced by its Sites pointer. Unused entries stay unobserved.
    sites: [core::mem::MaybeUninit<Site>; 128],
}

/// Physical libc input joins, all retained from the same actual mapped image.
/// Rust references describe memory; they do not authenticate source or custody.
struct LibcInputs {
    /// Exclusive pristine scratch inside the captured State role.
    storage: NonNull<RelayStorage>,
    /// Checked actual final-image TLS geometry, never ownership authority.
    plan: Plan,
    /// Actual mapped private ELF PHDR and page-size cross-check.
    aux: IndexedAux,
    /// Actual final PT_GNU_STACK memory-size hint.
    gnu_stack_bytes: usize,
    /// Permanent private env vector immediately followed by real raw aux pairs.
    envp: *mut *mut core::ffi::c_char,
    /// Maximum readable words from envp through the raw auxv terminator.
    env_aux_words: usize,
    /// Permanent bounded genuine terminated private program-name string.
    program_name: *mut core::ffi::c_char,
    /// Exact final source-qualified readonly literal, not a Rust replacement.
    dev_null: *const u8,
}

/// Affine same-owner transaction. Abandonment/errors are terminal by its unsafe
/// physical-entry contract; Drop does not release mappings or pretend cleanup.
pub struct InstalledLibcRelay {
    captured: CapturedMappedInitial,
    state: NonNull<RelayState>,
    libc: LibcInputs,
}

unsafe extern "C" {
    static mut __thread_list_lock: i32;
}

fn check(ok: bool) {
    if !ok {
        die(INVALID);
    }
}
fn extent(role: &crate::guest::tool_region::MappedImageExtent) -> Extent {
    Extent {
        lo: role.start + 4096,
        hi: role.end - 4096,
    }
}
fn overlaps(lo: usize, bytes: usize, other: usize, other_bytes: usize) -> bool {
    lo < other.saturating_add(other_bytes) && other < lo.saturating_add(bytes)
}

// Exact retained libc parsing rule: duplicates use the last indexed value.
// Values below AUX_CNT are indexed; retain genuine credentials, never turn a
// secure invocation into a nonsecure one by supplying a synthetic boolean.
unsafe fn validate_aux(captured: &CapturedMappedInitial, args: &LibcInputs) -> bool {
    let input = &captured.input;
    let handoff = extent(&input.layout.handoff);
    check(
        args.env_aux_words > 0
            && args.env_aux_words <= 512
            && (args.envp as usize) % core::mem::align_of::<usize>() == 0
            && handoff.covers(args.envp as usize, args.env_aux_words * 8),
    );
    let base = args.envp.cast::<usize>();
    let mut offset = 0;
    while offset < args.env_aux_words {
        if unsafe { base.add(offset).read() } == 0 {
            break;
        }
        offset += 1;
    }
    check(offset < args.env_aux_words);
    offset += 1;
    let mut aux = [0usize; 38];
    let mut ended = false;
    while offset + 1 < args.env_aux_words {
        let key = unsafe { base.add(offset).read() };
        let value = unsafe { base.add(offset + 1).read() };
        if key == 0 {
            ended = true;
            break;
        }
        if key < 38 {
            aux[key] = value;
        }
        offset += 2;
    }
    check(
        ended
            && [aux[3], aux[4], aux[5], aux[6]]
                == [
                    args.aux.phdr,
                    args.aux.phent,
                    args.aux.phnum,
                    args.aux.page_size,
                ],
    );
    // Caller authenticates all raw vector/string/source lifetimes, including
    // the presence and provenance of actual AT_RANDOM and credentials.
    aux[11] != aux[12] || aux[13] != aux[14] || aux[23] != 0
}

impl CapturedMappedInitial {
    /// Install the actual finite pre-libc SIGSYS relay, without running libc.
    ///
    /// # Safety
    /// All capture's physical same-birth/mapping/generation/host terminal
    /// obligations remain. This sole leader owns the exec-unshared FD table;
    /// no other thread, signal callback or private syscall operation may mutate
    /// descriptors, source pages, registrations, masks or relay state. External
    /// holders may share OFDs; observed status changes refuse, never repair.
    /// Actual inherited filter lineage already allows ONLY the adopted native
    /// gate and selected rt_sigreturn site; libc syscall sites TRAP with data0.
    /// It permits the direct setup/readback/cleanup operations used here.
    /// All input references/pointers are genuine bounded permanent backing.
    /// Sites come from the final sealed same-source image and identify EXACT
    /// instruction boundaries/caller roles, not merely matching byte patterns.
    /// Every reachable inline syscall of selected __init_libc/TLS/SSP is in
    /// this four-operation closure; any additional actual syscall is a failure.
    /// Storage is pristine zeroed unaliased RW State memory, disjoint from
    /// NativeControl and every live value; final TLS/backing/template/aux/name
    /// have the complete initialize_private_libc physical/foreign ABI contract.
    /// Whole stack/altstack capacities cover actual xstate plus handler depth;
    /// all bootstrap memory is accessible key0, DF clear, no PKRU opening needed.
    /// Final compiler closure must prove no hidden TLS/allocator/panic/unwind/
    /// interposable helpers before genuine TLS. Failure or token abandonment is
    /// immediately terminal under retained host kill/wait, never retry/unmap.
    pub unsafe fn install_libc_relay(self) -> InstalledLibcRelay {
        let input = &self.input;
        let wire = input.wire;
        let scalar = |i| super::scalar_value(wire.scalar(i));
        let tls = |i| super::scalar_value(wire.tls(i));
        // Recompute the SAME pure musl geometry; never consume a host Plan.
        let tls_extent = |start: u64, bytes: u64| crate::private_runtime::tls::layout::Extent {
            start: start as usize,
            bytes: bytes as usize,
        };
        let plan = match crate::private_runtime::tls::layout::plan(
            tls_extent(
                crate::guest::tool_region::BASE as u64,
                (crate::guest::tool_region::END - crate::guest::tool_region::BASE) as u64,
            ),
            tls_extent(tls(7), tls(8)),
            tls_extent(tls(9), tls(10)),
            tls_extent(tls(9), tls(11)),
            crate::private_runtime::tls::layout::Template {
                image: tls(3) as usize,
                file_bytes: tls(4) as usize,
                memory_bytes: tls(5) as usize,
                alignment: tls(6) as usize,
            },
        ) {
            Ok(plan) => plan,
            Err(_) => die(INVALID),
        };
        let args = LibcInputs {
            storage: match NonNull::new(scalar(3) as *mut RelayStorage) {
                Some(p) => p,
                None => die(INVALID),
            },
            plan,
            aux: IndexedAux {
                phdr: tls(0) as usize,
                phent: tls(1) as usize,
                phnum: tls(2) as usize,
                page_size: 4096,
            },
            gnu_stack_bytes: scalar(12) as usize,
            envp: super::scalar_value(wire.envp_address()) as *mut *mut core::ffi::c_char,
            env_aux_words: super::scalar_value(wire.env_aux_words()),
            program_name: super::scalar_value(wire.program_name_address())
                as *mut core::ffi::c_char,
            dev_null: scalar(13) as *const u8,
        };
        let state_extent = extent(&input.layout.state);
        let slot = args.storage.as_ptr();
        let c = input.control.as_ptr();
        check(
            INSTALLED.load(Ordering::Acquire).is_null()
                && slot as usize % core::mem::align_of::<RelayStorage>() == 0
                && state_extent.covers(slot as usize, core::mem::size_of::<RelayStorage>())
                && !overlaps(
                    slot as usize,
                    core::mem::size_of::<RelayStorage>(),
                    c as usize,
                    core::mem::size_of::<NativeControl>(),
                )
                && input.bootstrap_handler == bootstrap_sigsys as *const () as usize
                && input.prepared_tcb == args.plan.pthread().start
                && extent(&input.layout.tls)
                    .covers(args.plan.backing().start, args.plan.backing().bytes),
        );
        let bytes = slot.cast::<u8>();
        let mut i = 0;
        while i < core::mem::size_of::<RelayStorage>() {
            check(unsafe { bytes.add(i).read_volatile() } == 0);
            i += 1;
        }
        let site_bytes = super::scalar_value(wire.site_bytes());
        let site_count = super::scalar_value(wire.site_count());
        check(
            site_count > 0
                && site_count <= 128
                && extent(&input.layout.handoff)
                    .covers(site_bytes.as_ptr() as usize, site_bytes.len())
                && input.maps().any(|m| {
                    super::contains(
                        m,
                        site_bytes.as_ptr() as usize,
                        site_bytes.len(),
                        libc::PROT_READ as u64,
                    )
                }),
        );
        // SAFETY: checked exclusive zero RelayStorage. Each selected slot is
        // initialized by value before any reference or State publication.
        let site_base = unsafe { core::ptr::addr_of_mut!((*slot).sites).cast::<Site>() };
        let mut seen = [false; 4];
        let mut previous = 0;
        for written in 0..site_count {
            let record = super::scalar_value(wire.site(written));
            let site = Site {
                syscall_ip: record.syscall_ip,
                return_ip: record.return_ip,
                nr: record.number,
                operation: record.operation,
            };
            let (index, nr) = match site.operation {
                Operation::SetFs => (0, libc::SYS_arch_prctl),
                Operation::SetTid => (1, libc::SYS_set_tid_address),
                Operation::SecurePoll => (2, libc::SYS_poll),
                Operation::SecureOpen => (3, libc::SYS_open),
            };
            check(
                site.return_ip > previous
                    && site.syscall_ip.checked_add(2) == Some(site.return_ip)
                    && site.nr == nr as u64
                    && input.codes().any(|code| {
                        site.syscall_ip >= code.start as u64 && site.return_ip <= code.end as u64
                    }),
            );
            check(unsafe { (site.syscall_ip as *const u16).read_unaligned() } == 0x050f);
            previous = site.return_ip;
            seen[index] = true;
            // SAFETY: index of the outer finite wire iteration is distinct from
            // the operation index; every slot is written exactly once.
            unsafe { site_base.add(written).write(site) };
        }
        check(seen == [true; 4]);
        let lock = (&raw mut __thread_list_lock) as usize;
        check(
            input
                .maps()
                .any(|m| super::contains(m, lock, 4, (libc::PROT_READ | libc::PROT_WRITE) as u64))
                && input.maps().any(|m| {
                    super::contains(m, args.dev_null as usize, 10, libc::PROT_READ as u64)
                }),
        );
        let expected = b"/dev/null\0";
        for (offset, value) in expected.iter().enumerate() {
            check(unsafe { args.dev_null.add(offset).read() } == *value);
        }
        let secure = unsafe { validate_aux(&self, &args) };
        let tid = unsafe { kernel(libc::SYS_gettid, [0; 6]) };
        check(
            tid == i64::from(input.layout.owner_tid)
                && unsafe { kernel(libc::SYS_getpid, [0; 6]) } == tid,
        );
        let mut mask = 0_u64;
        check(
            unsafe {
                kernel(
                    libc::SYS_rt_sigprocmask,
                    [libc::SIG_SETMASK as u64, 0, (&raw mut mask) as u64, 8, 0, 0],
                )
            } == 0
                && mask == super::startup_mask()
                && unsafe { read_fs() } == input.resume.fs_base,
        );
        let original_fds = unsafe { [fd_identity(0), fd_identity(1), fd_identity(2)] };
        let stack = extent(&input.layout.stack);
        let altstack = extent(&input.layout.signal_stack);
        let state = unsafe { core::ptr::addr_of_mut!((*slot).state).cast::<RelayState>() };
        // SAFETY: complete scalar initialization in same owned permanent State.
        unsafe {
            state.write(RelayState {
                busy: AtomicBool::new(false),
                control: input.control,
                stack,
                altstack,
                sites: Sites {
                    base: NonNull::new_unchecked(site_base),
                    count: site_count,
                },
                restorer: crate::trap::FIXED_SIGNAL_RESTORER_ENTRY as usize,
                startup_mask: mask,
                tid,
                original_fs: input.resume.fs_base,
                expected_private_fs: input.prepared_tcb as u64,
                thread_list_lock: lock as u64,
                dev_null: args.dev_null as u64,
                progress: UnsafeCell::new(Progress {
                    libc_cleaned: false,
                    tool_init: false,
                    tool_sites: None,
                    frontend: frontend::Frontend::Bootstrap,
                    fs_set: false,
                    tid_set: false,
                    polled: false,
                    expected_opens: 0,
                    opens: [EMPTY_LEASE; 3],
                    opened: 0,
                    last_nr: 0,
                    last_result: 0,
                }),
                original_fds,
                secure,
                input_identity: fd_identity(i64::from(input.input_fd)),
            })
        };
        // Real wire layout, independent of libc's userspace wrapper.
        let installed_stack = KernelStack {
            ss_sp: altstack.lo as *mut c_void,
            ss_flags: 0,
            ss_size: (altstack.hi - altstack.lo) as u64,
        };
        check(
            unsafe {
                kernel(
                    libc::SYS_sigaltstack,
                    [(&raw const installed_stack) as u64, 0, 0, 0, 0, 0],
                )
            } == 0,
        );
        // State is valid before a handler can observe it. No fake publication
        // after installing an action whose first real event could race it.
        check(
            INSTALLED
                .compare_exchange(ptr::null_mut(), state, Ordering::Release, Ordering::Relaxed)
                .is_ok(),
        );
        let action = KernelSigaction {
            handler: bootstrap_sigsys as *const () as u64,
            flags: (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64,
            restorer: crate::trap::FIXED_SIGNAL_RESTORER_ENTRY,
            mask: 0,
        };
        check(
            unsafe {
                kernel(
                    libc::SYS_rt_sigaction,
                    [libc::SIGSYS as u64, (&raw const action) as u64, 0, 8, 0, 0],
                )
            } == 0,
        );
        let mut observed = KernelSigaction {
            handler: 0,
            flags: 0,
            restorer: 0,
            mask: 0,
        };
        let mut observed_stack = core::mem::MaybeUninit::<KernelStack>::uninit();
        let mut observed_mask = 0_u64;
        check(
            unsafe {
                kernel(
                    libc::SYS_rt_sigaction,
                    [libc::SIGSYS as u64, 0, (&raw mut observed) as u64, 8, 0, 0],
                )
            } == 0
                && observed == action
                && unsafe {
                    kernel(
                        libc::SYS_sigaltstack,
                        [0, observed_stack.as_mut_ptr() as u64, 0, 0, 0, 0],
                    )
                } == 0
                && unsafe {
                    kernel(
                        libc::SYS_rt_sigprocmask,
                        [
                            libc::SIG_SETMASK as u64,
                            0,
                            (&raw mut observed_mask) as u64,
                            8,
                            0,
                            0,
                        ],
                    )
                } == 0
                && observed_mask == mask,
        );
        let observed_stack = unsafe { observed_stack.assume_init() };
        check(
            observed_stack.ss_sp as usize == altstack.lo
                && observed_stack.ss_flags == 0
                && observed_stack.ss_size == (altstack.hi - altstack.lo) as u64,
        );
        InstalledLibcRelay {
            captured: self,
            state: unsafe { NonNull::new_unchecked(state) },
            libc: args,
        }
    }
}

// This private join is called by the SAME captured owner's adoption route.
// It cannot enable ToolInit or publish a region. Errors retain terminal
// ownership and deliberately do not release the exclusion for a retry.
pub(super) unsafe fn validate_after_libc(
    owner: &CapturedMappedInitial,
) -> Result<super::MappedInitialInputs, i32> {
    let raw = INSTALLED.load(Ordering::Acquire);
    if raw.is_null() {
        return Err(libc::EINVAL);
    }
    // SAFETY: installer release-published initialized same-generation storage;
    // borrow only its atomic before obtaining the existing exclusion.
    let busy = unsafe { &*(&raw const (*raw).busy) };
    if busy
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        die(REENTRY);
    }
    let s = unsafe { &*raw };
    let p = unsafe { &mut *s.progress.get() };
    let c = s.control.as_ptr();
    check(
        s.control == owner.input.control
            && p.libc_cleaned
            && p.fs_set
            && p.tid_set
            && !p.tool_init
            && p.tool_sites.is_none()
            && matches!(p.frontend, frontend::Frontend::Bootstrap),
    );
    check(
        unsafe { (&raw const (*c).phase).read_volatile() } == 1
            && unsafe { (&raw const (*c).native_state).read_volatile() } == 1
            && unsafe { (&raw const (*c).runtime_ready).read_volatile() } == 0
            && unsafe { read_fs() } == s.expected_private_fs,
    );
    let input = super::MappedInitialInputs::decode(owner.input.wire.bytes())?;
    input.check_structure()?;
    check(owner.input.matches_full(&input));
    p.tool_sites = Some(input.scalar.view());
    // Last mutable access precedes release. Some(View) authorizes nothing:
    // enable still requires actual region adoption and phase2 plus all checks.
    s.busy.store(false, Ordering::Release);
    Ok(input)
}

impl InstalledLibcRelay {
    /// Call actual private libc and retire every actual bootstrap FD lease.
    /// Returns the SAME captured owner for its existing adoption route; this
    /// does not publish ToolRegion, NativeControl, a Tool or any Ready result.
    ///
    /// # Safety
    /// Installer's full physical/sole-leader/FD/site/foreign ABI contract still
    /// holds. No constructors or other private operations occurred. Real kernel
    /// operations and their fixed ledger stay exclusive through cleanup. Any
    /// failure remains terminal; caller retains actual host wait authority.
    pub unsafe fn initialize_private_libc(self) -> CapturedMappedInitial {
        // SAFETY: physical inputs are retained from actual checked installer.
        unsafe {
            tls::initialize_private_libc(
                self.libc.plan,
                self.libc.aux,
                self.libc.gnu_stack_bytes,
                self.libc.envp,
                self.libc.program_name,
            )
        };
        let s = unsafe { self.state.as_ref() };
        // SIGSYS remains deliverable. Acquire the SAME exclusion guard before
        // creating any mutable progress reference, so an unexpected signal
        // refuses in handler CAS before it can form a second reference.
        check(
            s.busy
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok(),
        );
        let p = unsafe { &mut *s.progress.get() };
        check(
            p.fs_set
                && p.tid_set
                && p.opened <= 3
                && p.opened == p.expected_opens
                && p.polled == s.secure
                && unsafe { read_fs() } == s.expected_private_fs
                && unsafe { kernel(libc::SYS_gettid, [0; 6]) } == s.tid
                && unsafe { kernel(libc::SYS_getpid, [0; 6]) } == s.tid,
        );
        let c = s.control.as_ptr();
        check(
            unsafe { (&raw const (*c).private_clear_tid).read_volatile() } == s.thread_list_lock
                && unsafe { (&raw const (*c).runtime_ready).read_volatile() } == 0
                && unsafe { (&raw const (*c).phase).read_volatile() } == 1,
        );
        // Verify inherited standard descriptors BEFORE closing any lease too.
        // Originally closed slots may contain only a journaled fresh open.
        let before_close = unsafe { [fd_identity(0), fd_identity(1), fd_identity(2)] };
        let mut original = 0;
        while original < 3 {
            if s.original_fds[original].open {
                check(before_close[original] == s.original_fds[original]);
            } else if before_close[original].open {
                check(p.opens.iter().take(p.opened).any(|lease| {
                    !lease.closed
                        && lease.fd == original as i64
                        && lease.identity == before_close[original]
                }));
            }
            original += 1;
        }
        let mut i = 0;
        while i < p.opened {
            let lease = &mut p.opens[i];
            check(
                !lease.closed
                    && lease.fd >= 0
                    && lease.site != 0
                    && unsafe { fd_identity(lease.fd) } == lease.identity,
            );
            // Once only, including EINTR/ambiguous-close: never retry or erase
            // custody on failure. The original kernel result stays recorded.
            p.last_nr = libc::SYS_close as u64;
            p.last_result = unsafe { kernel(libc::SYS_close, [lease.fd as u64, 0, 0, 0, 0, 0]) };
            check(p.last_result == 0);
            lease.closed = true;
            check(
                unsafe {
                    kernel(
                        libc::SYS_fcntl,
                        [lease.fd as u64, libc::F_GETFD as u64, 0, 0, 0, 0],
                    )
                } == -i64::from(libc::EBADF),
            );
            i += 1;
        }
        let final_fds = unsafe { [fd_identity(0), fd_identity(1), fd_identity(2)] };
        check(final_fds == s.original_fds);
        // No original descriptor was closed/duplicated/replaced or its flags/
        // offsets mutated. Real open allocates a previously empty slot; every
        // such operation was journaled. No other descriptor operation is admitted.
        // Together with exec-unshared sole-leader custody this preserves all
        // other inherited OFDs, without a fake /proc snapshot or flag repair.
        p.libc_cleaned = true;
        // Last mutable progress use precedes release. No guard Drop/unwind or
        // fallible operation releases exclusion on a terminal failure.
        s.busy.store(false, Ordering::Release);
        self.captured
    }
}

const _: () = {
    assert!(core::mem::size_of::<KernelStack>() == 24);
    assert!(core::mem::align_of::<KernelStack>() == 8);
    assert!(core::mem::offset_of!(KernelStack, ss_sp) == 0);
    assert!(core::mem::offset_of!(KernelStack, ss_flags) == 8);
    assert!(core::mem::offset_of!(KernelStack, ss_size) == 16);
    assert!(core::mem::size_of::<KernelStat>() == 144);
    assert!(core::mem::align_of::<KernelStat>() == 8);
    assert!(core::mem::offset_of!(KernelStat, st_dev) == 0);
    assert!(core::mem::offset_of!(KernelStat, st_ino) == 8);
    assert!(core::mem::offset_of!(KernelStat, st_mode) == 24);
    assert!(core::mem::offset_of!(KernelStat, st_rdev) == 40);
};

// Same retained relay storage; this child has no second installation/owner.
pub(in crate::guest::exec_private) mod callback {
    //! Installed Running Tool callbacks borrow the SAME retired relay facts.
    //! This route grants no startup, Guest, successor, Ready or callback authority.
    use super::*;
    use crate::guest::event::SyscallEvent;
    use crate::trap::frame::SignalFrame;

    pub(in crate::guest::exec_private) fn present() -> bool {
        !INSTALLED.load(Ordering::Acquire).is_null()
    }

    fn callback_phase(phase: u64, ready: u64, native_state: u64) -> bool {
        phase == 4 && ready == 1 && native_state == 3
    }
    fn saved_stack_matches(bytes: [u8; 24], stack: Extent) -> bool {
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()) == stack.lo as u64
            && i32::from_le_bytes(bytes[8..12].try_into().unwrap()) == 0
            && stack.hi.checked_sub(stack.lo).is_some_and(|size| {
                size != 0 && u64::from_le_bytes(bytes[16..24].try_into().unwrap()) == size as u64
            })
    }
    fn complete_instruction(lo: u64, hi: u64, post: u64) -> bool {
        post.checked_sub(2)
            .is_some_and(|start| lo <= start && start < post && post <= hi)
    }

    // No mutable Progress borrow, and no saved pointer to movable initial controls.
    // The existing busy CAS excludes installation/cleanup and any signal reentry.
    unsafe fn verify_owner(s: &RelayState, p: &Progress, frame: &SignalFrame<'_>) {
        let c = s.control.as_ptr();
        check(callback_phase(
            tool_init::read(unsafe { &raw const (*c).phase }),
            tool_init::read(unsafe { &raw const (*c).runtime_ready }),
            tool_init::read(unsafe { &raw const (*c).native_state }),
        ));
        check(tool_init::read(unsafe { &raw const (*c).init_input_fd }) == u64::MAX);
        check(tool_init::read(unsafe { &raw const (*c).tool_fs }) == s.expected_private_fs);
        // This checks the actual current leader/Tool FS and the success-only guest
        // robust/clear-TID ledger. The bootstrap private registrations and old brk
        // are deliberately not used after genuine guest execution.
        check(super::super::super::callback_kernel_registrations().is_some());
        let region = match crate::guest::tool_region::published_owner() {
            Some(region) => region,
            None => die(INVALID),
        };
        let scope = match crate::guest::continuation::mapped_callback_facts(
            frame.register(libc::REG_RSP as usize) as usize,
            region,
        ) {
            Some(scope) => scope,
            None => die(INVALID),
        };
        let (installed_region, facts) =
            unsafe { frontend::verify_callback_frontend(s, p, scope.host, scope.mask) };
        check(core::ptr::eq(region, installed_region));
        check(
            frame.signal_mask() == scope.mask
                && saved_stack_matches(frame.signal_stack(), facts.stack),
        );
        check(frame.on_owned_signal_stack(facts.stack.lo, facts.stack.hi, facts.restorer));
        let rsp: usize;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags))
        };
        check(facts.stack.covers(rsp, 1));
    }

    /// # Safety
    /// `frame` is this invocation's exclusive actual SIGSYS frame, decoded by the
    /// normal signal handler under its reentry guard. Caller retains the physical
    /// immutable image, same initialized relay/control, actual installed Tool and
    /// pending continuation. This function validates the scoped Running ownership;
    /// classification by phase/IP never supplies it. All Tool effects must preserve
    /// Rust memory invariants and the retained image/wire/site provenance.
    pub(in crate::guest::exec_private) unsafe fn forward(
        event: &mut SyscallEvent,
        frame: &mut SignalFrame<'_>,
        observe: impl FnOnce(&SyscallEvent),
    ) {
        let raw = INSTALLED.load(Ordering::Acquire);
        if raw.is_null() {
            die(INVALID)
        }
        // SAFETY: installed relay storage remains live for this physical image.
        let s = unsafe { &*raw };
        if s.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            die(REENTRY);
        }
        // Only shared reads of the disjoint Progress while holding its existing
        // exclusion. No runtime/callback owner or Ready state is constructed here.
        let p = unsafe { &*s.progress.get() };
        unsafe { verify_owner(s, p, frame) };
        let post = frame.register(libc::REG_RIP as usize) as u64;
        let number = frame.register(libc::REG_RAX as usize);
        let registers = [
            libc::REG_RDI,
            libc::REG_RSI,
            libc::REG_RDX,
            libc::REG_R10,
            libc::REG_R8,
            libc::REG_R9,
        ];
        let args = registers.map(|r| frame.register(r as usize) as u64);
        check(event.number == number && event.args == args && event.instruction_pointer == post);
        let view = match p.tool_sites {
            Some(view) => view,
            None => die(INVALID),
        };
        let table = super::super::scalar_value(view.table(8));
        check(!table.is_empty() && table.len() <= 4096);
        let mut exact_site = false;
        for i in 0..table.len() {
            exact_site |= super::super::scalar_value(table.field(i, 0)) == post;
        }
        // The list is retained qualified immutable runtime instruction boundaries,
        // not a scan or permission for arbitrary bytes anywhere in an RX range.
        check(exact_site);
        let c = s.control.as_ptr();
        let count = tool_init::read(unsafe { &raw const (*c).private_code_count });
        check(count <= 64);
        let mut code = false;
        for i in 0..count as usize {
            let item = unsafe {
                (&raw const (*c).code)
                    .cast::<super::super::super::PrivateCode>()
                    .add(i)
            };
            code |= complete_instruction(
                tool_init::read(unsafe { &raw const (*item).lo }),
                tool_init::read(unsafe { &raw const (*item).hi }),
                post,
            );
        }
        check(
            code && post >= 2 && unsafe { ((post - 2) as *const u16).read_unaligned() } == 0x050f,
        );
        if number as u64 & 0x4000_0000 != 0 || tool_init::changes_startup_domain(number, args) {
            die(OPERATION);
        }
        // All existing nested process/signal/registration, runtime descriptor and
        // owner-mapping guards run unchanged. Only the physical execution leaf
        // differs: keep actual Tool FS, do not call event.forward/Guest FS.
        unsafe {
            crate::guest::trap_dispatch::forward_nested_tool_syscall_with(event, observe, |event| {
                let result = unsafe {
                    crate::trap::raw_syscall6_with_result(
                        event.number,
                        event.args,
                        event.guest_pkru,
                    )
                };
                event.result = result.result;
                event.guest_pkru = result.pkru;
            })
        };
        unsafe { verify_owner(s, p, frame) };
        // Linux may update the actual Tool PKRU result; normal trap return owns
        // committing RAX and PKRU to this same exclusive kernel frame afterward.
        s.busy.store(false, Ordering::Release);
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn only_restored_ready_callback_phase_is_eligible() {
            assert!(callback_phase(4, 1, 3));
            for values in [
                (1, 0, 1),
                (2, 0, 1),
                (2, 1, 1),
                (3, 1, 3),
                (4, 0, 3),
                (4, 1, 1),
                (6, 0, 1),
            ] {
                assert!(!callback_phase(values.0, values.1, values.2));
            }
        }
        #[test]
        fn syscall_boundary_requires_both_bytes_in_the_same_code_extent() {
            assert!(complete_instruction(0x1000, 0x2000, 0x1002));
            assert!(complete_instruction(0x1000, 0x2000, 0x2000));
            assert!(!complete_instruction(0x1000, 0x2000, 0x1001));
            assert!(!complete_instruction(0x1000, 0x2000, 0x2001));
            assert!(!complete_instruction(0, u64::MAX, 1));
            assert!(!complete_instruction(0x2000, 0x1000, 0x1002));
        }
        #[test]
        fn saved_altstack_requires_registered_extent_and_offstack_saved_flags() {
            let stack = Extent {
                lo: 0x1000,
                hi: 0x5000,
            };
            let mut bytes = [0; 24];
            bytes[0..8].copy_from_slice(&0x1000_u64.to_le_bytes());
            bytes[16..24].copy_from_slice(&0x4000_u64.to_le_bytes());
            assert!(saved_stack_matches(bytes, stack));
            for index in [0, 8, 16] {
                let mut changed = bytes;
                changed[index] ^= 1;
                assert!(!saved_stack_matches(changed, stack));
            }
            assert!(!saved_stack_matches(
                bytes,
                Extent {
                    lo: 0x5000,
                    hi: 0x1000
                }
            ));
        }
    }
}
