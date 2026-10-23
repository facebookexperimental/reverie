//! UNSAFE DRAFT ONLY. No product linkage/activation supplied.
//! Exact authority: musl 1.2.5 selected src/internal/{libc,pthread_impl}.h,
//! src/env/__init_tls.c and arch/x86_64/{pthread_arch.h,__set_thread_area.s}.
use core::cell::UnsafeCell;
use core::ffi::c_int;
use core::ffi::c_void;
use core::mem::align_of;
use core::mem::offset_of;
use core::mem::size_of;
use core::ptr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use super::layout::PTHREAD_BYTES;
use super::layout::Plan;

#[repr(C)]
struct TlsModule {
    next: *mut TlsModule,
    image: *mut c_void,
    len: usize,
    size: usize,
    align: usize,
    offset: usize,
}
#[repr(C)]
struct Libc {
    can_do_threads: u8,
    threaded: u8,
    secure: u8,
    need_locks: i8,
    threads_minus_1: c_int,
    auxv: *mut usize,
    tls_head: *mut TlsModule,
    tls_size: usize,
    tls_align: usize,
    tls_cnt: usize,
    page_size: usize,
    global_locale: [*const c_void; 6],
}
#[repr(C)]
struct RobustList {
    head: *mut c_void,
    off: isize,
    pending: *mut c_void,
}
/// Bitfield byte is opaque: Rust never reads/writes either C bitfield.
/// Volatile C fields below are represented only to validate offsets, not accessed.
#[repr(C)]
struct Pthread {
    self_: *mut Pthread,
    dtv: *mut usize,
    prev: *mut Pthread,
    next: *mut Pthread,
    sysinfo: usize,
    canary: usize,
    tid: c_int,
    errno_val: c_int,
    detach_state: c_int,
    cancel: c_int,
    canceldisable: u8,
    cancelasync: u8,
    flags_storage: u8,
    map_base: *mut u8,
    map_size: usize,
    stack: *mut c_void,
    stack_size: usize,
    guard_size: usize,
    result: *mut c_void,
    cancelbuf: *mut c_void,
    tsd: *mut *mut c_void,
    robust_list: RobustList,
    h_errno_val: c_int,
    timer_id: c_int,
    locale: *mut c_void,
    killlock: [c_int; 1],
    dlerror_buf: *mut u8,
    stdio_locks: *mut c_void,
}
const _: () = {
    assert!(size_of::<usize>() == 8 && size_of::<c_int>() == 4);
    assert!(size_of::<TlsModule>() == 48 && align_of::<TlsModule>() == 8);
    assert!(offset_of!(TlsModule, offset) == 40);
    assert!(size_of::<Libc>() == 104 && align_of::<Libc>() == 8);
    assert!(offset_of!(Libc, auxv) == 8 && offset_of!(Libc, tls_head) == 16);
    assert!(offset_of!(Libc, tls_size) == 24 && offset_of!(Libc, tls_align) == 32);
    assert!(offset_of!(Libc, tls_cnt) == 40 && offset_of!(Libc, global_locale) == 56);
    assert!(size_of::<Pthread>() == PTHREAD_BYTES && align_of::<Pthread>() == 8);
    assert!(offset_of!(Pthread, self_) == 0 && offset_of!(Pthread, dtv) == 8);
    assert!(offset_of!(Pthread, tid) == 48 && offset_of!(Pthread, flags_storage) == 66);
    assert!(offset_of!(Pthread, map_base) == 72 && offset_of!(Pthread, robust_list) == 136);
    assert!(offset_of!(Pthread, locale) == 168 && offset_of!(Pthread, killlock) == 176);
    assert!(offset_of!(Pthread, dlerror_buf) == 184 && offset_of!(Pthread, stdio_locks) == 192);
};

unsafe extern "C" {
    static mut __libc: Libc;
    static mut __default_stacksize: u32;
    fn __copy_tls(backing: *mut u8) -> *mut c_void;
    fn __init_tp(pthread: *mut c_void) -> c_int;
    // Single link-required trusted leaf, not a caller-provided address. The
    // final artifact must prove this hidden symbol is the exact retained
    // no-TLS/no-allocation/no-unwind terminal gate. No default implementation.
    fn hermit_loader_bootstrap_abort(reason: Failure) -> !;
}

#[repr(u32)]
#[derive(Clone, Copy)]
pub enum Failure {
    Reentry = 1,
    AuxMismatch = 2,
    LibcAlreadyInitialized = 3,
    CopyPlacement = 4,
    SetThreadPointer = 5,
    CopyDtv = 6,
    NotInstalled = 7,
}

/// Numeric values must come from the exact mapped fixed ET_EXEC, not guest auxv.
#[derive(Clone, Copy)]
pub struct IndexedAux {
    pub phdr: usize,
    pub phent: usize,
    pub phnum: usize,
    pub page_size: usize,
}

struct Context {
    plan: Plan,
    aux: IndexedAux,
    gnu_stack_bytes: usize,
}
// This leaf is independent of CONTEXT, including before installation. Final
// linkage and the qualified startup artifact must satisfy the extern contract.
fn die(reason: Failure) -> ! {
    // SAFETY: the linked trusted image must provide the fixed total terminal
    // primitive. A missing symbol is a link error, never a guessed pointer.
    unsafe { hermit_loader_bootstrap_abort(reason) }
}
// No public constructor mints ownership; install_before_libc has all real custody
// obligations. This storage is part of the mapped private runtime RW/BSS.
struct Cell<T>(UnsafeCell<T>);
// SAFETY: only the single stopped/bootstrap leader may initialize/read; the
// atomic one-use state excludes further initialization. Signals never access it.
unsafe impl<T> Sync for Cell<T> {}
static CONTEXT: Cell<core::mem::MaybeUninit<Context>> =
    Cell(UnsafeCell::new(core::mem::MaybeUninit::uninit()));
static MODULE: Cell<TlsModule> = Cell(UnsafeCell::new(TlsModule {
    next: ptr::null_mut(),
    image: ptr::null_mut(),
    len: 0,
    size: 0,
    align: 0,
    offset: 0,
}));
static STATE: AtomicU8 = AtomicU8::new(0); // 0 absent; 1 armed; 2 entered; 3 returned; 4 installing.

/// # Safety
/// Caller is the genuine sole bootstrap leader on owned Tool stack. Existing
/// ToolRegion physical owner exclusively retains zeroed RW backing and all
/// guards; mappings, template source bytes, MODULE and CONTEXT outlive libc.
/// `plan` was calculated from authenticated final fixed ET_EXEC single PT_TLS;
/// backing is disjoint from *all* image/control/stack/guard/other live extents.
/// Exact private libc state is still pristine; no constructors/allocations ran.
/// The linked abort symbol is a no-TLS/no-allocation/no-unwind exact-gate termination
/// leaf, usable under old/new/absent FS and on this private stack. It never
/// returns, transfers to Guest, unmaps live memory or releases host cleanup.
/// Bootstrap SIGSYS provenance/phase/reentrancy/gate/restorer/altstack/mask is
/// already installed BEFORE __init_libc; relay preserves changed actual FS on
/// return from __init_tp's arch_prctl and retains actual clear-tid ownership.
/// Authenticated private env/aux passed to __init_libc satisfy its full contract.
/// No signal/thread accesses CONTEXT or MODULE; asynchronous signals are blocked.
/// Final compiler closure must prove every reachable Rust path no TLS/unwind,
/// allocator, anonymous mmap or brk (including generated copy/panic helpers).
pub unsafe fn install_before_libc(
    plan: Plan,
    aux: IndexedAux,
    gnu_stack_bytes: usize,
) -> Result<(), ()> {
    STATE
        .compare_exchange(0, 4, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| ())?;
    // SAFETY: the caller guarantees exclusive physical ownership and no racing
    // installer. This writes context only; it does not create/adopt ownership.
    unsafe {
        (*CONTEXT.0.get()).write(Context {
            plan,
            aux,
            gnu_stack_bytes,
        });
    }
    STATE.store(1, Ordering::Release);
    Ok(())
}

/// Strong replacement for the archive's weak __init_tls, not __init_libc.
/// # Safety
/// Called exactly once by retained private __init_libc, after successful unsafe
/// install_before_libc; aux points to its readable indexed [usize;38] stack array.
/// Those exact stack bytes remain alive throughout this call; bootstrap relay
/// never touches this state. All installer obligations remain in force.
/// The final ELF must resolve exactly this strong symbol and the intended private
/// __libc/__copy_tls/__init_tp; their archive weak/hidden bindings need link audit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __init_tls(aux: *mut usize) {
    // Reject missing, incomplete or repeated installation before touching the
    // MaybeUninit. A successful acquire sees the completed release publication.
    if let Err(state) = STATE.compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire) {
        die(if state == 0 || state == 4 {
            Failure::NotInstalled
        } else {
            Failure::Reentry
        });
    }
    // SAFETY: only install_before_libc release-publishes state1, after writing
    // every Context field. This transition is one-use and excludes all writers.
    let c = unsafe { &*(*CONTEXT.0.get()).as_ptr() };
    // SAFETY: exact indexed aux array lifetime/extent is the ABI precondition.
    let observed = unsafe {
        [
            ptr::read(aux.add(3)),
            ptr::read(aux.add(4)),
            ptr::read(aux.add(5)),
            ptr::read(aux.add(6)),
        ]
    };
    if observed != [c.aux.phdr, c.aux.phent, c.aux.phnum, c.aux.page_size] {
        die(Failure::AuxMismatch)
    }
    // SAFETY: exact resolved private object address, not guest libc interposition.
    let libc = unsafe { ptr::addr_of_mut!(__libc) };
    // SAFETY: source-bound private libc and sole-leader access. Preserve auxv,
    // hwcap/sysinfo/env/security/locale fields initialized or used by __init_libc.
    if unsafe {
        ptr::read(&raw const (*libc).tls_head) != ptr::null_mut()
            || ptr::read(&raw const (*libc).tls_cnt) != 0
            || ptr::read(&raw const (*libc).tls_size) != 0
            || ptr::read(&raw const (*libc).tls_align) != 0
    } {
        die(Failure::LibcAlreadyInitialized)
    }
    let p = c.plan;
    // SAFETY: exclusive permanent module storage; all image/backing bounds and
    // zero-BSS/TCB/DTV guarantees were authenticated before entering this ABI.
    unsafe {
        ptr::write(
            MODULE.0.get(),
            TlsModule {
                next: ptr::null_mut(),
                image: p.template().image as *mut c_void,
                len: p.template().file_bytes,
                size: p.module_bytes(),
                align: p.tls_align(),
                offset: p.module_bytes(),
            },
        );
        ptr::write(&raw mut (*libc).tls_head, MODULE.0.get());
        ptr::write(&raw mut (*libc).tls_cnt, 1);
        ptr::write(&raw mut (*libc).tls_align, p.tls_align());
        ptr::write(&raw mut (*libc).tls_size, p.total_bytes());
        // Retain PT_GNU_STACK's existing musl default-thread-stack hint policy;
        // this does not allocate or change the already owned bootstrap stack.
        let current = ptr::read(&raw const __default_stacksize);
        if c.gnu_stack_bytes > current as usize {
            ptr::write(
                &raw mut __default_stacksize,
                c.gnu_stack_bytes.min(8 << 20) as u32,
            );
        }
    }
    // SAFETY: exact retained musl function; prezeroed ranges and valid metadata.
    let tp = unsafe { __copy_tls(p.backing().start as *mut u8) };
    if tp as usize != p.pthread().start {
        die(Failure::CopyPlacement)
    }
    // SAFETY: the copy target and DTV entries are valid initialized words in owned
    // RW memory; no pthread flags/bitfields are accessed from Rust.
    let td = tp.cast::<Pthread>();
    if unsafe {
        ptr::read(&raw const (*td).dtv) as usize != p.dtv().start
            || ptr::read(p.dtv().start as *const usize) != 1
            || ptr::read((p.dtv().start as *const usize).add(1)) != p.tls().start
    } {
        die(Failure::CopyDtv)
    }
    // SAFETY: installed pre-TLS relay forwards exact library syscall sites,
    // __init_tp writes self/FS/tid/etc on valid TCB. An actual FS transition may
    // precede failure: terminal must work in both states and mapping stays live.
    if unsafe { __init_tp(tp) } < 0 {
        die(Failure::SetThreadPointer)
    }
    // TLS initializer returned, NOT DetcoreReady or ToolRegion adopted. __init_libc
    // must still execute SSP/security setup; constructors remain prohibited until
    // a separate genuine one-use existing-owner adoption and full initialization.
    STATE.store(3, Ordering::Release);
}

// The full __init_libc wrapper calls this only after the real foreign call
// returns. This checks the one-use TLS initializer, not ToolRegion ownership,
// SSP policy, private FS on other threads, or Detcore readiness.
pub(super) fn require_tls_returned() {
    if STATE.load(Ordering::Acquire) != 3 {
        die(Failure::NotInstalled);
    }
}
