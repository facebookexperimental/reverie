//! W3 S5b lazy trap-and-patch hookup on S5a (428e1ae1): foreign-text
//! `SiteStore` backends and the promoter that drains S5a's pending
//! first-seen SVC sites (`reverie_inguest::trap`) into
//! `liteinst-aarch64-patch` flips.
//!
//! Boundary (settled design): reverie-inguest only records/drains
//! site addresses; this module owns mapping census use, island pool,
//! retry retention, and the foreign stores. The patch crate owns the
//! flip protocol and custody. The one per-architecture fact used
//! here — the 4-byte AArch64 instruction word — comes from the fact
//! crate (`liteinst_aarch64::INSN_LEN`); site addresses arrive
//! precomputed by S5a's handler (frame PC - 4). The only
//! `cfg(target_arch)` in this module is the drain glue to S5a's
//! AArch64-only table and the island-range registration.
//!
//! Every OS call — this module's and, once installed, the patch
//! crate's — goes through the patch crate's syscall gate, which the
//! promoter installs as the in-guest trusted gate
//! (`reverie_inguest::trap::raw_syscall6`). Raw libc syscalls from
//! these addresses would be seen as guest syscalls (or die with
//! SIGSYS in dispatch context).
//!
//! Selection (Trap / SudTrap / TrapAndPatch / PatchEager) is the
//! caller's cell decision per the musearch matrix (§5.2). This
//! promoter only executes admitted TrapAndPatch candidates and
//! never works around a platform-policy denial.
//!
//! INVARIANT (signal masking): drains mask all blockable signals
//! for their duration, and accordingly EVERY syscall issued inside
//! a drain — this module's, the patch crate's, and any future
//! StopControl's — must go through the trusted gate. A syscall
//! from any other address traps (SIGSYS), and a masked SIGSYS
//! kills the process; that is the intended fail-closed outcome,
//! so SIGSYS is never unblocked inside a drain. (Drain-path Vec
//! and Box allocations rely on the product's fixed allocator,
//! which issues no syscalls; a raw system allocator would break
//! this invariant.) Nothing drains in
//! production yet: backend invocation under an admitting selection
//! is the integration step. BLR x8 stays probe/refuse (absent here).
//!
//! Honest limit of the current island shape `[SVC, B site+4]`: a
//! promoted call branches to the island and re-executes SVC there,
//! so it still traps on every call — the flip buys a stable,
//! patcher-owned site word and custody, not trap avoidance. Island
//! addresses are registered with S5a's denylist before the flip so
//! those re-traps never consume pending-table slots. An island
//! that enters dispatch directly is future work; until then no
//! claim of skipped SIGSYS is made anywhere.

use liteinst_aarch64::emit::svc_island_words;
use liteinst_aarch64_patch::flip::FlipRequest;
use liteinst_aarch64_patch::gate::{GateSyscall, gate6};
use liteinst_aarch64_patch::island::Island;
use liteinst_aarch64_patch::mapping::{MappingFacts, qualify_mapping};
use liteinst_aarch64_patch::site::{
    FallbackPermission, Site, SiteState, StopControl, StrategyPreference,
};
use liteinst_aarch64_patch::store::SiteStore;
use liteinst_aarch64_patch::{PatchError, Patcher};

/// `PROT_BTI` (arm64). `mprotect` clears `VM_ARM64_BTI` unless the
/// flag is present in BOTH the window and the restore protections,
/// and maps perms cannot express it — `MappingFacts::bti` (from
/// smaps VmFlags) is the only source. On non-AArch64 targets the
/// smaps flag never appears, so the bit is never set.
const PROT_BTI: libc::c_int = 0x10;

fn bti_bit(facts: &MappingFacts) -> libc::c_int {
    if facts.bti { PROT_BTI } else { 0 }
}

/// The in-guest trusted gate as a patch-crate `GateSyscall`.
struct InguestGate;

// SAFETY: forwards exactly the named syscall through the trusted
// gate whose instruction address the in-guest filter admits.
unsafe impl GateSyscall for InguestGate {
    unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64 {
        // SAFETY: same raw contract, forwarded.
        unsafe { reverie_inguest::trap::raw_syscall6(nr, args) }
    }
}

static INGUEST_GATE: InguestGate = InguestGate;

/// Install the in-guest trusted gate as the patch crate's syscall
/// gate. Called by promoter construction; safe to call again with
/// the same gate. Backends that run before the runtime exists must
/// call this before any other patch-crate entry.
pub fn install_inguest_gate() -> Result<(), PatchError> {
    // SAFETY: INGUEST_GATE keeps the GateSyscall contract for the
    // process lifetime (it is a static with no state).
    unsafe { liteinst_aarch64_patch::gate::install_gate(&INGUEST_GATE) }
}

fn os_err_from(ret: i64, op: &'static str) -> PatchError {
    liteinst_aarch64_patch::gate::check(ret, op).unwrap_err()
}

/// Promoter admission gate, checked under the lease before any
/// island work or store: the mapping must be windowable, contain
/// the site, lie outside the runtime's own gate text, and the site
/// must be instruction-aligned. `Site::from_rx` and the emitter
/// re-check containment/alignment downstream; refusing here keeps
/// a doomed candidate from consuming island custody.
pub fn admit(addr: u64, facts: &MappingFacts) -> bool {
    if !facts.windowable()
        || !facts.contains(addr)
        || !addr.is_multiple_of(liteinst_aarch64::INSN_LEN as u64)
    {
        return false;
    }
    // Denylist: never patch runtime-owned text (fixed gates where
    // published, both syscall gate pages, the restorer entry, and
    // the SIGSYS handler page, on every architecture). A flipped
    // gate word would break every trusted syscall in the process,
    // including this promoter's own store path.
    if reverie_inguest::trap::is_runtime_text(addr) {
        return false;
    }
    true
}

/// Foreign store via a leased `mprotect` window over exactly the
/// qualified page span. The window is opened per flip under the
/// patcher lease and the exact original protections (including
/// BTI, which maps perms cannot express) are restored by
/// `finish_write` (idempotent once closed).
pub struct MprotectStore {
    addr: u64,
    page_base: usize,
    page_len: usize,
    orig_prot: libc::c_int,
    open: bool,
}

impl MprotectStore {
    /// Store for the site at `addr` under qualified `facts`.
    pub fn new(addr: u64, facts: MappingFacts) -> Self {
        Self {
            addr,
            page_base: facts.page_span.0 as usize,
            page_len: facts.page_span.1 as usize,
            orig_prot: facts.orig_prot | bti_bit(&facts),
            open: false,
        }
    }

    fn set_prot(&self, prot: libc::c_int, op: &'static str) -> Result<(), PatchError> {
        // SAFETY: the span is the qualified page span from the
        // site's own facts, leased by the patcher for this store.
        let ret = unsafe {
            gate6(
                libc::SYS_mprotect,
                [
                    self.page_base as u64,
                    self.page_len as u64,
                    prot as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        liteinst_aarch64_patch::gate::check(ret, op)?;
        Ok(())
    }
}

// SAFETY: the store names the site word through the same VA the CPU
// executes; the window only widens that page to writable for the
// store between begin/finish, under the patcher lease.
unsafe impl SiteStore for MprotectStore {
    fn read_word(&self) -> u32 {
        unsafe { (self.addr as *const u32).read_volatile() }
    }
    fn write_addr(&self) -> u64 {
        self.addr
    }
    fn begin_write(&mut self) -> Result<(), PatchError> {
        if self.open {
            return Ok(());
        }
        let window =
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC | (self.orig_prot & PROT_BTI);
        self.set_prot(window, "mprotect window open")?;
        self.open = true;
        Ok(())
    }
    fn store_word(&mut self, word: u32) -> Result<(), PatchError> {
        if !self.open {
            return Err(PatchError::MappingRefused("mprotect window not open"));
        }
        unsafe { (self.addr as *mut u32).write_volatile(word) };
        Ok(())
    }
    fn finish_write(&mut self) -> Result<(), PatchError> {
        if !self.open {
            return Ok(());
        }
        // On failure stay marked open so completion retries the
        // restore; the patcher surfaces this as SyncPending custody.
        self.set_prot(self.orig_prot, "mprotect restore")?;
        self.open = false;
        Ok(())
    }
}

impl Drop for MprotectStore {
    fn drop(&mut self) {
        // Backstop: a site dropped with its window somehow open
        // must not leave guest text RWX. Best effort only; the
        // protocol path always finishes explicitly first.
        if self.open {
            let _ = self.set_prot(self.orig_prot, "mprotect restore (drop)");
            self.open = false;
        }
    }
}

/// Foreign store via `/proc/self/mem`: no protection window.
/// Unlike `process_vm_writev` (no FOLL_FORCE: EFAULT on R-X text),
/// proc-mem writes reach read-only private text and break COW
/// exactly as an mprotect window store would. Used only under
/// explicit selector permission (`StoreFallback::AllowProcMem`)
/// after the mprotect window was refused; never as an
/// errno-triggered bypass.
pub struct ProcMemStore {
    addr: u64,
    fd: Option<libc::c_int>,
}

impl ProcMemStore {
    /// Store for the site at `addr`.
    pub fn new(addr: u64) -> Self {
        Self { addr, fd: None }
    }
}

// SAFETY: pwrite64 on /proc/self/mem at the site VA writes the same
// physical word the CPU executes there (proc-mem access uses
// FOLL_FORCE, breaking COW for private file text without touching
// the file); the patcher lease and revalidation bound when it runs.
unsafe impl SiteStore for ProcMemStore {
    fn read_word(&self) -> u32 {
        unsafe { (self.addr as *const u32).read_volatile() }
    }
    fn write_addr(&self) -> u64 {
        self.addr
    }
    fn begin_write(&mut self) -> Result<(), PatchError> {
        if self.fd.is_some() {
            return Ok(());
        }
        let path = c"/proc/self/mem";
        // SAFETY: path is a valid C string; O_RDWR for the write.
        let fd = unsafe {
            gate6(
                libc::SYS_openat,
                [
                    libc::AT_FDCWD as u64,
                    path.as_ptr() as u64,
                    (libc::O_RDWR | libc::O_CLOEXEC) as u64,
                    0,
                    0,
                    0,
                ],
            )
        };
        self.fd =
            Some(liteinst_aarch64_patch::gate::check(fd, "openat /proc/self/mem")? as libc::c_int);
        Ok(())
    }
    fn store_word(&mut self, word: u32) -> Result<(), PatchError> {
        let fd = self
            .fd
            .ok_or(PatchError::MappingRefused("proc-mem store not open"))?;
        // SAFETY: word outlives the call; offset is the site VA.
        let n = unsafe {
            gate6(
                libc::SYS_pwrite64,
                [
                    fd as u64,
                    core::ptr::addr_of!(word) as u64,
                    4,
                    self.addr,
                    0,
                    0,
                ],
            )
        };
        if n == 4 {
            Ok(())
        } else if n < 0 {
            Err(os_err_from(n, "pwrite64 /proc/self/mem"))
        } else {
            Err(PatchError::MappingRefused("partial /proc/self/mem write"))
        }
    }
    fn finish_write(&mut self) -> Result<(), PatchError> {
        if let Some(fd) = self.fd.take() {
            // SAFETY: fd is the one begin_write opened, closed once.
            let ret = unsafe { gate6(libc::SYS_close, [fd as u64, 0, 0, 0, 0, 0]) };
            liteinst_aarch64_patch::gate::check(ret, "close /proc/self/mem")?;
        }
        Ok(())
    }
}

impl Drop for ProcMemStore {
    fn drop(&mut self) {
        let _ = self.finish_write();
    }
}

/// What happened to one drained candidate. Post-store outcomes are
/// custody, never refusals: `CustodyPending` means the word may be
/// live and the site is retained for completion/rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromoteOutcome {
    /// Site flipped to its island branch and settled.
    Flipped,
    /// Refused before any store (mapping, generation, strategy, or
    /// capability); the site word is untouched and stays trapping.
    Refused,
    /// Custody is unresolved. Two shapes, told apart by custody
    /// location: a RETAINED site (its store was issued or may
    /// have been; drive [`LazyPromoter::complete_pending`]), or
    /// an unheld candidate blocked before any store (pre-store
    /// shortfall, mask failure, or another site's custody). Who
    /// owns an unheld candidate depends on the entry point: on
    /// the DRAIN path the promoter defers it internally and
    /// retries it at the next drain — never re-drain it as a
    /// fresh candidate from the source. A direct
    /// [`LazyPromoter::promote_one`] defers NOTHING: the caller
    /// still owns the candidate and must retry it after the
    /// blocking custody settles.
    CustodyPending,
}

/// Whether a refused mprotect window may fall back to the
/// /proc/self/mem store. Default `RefuseWindow`: a refused window
/// (including platform-policy errnos — MDWE/SELinux execmem,
/// W^X seccomp) means Refused with the site still trapping;
/// falling back on a policy errno would work around the denial.
/// `AllowProcMem` is an explicit selector permission (HOOKUP
/// design amendment): the selection cell, never the errno,
/// authorizes the second store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StoreFallback {
    /// Refused window = Refused. The default.
    #[default]
    RefuseWindow,
    /// Selector explicitly permits /proc/self/mem after a
    /// refused window.
    AllowProcMem,
}

/// Classify a flip error by whether the Site must be retained.
/// The STATE is the sole post-store discriminator: the patcher
/// sets SyncPending/RetainedStop before issuing the store and
/// before sync/restore can fail (finish_publication builds
/// RestoreFailed only after setting that state), so every
/// post-store error arrives with a non-Unpatched state and is
/// custody. Store/Sync/Restore failures paired with Unpatched
/// are therefore unreachable; they classify as plain refusals
/// here rather than retaining a site no completion path could
/// settle (which would wedge the global custody count).
/// Pre-store custody (a resume shortfall on an Unpatched site:
/// nothing was written, but executors may still be stopped)
/// does NOT retain the site — it retains the STOP, which the
/// promoter retries before new work (see `stop_retained`).
fn classify(err: &PatchError, state: SiteState) -> (PromoteOutcome, bool) {
    if state != SiteState::Unpatched {
        return (PromoteOutcome::CustodyPending, true);
    }
    debug_assert!(
        !matches!(
            err,
            PatchError::StoreFailed { .. }
                | PatchError::SyncFailed { .. }
                | PatchError::RestoreFailed { .. }
        ),
        "post-store error with Unpatched state: patcher contract broken ({err:?})"
    );
    match err {
        // Pre-store: the lease could not be cleanly released, so
        // executors may still be stopped — custody of the STOP,
        // not of any site.
        PatchError::ResumeIncomplete | PatchError::CleanupFailed { .. } => {
            (PromoteOutcome::CustodyPending, false)
        }
        _ => (PromoteOutcome::Refused, false),
    }
}

/// Whether a resume outcome fully released every executor:
/// non-empty and every entry acknowledged/released. An empty
/// Vec is a shortfall (no executor was even reported), matching
/// the patch crate's settlement rule.
fn all_acknowledged(states: &[liteinst_aarch64_patch::site::ResumeState]) -> bool {
    use liteinst_aarch64_patch::site::ResumeState;
    !states.is_empty()
        && states
            .iter()
            .all(|s| matches!(s, ResumeState::SyncAcked | ResumeState::Released))
}

/// Whether a flip refusal is the store-selection fallback point:
/// the window itself was refused before any store.
fn is_window_refusal(err: &PatchError) -> bool {
    matches!(err, PatchError::WindowRefused { .. })
}

/// RAII signal mask across a drain: no handler may observe the
/// mid-lease window (stopped executors, RWX page) on this thread.
struct SignalMask {
    old: u64,
    active: bool,
}

impl SignalMask {
    /// Install the full mask, or None when the gate refused it.
    /// Callers must NOT proceed unmasked silently: a drain that
    /// cannot mask does no work (its candidates stay pending).
    fn block_all() -> Option<Self> {
        let full: u64 = u64::MAX;
        let mut old: u64 = 0;
        // SAFETY: mask pointers are valid 8-byte sigsets for the call.
        let ret = unsafe {
            gate6(
                libc::SYS_rt_sigprocmask,
                [
                    libc::SIG_BLOCK as u64,
                    core::ptr::addr_of!(full) as u64,
                    core::ptr::addr_of_mut!(old) as u64,
                    8,
                    0,
                    0,
                ],
            )
        };
        if ret != 0 {
            return None;
        }
        Some(Self { old, active: true })
    }
}

impl Drop for SignalMask {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: restores the mask captured at block time.
            unsafe {
                gate6(
                    libc::SYS_rt_sigprocmask,
                    [
                        libc::SIG_SETMASK as u64,
                        core::ptr::addr_of!(self.old) as u64,
                        0,
                        8,
                        0,
                        0,
                    ],
                );
            }
        }
    }
}

/// Process-wide post-store custody count (pending sites plus
/// retained stops, across ALL promoter instances). Custody is a
/// process property — executors are stopped process-wide — so a
/// second promoter must never resume onto another promoter's
/// unsynced RWX page. Scope: this backstop covers SEQUENTIAL use
/// of promoter instances on one thread (the gate is check-then-
/// act, so concurrent promoters on different threads are not a
/// supported design). Production holds exactly one promoter.
static GLOBAL_CUSTODY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn custody_enter() {
    GLOBAL_CUSTODY.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

fn custody_exit() {
    GLOBAL_CUSTODY.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
}

fn global_custody_held() -> bool {
    GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst) > 0
}

/// The promoter: patcher + retained sites + island pool. Arenas in
/// this slice are one island per flipped site (retained by the
/// `Site` itself); entry-allocator arenas are a sizing follow-up
/// that does not change this boundary.
///
/// Production holds exactly one promoter per process. The
/// process-wide custody counter is a backstop, not a concurrency
/// design: while any promoter holds post-store custody, every
/// promoter refuses work whose paths resume executors.
///
/// Caller contract for `CustodyPending`: this type's signal mask
/// is dropped when the call that returned the outcome returns.
/// If that outcome is `CustodyPending`, the caller must drive
/// [`LazyPromoter::complete_pending`] to settlement before
/// returning this thread to guest code that expects its
/// pre-drain signal mask and executor state. Settlement is
/// observable through [`LazyPromoter::unsettled_custody`]:
/// `complete_pending` returning an empty vector is ambiguous
/// (settled, still failing, and blocked by another promoter all
/// look alike), the query is not. There is no rollback API on
/// this type; completion is the only exit from custody.
///
/// Signal window: the mask is restored as the returning call
/// unwinds, so an async signal that arrived during the drain may
/// be delivered immediately at that restore — BEFORE the caller
/// can drive completion. A handler running in that window must
/// not resume guest execution while custody is unsettled:
/// executors may still be stopped on an unsynced page.
pub struct LazyPromoter {
    patcher: Patcher,
    sites: Vec<Site>,
    retained_refusals: Vec<u64>,
    generation: u64,
    /// A resume shortfall before any Site existed (acquire held,
    /// refusal could not release). Settled before new work.
    stop_retained: bool,
    store_fallback: StoreFallback,
    mask_failed: bool,
    /// (site addr, island lo, island hi) for every retained site,
    /// so a site that settles back to Unpatched releases its
    /// denylist range instead of burning it for good.
    island_ranges: Vec<(u64, u64, u64)>,
    /// Candidates consumed from a drain source but not yet
    /// attempted because an earlier candidate entered custody.
    /// Retried (in order) at the next drain, before the source.
    deferred: std::collections::VecDeque<u64>,
}

impl LazyPromoter {
    /// Promoter with an attested patcher. Attestation forks a
    /// probe child: construct BEFORE extra threads exist and
    /// before the guest (and its syscall filter) starts, or the
    /// probe's own child custody cannot be guaranteed.
    pub fn attested(generation: u64) -> Result<Self, PatchError> {
        install_inguest_gate()?;
        Ok(Self {
            patcher: Patcher::attested()?,
            sites: Vec::new(),
            retained_refusals: Vec::new(),
            generation,
            stop_retained: false,
            store_fallback: StoreFallback::default(),
            mask_failed: false,
            island_ranges: Vec::new(),
            deferred: std::collections::VecDeque::new(),
        })
    }

    /// Promoter whose patcher refuses every flip before any store
    /// (no cache attestation). Still installs the gate, so drain
    /// bookkeeping syscalls take the trusted path.
    pub fn unattested(generation: u64) -> Self {
        let _ = install_inguest_gate();
        Self {
            patcher: Patcher::new(),
            sites: Vec::new(),
            retained_refusals: Vec::new(),
            generation,
            stop_retained: false,
            store_fallback: StoreFallback::default(),
            mask_failed: false,
            island_ranges: Vec::new(),
            deferred: std::collections::VecDeque::new(),
        }
    }

    /// Promoter over a caller-supplied patcher (integration and
    /// fault-injection tests). The caller owns attestation timing.
    pub fn with_patcher(patcher: Patcher, generation: u64) -> Result<Self, PatchError> {
        install_inguest_gate()?;
        Ok(Self {
            patcher,
            sites: Vec::new(),
            retained_refusals: Vec::new(),
            generation,
            stop_retained: false,
            store_fallback: StoreFallback::default(),
            mask_failed: false,
            island_ranges: Vec::new(),
            deferred: std::collections::VecDeque::new(),
        })
    }

    /// Set the store-selection fallback permission (selector-owned;
    /// default RefuseWindow). Never derived from an errno.
    pub fn set_store_fallback(&mut self, fallback: StoreFallback) {
        self.store_fallback = fallback;
    }

    /// The current store-fallback permission.
    pub fn store_fallback(&self) -> StoreFallback {
        self.store_fallback
    }

    /// Whether the most recent drain could not install its signal
    /// mask and therefore did no work.
    pub fn mask_failed(&self) -> bool {
        self.mask_failed
    }

    /// Advance the promoter-owned mapping generation (call on any
    /// munmap/mmap-replace/mprotect-under-site/exec event the census
    /// observes). Qualification happens under the lease against
    /// this generation, so a bump between drains requalifies every
    /// later candidate from fresh facts. Selector/census API: it
    /// has no internal caller by design.
    pub fn bump_generation(&mut self) {
        self.generation += 1;
    }

    /// Sites refused so far and retained (never re-queued upstream).
    pub fn retained_refusals(&self) -> &[u64] {
        &self.retained_refusals
    }

    /// Number of sites this promoter holds custody of.
    pub fn held_sites(&self) -> usize {
        self.sites.len()
    }

    /// Whether this promoter still holds unsettled custody: a
    /// retained stop (executors may still be stopped) or any site
    /// in post-store `SyncPending`/`RetainedStop`. This is the
    /// settlement signal for the `CustodyPending` caller
    /// contract — drive [`LazyPromoter::complete_pending`] until
    /// this returns false. (Another promoter's custody also
    /// blocks work, but is not this instance's to settle.)
    pub fn unsettled_custody(&self) -> bool {
        self.stop_retained || self.own_pending_custody()
    }

    /// Whether any held site is in post-store custody
    /// (SyncPending/RetainedStop) or a stop is retained. While
    /// true, NO new promotion, drain, or later completion may
    /// run: every resume path would release executors onto a
    /// page whose word is not yet synced/restored (the W^X
    /// no-resume rule applies across sites, not per site).
    fn custody_blocking(&self) -> bool {
        global_custody_held()
            || self.stop_retained
            || self.sites.iter().any(|s| {
                matches!(
                    s.state(),
                    SiteState::SyncPending { .. } | SiteState::RetainedStop { .. }
                )
            })
    }

    fn own_pending_custody(&self) -> bool {
        self.sites.iter().any(|s| {
            matches!(
                s.state(),
                SiteState::SyncPending { .. } | SiteState::RetainedStop { .. }
            )
        })
    }

    fn own_custody_count(&self) -> usize {
        self.sites
            .iter()
            .filter(|s| {
                matches!(
                    s.state(),
                    SiteState::SyncPending { .. } | SiteState::RetainedStop { .. }
                )
            })
            .count()
            + usize::from(self.stop_retained)
    }

    fn other_custody_held(&self) -> bool {
        GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst) > self.own_custody_count()
    }

    /// Mark the stop retained after a resume shortfall, entering
    /// process-wide custody exactly once until settled.
    fn set_stop_retained(&mut self) {
        if !self.stop_retained {
            self.stop_retained = true;
            custody_enter();
        }
    }

    /// Retry releasing a retained stop. Clears `stop_retained`
    /// ONLY when every executor acknowledged (an error-free empty
    /// acknowledgement is NOT enough: empty is a shortfall).
    /// Returns true when settled.
    fn settle_retained_stop(&mut self, stop: &mut dyn StopControl) -> bool {
        if !self.stop_retained {
            return true;
        }
        match stop.resume() {
            Ok(states) if all_acknowledged(&states) => {
                self.stop_retained = false;
                custody_exit();
                true
            }
            _ => false,
        }
    }

    /// Drain S5a's pending table (`drain_pending_promotion_sites`)
    /// and promote what it held, in first-observed order. Signals
    /// are masked across the whole drain (leases and windows
    /// inside it must not be observed by a handler on this thread).
    /// Call only at ordinary quiescent points.
    pub fn drain_pending(&mut self, stop: &mut dyn StopControl) -> Vec<(u64, PromoteOutcome)> {
        self.mask_failed = false;
        let Some(_mask) = SignalMask::block_all() else {
            self.mask_failed = true;
            return Vec::new();
        };
        // S5a's pending table exists only where its AArch64 SIGSYS
        // handler records into it. Off that architecture there is
        // no table to drain (x86 keeps its own patcher path), so
        // the drain is empty by construction.
        #[cfg(target_arch = "aarch64")]
        {
            self.drain_and_promote(
                &mut |buf| reverie_inguest::trap::drain_pending_promotion_sites(buf),
                stop,
            )
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = stop;
            Vec::new()
        }
    }

    /// Drain entry point over an arbitrary FIFO source shaped like
    /// S5a's drain surface. Returns per-site outcomes in drain order.
    pub fn drain_and_promote(
        &mut self,
        source: &mut dyn FnMut(&mut [u64]) -> usize,
        stop: &mut dyn StopControl,
    ) -> Vec<(u64, PromoteOutcome)> {
        // A retained stop or any post-store custody is settled
        // BEFORE draining new candidates: while executors may
        // still be stopped (or a held page is unsynced/RWX), no
        // new work starts — its resumes would release executors
        // onto the custody site's page — and the pending table
        // is left untouched for a later drain. In particular, do
        // not settle a retained stop while another custody (this
        // promoter's pending site or another promoter's) exists:
        // that settlement is itself a resume.
        if self.other_custody_held() || self.own_pending_custody() {
            return Vec::new();
        }
        if !self.settle_retained_stop(stop) || self.custody_blocking() {
            return Vec::new();
        }
        // Deferred candidates from an interrupted earlier batch
        // go first, in their original order.
        let mut out = Vec::new();
        while let Some(addr) = self.deferred.pop_front() {
            let outcome = self.promote_one(addr, stop);
            let blocked = outcome == PromoteOutcome::CustodyPending
                && !self.sites.iter().any(|s| s.addr() == addr);
            out.push((addr, outcome));
            if blocked {
                self.deferred.push_front(addr);
                return out;
            }
            if outcome == PromoteOutcome::CustodyPending {
                return out;
            }
        }
        let mut buf = [0u64; 64];
        let n = source(&mut buf);
        out.reserve(n);
        for (i, &addr) in buf[..n].iter().enumerate() {
            let outcome = self.promote_one(addr, stop);
            out.push((addr, outcome));
            if outcome == PromoteOutcome::CustodyPending {
                // The CURRENT candidate joins the backlog too
                // when nobody retained it (pre-store shortfall,
                // mask failure): S5a already consumed it from the
                // source, so this promoter is its only owner.
                if !self.sites.iter().any(|s| s.addr() == addr)
                    && !self.retained_refusals.contains(&addr)
                {
                    self.deferred.push_back(addr);
                }
                // The rest of this batch was already consumed
                // from the source (S5a's cursor advanced), so the
                // promoter — not the caller — retains it: backlog
                // every remaining candidate for the next drain
                // instead of dropping it on the floor. Their
                // outcomes this round are CustodyPending (blocked,
                // not attempted).
                for &rest in &buf[i + 1..n] {
                    self.deferred.push_back(rest);
                    out.push((rest, PromoteOutcome::CustodyPending));
                }
                break;
            }
        }
        out
    }

    /// Complete every custody-pending site (SyncPending /
    /// RetainedStop) through the patcher's complete_sync, in
    /// retention order. Settled flips report Flipped; sites that
    /// settle back to the original word (rollback completions)
    /// report Refused and are dropped from custody.
    pub fn complete_pending(&mut self, stop: &mut dyn StopControl) -> Vec<(u64, PromoteOutcome)> {
        self.mask_failed = false;
        let Some(_mask) = SignalMask::block_all() else {
            self.mask_failed = true;
            return Vec::new();
        };
        // Another promoter's custody blocks even completions here:
        // every completion path resumes executors. This promoter's
        // own pending sites are the work to complete, so they do
        // not trigger this gate. Check it before settling a
        // separately retained stop for the same reason.
        if self.other_custody_held() {
            return Vec::new();
        }
        let mut out = Vec::new();
        if !self.own_pending_custody() {
            // With no post-store site anywhere, a separately
            // retained stop can be settled safely on its own.
            let _ = self.settle_retained_stop(stop);
            return out;
        }
        let mut settled_unpatched: Vec<u64> = Vec::new();
        let mut all_settled = true;
        for site in &mut self.sites {
            if !matches!(
                site.state(),
                SiteState::SyncPending { .. } | SiteState::RetainedStop { .. }
            ) {
                continue;
            }
            let outcome = match self.patcher.complete_sync(site, stop) {
                Ok(()) => match site.state() {
                    SiteState::Flipped => PromoteOutcome::Flipped,
                    SiteState::Unpatched => PromoteOutcome::Refused,
                    _ => PromoteOutcome::CustodyPending,
                },
                Err(ref e) => classify(e, site.state()).0,
            };
            if !matches!(
                site.state(),
                SiteState::SyncPending { .. } | SiteState::RetainedStop { .. }
            ) {
                custody_exit();
            }
            if site.state() == SiteState::Unpatched {
                settled_unpatched.push(site.addr());
            }
            let settled = outcome != PromoteOutcome::CustodyPending;
            out.push((site.addr(), outcome));
            if !settled {
                all_settled = false;
                // Stop at the first unsettled custody: completing
                // a LATER site would resume executors onto this
                // site's still-unsynced, possibly RWX page.
                break;
            }
        }
        // Sites settled back to the original word leave custody:
        // drop them and release their island denylist ranges so
        // neither custody nor range slots leak for good.
        if !settled_unpatched.is_empty() {
            self.sites
                .retain(|s| !settled_unpatched.contains(&s.addr()));
            self.island_ranges.retain(|(addr, lo, hi)| {
                if settled_unpatched.contains(addr) {
                    #[cfg(target_arch = "aarch64")]
                    reverie_inguest::trap::unregister_pending_promotion_island(*lo, *hi);
                    let _ = (lo, hi);
                    false
                } else {
                    true
                }
            });
        }
        if all_settled && !self.other_custody_held() && !self.own_pending_custody() {
            // A separately retained stop can be settled only once
            // every site completed above has actually settled.
            let _ = self.settle_retained_stop(stop);
        }
        out
    }

    /// Promote one drained candidate. Candidates already held or
    /// already refused are refused again without re-flipping.
    pub fn promote_one(&mut self, addr: u64, stop: &mut dyn StopControl) -> PromoteOutcome {
        self.mask_failed = false;
        let Some(_mask) = SignalMask::block_all() else {
            self.mask_failed = true;
            return PromoteOutcome::CustodyPending;
        };
        if self.other_custody_held() || self.own_pending_custody() {
            // Blocked by another site's custody: do not settle a
            // retained stop either, because that settlement itself
            // resumes executors. The candidate is NOT consumed or
            // retained; the caller still owns it and may retry
            // after the custody settles. CustodyPending here
            // describes the promoter's state, not this candidate's.
            return PromoteOutcome::CustodyPending;
        }
        if !self.settle_retained_stop(stop) || self.custody_blocking() {
            return PromoteOutcome::CustodyPending;
        }
        if self.sites.iter().any(|s| s.addr() == addr) || self.retained_refusals.contains(&addr) {
            return PromoteOutcome::Refused;
        }
        let outcome = self.try_promote(addr, stop);
        if outcome == PromoteOutcome::Refused {
            self.retained_refusals.push(addr);
        }
        outcome
    }

    /// Release a lease this promoter acquired after a pre-flip
    /// refusal. A resume shortfall retains the stop for
    /// complete_pending to retry: executors may still be stopped.
    fn resume_or_retain(&mut self, stop: &mut dyn StopControl) -> PromoteOutcome {
        match stop.resume() {
            Ok(states) if all_acknowledged(&states) => PromoteOutcome::Refused,
            _ => {
                self.set_stop_retained();
                PromoteOutcome::CustodyPending
            }
        }
    }

    fn try_promote(&mut self, addr: u64, stop: &mut dyn StopControl) -> PromoteOutcome {
        // Acquire BEFORE qualifying or reading anything the flip
        // will trust: a mapping change between qualification and
        // the store is otherwise a live TOCTOU (stale protections
        // restored, or a deref of an unmapped site). Qualification
        // and the word read repeat INSIDE every attempt, each under
        // its own lease: the proc-mem retry re-acquires first, so
        // nothing read under a released lease is ever trusted.
        if stop.acquire().is_err() {
            return PromoteOutcome::Refused;
        }
        // Store attempts in settled order: mprotect window first;
        // /proc/self/mem only under explicit selector permission
        // and only when the window itself was refused. Each
        // attempt reserves a fresh island (a refused attempt's
        // island was retained by its dropped Site unpublished and
        // is unmapped with it; its denylist range is released).
        let proc_mem_permitted = self.store_fallback == StoreFallback::AllowProcMem;
        for attempt in 0..2 {
            let facts = match qualify_mapping(addr, self.generation) {
                Ok(f) => f,
                Err(_) => return self.resume_or_retain(stop),
            };
            if !admit(addr, &facts) {
                return self.resume_or_retain(stop);
            }
            let original = unsafe { (addr as *const u32).read_volatile() };
            let mut island = match Island::reserve(2) {
                Ok(i) => i,
                Err(_) => return self.resume_or_retain(stop),
            };
            let words = match svc_island_words(original, addr, island.entry_addr()) {
                Some(w) => w,
                None => return self.resume_or_retain(stop),
            };
            if island.fill(&words).is_err() {
                return self.resume_or_retain(stop);
            }
            // Register the island range only now that the site is
            // admitted and the flip is next: refusals above burn
            // no lifetime range slot. Released again below on any
            // outcome that does not retain the site.
            #[cfg(target_arch = "aarch64")]
            let island_range = (
                island.entry_addr(),
                island.entry_addr() + island.mapped_len() as u64,
            );
            #[cfg(not(target_arch = "aarch64"))]
            let island_range = (0, 0);
            #[cfg(not(target_arch = "aarch64"))]
            let _ = island_range;
            #[cfg(target_arch = "aarch64")]
            if !reverie_inguest::trap::register_pending_promotion_island(
                island_range.0,
                island_range.1,
            ) {
                return self.resume_or_retain(stop);
            }
            let store: Box<dyn SiteStore> = if attempt == 1 {
                Box::new(ProcMemStore::new(addr))
            } else {
                Box::new(MprotectStore::new(addr, facts))
            };
            let mut site = match unsafe { Site::from_rx(addr, original, facts, store) } {
                Ok(s) => s,
                Err(_) => {
                    #[cfg(target_arch = "aarch64")]
                    reverie_inguest::trap::unregister_pending_promotion_island(
                        island_range.0,
                        island_range.1,
                    );
                    return self.resume_or_retain(stop);
                }
            };
            match self.patcher.flip_preacquired(
                &mut site,
                FlipRequest {
                    island: Some(island),
                    strategy: StrategyPreference::BranchOnly,
                    fallback: FallbackPermission::RefuseTrap,
                    trap_route: None,
                    mapping_facts: Some(facts),
                },
                stop,
            ) {
                Ok(_) => {
                    self.island_ranges
                        .push((addr, island_range.0, island_range.1));
                    self.sites.push(site);
                    return PromoteOutcome::Flipped;
                }
                Err(e) => {
                    // Window refusal is the ONLY fallback point and
                    // only under explicit selector permission. The
                    // lease was already released by flip_preacquired
                    // on this pre-store path, so re-acquire — and
                    // the loop re-qualifies and re-reads under the
                    // new lease before trusting anything.
                    if attempt == 0 && proc_mem_permitted && is_window_refusal(&e) {
                        #[cfg(target_arch = "aarch64")]
                        reverie_inguest::trap::unregister_pending_promotion_island(
                            island_range.0,
                            island_range.1,
                        );
                        if stop.acquire().is_err() {
                            return PromoteOutcome::Refused;
                        }
                        continue;
                    }
                    let (outcome, retain) = classify(&e, site.state());
                    if !retain {
                        #[cfg(target_arch = "aarch64")]
                        reverie_inguest::trap::unregister_pending_promotion_island(
                            island_range.0,
                            island_range.1,
                        );
                    }
                    if retain {
                        custody_enter();
                        self.island_ranges
                            .push((addr, island_range.0, island_range.1));
                        self.sites.push(site);
                    }
                    if outcome == PromoteOutcome::CustodyPending && !retain {
                        // Pre-store resume shortfall: no site custody,
                        // the STOP is retained for settlement.
                        self.set_stop_retained();
                    }
                    return outcome;
                }
            }
        }
        PromoteOutcome::Refused
    }
}

impl Drop for LazyPromoter {
    fn drop(&mut self) {
        // Unsettled custody is LEAKED, never balanced away: while
        // a site is SyncPending/RetainedStop (or a stop is
        // retained) executors may still be stopped on an unsynced,
        // possibly RWX page whose restore was only best-effort.
        // Decrementing GLOBAL_CUSTODY here would reopen the gate
        // and let another promoter resume onto that page. Leaking
        // the count fails closed for the process lifetime, which
        // is the honest outcome for abandoning custody.
        // Production promoters are process-lifetime; tests settle
        // custody (or exit the child process) before dropping.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use liteinst_aarch64_patch::mapping::Provenance;
    use liteinst_aarch64_patch::site::ResumeState;

    fn facts(page_base: u64, provenance: Provenance) -> MappingFacts {
        let page = liteinst_aarch64_patch::page_size().unwrap();
        MappingFacts {
            page_span: (page_base & !(page - 1), page),
            orig_prot: libc::PROT_READ | libc::PROT_EXEC,
            provenance,
            generation: 1,
            bti: false,
        }
    }

    fn rx_page_with(word: u32) -> (*mut u8, usize) {
        let page = liteinst_aarch64_patch::page_size().unwrap() as usize;
        // SAFETY: fresh anonymous page, written then made R-X.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        unsafe { (p as *mut u32).write_volatile(word) };
        assert_eq!(
            unsafe { libc::mprotect(p, page, libc::PROT_READ | libc::PROT_EXEC) },
            0
        );
        (p as *mut u8, page)
    }

    #[cfg(target_arch = "aarch64")]
    type NearIslandPages = (
        Island,
        (*mut u8, usize),
        (*mut u8, usize),
        Vec<(*mut u8, usize)>,
    );

    #[cfg(target_arch = "aarch64")]
    fn rx_pages_near_island(word: u32) -> NearIslandPages {
        // B-range placement helper: map a
        // ten-page run directly below a dummy island (which holds
        // the highest gap) — eight PROT_NONE slot pages under two
        // RX site pages. The caller unmaps one GROUP of four
        // slots immediately before each promote_one; the
        // promoter's Island::reserve (two top-down first-fit
        // mmaps, RW then RX) then lands in that freed group in
        // the common case (four pages, so an intervening heap
        // mmap stealing the topmost page cannot starve the RX
        // alias), a few pages from the sites. This is a strong
        // bias, not a guarantee: some attempts still land far,
        // which the custody test's bounded retry absorbs.
        // Without the reserved
        // slots a fresh reserve routinely lands >128 MiB away on
        // hosts with large per-thread malloc arenas. No skip:
        // every candidate run either maps exactly or the scan
        // panics. Slots are returned nearest-pair first.
        let dummy = Island::reserve(2).unwrap();
        let base = dummy.entry_addr();
        let page = liteinst_aarch64_patch::page_size().unwrap() as usize;
        let run = 10 * page as u64;
        let mut candidates: Vec<u64> = Vec::new();
        if let Some(below) = base.checked_sub(run) {
            candidates.push(below);
        }
        for k in 1..=112u64 {
            if let Some(below) = base.checked_sub(run + k * 0x10_0000) {
                candidates.push(below);
            }
        }
        for k in 0..=112u64 {
            candidates.push(base + page as u64 + k * 0x10_0000);
        }
        let map_exact = |addr: u64| {
            // SAFETY: MAP_FIXED_NOREPLACE either maps exactly at
            // addr or fails without replacing anything.
            let p = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    page,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED_NOREPLACE | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED || p as u64 != addr {
                if p != libc::MAP_FAILED {
                    unsafe { libc::munmap(p, page) };
                }
                None
            } else {
                Some(p as *mut u8)
            }
        };
        for start in candidates {
            let mut pages: Vec<*mut u8> = Vec::new();
            for i in 0..10u64 {
                match map_exact(start + i * page as u64) {
                    Some(pg) => pages.push(pg),
                    None => break,
                }
            }
            if pages.len() < 10 {
                for pg in pages {
                    unsafe { libc::munmap(pg as *mut libc::c_void, page) };
                }
                continue;
            }
            // Layout low->high: slot group 2 (4), slot group 1
            // (4), site A, site B. Sites get the word and RX;
            // slots go PROT_NONE (VMA held, nothing executable).
            let (pa, pb) = (pages[8], pages[9]);
            unsafe {
                (pa as *mut u32).write_volatile(word);
                (pb as *mut u32).write_volatile(word);
                for site in [pa, pb] {
                    assert_eq!(
                        libc::mprotect(
                            site as *mut libc::c_void,
                            page,
                            libc::PROT_READ | libc::PROT_EXEC
                        ),
                        0
                    );
                }
                for slot in &pages[..8] {
                    assert_eq!(
                        libc::mprotect(*slot as *mut libc::c_void, page, libc::PROT_NONE),
                        0
                    );
                }
            }
            let slots = vec![
                (pages[4], page),
                (pages[5], page),
                (pages[6], page),
                (pages[7], page),
                (pages[0], page),
                (pages[1], page),
                (pages[2], page),
                (pages[3], page),
            ];
            return (dummy, (pa, page), (pb, page), slots);
        }
        panic!("no exact ten-page placement near dummy island");
    }

    fn perms_at(addr: u64) -> String {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        for line in maps.lines() {
            let (range, rest) = line.split_once(' ').unwrap();
            let (lo, hi) = range.split_once('-').unwrap();
            let lo = u64::from_str_radix(lo, 16).unwrap();
            let hi = u64::from_str_radix(hi, 16).unwrap();
            if addr >= lo && addr < hi {
                return rest.split_whitespace().next().unwrap().to_string();
            }
        }
        panic!("no mapping contains {addr:#x}");
    }

    struct RefusingStop;
    // SAFETY: refuses acquisition, so no executor is ever stopped or
    // resumed by this control; the patcher must refuse before any store.
    unsafe impl StopControl for RefusingStop {
        fn acquire(&mut self) -> Result<(), PatchError> {
            Err(PatchError::Unsupported("test stop refuses"))
        }
        fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn admit_accepts_aligned_windowable_contained() {
        assert!(admit(0x4010, &facts(0x4000, Provenance::PrivateFile)));
        assert!(admit(0x4000, &facts(0x4000, Provenance::PrivateAnon)));
    }

    #[test]
    fn admit_refuses_misaligned() {
        assert!(!admit(0x4001, &facts(0x4000, Provenance::PrivateAnon)));
        assert!(!admit(0x4002, &facts(0x4000, Provenance::PrivateAnon)));
    }

    #[test]
    fn admit_refuses_non_windowable() {
        assert!(!admit(0x4000, &facts(0x4000, Provenance::Shared)));
        assert!(!admit(0x4000, &facts(0x4000, Provenance::Unknown)));
    }

    #[test]
    fn admit_refuses_outside_span() {
        // Span is [page, 2*page) at ANY runtime page size: just
        // below and just at the end are both outside.
        let page = liteinst_aarch64_patch::page_size().unwrap();
        let f = facts(page, Provenance::PrivateAnon);
        assert!(!admit(page - 4, &f));
        assert!(!admit(2 * page, &f));
        assert!(admit(page, &f));
    }

    #[test]
    fn classify_separates_pre_store_from_custody() {
        assert_eq!(
            classify(&PatchError::CacheOpsUnavailable, SiteState::Unpatched),
            (PromoteOutcome::Refused, false)
        );
        // Post-store errors are classified by state alone: with a
        // pending state (SyncPending OR RetainedStop — the state
        // check is the only post-store discriminator left) they
        // are custody. The Unpatched pairing is unreachable (the
        // patcher sets the pending state before storing) and is
        // rejected by classify's debug_assert, so it is not
        // called here.
        assert_eq!(
            classify(
                &PatchError::SyncFailed {
                    source: Box::new(PatchError::CacheOpsUnavailable)
                },
                SiteState::SyncPending {
                    pending: liteinst_aarch64_patch::site::PendingWord::Patch(0)
                }
            ),
            (PromoteOutcome::CustodyPending, true)
        );
        // RetainedStop pins: a state check narrowed to
        // SyncPending only would misclassify every one of these
        // as a plain refusal and let completion resume onto an
        // unsynced page.
        for err in [
            PatchError::SyncFailed {
                source: Box::new(PatchError::CacheOpsUnavailable),
            },
            PatchError::RestoreFailed {
                source: Box::new(PatchError::CacheOpsUnavailable),
            },
            PatchError::ResumeIncomplete,
        ] {
            assert_eq!(
                classify(
                    &err,
                    SiteState::RetainedStop {
                        pending: liteinst_aarch64_patch::site::PendingWord::Patch(0)
                    }
                ),
                (PromoteOutcome::CustodyPending, true),
                "{err:?} with RetainedStop must stay custody"
            );
        }
        // Pre-store resume shortfall: custody of the STOP, no site.
        assert_eq!(
            classify(&PatchError::ResumeIncomplete, SiteState::Unpatched),
            (PromoteOutcome::CustodyPending, false)
        );
        assert_eq!(
            classify(
                &PatchError::CleanupFailed {
                    expected: 1,
                    found: 2
                },
                SiteState::Unpatched
            ),
            (PromoteOutcome::CustodyPending, false)
        );
        assert_eq!(
            classify(
                &PatchError::StoreFailed {
                    source: Box::new(PatchError::CacheOpsUnavailable)
                },
                SiteState::SyncPending {
                    pending: liteinst_aarch64_patch::site::PendingWord::Patch(0)
                }
            ),
            (PromoteOutcome::CustodyPending, true)
        );
        assert_eq!(
            classify(
                &PatchError::NotSvc { word: 0 },
                SiteState::SyncPending {
                    pending: liteinst_aarch64_patch::site::PendingWord::Patch(0)
                }
            ),
            (PromoteOutcome::CustodyPending, true)
        );
    }

    #[test]
    fn mprotect_store_windows_restores_exact_protection() {
        // Serialize mmap placement with the promoter flip tests:
        // parallel page/island mapping here can push a promoter's
        // island outside B range of its sites in another test.
        let _serial = promoter_test_serial();
        let (p, page) = rx_page_with(0x1111_1111);
        assert_eq!(perms_at(p as u64), "r-xp");
        let mut store = MprotectStore::new(p as u64, facts(p as u64, Provenance::PrivateAnon));
        // Guard: no store before the window is open.
        assert!(matches!(
            store.store_word(0x2222_2222),
            Err(PatchError::MappingRefused(_))
        ));
        store.begin_write().unwrap();
        assert_eq!(perms_at(p as u64), "rwxp");
        store.store_word(0x2222_2222).unwrap();
        store.finish_write().unwrap();
        // Restored exactly: same perms as before the window. Kills
        // "skip the restore" and "restore RWX" mutations.
        assert_eq!(perms_at(p as u64), "r-xp");
        assert_eq!(store.read_word(), 0x2222_2222);
        // Finish closed the window: further stores are refused again.
        assert!(matches!(
            store.store_word(0x3333_3333),
            Err(PatchError::MappingRefused(_))
        ));
        store.finish_write().unwrap();
        unsafe { libc::munmap(p as *mut libc::c_void, page) };
    }

    #[test]
    fn proc_mem_store_changes_word_in_rx_text() {
        // Serialize mmap placement with the promoter flip tests:
        // parallel page/island mapping here can push a promoter's
        // island outside B range of its sites in another test.
        let _serial = promoter_test_serial();
        let (p, page) = rx_page_with(0x3333_3333);
        let mut store = ProcMemStore::new(p as u64);
        assert!(matches!(
            store.store_word(0x4444_4444),
            Err(PatchError::MappingRefused(_))
        ));
        store.begin_write().unwrap();
        store.store_word(0x4444_4444).unwrap();
        store.finish_write().unwrap();
        assert_eq!(store.read_word(), 0x4444_4444);
        // No window existed: protections never moved.
        assert_eq!(perms_at(p as u64), "r-xp");
        assert!(matches!(
            store.store_word(0x5555_5555),
            Err(PatchError::MappingRefused(_))
        ));
        unsafe { libc::munmap(p as *mut libc::c_void, page) };
    }

    #[test]
    fn drain_promotes_in_order_and_retains_refusals() {
        let _serial = promoter_test_serial();
        // Mapped SVC words, so admission runs real qualification.
        // What refuses here: RefusingStop's acquire, on BOTH
        // architectures, before any island work. The patcher's own unattested
        // refusal is covered in the patch crate and natively.
        let (p, page) = rx_page_with(0xd400_0001);
        let a = p as u64;
        let b = p as u64 + 4;
        let mut promoter = LazyPromoter::unattested(1);
        let pending = [a, b, a];
        let mut cursor = 0usize;
        let mut stop = RefusingStop;
        let out = promoter.drain_and_promote(
            &mut |buf| {
                let n = (pending.len() - cursor).min(buf.len());
                buf[..n].copy_from_slice(&pending[cursor..cursor + n]);
                cursor += n;
                n
            },
            &mut stop,
        );
        assert_eq!(
            out,
            [
                (a, PromoteOutcome::Refused),
                (b, PromoteOutcome::Refused),
                (a, PromoteOutcome::Refused),
            ]
        );
        assert_eq!(promoter.retained_refusals(), [a, b]);
        assert_eq!(promoter.held_sites(), 0);
        unsafe { libc::munmap(p as *mut libc::c_void, page) };
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn drain_pending_consumes_s5a_table() {
        let _serial = promoter_test_serial();
        let mut sink = [0u64; 64];
        let _ = reverie_inguest::trap::drain_pending_promotion_sites(&mut sink);
        // Mapped SVC candidates, so admission reaches the patcher's
        // own refusal (unattested) instead of dying at qualification.
        let (p, page) = rx_page_with(0xd400_0001);
        reverie_inguest::trap::record_pending_promotion_site(p as u64);
        reverie_inguest::trap::record_pending_promotion_site(p as u64 + 4);
        let mut promoter = LazyPromoter::unattested(1);
        let mut stop = RefusingStop;
        let out = promoter.drain_pending(&mut stop);
        assert_eq!(
            out,
            [
                (p as u64, PromoteOutcome::Refused),
                (p as u64 + 4, PromoteOutcome::Refused),
            ]
        );
        assert!(promoter.drain_pending(&mut stop).is_empty());
        unsafe { libc::munmap(p as *mut libc::c_void, page) };
    }

    static PROMOTER_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Serial guard that also restores the process-wide custody
    /// counter to its entry baseline on drop. Production Drop
    /// deliberately LEAKS unsettled custody (fail closed), so
    /// without this one panicking custody test would poison
    /// GLOBAL_CUSTODY for every later test in the process and
    /// bury the real failure under cascades. On unwind it only
    /// restores (the original panic propagates); on clean exit
    /// any imbalance is itself a test failure, in bounded time
    /// (one store, never a decrement loop that an underflowed
    /// counter would spin ~2^64 times under the serial lock).
    struct SerialCustodyGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        baseline: usize,
    }

    impl Drop for SerialCustodyGuard {
        fn drop(&mut self) {
            let now = GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst);
            GLOBAL_CUSTODY.store(self.baseline, std::sync::atomic::Ordering::SeqCst);
            if !std::thread::panicking() {
                assert_eq!(now, self.baseline, "test leaked custody");
            }
        }
    }

    fn promoter_test_serial() -> SerialCustodyGuard {
        let guard = PROMOTER_TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        SerialCustodyGuard {
            baseline: GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
            _guard: guard,
        }
    }

    /// Proof that a re-exec child actually ran its one selected
    /// test: a wrong `--exact` path makes libtest print
    /// "running 0 tests" and exit 0, which a status-only parent
    /// assert reads as success (the island-registry bug class).
    fn assert_child_ran(out: &std::process::Output) {
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("running 1 test"),
            "re-exec child ran no test (wrong --exact path?): {out:?}"
        );
    }

    #[cfg(target_arch = "aarch64")]
    static SYNC_FAIL_ONCE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    #[cfg(target_arch = "aarch64")]
    unsafe fn sync_fail_once(rw: *mut u8, rx: *mut u8, len: usize) -> Result<(), PatchError> {
        if SYNC_FAIL_ONCE.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(PatchError::Unsupported("injected sync failure"));
        }
        // SAFETY: forwarded to the real dual-alias sync.
        unsafe { liteinst_aarch64_patch::cache::sync_icache(rw, rx, len) }
    }

    #[cfg(target_arch = "aarch64")]
    struct SingleThreadStop {
        acquires: u32,
        resumes: u32,
        resume_failures: u32,
    }
    // SAFETY (test): the test process runs this promotion on its only
    // relevant thread while no other thread executes the site, so the
    // stopped-executor set is trivially the caller itself, already
    // stopped at this call. Resume acknowledges that one executor.
    #[cfg(target_arch = "aarch64")]
    unsafe impl StopControl for SingleThreadStop {
        fn acquire(&mut self) -> Result<(), PatchError> {
            self.acquires += 1;
            Ok(())
        }
        fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
            self.resumes += 1;
            if self.resume_failures > 0 {
                self.resume_failures -= 1;
                return Ok(vec![ResumeState::Unknown]);
            }
            Ok(vec![ResumeState::Released])
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn call_getpid_site(site: u64) -> i64 {
        let ret: i64;
        // SAFETY: site holds `svc #0; ret` (or its flipped branch to
        // an island doing the same); x8 carries SYS_getpid in.
        unsafe {
            core::arch::asm!(
                "str x30, [sp, #-16]!",
                "mov x8, #172",
                "blr {site}",
                "ldr x30, [sp], #16",
                site = in(reg) site,
                lateout("x0") ret,
                out("x8") _,
                options()
            );
        }
        ret
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn promote_one_flips_svc_and_call_result_is_unchanged() {
        let _serial = promoter_test_serial();
        // Page: [svc #0, ret]. The site is the SVC.
        let page = liteinst_aarch64_patch::page_size().unwrap() as usize;
        // SAFETY: fresh anonymous page, filled then made R-X.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        unsafe {
            (p as *mut u32).write_volatile(0xd400_0001);
            (p as *mut u32).add(1).write_volatile(0xd65f_03c0);
            assert_eq!(
                libc::mprotect(p, page, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
        }
        let site = p as u64;
        let before = unsafe { call_getpid_site(site) };
        assert_eq!(before, std::process::id() as i64);
        assert_eq!(perms_at(site), "r-xp");

        let mut promoter = LazyPromoter::attested(1).unwrap();
        let mut stop = SingleThreadStop {
            acquires: 0,
            resumes: 0,
            resume_failures: 0,
        };
        assert_eq!(
            promoter.promote_one(site, &mut stop),
            PromoteOutcome::Flipped
        );
        assert_eq!(promoter.held_sites(), 1);
        // A held site is never promoted twice.
        assert_eq!(
            promoter.promote_one(site, &mut stop),
            PromoteOutcome::Refused
        );
        assert_eq!(promoter.held_sites(), 1);
        let word = unsafe { (site as *const u32).read_volatile() };
        assert!(
            matches!(
                liteinst_aarch64::decode(word),
                liteinst_aarch64::Insn::Branch { .. }
            ),
            "flipped word {word:#010x} is not B"
        );
        assert_eq!(perms_at(site), "r-xp");
        let after = unsafe { call_getpid_site(site) };
        assert_eq!(after, before);
        unsafe { libc::munmap(p, page) };
        core::mem::forget(promoter);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn resume_shortfall_is_custody_then_completes() {
        let _serial = promoter_test_serial();
        let (p, page) = rx_page_with(0xd400_0001);
        let site = p as u64;
        let mut promoter = LazyPromoter::attested(1).unwrap();
        let mut stop = SingleThreadStop {
            acquires: 0,
            resumes: 0,
            resume_failures: 1,
        };
        assert_eq!(
            promoter.promote_one(site, &mut stop),
            PromoteOutcome::CustodyPending
        );
        assert_eq!(promoter.held_sites(), 1);
        let done = promoter.complete_pending(&mut stop);
        assert_eq!(done, [(site, PromoteOutcome::Flipped)]);
        let word = unsafe { (site as *const u32).read_volatile() };
        assert!(matches!(
            liteinst_aarch64::decode(word),
            liteinst_aarch64::Insn::Branch { .. }
        ));
        unsafe { libc::munmap(p as *mut libc::c_void, page) };
        core::mem::forget(promoter);
    }
    #[cfg(target_arch = "aarch64")]
    struct ActingStop {
        page: u64,
        len: usize,
        munmap: bool,
        acquires: u32,
        resumes: u32,
    }
    // SAFETY (test): single-threaded harness stop that plays the
    // racing guest INSIDE acquire: it changes the site mapping
    // after the promoter believes executors are stopped. If
    // qualification had happened before acquire (the old order),
    // the flip would trust stale facts; with acquire-first it
    // must refuse cleanly. Executions never enter the site here.
    #[cfg(target_arch = "aarch64")]
    unsafe impl StopControl for ActingStop {
        fn acquire(&mut self) -> Result<(), PatchError> {
            self.acquires += 1;
            if self.munmap {
                unsafe { libc::munmap(self.page as *mut libc::c_void, self.len) };
            } else {
                unsafe {
                    libc::mprotect(
                        self.page as *mut libc::c_void,
                        self.len,
                        libc::PROT_READ | libc::PROT_WRITE,
                    )
                };
            }
            Ok(())
        }
        fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
            self.resumes += 1;
            Ok(vec![ResumeState::Released])
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn toctou_guest_change_inside_acquire_refuses() {
        let _serial = promoter_test_serial();
        // mprotect-to-RW inside acquire: qualification under the
        // lease must see non-executable and refuse, leaving the
        // guest's own RW protections untouched (not clobbered by
        // a stale restore).
        let (p, page) = rx_page_with(0xd400_0001);
        let mut promoter = LazyPromoter::attested(1).unwrap();
        let mut stop = ActingStop {
            page: p as u64,
            len: page,
            munmap: false,
            acquires: 0,
            resumes: 0,
        };
        assert_eq!(
            promoter.promote_one(p as u64, &mut stop),
            PromoteOutcome::Refused
        );
        assert_eq!((stop.acquires, stop.resumes), (1, 1));
        assert_eq!(perms_at(p as u64), "rw-p");
        // munmap inside acquire: no mapping contains the site;
        // the promoter must refuse, never deref the unmapped word.
        let (p2, page2) = rx_page_with(0xd400_0001);
        let mut stop2 = ActingStop {
            page: p2 as u64,
            len: page2,
            munmap: true,
            acquires: 0,
            resumes: 0,
        };
        assert_eq!(
            promoter.promote_one(p2 as u64, &mut stop2),
            PromoteOutcome::Refused
        );
        assert_eq!((stop2.acquires, stop2.resumes), (1, 1));
        unsafe { libc::munmap(p as *mut libc::c_void, page) };
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn bti_guard_survives_a_store_cycle() {
        let _serial = promoter_test_serial();
        // Fork WITHOUT exec: the child shares this mapping, so
        // its BLR really targets the BTI page (the previous
        // fork+exec form jumped to an unmapped address and could
        // not distinguish SIGILL from SIGSEGV).
        let page = liteinst_aarch64_patch::page_size().unwrap() as usize;
        const PROT_BTI: libc::c_int = 0x10;
        // SAFETY: fresh anonymous page owned by this test.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        unsafe {
            (p as *mut u32).write_volatile(0xd65f_03c0); // ret, no pad
        }
        if unsafe { libc::mprotect(p, page, libc::PROT_READ | libc::PROT_EXEC | PROT_BTI) } != 0 {
            // No BTI on this host/kernel: nothing to preserve.
            // (On BTI metal this path is not taken; the harness
            // records the same scenario natively.)
            unsafe { libc::munmap(p, page) };
            return;
        }
        fn child_blr_status(p: *mut core::ffi::c_void) -> i32 {
            // SAFETY: fork child performs one BLR then _exit;
            // parent reaps it here.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                unsafe {
                    core::arch::asm!("str x30, [sp, #-16]!", "blr {site}", "ldr x30, [sp], #16", site = in(reg) p as u64, options());
                    libc::_exit(0);
                }
            }
            let mut status: libc::c_int = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            status
        }
        let before = child_blr_status(p);
        assert!(
            libc::WIFSIGNALED(before) && libc::WTERMSIG(before) == libc::SIGILL,
            "before store cycle: expected SIGILL, status={before:#x}"
        );
        let mut facts = facts(p as u64, Provenance::PrivateAnon);
        facts.bti = true;
        let mut store = MprotectStore::new(p as u64, facts);
        store.begin_write().unwrap();
        store.store_word(0xd65f_03c0).unwrap();
        store.finish_write().unwrap();
        let after = child_blr_status(p);
        assert!(
            libc::WIFSIGNALED(after) && libc::WTERMSIG(after) == libc::SIGILL,
            "after store cycle: BTI stripped, status={after:#x}"
        );
        // Counter-arm: the same shape WITHOUT BTI runs cleanly,
        // proving the fault above is the guard, not the mapping.
        let (q, qpage) = rx_page_with(0xd65f_03c0);
        let clean = child_blr_status(q as *mut core::ffi::c_void);
        assert!(
            libc::WIFEXITED(clean) && libc::WEXITSTATUS(clean) == 0,
            "non-BTI counter-arm must run, status={clean:#x}"
        );
        unsafe { libc::munmap(q as *mut libc::c_void, qpage) };
        unsafe { libc::munmap(p, page) };
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stores_run_under_the_real_seccomp_filter() {
        // Child: install the exact-address filter, then drive the
        // stores, qualification and the signal mask. Any syscall
        // that bypasses the trusted gate traps to the handler,
        // which exits 77 via the gate; success exits 0 via the
        // gate with the marker. Parent asserts both.
        const CHILD: &str = "REVERIE_S5B_SECCOMP_CHILD";
        if std::env::var_os(CHILD).is_some() {
            child_under_filter();
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lazy_promote::tests::stores_run_under_the_real_seccomp_filter",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&out);
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("SECCOMP_OK"),
            "{out:?}"
        );
    }

    #[cfg(target_os = "linux")]
    fn child_under_filter() -> ! {
        use liteinst_aarch64_patch::gate::gate6;
        fn gate_exit(code: i64) -> ! {
            // SAFETY: exit_group through the (possibly gate) entry.
            unsafe {
                gate6(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]);
            }
            std::process::abort()
        }
        // Any trapped (non-gate) syscall lands here.
        extern "C" fn trapped(
            _sig: libc::c_int,
            _info: *mut libc::siginfo_t,
            _ctx: *mut libc::c_void,
        ) {
            gate_exit(77);
        }
        let (p, _page) = rx_page_with(0x1111_1111);
        let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
        sa.sa_sigaction = trapped as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO;
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGSYS, &sa, core::ptr::null_mut()) },
            0
        );
        install_inguest_gate().unwrap();
        let filter = reverie_inguest::seccomp::SeccompFilter::for_trusted_gates(
            reverie_inguest::trap::trusted_gate(),
            reverie_inguest::trap::guest_syscall_gate(),
        )
        .unwrap();
        let mut filter = filter;
        // SAFETY: ordinary startup context in a fresh child.
        unsafe { filter.install() }.unwrap();
        // From here, ONLY gate syscalls may run.
        let mut mstore = MprotectStore::new(p as u64, facts(p as u64, Provenance::PrivateAnon));
        if mstore.begin_write().is_err()
            || mstore.store_word(0x2222_2222).is_err()
            || mstore.finish_write().is_err()
        {
            gate_exit(78);
        }
        let mut pstore = ProcMemStore::new(p as u64);
        if pstore.begin_write().is_err()
            || pstore.store_word(0x3333_3333).is_err()
            || pstore.finish_write().is_err()
        {
            gate_exit(79);
        }
        if liteinst_aarch64_patch::mapping::qualify_mapping(p as u64, 1).is_err() {
            gate_exit(80);
        }
        {
            let _mask = SignalMask::block_all();
            if _mask.is_none() {
                gate_exit(81);
            }
        }
        if mstore.read_word() != 0x3333_3333 {
            gate_exit(82);
        }
        let marker = b"SECCOMP_OK\n";
        // SAFETY: stdout write of the marker through the gate.
        unsafe {
            gate6(
                libc::SYS_write,
                [1, marker.as_ptr() as u64, marker.len() as u64, 0, 0, 0],
            );
        }
        gate_exit(0);
    }
    #[test]
    fn empty_resume_is_a_shortfall() {
        assert!(!all_acknowledged(&[]));
        assert!(all_acknowledged(&[ResumeState::Released]));
        assert!(!all_acknowledged(&[ResumeState::Unknown]));
    }

    #[test]
    fn admit_refuses_runtime_gate_text() {
        let ip = reverie_inguest::trap::trusted_gate().syscall_ip;
        // Facts whose span is the gate's own page: windowable and
        // containing, so only the runtime-text denylist refuses.
        assert!(!admit(ip, &facts(ip, Provenance::PrivateAnon)));
        let guest = reverie_inguest::trap::guest_syscall_gate().syscall_ip;
        assert!(!admit(guest, &facts(guest, Provenance::PrivateAnon)));
    }

    #[cfg(target_os = "linux")]
    struct MaskFailGate;
    // SAFETY: forwards exactly, except rt_sigprocmask which fails.
    #[cfg(target_os = "linux")]
    unsafe impl liteinst_aarch64_patch::gate::GateSyscall for MaskFailGate {
        unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64 {
            if nr == libc::SYS_rt_sigprocmask {
                return -(libc::EPERM as i64);
            }
            // SAFETY: forwarded under the same contract.
            unsafe { reverie_inguest::trap::raw_syscall6(nr, args) }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mask_failure_does_no_work_and_is_reported() {
        // Re-exec child: the gate is process-global, so the
        // failing gate must be installed in a fresh process.
        const CHILD: &str = "REVERIE_S5B_MASKFAIL_CHILD";
        if std::env::var_os(CHILD).is_some() {
            static FAILING: MaskFailGate = MaskFailGate;
            // SAFETY: first gate call in this fresh child.
            unsafe { liteinst_aarch64_patch::gate::install_gate(&FAILING) }.unwrap();
            let mut promoter = LazyPromoter::unattested(1);
            let mut stop = RefusingStop;
            let out = promoter.drain_pending(&mut stop);
            assert!(out.is_empty());
            assert!(promoter.mask_failed());
            // Direct promote_one on mask failure: CustodyPending,
            // and the candidate stays CALLER-owned — not deferred,
            // not retained, not held (the drain path defers; a
            // direct call defers nothing).
            let baseline = GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                promoter.promote_one(0x5000, &mut stop),
                PromoteOutcome::CustodyPending
            );
            assert!(promoter.mask_failed());
            assert_eq!(promoter.held_sites(), 0);
            assert!(promoter.retained_refusals().is_empty());
            assert!(promoter.deferred.is_empty());
            assert!(!promoter.unsettled_custody());
            assert_eq!(
                GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
                baseline
            );
            std::process::exit(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lazy_promote::tests::mask_failure_does_no_work_and_is_reported",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&out);
        assert!(out.status.success(), "{out:?}");
    }
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn custody_site_blocks_all_new_work_until_settled() {
        let _serial = promoter_test_serial();
        // The causal scenario needs two real flips, and a flip is
        // refused before any store when the promoter's fresh
        // island lands outside B range — a placement outcome of
        // the host mmap layout (large per-thread arenas push fresh
        // reserves hundreds of MiB away on some hosts), not of the
        // custody logic under test. The slot-group placement in
        // rx_pages_near_island makes an attempt succeed with high
        // probability; a placement-refused attempt (Refused, word
        // untouched, no custody) is rebuilt from scratch, bounded
        // at 32 attempts and then a hard failure. Every custody
        // assertion below runs in full on the placed attempt.
        for _attempt in 0..32 {
            // Site A: sync fails after the store -> SyncPending with
            // executors still stopped and its page still RWX.
            SYNC_FAIL_ONCE.store(true, std::sync::atomic::Ordering::SeqCst);
            let patcher = Patcher::attested_with_sync(sync_fail_once).unwrap();
            let mut promoter = LazyPromoter::with_patcher(patcher, 1).unwrap();
            let (dummy_island, (pa, page_a), (pb, page_b), slots) =
                rx_pages_near_island(0xd400_0001);
            let mut stop = SingleThreadStop {
                acquires: 0,
                resumes: 0,
                resume_failures: 0,
            };
            // Free the nearest slot group: A's island must land there.
            for (slot, len) in &slots[..4] {
                unsafe { libc::munmap(*slot as *mut libc::c_void, *len) };
            }
            let out_a = promoter.promote_one(pa as u64, &mut stop);
            if out_a == PromoteOutcome::Refused {
                // Placement refusal ONLY: prove nothing was stored
                // (both words original, protections untouched, the
                // lease fully released) before treating this as a
                // retryable placement outcome. Any other refusal
                // shape is a hard failure here, not a retry.
                assert_eq!(unsafe { (pa as *const u32).read_volatile() }, 0xd400_0001);
                assert_eq!(unsafe { (pb as *const u32).read_volatile() }, 0xd400_0001);
                assert_eq!(perms_at(pa as u64), "r-xp");
                assert_eq!(perms_at(pb as u64), "r-xp");
                assert_eq!(stop.acquires, stop.resumes);
                // Nothing was stored and no custody exists, so
                // dropping the promoter is safe. Leak the dummy
                // island so the next attempt's mmap layout differs:
                // rebuilding identical layout would deterministically
                // reproduce the same far island.
                assert!(!promoter.unsettled_custody());
                core::mem::forget(dummy_island);
                drop(promoter);
                unsafe {
                    libc::munmap(pa as *mut libc::c_void, page_a);
                    libc::munmap(pb as *mut libc::c_void, page_b);
                    for (slot, len) in &slots[4..] {
                        libc::munmap(*slot as *mut libc::c_void, *len);
                    }
                }
                continue;
            }
            assert_eq!(out_a, PromoteOutcome::CustodyPending);
            let (acq, res) = (stop.acquires, stop.resumes);
            assert_eq!(perms_at(pa as u64), "rwxp");
            // Site B must not even acquire: any resume of B would
            // release executors onto A's unsynced RWX page.
            assert_eq!(
                promoter.promote_one(pb as u64, &mut stop),
                PromoteOutcome::CustodyPending
            );
            assert_eq!((stop.acquires, stop.resumes), (acq, res));
            // Settle A, then B is free to proceed.
            let done = promoter.complete_pending(&mut stop);
            assert_eq!(done, [(pa as u64, PromoteOutcome::Flipped)]);
            assert_eq!(perms_at(pa as u64), "r-xp");
            // Free the second slot group for B's island.
            for (slot, len) in &slots[4..] {
                unsafe { libc::munmap(*slot as *mut libc::c_void, *len) };
            }
            // Snapshot before B: the stop is cumulative over the
            // whole attempt (A's acquire + complete_sync's
            // acquire/resume leave it at (2,1)), so B's refusal
            // must be judged on equal DELTAS, not raw equality.
            let (acq_b, res_b) = (stop.acquires, stop.resumes);
            let out_b = promoter.promote_one(pb as u64, &mut stop);
            if out_b == PromoteOutcome::Refused {
                // Placement refusal for B only: prove B untouched
                // (word original, protections restored, every
                // acquire resumed) before retrying. A is flipped
                // and settled. Abandon this attempt (the promoter
                // forget leaks A's island range slot, a lifetime
                // slot in a test process) and rebuild.
                assert_eq!(unsafe { (pb as *const u32).read_volatile() }, 0xd400_0001);
                assert_eq!(perms_at(pb as u64), "r-xp");
                assert_eq!(
                    stop.acquires - acq_b,
                    stop.resumes - res_b,
                    "B refusal must release its own lease exactly once"
                );
                assert!(!promoter.unsettled_custody());
                core::mem::forget(dummy_island);
                core::mem::forget(promoter);
                unsafe {
                    libc::munmap(pa as *mut libc::c_void, page_a);
                    libc::munmap(pb as *mut libc::c_void, page_b);
                }
                continue;
            }
            assert_eq!(out_b, PromoteOutcome::Flipped);
            unsafe { libc::munmap(pa as *mut libc::c_void, page_a) };
            unsafe { libc::munmap(pb as *mut libc::c_void, page_b) };
            core::mem::forget(promoter);
            return;
        }
        panic!(
            "custody scenario never completed in 32 attempts (placement or BTI refusal \
             every time; under qemu export QEMU_CPU=cortex-a72)"
        );
    }
    #[test]
    fn deferred_batch_survives_custody_block() {
        let _serial = promoter_test_serial();
        // Causal shape: the source is CONSUMED by the first
        // drain; the first candidate's promotion creates custody
        // (resume shortfall on its pre-store refusal), so BOTH
        // candidates must survive inside the promoter. The
        // second drain's source is genuinely empty — removing
        // deferred retention makes it yield nothing.
        struct ShortfallThenRelease {
            release: std::sync::atomic::AtomicBool,
            acquires: usize,
        }
        // SAFETY (test): scripted stop; no executor exists.
        unsafe impl StopControl for ShortfallThenRelease {
            fn acquire(&mut self) -> Result<(), PatchError> {
                self.acquires += 1;
                Ok(())
            }
            fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
                if self.release.load(std::sync::atomic::Ordering::SeqCst) {
                    Ok(vec![ResumeState::Released])
                } else {
                    Ok(vec![ResumeState::Unknown])
                }
            }
        }
        let baseline = GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst);
        let mut promoter = LazyPromoter::unattested(1);
        let mut stop = ShortfallThenRelease {
            release: std::sync::atomic::AtomicBool::new(false),
            acquires: 0,
        };
        let mut source_calls = 0;
        let first = promoter.drain_and_promote(
            &mut |buf| {
                source_calls += 1;
                buf[..2].copy_from_slice(&[0x5000, 0x6000]);
                2
            },
            &mut stop,
        );
        assert_eq!(
            first,
            [
                (0x5000, PromoteOutcome::CustodyPending),
                (0x6000, PromoteOutcome::CustodyPending),
            ]
        );
        assert!(promoter.retained_refusals().is_empty());
        assert_eq!(promoter.held_sites(), 0);
        // The pre-store shortfall retained the STOP in process-wide
        // custody (mPreStore: deleting set_stop_retained leaves
        // both of these at baseline/false).
        assert_eq!(
            GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
            baseline + 1
        );
        assert!(promoter.unsettled_custody());
        // While the stop still shortfalls, a further drain does no
        // work at all: no acquires, no source call, empty result —
        // and complete_pending's empty return stays distinguishable
        // through unsettled_custody.
        let acquires_before = stop.acquires;
        let blocked = promoter.drain_and_promote(
            &mut |_buf| {
                source_calls += 1;
                0
            },
            &mut stop,
        );
        assert!(blocked.is_empty());
        assert_eq!(stop.acquires, acquires_before);
        assert_eq!(source_calls, 1, "blocked drain must not touch the source");
        assert!(promoter.complete_pending(&mut stop).is_empty());
        assert!(promoter.unsettled_custody());
        // Settle the stop, then drain from a truly empty source:
        // both candidates replay from the deferred backlog and
        // land in retained_refusals.
        stop.release
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let second = promoter.drain_and_promote(
            &mut |_buf| {
                source_calls += 1;
                0
            },
            &mut stop,
        );
        assert_eq!(
            second,
            [
                (0x5000, PromoteOutcome::Refused),
                (0x6000, PromoteOutcome::Refused),
            ]
        );
        assert_eq!(promoter.retained_refusals(), [0x5000, 0x6000]);
        assert_eq!(promoter.held_sites(), 0);
        assert!(!promoter.unsettled_custody());
        assert_eq!(
            GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
            baseline
        );
    }
    #[test]
    fn deferred_replay_requeues_current_candidate_at_front() {
        let _serial = promoter_test_serial();
        // Scripted resume outcomes drive one candidate through
        // TWO unheld CustodyPending results: once from the source
        // batch, once from the deferred replay. The replay must
        // put it back at the FRONT (mDeferFrontDrop: deleting the
        // push_front loses it; push_back reorders it after B).
        struct ScriptedStop {
            script: std::collections::VecDeque<bool>,
        }
        // SAFETY (test): scripted stop; no executor exists.
        unsafe impl StopControl for ScriptedStop {
            fn acquire(&mut self) -> Result<(), PatchError> {
                Ok(())
            }
            fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
                if self.script.pop_front().unwrap_or(true) {
                    Ok(vec![ResumeState::Released])
                } else {
                    Ok(vec![ResumeState::Unknown])
                }
            }
        }
        let mut promoter = LazyPromoter::unattested(1);
        // Resumes in order: A-refusal shortfall, settle, A-replay
        // shortfall, settle, A refusal releases, B refusal releases.
        let mut stop = ScriptedStop {
            script: [false, true, false, true, true, true].into_iter().collect(),
        };
        let first = promoter.drain_and_promote(
            &mut |buf| {
                buf[..2].copy_from_slice(&[0x5000, 0x6000]);
                2
            },
            &mut stop,
        );
        assert_eq!(
            first,
            [
                (0x5000, PromoteOutcome::CustodyPending),
                (0x6000, PromoteOutcome::CustodyPending),
            ]
        );
        // Replay: A shortfalls again and must be re-queued at the
        // front; B is not attempted this round.
        let replay = promoter.drain_and_promote(&mut |_buf| 0, &mut stop);
        assert_eq!(replay, [(0x5000, PromoteOutcome::CustodyPending)]);
        // Final drain yields A then B, in original order.
        let last = promoter.drain_and_promote(&mut |_buf| 0, &mut stop);
        assert_eq!(
            last,
            [
                (0x5000, PromoteOutcome::Refused),
                (0x6000, PromoteOutcome::Refused),
            ]
        );
        assert_eq!(promoter.retained_refusals(), [0x5000, 0x6000]);
        assert!(!promoter.unsettled_custody());
    }
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn flipped_site_island_is_denylisted_in_s5a_table() {
        use reverie_inguest::trap::PendingPromotionRecord;
        // Re-exec child: the pending table retains known sites for
        // the process lifetime, so the NewSite leg needs a fresh
        // process to be deterministic.
        const CHILD: &str = "REVERIE_S5B_DENYLIST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let _serial = promoter_test_serial();
            let (_dummy_island, (pa, _page_a), (pb, _page_b), slots) =
                rx_pages_near_island(0xd400_0001);
            let site = pa as u64;
            let mut promoter = LazyPromoter::attested(1).unwrap();
            let mut stop = SingleThreadStop {
                acquires: 0,
                resumes: 0,
                resume_failures: 0,
            };
            for (slot, len) in &slots[..4] {
                unsafe { libc::munmap(*slot as *mut libc::c_void, *len) };
            }
            assert_eq!(
                promoter.promote_one(site, &mut stop),
                PromoteOutcome::Flipped
            );
            // The flip registered its island range (M11reg: without
            // registration the island SVC would be a fresh candidate).
            let &(_, lo, hi) = promoter.island_ranges.first().unwrap();
            assert!(lo < hi);
            assert_eq!(
                reverie_inguest::trap::record_pending_promotion_site(lo),
                PendingPromotionRecord::AlreadyKnown
            );
            assert_eq!(
                reverie_inguest::trap::record_pending_promotion_site(lo + 4),
                PendingPromotionRecord::AlreadyKnown
            );
            // An address outside the island is a real new candidate.
            assert_eq!(
                reverie_inguest::trap::record_pending_promotion_site(pb as u64),
                PendingPromotionRecord::NewSite
            );
            std::process::exit(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lazy_promote::tests::flipped_site_island_is_denylisted_in_s5a_table",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&out);
        assert!(out.status.success(), "{out:?}");
    }
    #[test]
    fn settled_unpatched_site_leaves_custody_and_ranges() {
        use liteinst_aarch64_patch::flip::FlipRequest;
        use liteinst_aarch64_patch::site::{StrategyPreference, TrapRoute};
        let _serial = promoter_test_serial();
        struct FailStore {
            word: *mut u32,
            fail: std::sync::Arc<std::sync::atomic::AtomicBool>,
        }
        // SAFETY (test): the word outlives the site in this test.
        unsafe impl Send for FailStore {}
        // SAFETY (test): models a store that can be told to fail;
        // writes name the same test word throughout.
        unsafe impl liteinst_aarch64_patch::store::SiteStore for FailStore {
            fn read_word(&self) -> u32 {
                unsafe { self.word.read_volatile() }
            }
            fn write_addr(&self) -> u64 {
                self.word as u64
            }
            fn begin_write(&mut self) -> Result<(), PatchError> {
                Ok(())
            }
            fn store_word(&mut self, word: u32) -> Result<(), PatchError> {
                if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(PatchError::Os {
                        op: "test store",
                        errno: libc::EIO,
                    });
                }
                unsafe { self.word.write_volatile(word) };
                Ok(())
            }
            fn finish_write(&mut self) -> Result<(), PatchError> {
                Ok(())
            }
        }
        struct OpenStop;
        // SAFETY (test): scripted stop; no executor exists.
        unsafe impl StopControl for OpenStop {
            fn acquire(&mut self) -> Result<(), PatchError> {
                Ok(())
            }
            fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
                Ok(vec![ResumeState::Released])
            }
        }
        unsafe fn sync_ok(_rw: *mut u8, _rx: *mut u8, _len: usize) -> Result<(), PatchError> {
            Ok(())
        }
        let baseline = GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst);
        let fail = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut word = 0xd400_0001u32;
        let addr = 0x1000u64;
        let mut promoter = LazyPromoter::with_patcher(Patcher::test_with_sync(sync_ok), 7).unwrap();
        let store = Box::new(FailStore {
            word: std::ptr::from_mut(&mut word),
            fail: fail.clone(),
        });
        let mut site = unsafe {
            liteinst_aarch64_patch::site::Site::from_rx(
                addr,
                word,
                facts(addr, Provenance::PrivateFile),
                store,
            )
        }
        .unwrap();
        // SAFETY (test): claims a route for this exact site; the
        // fake stop never executes the word.
        let route = unsafe { TrapRoute::arm(addr, 0x4c00, 1) };
        let mut stop = OpenStop;
        // Pre-acquire to mirror try_promote's lease, then drive a
        // store-failing flip so the site lands in SyncPending.
        stop.acquire().unwrap();
        let outcome = promoter.patcher.flip_preacquired(
            &mut site,
            FlipRequest {
                island: None,
                strategy: StrategyPreference::TrapOnly,
                fallback: FallbackPermission::RefuseTrap,
                trap_route: Some(route),
                mapping_facts: Some(facts(addr, Provenance::PrivateFile)),
            },
            &mut stop,
        );
        assert!(matches!(outcome, Err(PatchError::StoreFailed { .. })));
        assert!(matches!(site.state(), SiteState::SyncPending { .. }));
        // Install custody exactly as try_promote's retain path does.
        custody_enter();
        #[cfg(target_arch = "aarch64")]
        {
            use reverie_inguest::trap::PendingPromotionRecord;
            assert!(reverie_inguest::trap::register_pending_promotion_island(
                0x9000, 0xa000
            ));
            assert_eq!(
                reverie_inguest::trap::record_pending_promotion_site(0x9000),
                PendingPromotionRecord::AlreadyKnown
            );
        }
        promoter.island_ranges.push((addr, 0x9000, 0xa000));
        promoter.sites.push(site);
        fail.store(false, std::sync::atomic::Ordering::SeqCst);
        let done = promoter.complete_pending(&mut stop);
        assert_eq!(done, [(addr, PromoteOutcome::Refused)]);
        // Settled back to the original word: custody is released —
        // site dropped, range freed, global counter balanced.
        assert_eq!(promoter.held_sites(), 0);
        assert!(promoter.island_ranges.is_empty());
        #[cfg(target_arch = "aarch64")]
        {
            use reverie_inguest::trap::PendingPromotionRecord;
            // The settled-unpatched release unregistered the range
            // (M11unreg: without it this stays AlreadyKnown).
            assert_eq!(
                reverie_inguest::trap::record_pending_promotion_site(0x9000),
                PendingPromotionRecord::NewSite
            );
            let mut sink = [0u64; 64];
            let _ = reverie_inguest::trap::drain_pending_promotion_sites(&mut sink);
        }
        assert_eq!(
            GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
            baseline
        );
        assert_eq!(word, 0xd400_0001);
    }

    #[test]
    fn global_custody_blocks_other_promoters() {
        let _serial = promoter_test_serial();
        let baseline = GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst);
        custody_enter();
        let mut other = LazyPromoter::unattested(1);
        assert!(other.custody_blocking());
        assert!(other.other_custody_held());
        let mut stop = RefusingStop;
        assert_eq!(
            other.promote_one(0x5000, &mut stop),
            PromoteOutcome::CustodyPending
        );
        custody_exit();
        assert_eq!(
            GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
            baseline
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn drop_leaks_unsettled_custody_fail_closed() {
        // Re-exec child: the leaked global count is process-wide
        // and permanent by design, so it must not poison this
        // process. Dropping a promoter that holds custody must
        // NOT balance GLOBAL_CUSTODY (mDropBalance: the old
        // decrementing Drop reopens the cross-promoter gate while
        // executors may still be stopped).
        const CHILD: &str = "REVERIE_S5B_DROP_CHILD";
        if std::env::var_os(CHILD).is_some() {
            struct ShortfallStop {
                acquires: usize,
            }
            // SAFETY (test): scripted stop; no executor exists.
            unsafe impl StopControl for ShortfallStop {
                fn acquire(&mut self) -> Result<(), PatchError> {
                    self.acquires += 1;
                    Ok(())
                }
                fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
                    Ok(vec![ResumeState::Unknown])
                }
            }
            let baseline = GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst);
            let mut promoter = LazyPromoter::unattested(1);
            let mut stop = ShortfallStop { acquires: 0 };
            // Pre-store refusal + resume shortfall retains the stop.
            assert_eq!(
                promoter.promote_one(0x5000, &mut stop),
                PromoteOutcome::CustodyPending
            );
            assert!(promoter.unsettled_custody());
            assert_eq!(
                GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
                baseline + 1
            );
            drop(promoter);
            // The count stays leaked after the drop...
            assert_eq!(
                GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
                baseline + 1,
                "Drop must leak unsettled custody, not balance it"
            );
            // ...so a fresh promoter is still blocked, without
            // even acquiring its stop.
            let mut fresh = LazyPromoter::unattested(1);
            let mut stop2 = ShortfallStop { acquires: 0 };
            assert_eq!(
                fresh.promote_one(0x5000, &mut stop2),
                PromoteOutcome::CustodyPending
            );
            assert_eq!(stop2.acquires, 0);
            drop(fresh);
            // Second leg, the more dangerous case: a promoter
            // holding a SyncPending SITE (mDropSites: a Drop that
            // releases only site custody would reopen the gate
            // while the site's page may be unsynced/RWX).
            use liteinst_aarch64_patch::flip::FlipRequest;
            use liteinst_aarch64_patch::site::{StrategyPreference, TrapRoute};
            struct FailStore {
                word: *mut u32,
            }
            // SAFETY (test): the word outlives the site below.
            unsafe impl Send for FailStore {}
            // SAFETY (test): models a store whose write always
            // fails after begin; reads/writes name the same word.
            unsafe impl liteinst_aarch64_patch::store::SiteStore for FailStore {
                fn read_word(&self) -> u32 {
                    unsafe { self.word.read_volatile() }
                }
                fn write_addr(&self) -> u64 {
                    self.word as u64
                }
                fn begin_write(&mut self) -> Result<(), PatchError> {
                    Ok(())
                }
                fn store_word(&mut self, _word: u32) -> Result<(), PatchError> {
                    Err(PatchError::Os {
                        op: "test store",
                        errno: libc::EIO,
                    })
                }
                fn finish_write(&mut self) -> Result<(), PatchError> {
                    Ok(())
                }
            }
            struct OpenStop;
            // SAFETY (test): scripted stop; no executor exists.
            unsafe impl StopControl for OpenStop {
                fn acquire(&mut self) -> Result<(), PatchError> {
                    Ok(())
                }
                fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
                    Ok(vec![ResumeState::Released])
                }
            }
            unsafe fn sync_ok(_rw: *mut u8, _rx: *mut u8, _len: usize) -> Result<(), PatchError> {
                Ok(())
            }
            let baseline2 = GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst);
            let mut word = 0xd400_0001u32;
            let addr = 0x1000u64;
            let mut promoter2 =
                LazyPromoter::with_patcher(Patcher::test_with_sync(sync_ok), 7).unwrap();
            let store = Box::new(FailStore {
                word: std::ptr::from_mut(&mut word),
            });
            let mut site = unsafe {
                liteinst_aarch64_patch::site::Site::from_rx(
                    addr,
                    word,
                    facts(addr, Provenance::PrivateFile),
                    store,
                )
            }
            .unwrap();
            // SAFETY (test): claims a route for this exact site;
            // the fake stop never executes the word.
            let route = unsafe { TrapRoute::arm(addr, 0x4c00, 1) };
            let mut open_stop = OpenStop;
            open_stop.acquire().unwrap();
            let outcome = promoter2.patcher.flip_preacquired(
                &mut site,
                FlipRequest {
                    island: None,
                    strategy: StrategyPreference::TrapOnly,
                    fallback: FallbackPermission::RefuseTrap,
                    trap_route: Some(route),
                    mapping_facts: Some(facts(addr, Provenance::PrivateFile)),
                },
                &mut open_stop,
            );
            assert!(matches!(outcome, Err(PatchError::StoreFailed { .. })));
            assert!(matches!(site.state(), SiteState::SyncPending { .. }));
            // Install custody exactly as try_promote's retain does.
            custody_enter();
            promoter2.sites.push(site);
            assert!(promoter2.unsettled_custody());
            assert_eq!(
                GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
                baseline2 + 1
            );
            drop(promoter2);
            assert_eq!(
                GLOBAL_CUSTODY.load(std::sync::atomic::Ordering::SeqCst),
                baseline2 + 1,
                "Drop must leak SyncPending site custody, not release it"
            );
            std::process::exit(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lazy_promote::tests::drop_leaks_unsettled_custody_fail_closed",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&out);
        assert!(out.status.success(), "{out:?}");
    }
    #[cfg(target_arch = "aarch64")]
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[cfg(target_arch = "aarch64")]
    const BPF_LD_W_ABS: u16 = 0x20;
    #[cfg(target_arch = "aarch64")]
    const BPF_JMP_JEQ_K: u16 = 0x15;
    #[cfg(target_arch = "aarch64")]
    const BPF_ALU_AND_K: u16 = 0x54;
    #[cfg(target_arch = "aarch64")]
    const BPF_RET_K: u16 = 0x06;
    #[cfg(target_arch = "aarch64")]
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    #[cfg(target_arch = "aarch64")]
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    #[cfg(target_arch = "aarch64")]
    const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
        SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    #[cfg(target_arch = "aarch64")]
    const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
        SockFilter { code, jt, jf, k }
    }

    #[cfg(target_arch = "aarch64")]
    fn install_seccomp_program(prog: &[SockFilter]) {
        #[repr(C)]
        struct SockFprog {
            len: u16,
            filter: *const SockFilter,
        }
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            let rc = libc::syscall(libc::SYS_seccomp, 1u32, 0u32, &fprog as *const SockFprog);
            assert_eq!(rc, 0, "seccomp install failed");
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn install_window_refusing_filter() {
        // BPF: mprotect(226) with prot&(W|X)==(W|X) -> ERRNO EACCES;
        // everything else ALLOW.
        install_seccomp_program(&[
            bpf_stmt(BPF_LD_W_ABS, 0),
            bpf_jump(BPF_JMP_JEQ_K, 226, 0, 4),
            bpf_stmt(BPF_LD_W_ABS, 32),
            bpf_stmt(BPF_ALU_AND_K, 0x6),
            bpf_jump(BPF_JMP_JEQ_K, 0x6, 0, 1),
            bpf_stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EACCES as u32),
            bpf_stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ]);
    }

    #[cfg(target_arch = "aarch64")]
    struct SecondAcquireAction {
        page: u64,
        len: usize,
        action: String,
        acquires: u32,
        resumes: u32,
    }
    // SAFETY (test): the stop plays the racing guest on the second
    // acquire; single-threaded child, page owned by the test.
    #[cfg(target_arch = "aarch64")]
    unsafe impl StopControl for SecondAcquireAction {
        fn acquire(&mut self) -> Result<(), PatchError> {
            self.acquires += 1;
            if self.acquires == 2 {
                unsafe {
                    match self.action.as_str() {
                        "rw" => {
                            libc::mprotect(
                                self.page as *mut libc::c_void,
                                self.len,
                                libc::PROT_READ | libc::PROT_WRITE,
                            );
                        }
                        "fixed" => {
                            let p = libc::mmap(
                                self.page as *mut libc::c_void,
                                self.len,
                                libc::PROT_READ | libc::PROT_WRITE,
                                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                                -1,
                                0,
                            );
                            assert_ne!(p, libc::MAP_FAILED);
                            (self.page as *mut u32).write_volatile(0x1122_3344);
                        }
                        "munmap" => {
                            libc::munmap(self.page as *mut libc::c_void, self.len);
                        }
                        "none" => {
                            libc::mprotect(
                                self.page as *mut libc::c_void,
                                self.len,
                                libc::PROT_NONE,
                            );
                        }
                        _ => unreachable!(),
                    }
                }
            }
            Ok(())
        }
        fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
            self.resumes += 1;
            Ok(vec![ResumeState::Released])
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn retry_requalifies_under_second_lease() {
        // Re-exec child per action: a refused window (seccomp
        // EACCES on W+X mprotect) triggers the proc-mem retry;
        // at acquire #2 the guest changes the mapping. The retry
        // must re-qualify and re-read — never store through the
        // first lease's facts.
        const CHILD: &str = "REVERIE_S5B_RV2_ACTION";
        if let Ok(action) = std::env::var(CHILD) {
            let _serial = promoter_test_serial();
            let (p, page) = rx_page_with(0xd400_0001);
            let site = p as u64;
            install_window_refusing_filter();
            let mut promoter = LazyPromoter::attested(1).unwrap();
            promoter.set_store_fallback(StoreFallback::AllowProcMem);
            let mut stop = SecondAcquireAction {
                page: site,
                len: page,
                action,
                acquires: 0,
                resumes: 0,
            };
            let outcome = promoter.promote_one(site, &mut stop);
            assert_eq!(outcome, PromoteOutcome::Refused);
            assert_eq!(stop.acquires, 2);
            assert_eq!(stop.resumes, 2);
            std::process::exit(0);
        }
        for action in ["rw", "fixed", "munmap", "none"] {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "lazy_promote::tests::retry_requalifies_under_second_lease",
                    "--nocapture",
                ])
                .env(CHILD, action)
                .output()
                .unwrap();
            assert_child_ran(&out);
            assert!(out.status.success(), "action {action}: {out:?}");
        }
    }

    #[cfg(target_arch = "aarch64")]
    struct WindowPwriteFailGate {
        armed: std::sync::atomic::AtomicBool,
        pwrite_fired: std::sync::atomic::AtomicBool,
    }

    #[cfg(target_arch = "aarch64")]
    static WINDOW_PWRITE_FAIL_GATE: WindowPwriteFailGate = WindowPwriteFailGate {
        armed: std::sync::atomic::AtomicBool::new(false),
        pwrite_fired: std::sync::atomic::AtomicBool::new(false),
    };

    // SAFETY: forwards every syscall faithfully through the
    // trusted gate except, while armed, the W+X window mprotect
    // (EACCES) and every pwrite64 (EIO).
    #[cfg(target_arch = "aarch64")]
    unsafe impl liteinst_aarch64_patch::gate::GateSyscall for WindowPwriteFailGate {
        unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64 {
            use std::sync::atomic::Ordering;
            if self.armed.load(Ordering::SeqCst) {
                if nr == libc::SYS_mprotect
                    && args[2] & (libc::PROT_WRITE as u64) != 0
                    && args[2] & (libc::PROT_EXEC as u64) != 0
                {
                    return -(libc::EACCES as i64);
                }
                if nr == libc::SYS_pwrite64 {
                    self.pwrite_fired.store(true, Ordering::SeqCst);
                    return -(libc::EIO as i64);
                }
            }
            // SAFETY: same raw contract, forwarded.
            unsafe { reverie_inguest::trap::raw_syscall6(nr, args) }
        }
    }

    #[cfg(target_arch = "aarch64")]
    struct RestoreFailOnceGate {
        armed: std::sync::atomic::AtomicBool,
        fired: std::sync::atomic::AtomicBool,
    }

    #[cfg(target_arch = "aarch64")]
    static RESTORE_FAIL_GATE: RestoreFailOnceGate = RestoreFailOnceGate {
        armed: std::sync::atomic::AtomicBool::new(false),
        fired: std::sync::atomic::AtomicBool::new(false),
    };

    // SAFETY: forwards every syscall faithfully through the
    // trusted gate except the single armed restore mprotect.
    #[cfg(target_arch = "aarch64")]
    unsafe impl liteinst_aarch64_patch::gate::GateSyscall for RestoreFailOnceGate {
        unsafe fn syscall6(&self, nr: i64, args: [u64; 6]) -> i64 {
            use std::sync::atomic::Ordering;
            if self.armed.load(Ordering::SeqCst)
                && nr == libc::SYS_mprotect
                && args[2] & (libc::PROT_EXEC as u64) != 0
                && args[2] & (libc::PROT_WRITE as u64) == 0
                && !self.fired.swap(true, Ordering::SeqCst)
            {
                return -(libc::EACCES as i64);
            }
            // SAFETY: same raw contract, forwarded.
            unsafe { reverie_inguest::trap::raw_syscall6(nr, args) }
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn restore_failure_is_custody_then_completes() {
        // Re-exec child: the gate is process-global. The installed
        // gate fails exactly ONE restore mprotect (R|X without W),
        // so the window opens, the word stores and syncs, and
        // finish_write fails -> RestoreFailed custody. The
        // promoter must retain the site with the page still RWX,
        // resume nobody, block other work, and then complete to
        // Flipped once the gate stops failing. (The resume-on-
        // restore-failure mutant in the patcher fails the
        // resumes==0 assert below; classify's own RestoreFailed
        // handling is by state, pinned in the classify test.)
        const CHILD: &str = "REVERIE_S5B_RESTORE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            use std::sync::atomic::Ordering;
            let _serial = promoter_test_serial();
            // SAFETY: first gate install in this fresh child; the
            // gate is a static that keeps the contract for life.
            unsafe { liteinst_aarch64_patch::gate::install_gate(&RESTORE_FAIL_GATE) }.unwrap();
            let patcher = Patcher::attested().unwrap();
            let (_dummy_island, (pa, _page_a), (pb, _page_b), slots) =
                rx_pages_near_island(0xd400_0001);
            let (site, other) = (pa as u64, pb as u64);
            let mut promoter = LazyPromoter::unattested(1);
            promoter.patcher = patcher;
            RESTORE_FAIL_GATE.armed.store(true, Ordering::SeqCst);
            let mut stop = SingleThreadStop {
                acquires: 0,
                resumes: 0,
                resume_failures: 0,
            };
            for (slot, len) in &slots[..4] {
                unsafe { libc::munmap(*slot as *mut libc::c_void, *len) };
            }
            assert_eq!(
                promoter.promote_one(site, &mut stop),
                PromoteOutcome::CustodyPending
            );
            assert!(RESTORE_FAIL_GATE.fired.load(Ordering::SeqCst));
            assert_eq!(promoter.held_sites(), 1);
            assert!(promoter.unsettled_custody());
            assert_eq!(perms_at(site), "rwxp");
            assert_eq!(stop.resumes, 0, "restore failure must not resume");
            // Other work is blocked by the custody, without even
            // acquiring the stop.
            let acquires_before = stop.acquires;
            assert_eq!(
                promoter.promote_one(other, &mut stop),
                PromoteOutcome::CustodyPending
            );
            assert_eq!(stop.acquires, acquires_before);
            // The one-shot failure is spent: completion restores
            // protections and settles to Flipped.
            let done = promoter.complete_pending(&mut stop);
            assert_eq!(done, [(site, PromoteOutcome::Flipped)]);
            assert_eq!(perms_at(site), "r-xp");
            assert!(!promoter.unsettled_custody());
            std::process::exit(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lazy_promote::tests::restore_failure_is_custody_then_completes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&out);
        assert!(out.status.success(), "{out:?}");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn refused_attempt_releases_island_range_slot() {
        // Re-exec child: the denylist is process-global with 64
        // lifetime slots, so the capacity proof needs a fresh
        // process. An unattested promoter registers its island
        // range, then refuses inside flip (CacheOpsUnavailable):
        // the range must be released, leaving all 64 slots for
        // manual registrations afterwards.
        const CHILD: &str = "REVERIE_S5B_RANGE_SLOT_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let _serial = promoter_test_serial();
            let (p, _page) = rx_page_with(0xd400_0001);
            let mut promoter = LazyPromoter::unattested(1);
            let mut stop = SingleThreadStop {
                acquires: 0,
                resumes: 0,
                resume_failures: 0,
            };
            assert_eq!(
                promoter.promote_one(p as u64, &mut stop),
                PromoteOutcome::Refused
            );
            for i in 0..64u64 {
                let lo = 0xa000_0000 + i * 0x1_0000;
                assert!(
                    reverie_inguest::trap::register_pending_promotion_island(lo, lo + 0x8000),
                    "range slot {i} unavailable after refused attempt"
                );
            }
            std::process::exit(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lazy_promote::tests::refused_attempt_releases_island_range_slot",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&out);
        assert!(out.status.success(), "{out:?}");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn proc_mem_pwrite_failure_completes_to_unpatched() {
        // Re-exec child: the installed gate (not seccomp, so this
        // also runs under qemu) refuses the W+X window AND every
        // pwrite64. With explicit proc-mem permission, the first
        // attempt gets WindowRefused, the retry's pwrite fails
        // after begin (StoreFailed custody), and completion
        // settles back to Unpatched because the word never landed.
        const CHILD: &str = "REVERIE_S5B_PWRITE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            use std::sync::atomic::Ordering;
            let _serial = promoter_test_serial();
            // SAFETY: first gate install in this fresh child.
            unsafe { liteinst_aarch64_patch::gate::install_gate(&WINDOW_PWRITE_FAIL_GATE) }
                .unwrap();
            let patcher = Patcher::attested().unwrap();
            let (p, _page) = rx_page_with(0xd400_0001);
            let site = p as u64;
            let mut promoter = LazyPromoter::unattested(1);
            promoter.patcher = patcher;
            promoter.set_store_fallback(StoreFallback::AllowProcMem);
            WINDOW_PWRITE_FAIL_GATE.armed.store(true, Ordering::SeqCst);
            let mut stop = SingleThreadStop {
                acquires: 0,
                resumes: 0,
                resume_failures: 0,
            };
            assert_eq!(
                promoter.promote_one(site, &mut stop),
                PromoteOutcome::CustodyPending
            );
            assert_eq!(promoter.held_sites(), 1);
            assert!(promoter.unsettled_custody());
            assert!(
                WINDOW_PWRITE_FAIL_GATE
                    .pwrite_fired
                    .load(std::sync::atomic::Ordering::SeqCst)
            );
            // Exactly one resume so far (the refused window's lease
            // release); the post-store StoreFailed must add none.
            assert_eq!(stop.resumes, 1, "StoreFailed custody must not resume");
            // The failed pwrite left custody: other work is blocked
            // without acquiring (mPwrite reporting Flipped here
            // would let this second promotion proceed).
            let (po, _page_o) = rx_page_with(0xd400_0001);
            let acquires_before = stop.acquires;
            assert_eq!(
                promoter.promote_one(po as u64, &mut stop),
                PromoteOutcome::CustodyPending
            );
            assert_eq!(stop.acquires, acquires_before);
            let done = promoter.complete_pending(&mut stop);
            assert_eq!(done, [(site, PromoteOutcome::Refused)]);
            assert_eq!(promoter.held_sites(), 0);
            assert_eq!(unsafe { (site as *const u32).read_volatile() }, 0xd400_0001);
            assert_eq!(perms_at(site), "r-xp");
            std::process::exit(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lazy_promote::tests::proc_mem_pwrite_failure_completes_to_unpatched",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert_child_ran(&out);
        assert!(out.status.success(), "{out:?}");
    }
}
