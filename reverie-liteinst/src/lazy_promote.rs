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

/// Foreign store via `/proc/self/mem`: no protection window, for
/// environments where the mprotect window is refused. Unlike
/// `process_vm_writev` (no FOLL_FORCE: EFAULT on R-X text), proc-mem
/// writes reach read-only private text and break COW exactly as an
/// mprotect window store would. Used only after the mprotect
/// window probe refuses, per the settled try order.
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
    /// The store was issued (or may have been) and custody is
    /// unresolved: sync/resume shortfall, restore failure, or a
    /// lease that could not be released. Drive
    /// [`LazyPromoter::complete_pending`];
    /// never re-drain this site as a fresh candidate.
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

/// Classify a flip error by when it can occur, and whether the
/// Site must be retained. Post-store errors retain the site.
/// Pre-store custody (a resume shortfall on an Unpatched site:
/// nothing was written, but executors may still be stopped)
/// does NOT retain the site — it retains the STOP, which the
/// promoter retries before new work (see `stop_retained`).
fn classify(err: &PatchError, state: SiteState) -> (PromoteOutcome, bool) {
    if state != SiteState::Unpatched {
        return (PromoteOutcome::CustodyPending, true);
    }
    match err {
        PatchError::StoreFailed { .. } | PatchError::SyncFailed { .. } => {
            (PromoteOutcome::CustodyPending, true)
        }
        PatchError::RestoreFailed { .. } => (PromoteOutcome::CustodyPending, true),
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

/// The promoter: patcher + retained sites + island pool. Arenas in
/// this slice are one island per flipped site (retained by the
/// `Site` itself); entry-allocator arenas are a sizing follow-up
/// that does not change this boundary.
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
    /// later candidate from fresh facts.
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

    /// Whether any held site is in post-store custody
    /// (SyncPending/RetainedStop) or a stop is retained. While
    /// true, NO new promotion, drain, or later completion may
    /// run: every resume path would release executors onto a
    /// page whose word is not yet synced/restored (the W^X
    /// no-resume rule applies across sites, not per site).
    fn custody_blocking(&self) -> bool {
        self.stop_retained
            || self.sites.iter().any(|s| {
                matches!(
                    s.state(),
                    SiteState::SyncPending { .. } | SiteState::RetainedStop { .. }
                )
            })
    }

    /// Retry releasing a retained stop. Clears `stop_retained`
    /// ONLY when every executor acknowledged (or the stop reports
    /// none retained by an error-free empty acknowledgement is NOT
    /// enough: empty is a shortfall). Returns true when settled.
    fn settle_retained_stop(&mut self, stop: &mut dyn StopControl) -> bool {
        if !self.stop_retained {
            return true;
        }
        match stop.resume() {
            Ok(states) if all_acknowledged(&states) => {
                self.stop_retained = false;
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
        // is left untouched for a later drain.
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
        let Some(_mask) = SignalMask::block_all() else {
            self.mask_failed = true;
            return Vec::new();
        };
        let mut out = Vec::new();
        if !self.settle_retained_stop(stop) {
            return out;
        }
        let mut settled_unpatched: Vec<u64> = Vec::new();
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
            if site.state() == SiteState::Unpatched {
                settled_unpatched.push(site.addr());
            }
            let settled = outcome != PromoteOutcome::CustodyPending;
            out.push((site.addr(), outcome));
            if !settled {
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
        if !self.settle_retained_stop(stop) || self.custody_blocking() {
            // Blocked by another site's custody (or a retained
            // stop): the candidate is NOT consumed or retained —
            // the caller still owns it and may retry after the
            // custody settles. CustodyPending here describes the
            // promoter's state, not this candidate's.
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
                self.stop_retained = true;
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
                        self.island_ranges
                            .push((addr, island_range.0, island_range.1));
                        self.sites.push(site);
                    }
                    if outcome == PromoteOutcome::CustodyPending && !retain {
                        // Pre-store resume shortfall: no site custody,
                        // the STOP is retained for settlement.
                        self.stop_retained = true;
                    }
                    return outcome;
                }
            }
        }
        PromoteOutcome::Refused
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
        let page = liteinst_aarch64_patch::page_size().unwrap();
        assert!(!admit(
            0x4000 + page,
            &facts(0x4000, Provenance::PrivateAnon)
        ));
        assert!(!admit(0x3000, &facts(0x4000, Provenance::PrivateAnon)));
    }

    #[test]
    fn classify_separates_pre_store_from_custody() {
        assert_eq!(
            classify(&PatchError::CacheOpsUnavailable, SiteState::Unpatched),
            (PromoteOutcome::Refused, false)
        );
        assert_eq!(
            classify(
                &PatchError::SyncFailed {
                    source: Box::new(PatchError::CacheOpsUnavailable)
                },
                SiteState::Unpatched
            ),
            (PromoteOutcome::CustodyPending, true)
        );
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
                SiteState::Unpatched
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
        // Mapped SVC words, so admission runs real qualification.
        // What refuses here, by architecture: on x86 the island
        // reserve itself (Unsupported, before acquire); on aarch64
        // the RefusingStop's acquire. The patcher's own unattested
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
        let _serial = PROMOTER_TEST_SERIAL.lock().unwrap();
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

    #[cfg(target_arch = "aarch64")]
    static PROMOTER_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let _serial = PROMOTER_TEST_SERIAL.lock().unwrap();
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
        let _serial = PROMOTER_TEST_SERIAL.lock().unwrap();
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
        assert!(out.status.success(), "{out:?}");
    }
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn custody_site_blocks_all_new_work_until_settled() {
        let _serial = PROMOTER_TEST_SERIAL.lock().unwrap();
        // Site A: sync fails after the store -> SyncPending with
        // executors still stopped and its page still RWX.
        SYNC_FAIL_ONCE.store(true, std::sync::atomic::Ordering::SeqCst);
        let patcher = Patcher::attested_with_sync(sync_fail_once).unwrap();
        let mut promoter = LazyPromoter::with_patcher(patcher, 1).unwrap();
        let (pa, page_a) = rx_page_with(0xd400_0001);
        let (pb, page_b) = rx_page_with(0xd400_0001);
        let mut stop = SingleThreadStop {
            acquires: 0,
            resumes: 0,
            resume_failures: 0,
        };
        assert_eq!(
            promoter.promote_one(pa as u64, &mut stop),
            PromoteOutcome::CustodyPending
        );
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
        assert_eq!(
            promoter.promote_one(pb as u64, &mut stop),
            PromoteOutcome::Flipped
        );
        unsafe { libc::munmap(pa as *mut libc::c_void, page_a) };
        unsafe { libc::munmap(pb as *mut libc::c_void, page_b) };
        core::mem::forget(promoter);
    }
    #[test]
    fn deferred_batch_survives_custody_block() {
        // First candidate refuses (retained), second is consumed
        // from the source in the same batch: it must be deferred
        // inside the promoter, not dropped. The proof is the
        // SECOND drain (empty source) still yielding it.
        let mut promoter = LazyPromoter::unattested(1);
        promoter.stop_retained = true;
        let mut stop = RefusingStop;
        // settle will fail (RefusingStop resume returns empty ->
        // shortfall), so the whole batch defers without source use.
        let first = promoter.drain_and_promote(
            &mut |buf| {
                buf[..2].copy_from_slice(&[0x5000, 0x6000]);
                2
            },
            &mut stop,
        );
        assert!(
            first.is_empty(),
            "blocked drain must not consume: {first:?}"
        );
        promoter.stop_retained = false;
        let second = promoter.drain_and_promote(
            &mut |buf| {
                buf[..2].copy_from_slice(&[0x5000, 0x6000]);
                2
            },
            &mut stop,
        );
        assert_eq!(second.len(), 2);
        assert_eq!(promoter.retained_refusals(), [0x5000, 0x6000]);
    }
}
