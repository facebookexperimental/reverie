/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Runtime-free LiteInst launch mode ("trap-only").
//!
//! Trap-only LiteInst loads nothing into the guest: no preload, no runtime,
//! no handshake. It launches through the ordinary ptrace tracer and keeps the
//! dynamic LiteInst runtime configuration absent, so every lifecycle branch
//! that distinguishes the preload hybrid takes its plain-ptrace arm.
//!
//! Patching state is kept separately, in one [`SiteTable`] per guest address
//! space. A later increment rewrites first-seen x86_64 `syscall` sites to
//! `int 0x80` in place, from the tracer, so that later executions arrive as
//! `AUDIT_ARCH_I386` seccomp stops. That scheme needs the kernel's IA-32
//! syscall entry, so a trap-only launch probes for it and fails closed when it
//! is missing. There is no fallback to plain ptrace under the LiteInst label.
//!
//! The only public patching state is [`SitePatching::Off`]: no guest byte is
//! ever written, and a trap-only run is observably the ordinary ptrace run.
//! The seccomp filter is byte-identical to plain ptrace's; it still kills any
//! non-x86_64 syscall.
//!
//! A test-only `SitePatching::On` rewrites sites. Its filter stops
//! `AUDIT_ARCH_I386` syscalls with [`TAG_I386`] instead of killing the process,
//! and stops an x86_64 syscall from the page's traced `syscall` stub ([`SLOT`])
//! with [`TAG_SLOT`]. The tracer runs a patched site's syscall through that
//! stub with every signal blocked (the "masked hop", in `task.rs`), and shows
//! the tool and the guest the registers the original `syscall` would have
//! produced.
//!
//! The site-table lifecycle (P2 spec sections 4 and 5, in
//! `task_trap_only.rs`) keeps one table per address space, shared by
//! `CLONE_VM` children, copied on fork and replaced on exec. It restores
//! patched bytes at the seccomp stop of each syscall named in the bullets
//! below, before that syscall runs. A change to the guest's text made any
//! other way is not seen; the P2e gates below name the ways known so far.
//! - before a syscall that creates a second executing task (a `CLONE_VM`
//!   clone without `CLONE_VFORK`, or any `CLONE_UNTRACED` clone) runs, every
//!   site is restored and the table is disabled for good;
//! - before a mapping change (`mmap(MAP_FIXED)`, `munmap`, `mremap`,
//!   `mprotect`, `pkey_mprotect`, `madvise`, `shmat`, `remap_file_pages`)
//!   runs, the sites it can reach are restored;
//! - before any `process_madvise` runs, every site of the caller's table is
//!   restored: the tracer reads neither its `iovec` array nor which process
//!   its pidfd names. No site is patched at a `process_madvise` stop (nor at
//!   a mapping change's);
//! - before the guest installs a seccomp filter or syscall user dispatch,
//!   every site is restored and the table and all its descendants (fork,
//!   clone and exec) are disabled.
//!
//! A restore reads each site first and puts back only the bytes that still
//! hold the patch, so a byte the guest stored over the patch is kept.
//!
//! The timer rules are not implemented yet, which is why `On` stays
//! test-only. Neither are these, each a gate on releasing `On` (P2e) unless
//! a later step handles it:
//! - a mapping change that passes no seccomp stop (an `io_uring`
//!   `IORING_OP_MADVISE`), and `brk`, which the mapping rules omit: a heap
//!   page the guest made `r-x` and that got patched keeps a live site after
//!   `brk` shrinks over it;
//! - a write to the file behind a patched private file mapping: the patch
//!   write gave the page a private copy, so the guest no longer sees later
//!   changes to the file on that page, as it would under plain ptrace;
//! - another process writing the guest's text (`process_vm_writev`,
//!   `/proc/<pid>/mem`), which can race a restore's read and write;
//! - the guest writing its own text through its `mem` file (a `write` or
//!   `pwrite` to `/proc/self/mem`), whose stop restores nothing: a byte of a
//!   site that the write leaves alone keeps the patch (`0x80` where plain
//!   ptrace has `0x05`, after a write over the first byte only) until the
//!   next restore, and that restore takes a byte the guest wrote with the
//!   patch's own value back to the original; and a guest that writes its own
//!   `int 0x80` (`cd 80`) over a live site's address has it routed as that
//!   site's x86_64 syscall, where plain ptrace kills the process with SIGSYS;
//! - a seccomp filter or syscall user dispatch installed before the tracee
//!   starts (inherited from the launcher), which never reaches the lineage
//!   check;
//! - a `process_madvise` whose pidfd names a traced process with another
//!   address space restores the caller's table, not the target's. When the
//!   target's address space is not the caller's (`mm != current->mm`), the
//!   kernel accepts only `MADV_COLD`, `MADV_PAGEOUT`, `MADV_WILLNEED` and
//!   `MADV_COLLAPSE` (`process_madvise_remote_valid` in `mm/madvise.c`), and
//!   each keeps a page's contents, so no difference from plain ptrace is
//!   known; a kernel that accepted more advice would open one. A target that
//!   shares the caller's address space (the caller itself, the parent a vfork
//!   child runs for, or a process created with `CLONE_VM`) accepts any
//!   advice, but it uses the caller's table: the restore puts back every
//!   site of it, and the calling site is not patched at that stop even when
//!   this is its first call, so no site holds the patch when the call runs
//!   (`trap_only_p2_t6c_process_madvise_first_call_leaves_its_site_unpatched`).
//!   No test names another process;
//! - syscalls a Tool injects bypass the lifecycle: a Tool that substitutes a
//!   clone reaches the new-child stop with no recorded flags, which restores
//!   and disables (the undecided path); one that substitutes a mapping
//!   change is not seen at all.
//!
//! Also P2e gates, for want of an end-to-end test: the `pkey_mprotect`,
//! `remap_file_pages`, `shmat(SHM_REMAP)` and `PROT_GROWSDOWN` rules (their
//! ranges have a unit test only), a mapping syscall that fails (it restores
//! anyway), and a new child when `kcmp(KCMP_VM)` cannot answer.
//!
//! Out of scope rather than a gate: `userfaultfd`'s `UFFDIO_MOVE`, which
//! remaps pages without a mapping syscall. The kernel moves a page only
//! between two anonymous mappings that are both writable (`VM_WRITE`) and
//! have equal access flags, so it can neither take a page from patched text,
//! which is `r-x`, nor put one over it.
//!
//! Gates on the P2d steps, which exercise the masked hop further: an
//! asynchronous signal and an `ERESTART*` restart through an in-place hop
//! (a syscall run at its own site), and a `SIGSTOP` during an in-place hop:
//! the deferral described below runs at either hop's target, and no test is
//! known to run it in place.
//!
//! # SIGSTOP inside the masked hop: known differences from plain ptrace
//!
//! The hop's mask cannot hold SIGSTOP, so a SIGSTOP pending when the hop
//! starts is dequeued before the patched syscall runs, where plain ptrace
//! delivers it after. The hop suppresses such a SIGSTOP, settles it from one
//! read of the thread's pending signals once the slot's seccomp stop
//! arrives, and raises it again, before the syscall, with the original
//! siginfo restored at its delivery stop (P2-SPEC O1.4, section 8 item 2;
//! `trap_only_reraise_stops` in `task_trap_only.rs` has the details). With
//! patching `On`, these differences remain, each pinned by a test:
//!
//! - Visible to the Tool and the guest, undetected: a SIGCONT sent in the
//!   window between that read and the re-raise (the tracer's own work
//!   between them, whose length the host's scheduling decides) is
//!   discarded by the re-raised SIGSTOP. Under plain ptrace the SIGCONT
//!   discards the SIGSTOP instead and is delivered: the Tool loses a
//!   SIGCONT signal event, the guest's SIGCONT handler does not run, and a
//!   SIGSTOP delivery stop happens instead (reverie suppresses it before the
//!   Tool or the guest sees it), which restarts a blocking syscall it
//!   interrupts.
//!   A SIGCONT to a non-seized tracee that is not stopped leaves no trace,
//!   so the hop cannot detect it (`trap_only_p2_sigcont_after_the_pending_read_is_lost`).
//!   Hermit's scheduler does not close this for Hermit guests: a signal a
//!   guest sends is queued at the sender's own syscall, and a thread doing
//!   external IO runs its syscall outside its turn, so a guest's
//!   `kill -STOP; kill -CONT` can straddle the window. Making `On` public
//!   (P2e) therefore requires closing this window, or refusing at run time
//!   whatever can reach it, first.
//! - Refused (`TrapOnlyHopDeferredStopBehindStopSignal`): a SIGTSTP,
//!   SIGTTIN or SIGTTOU pending at the read. It may have discarded a SIGCONT
//!   sent after the deferred SIGSTOP, which under plain ptrace discarded the
//!   SIGSTOP, and nothing left in the pending signals says whether it did,
//!   so the run fails closed, also when plain ptrace would have completed
//!   (`trap_only_p2_sigcont_then_a_stop_signal_fails_closed`).
//! - Refused (`TrapOnlyHopDeferredStopMultiThread`): a deferred SIGSTOP in a
//!   thread group of more than one thread. Unreachable while sites are
//!   retired before a second task shares the address space (unit test only).
//! - Invisible to the Tool and the guest (reverie suppresses every SIGSTOP),
//!   only in the siginfo or number of SIGSTOP delivery stops: see
//!   `trap_only_reraise_stops`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use crate::LiteinstInstrumentationStats;

/// Whether a trap-only LiteInst run rewrites syscall sites in the guest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SitePatching {
    /// Never write a guest byte. Every syscall takes the ordinary ptrace
    /// seccomp path, so the run is the ptrace run.
    Off,
    /// Rewrite first-seen syscall sites to `int 0x80` and run each patched
    /// site's syscall through the traced slot. Test-only until the patched
    /// path is released.
    #[cfg(test)]
    On,
}

impl SitePatching {
    /// Whether this state rewrites guest syscall sites, and so needs the
    /// trap-only seccomp filter.
    pub(crate) fn rewrites_sites(self) -> bool {
        match self {
            Self::Off => false,
            #[cfg(test)]
            Self::On => true,
        }
    }
}

impl fmt::Display for SitePatching {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => formatter.write_str("off"),
            #[cfg(test)]
            Self::On => formatter.write_str("on"),
        }
    }
}

/// Seccomp `Trace` data of an `AUDIT_ARCH_I386` syscall stop, which a patched
/// site (`int 0x80`) produces. Plain ptrace kills the process instead.
pub(crate) const TAG_I386: u16 = 0x7101;

/// Seccomp `Trace` data of an x86_64 syscall stop whose instruction pointer is
/// [`SLOT_RET`], whatever the syscall number (including numbers the tool does
/// not subscribe to and `rt_sigreturn`).
pub(crate) const TAG_SLOT: u16 = 0x7102;

/// The traced `syscall; ud2` stub of the private page (`cp::mmap`), through
/// which the tracer will run a patched site's syscall. Plain ptrace never
/// executes it.
pub(crate) const SLOT: u64 = crate::cp::PRIVATE_PAGE_OFFSET as u64 + 4;

/// The instruction pointer seccomp reports for [`SLOT`]'s syscall: the
/// address after its two-byte `syscall`.
pub(crate) const SLOT_RET: u64 = SLOT + 2;

/// Why a site's patch was undone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetiredReason {
    /// A second task began executing the address space; the tracer never
    /// writes text another thread may be executing.
    MultiTask,
    /// A mapping change could reach the site's page (it could make the text
    /// writable, move it, drop it or revert it).
    Mapping,
    /// The guest installed a seccomp filter, which must never see an
    /// `AUDIT_ARCH_I386` entry that plain ptrace would not produce.
    GuestSeccomp,
    /// The guest enabled syscall user dispatch, which must never see an
    /// `int 0x80` entry that plain ptrace would not produce.
    Sud,
    /// The site carried a number plain ptrace's filter allows without a stop
    /// (`rt_sigreturn`, or a number the syscall table does not know). The
    /// tracer ran that call invisibly and then restored the site, so the
    /// allowed number never costs a stop again (P2 spec O4 rule 3).
    AllowClass,
}

/// Whether a site's bytes are currently patched.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SiteState {
    /// The site holds `int 0x80`.
    Live,
    /// The original bytes were restored and read back.
    Retired(RetiredReason),
}

#[derive(Clone, Copy, Debug)]
struct SiteEntry {
    original: [u8; 2],
    state: SiteState,
}

/// Why an address space no longer patches sites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DisabledReason {
    /// The address space gained a second executing task.
    MultiTask,
    /// The tool does not subscribe to every syscall, so a patched site could
    /// carry an allowed number that must not become a tool-visible stop.
    PartialSubscription,
    /// This task lineage installed (or tried to install) a seccomp filter.
    GuestSeccomp,
    /// This task lineage enabled (or tried to enable) syscall user dispatch.
    Sud,
}

/// Whether an address space may gain new patched sites.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TableState {
    Patchable,
    Disabled(DisabledReason),
}

/// Patched syscall sites of one guest address space.
///
/// Each entry maps a site address to the two original instruction bytes that
/// the patch replaced, so that the bytes can be restored before the guest
/// changes or discards the page. With [`SitePatching::Off`] the table is
/// never populated.
#[derive(Clone, Debug)]
pub struct SiteTable {
    patching: SitePatching,
    state: TableState,
    sites: BTreeMap<u64, SiteEntry>,
    /// Set once a task of this address space installs (or tries to install)
    /// a guest seccomp filter or syscall user dispatch. Every table derived
    /// from this one, by fork or by exec, starts disabled with this reason.
    ///
    /// It lives in the table, so it is shared by every task of the address
    /// space. That is a superset of the tasks a filter reaches (a filter
    /// without TSYNC stays on the calling thread), and so conservative.
    lineage: Option<DisabledReason>,
}

impl SiteTable {
    /// Creates an empty table for a fresh address space.
    pub fn new(patching: SitePatching) -> Self {
        Self {
            patching,
            state: TableState::Patchable,
            sites: BTreeMap::new(),
            lineage: None,
        }
    }

    /// The empty table of the address space an exec installs: patchable,
    /// unless this lineage installed a guest filter or syscall user dispatch
    /// (filters survive exec; SUD does not, but stays disabled
    /// conservatively, P2 spec section 5).
    pub(crate) fn after_exec(&self) -> Self {
        let mut fresh = Self::new(self.patching);
        fresh.lineage = self.lineage;
        if let Some(reason) = self.lineage {
            fresh.disable(reason);
        }
        fresh
    }

    /// Marks the lineage of this address space, and disables it.
    pub(crate) fn mark_lineage(&mut self, reason: DisabledReason) {
        if self.lineage.is_none() {
            self.lineage = Some(reason);
        }
        self.disable(reason);
    }

    /// Returns the patching state of this address space.
    pub fn patching(&self) -> SitePatching {
        self.patching
    }

    /// Returns the number of sites whose bytes are currently patched.
    pub fn patched_sites(&self) -> usize {
        self.sites
            .values()
            .filter(|entry| entry.state == SiteState::Live)
            .count()
    }

    pub(crate) fn state(&self) -> TableState {
        self.state
    }

    pub(crate) fn disable(&mut self, reason: DisabledReason) {
        self.state = TableState::Disabled(reason);
    }

    /// Whether new sites may be patched in this address space.
    pub(crate) fn accepts_new_sites(&self) -> bool {
        self.patching.rewrites_sites() && self.state == TableState::Patchable
    }

    pub(crate) fn is_live(&self, site: u64) -> bool {
        self.sites
            .get(&site)
            .is_some_and(|entry| entry.state == SiteState::Live)
    }

    /// The number of sites ever patched in this address space.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> usize {
        self.sites.len()
    }

    /// Whether the site was ever patched (live or retired).
    pub(crate) fn knows(&self, site: u64) -> bool {
        self.sites.contains_key(&site)
    }

    #[cfg(test)]
    pub(crate) fn site_state(&self, site: u64) -> Option<SiteState> {
        self.sites.get(&site).map(|entry| entry.state)
    }

    /// Live sites with their original bytes, in address order.
    pub(crate) fn live_sites(&self) -> Vec<(u64, [u8; 2])> {
        self.sites
            .iter()
            .filter(|(_, entry)| entry.state == SiteState::Live)
            .map(|(site, entry)| (*site, entry.original))
            .collect()
    }

    pub(crate) fn record_live(&mut self, site: u64, original: [u8; 2]) {
        self.sites.insert(
            site,
            SiteEntry {
                original,
                state: SiteState::Live,
            },
        );
    }

    pub(crate) fn retire(&mut self, site: u64, reason: RetiredReason) {
        if let Some(entry) = self.sites.get_mut(&site) {
            entry.state = SiteState::Retired(reason);
        }
    }

    /// Restores (through each of `tids`) every live site whose two bytes
    /// intersect one of `ranges`, and marks it retired. Returns the number
    /// of sites retired.
    ///
    /// Each site is read before it is written (see [`restore_site`]): only
    /// a byte that still holds the patch is put back, so a byte the guest
    /// has since stored over the patch (through `/proc/self/mem`, say) is
    /// kept, as it would be under plain ptrace, and a task that shares an
    /// address space already restored through another tid is not written
    /// again. The read and the write are not atomic: this relies on every
    /// task of the address space being stopped, which leaves only another
    /// process's write (`process_vm_writev`, `/proc/<pid>/mem`) able to race
    /// with it (a P2e gate, see the module doc).
    pub(crate) fn restore_sites(
        &mut self,
        tids: &[nix::unistd::Pid],
        ranges: &[(u64, u64)],
        reason: RetiredReason,
    ) -> Result<usize, anyhow::Error> {
        let mut restored = 0;
        for (site, original) in self.live_sites() {
            let end = site.saturating_add(2);
            if !ranges
                .iter()
                .any(|(start, stop)| site < *stop && end > *start)
            {
                continue;
            }
            for tid in tids {
                restore_site(*tid, site, original)?;
            }
            self.retire(site, reason);
            restored += 1;
        }
        Ok(restored)
    }
}

/// Every address: a range for [`SiteTable::restore_sites`] that reaches all
/// sites.
pub(crate) const ALL_ADDRESSES: (u64, u64) = (0, u64::MAX);

/// The bytes of a patched site: `int 0x80`.
pub(crate) const PATCHED_BYTES: [u8; 2] = [0xcd, 0x80];

/// The bytes of an x86_64 `syscall` instruction.
pub(crate) const SYSCALL_BYTES: [u8; 2] = [0x0f, 0x05];

/// A trap-only run failed closed.
///
/// Each variant names a state the tracer refuses to continue from rather
/// than guess. The text starts with the variant name.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TrapOnlyFailure {
    /// Writing a site's bytes did not stick: reading them back found other
    /// bytes.
    #[error("TrapOnlyPatchReadback: site {site:#x} reads {found:02x?} after writing {wrote:02x?}")]
    PatchReadback {
        /// The site address.
        site: u64,
        /// The bytes written.
        wrote: [u8; 2],
        /// The bytes read back.
        found: [u8; 2],
    },
    /// An `AUDIT_ARCH_I386` syscall stop that is not a live patched site
    /// (guest code that really uses the IA-32 ABI) could not be turned into
    /// the kill that plain ptrace's filter produces.
    #[error("TrapOnlyForeignI386: int 0x80 at {rip:#x}: {reason}")]
    ForeignI386 {
        /// The instruction pointer after the `int 0x80`.
        rip: u64,
        /// What failed.
        reason: String,
    },
    /// A stop during the masked hop that the hop does not handle.
    #[error("TrapOnlyHopUnexpectedStop: {phase} for site {site:#x}: {stop}")]
    HopUnexpectedStop {
        /// Which hop step was waiting.
        phase: &'static str,
        /// The patched site.
        site: u64,
        /// The stop that arrived.
        stop: String,
    },
    /// A stop from the private page's traced `syscall` stub outside a hop.
    #[error(
        "TrapOnlyStraySlotStop: slot seccomp stop at {rip:#x} (orig_rax {orig_rax}) outside a hop"
    )]
    StraySlotStop {
        /// The reported instruction pointer.
        rip: u64,
        /// The reported syscall number.
        orig_rax: i64,
    },
    /// A timer single-step ended at a patched site's `int 0x80` stop that
    /// carries a number plain ptrace's filter allows without a stop (P2 spec
    /// O4 rule 4). Under plain ptrace that step runs the syscall and ends
    /// after it; reproducing that inside the timer's step loop is not
    /// implemented, so the run fails closed instead of resuming the stop.
    #[error(
        "TrapOnlyAllowClassInTimerStep: a timer single-step reached site {site:#x} carrying allowed syscall {nr}"
    )]
    AllowClassInTimerStep {
        /// The patched site.
        site: u64,
        /// The (sign-extended 32-bit) syscall number.
        nr: i64,
    },
    /// A patched site carried a syscall number that seccomp passes through
    /// without running the filter (x86_64 335 `uretprobe` and 336 `uprobe`).
    /// Plain ptrace runs it at the original site with no stop; the masked hop
    /// cannot, because the slot's `syscall` would bypass the filter too, so
    /// the run fails closed before the hop.
    #[error(
        "TrapOnlySeccompBypassingNumber: site {site:#x} carries syscall {nr}, which seccomp does not filter"
    )]
    SeccompBypassingNumber {
        /// The patched site.
        site: u64,
        /// The (sign-extended 32-bit) syscall number.
        nr: i64,
    },
    /// At the syscall-exit stop of the masked hop the instruction pointer was
    /// neither the hop target's return address nor, for `rt_sigreturn`, the
    /// signal frame's saved instruction pointer (P2 spec O4, H4). Rewriting
    /// the registers would resume the guest at an unknown address.
    #[error(
        "TrapOnlyHopExitRip: syscall {nr} for site {site:#x} left rip {rip:#x} at its exit stop, expected {expected}"
    )]
    HopExitRip {
        /// The patched site.
        site: u64,
        /// The syscall number.
        nr: i64,
        /// The instruction pointer found at the exit stop.
        rip: u64,
        /// The accepted instruction pointer(s), rendered.
        expected: String,
    },
    /// The masked hop deferred a SIGSTOP while the thread group had more
    /// than one thread. Deciding whether the deferred SIGSTOP is still owed
    /// (a SIGCONT discards stop signals from every thread's queue) and where
    /// to raise it again reads only the hopping thread's pending signals, so
    /// it holds only for a single-threaded group. Sites are retired before a
    /// second task can share the address space (`MultiTaskLiveSites`), so a
    /// hop never runs in such a group; the hop refuses rather than rely on it.
    #[error(
        "TrapOnlyHopDeferredStopMultiThread: site {site:#x} deferred a SIGSTOP in a thread group of {threads} threads"
    )]
    HopDeferredStopMultiThread {
        /// The patched site.
        site: u64,
        /// The `Threads:` count of the hopping thread's group.
        threads: u64,
    },
    /// The masked hop deferred a SIGSTOP, and when it settled the deferral a
    /// stop signal other than SIGSTOP (SIGTSTP, SIGTTIN or SIGTTOU) was
    /// pending. Sending any stop signal discards every pending SIGCONT, so a
    /// SIGCONT sent after the deferred SIGSTOP and before that stop signal
    /// has left no trace: under plain ptrace it discarded the SIGSTOP (still
    /// pending there), while the hop, seeing no SIGCONT, would raise the
    /// SIGSTOP again. Whether such a SIGCONT was sent cannot be read from
    /// the pending signals (a stop signal pending since before the SIGSTOP
    /// looks the same, as does one sent again after a SIGCONT discarded it),
    /// so the hop refuses rather than guess.
    #[error(
        "TrapOnlyHopDeferredStopBehindStopSignal: site {site:#x} deferred a SIGSTOP while signal {signal} was pending"
    )]
    HopDeferredStopBehindStopSignal {
        /// The patched site.
        site: u64,
        /// The pending stop signal (the lowest-numbered, if several).
        signal: i32,
    },
    /// A second executing task appeared in an address space that still had
    /// live sites or still accepted new ones: the restore that must precede
    /// the task-creating syscall did not happen.
    #[error(
        "TrapOnlyMultiTaskLiveSites: new task {child} shares the address space with {live} live site(s), table {state}"
    )]
    MultiTaskLiveSites {
        /// The new task.
        child: i32,
        /// The live sites found.
        live: usize,
        /// The table state found.
        state: String,
    },
}

/// Why a site was not patched at its first stop. Not an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PatchDecline {
    /// The site is not in a private, executable, non-writable mapping.
    Mapping(String),
}

/// Whether `site` lies in Reverie's private page or the legacy vsyscall page.
pub(crate) fn is_reserved_site(site: u64) -> bool {
    const VSYSCALL_START: u64 = 0xffff_ffff_ff60_0000;
    let page = crate::cp::PRIVATE_PAGE_OFFSET as u64;
    (page..page + crate::cp::PRIVATE_PAGE_SIZE as u64).contains(&site)
        || (VSYSCALL_START..VSYSCALL_START + 0x1000).contains(&site)
}

fn proc_mem(tid: nix::unistd::Pid, write: bool) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .open(format!("/proc/{tid}/mem"))
}

/// Reads the two bytes at `site` in a stopped tracee.
pub(crate) fn read_site(tid: nix::unistd::Pid, site: u64) -> std::io::Result<[u8; 2]> {
    use std::os::unix::fs::FileExt;
    let mut bytes = [0u8; 2];
    proc_mem(tid, false)?.read_exact_at(&mut bytes, site)?;
    Ok(bytes)
}

/// Writes two bytes at `site` in a stopped tracee through `/proc/<tid>/mem`
/// (a FOLL_FORCE write, so a read-only text page is written through a private
/// copy), then reads them back.
///
/// Returns the bytes read back. `skip_write` (tests only) leaves the page
/// untouched so that the readback check can be shown to fire.
pub(crate) fn write_site(
    tid: nix::unistd::Pid,
    site: u64,
    bytes: [u8; 2],
    skip_write: bool,
) -> Result<(), anyhow::Error> {
    use std::os::unix::fs::FileExt;
    let mem = proc_mem(tid, true)?;
    if !skip_write {
        mem.write_all_at(&bytes, site)?;
    }
    let mut found = [0u8; 2];
    mem.read_exact_at(&mut found, site)?;
    if found != bytes {
        return Err(anyhow::Error::new(TrapOnlyFailure::PatchReadback {
            site,
            wrote: bytes,
            found,
        }));
    }
    Ok(())
}

/// The bytes that restoring a patched site whose original bytes are
/// `original` should leave, given the bytes `found` there now: each byte that
/// still holds the patch goes back to its original value, and any other byte
/// is the guest's own and stays.
pub(crate) fn restored_bytes(found: [u8; 2], original: [u8; 2]) -> [u8; 2] {
    [0, 1].map(|i| {
        if found[i] == PATCHED_BYTES[i] {
            original[i]
        } else {
            found[i]
        }
    })
}

/// Restores one patched site in a stopped tracee: reads the site first,
/// writes only when a byte of the patch is still there (see
/// [`restored_bytes`]), and reads the write back.
pub(crate) fn restore_site(
    tid: nix::unistd::Pid,
    site: u64,
    original: [u8; 2],
) -> Result<(), anyhow::Error> {
    let found = read_site(tid, site)?;
    let bytes = restored_bytes(found, original);
    if bytes == found {
        return Ok(());
    }
    write_site(tid, site, bytes, false)
}

/// Checks that `site` is inside a mapping that is private, executable and not
/// writable (`r-xp`) in `/proc/<tid>/maps`.
pub(crate) fn site_mapping_is_patchable(
    tid: nix::unistd::Pid,
    site: u64,
) -> Result<Result<(), PatchDecline>, std::io::Error> {
    let maps = std::fs::read_to_string(format!("/proc/{tid}/maps"))?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        // The two bytes must both lie in the mapping.
        if start <= site && site + 2 <= end {
            return Ok(if perms == "r-xp" {
                Ok(())
            } else {
                Err(PatchDecline::Mapping(line.to_owned()))
            });
        }
    }
    Ok(Err(PatchDecline::Mapping(format!(
        "no single mapping holds {site:#x}..{:#x}",
        site + 2
    ))))
}

/// Test-only controls for a trap-only run.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct TrapOnlyTestHooks {
    /// Skip every patch write, so the readback finds the original bytes.
    pub(crate) skip_patch_write: std::sync::atomic::AtomicBool,
    /// Drop the clone flags recorded at every creating stop, as if a Tool
    /// had injected the clone, so that each new-child stop takes the
    /// undecided path.
    pub(crate) forget_clone_flags: std::sync::atomic::AtomicBool,
    /// Flip `CLONE_VM` in the clone flags recorded at every creating stop,
    /// as seen by the new-child stop only, so that they disagree with
    /// `kcmp(KCMP_VM)`: a real fork is recorded as sharing the address
    /// space, a real thread as not sharing it. The creating stop itself
    /// still acts on the real flags.
    pub(crate) flip_recorded_clone_vm: std::sync::atomic::AtomicBool,
    /// Flip `CLONE_VFORK` in the clone flags recorded at every creating
    /// stop, as seen by the new-child stop only, so that they disagree with
    /// the kind of new-child stop that arrives: a real fork or thread is
    /// recorded as a vfork, a real vfork as not one. The creating stop
    /// itself still acts on the real flags.
    pub(crate) flip_recorded_clone_vfork: std::sync::atomic::AtomicBool,
    /// Make H4 see the slot exit stop's rip one byte past where the kernel
    /// left it (the tracee is not changed), to exercise `TrapOnlyHopExitRip`.
    pub(crate) displace_hop_exit_rip: std::sync::atomic::AtomicBool,
    /// Every table the run created after the root one, labelled by how
    /// (`fork`, `share`, `exec`), so a test can inspect non-root tables.
    pub(crate) tables: Mutex<Vec<(String, Arc<Mutex<SiteTable>>)>>,
    /// Lifecycle decisions, in order.
    pub(crate) log: Mutex<Vec<String>>,
}

#[cfg(test)]
impl TrapOnlyTestHooks {
    pub(crate) fn record_table(&self, label: String, table: &Arc<Mutex<SiteTable>>) {
        self.tables.lock().unwrap().push((label, Arc::clone(table)));
    }

    pub(crate) fn record(&self, event: String) {
        self.log.lock().unwrap().push(event);
    }
}

/// Configuration shared by every task of a trap-only run.
#[derive(Debug)]
pub(crate) struct TrapOnlyShared {
    /// The tool subscribes to every syscall except `rt_sigreturn`, which the
    /// filter always allows. Patching needs it: a patched site must never
    /// carry a number that plain ptrace would run without a stop.
    pub(crate) full_subscription: bool,
    #[cfg(test)]
    pub(crate) hooks: Arc<TrapOnlyTestHooks>,
}

/// Trap-only state of one traced task.
#[derive(Debug)]
pub(crate) struct TrapOnlyTask {
    /// The site table of this task's address space.
    pub(crate) sites: Arc<Mutex<SiteTable>>,
    pub(crate) shared: Arc<TrapOnlyShared>,
    /// The normalized registers of the patched-site stop this task is parked
    /// at, until its syscall has been consumed (by the hop, by a skip, or by a
    /// failure). While it is set the task must not be resumed from that stop
    /// with its syscall number intact.
    pub(crate) live_entry: Option<libc::user_regs_struct>,
    /// Registers to restore into both tasks of a new-child stop that a hop
    /// returned to the run loop.
    pub(crate) new_child_view: Option<libc::user_regs_struct>,
    /// Set while the masked hop runs; the hop must never single-step.
    pub(crate) in_hop: bool,
    /// The clone flags of the task-creating syscall this task is parked at,
    /// decoded at its creating stop; consumed by the new-child stop.
    pub(crate) pending_clone_flags: Option<u64>,
    /// Set when a timer single-step ended at this task's current seccomp
    /// stop, and consumed by H0, which must then refuse an Allow-class
    /// number (O4 rule 4). The r11 H0 builds does not depend on it: plain
    /// ptrace's timer clears the TF that the stepped `syscall` saved in r11.
    pub(crate) stepped_entry: bool,
    /// The SIGSTOPs the masked hop dequeued at its slot and re-raised at H3
    /// (P2-SPEC O1.4), at most one per signal queue, until the re-raised
    /// SIGSTOP's delivery stop, identified by its tag, restores the original
    /// siginfo. Cleared at this task's next seccomp stop: a re-raised SIGSTOP
    /// is delivered before the thread returns to user mode, so one still here
    /// when the thread next enters a syscall was discarded by a SIGCONT, as
    /// the original would have been. (Event stops such as an exec's come
    /// before the delivery and keep it.) An entry is only ever applied to a
    /// delivery stop carrying its own tag, so one that outlives its SIGSTOP
    /// cannot rewrite another SIGSTOP's siginfo.
    pub(crate) reraised_stops: Vec<ReraisedStop>,
}

/// A SIGSTOP the masked hop suppressed at its slot stop and re-raised.
#[derive(Clone, Copy)]
pub(crate) struct ReraisedStop {
    /// The tag the re-raised SIGSTOP carries as its `si_value` (it is sent
    /// with `si_code` `SI_QUEUE` and the tracer's pid).
    pub(crate) tag: u64,
    /// The siginfo of the original SIGSTOP's delivery stop.
    pub(crate) info: libc::siginfo_t,
}

impl std::fmt::Debug for ReraisedStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReraisedStop")
            .field("tag", &self.tag)
            .field("si_signo", &self.info.si_signo)
            .field("si_code", &self.info.si_code)
            .finish()
    }
}

impl TrapOnlyTask {
    pub(crate) fn root(sites: Arc<Mutex<SiteTable>>, shared: Arc<TrapOnlyShared>) -> Self {
        Self {
            sites,
            shared,
            live_entry: None,
            new_child_view: None,
            in_hop: false,
            pending_clone_flags: None,
            stepped_entry: false,
            reraised_stops: Vec::new(),
        }
    }

    /// State for a new task: shares the table when it shares the address
    /// space, and otherwise copies it (the patched bytes are already in the
    /// child's copy of the text).
    pub(crate) fn child(&self, shares_address_space: bool) -> Self {
        let sites = if shares_address_space {
            Arc::clone(&self.sites)
        } else {
            Arc::new(Mutex::new(self.lock().clone()))
        };
        #[cfg(test)]
        self.shared.hooks.record_table(
            if shares_address_space {
                "share"
            } else {
                "fork"
            }
            .to_owned(),
            &sites,
        );
        Self::root(sites, Arc::clone(&self.shared))
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, SiteTable> {
        self.sites
            .lock()
            .expect("LiteInst trap-only site table lock poisoned")
    }

    /// Disables further patching of the address space and restores every
    /// live site through each of `tids` (reading each write back). Returns
    /// the number of sites restored.
    pub(crate) fn retire_all(
        &self,
        tids: &[nix::unistd::Pid],
        site_reason: RetiredReason,
        table_reason: DisabledReason,
    ) -> Result<usize, anyhow::Error> {
        let mut table = self.lock();
        table.disable(table_reason);
        table.restore_sites(tids, &[ALL_ADDRESSES], site_reason)
    }
}

/// Trap-only launch configuration carried by a `TracerBuilder`.
#[derive(Clone, Debug)]
pub(crate) struct LiteinstTrapOnlyConfig {
    pub(crate) root_sites: Arc<Mutex<SiteTable>>,
    pub(crate) instrumentation_stats: Option<Arc<Mutex<LiteinstInstrumentationStats>>>,
    #[cfg(test)]
    pub(crate) ia32_probe_override: Option<Ia32EmulationProbe>,
    #[cfg(test)]
    pub(crate) hooks: Arc<TrapOnlyTestHooks>,
}

impl LiteinstTrapOnlyConfig {
    pub(crate) fn new(patching: SitePatching, collect_stats: bool) -> Self {
        Self {
            root_sites: Arc::new(Mutex::new(SiteTable::new(patching))),
            instrumentation_stats: collect_stats
                .then(|| Arc::new(Mutex::new(LiteinstInstrumentationStats::default()))),
            #[cfg(test)]
            ia32_probe_override: None,
            #[cfg(test)]
            hooks: Arc::default(),
        }
    }

    /// The root task's trap-only state for a run whose tool subscribes to
    /// `events`.
    pub(crate) fn root_task(&self, events: &reverie::Subscription) -> TrapOnlyTask {
        let full_subscription = has_full_subscription(events);
        if !full_subscription {
            self.root_sites
                .lock()
                .expect("LiteInst trap-only site table lock poisoned")
                .disable(DisabledReason::PartialSubscription);
        }
        TrapOnlyTask::root(
            Arc::clone(&self.root_sites),
            Arc::new(TrapOnlyShared {
                full_subscription,
                #[cfg(test)]
                hooks: Arc::clone(&self.hooks),
            }),
        )
    }

    /// Returns the patching state of the root address space.
    pub(crate) fn patching(&self) -> SitePatching {
        self.root_sites
            .lock()
            .expect("LiteInst trap-only site table lock poisoned")
            .patching()
    }

    /// Returns the IA-32 syscall-entry probe result for this launch.
    pub(crate) fn ia32_probe(&self) -> Ia32EmulationProbe {
        #[cfg(test)]
        if let Some(probe) = self.ia32_probe_override.clone() {
            return probe;
        }
        probe_ia32_emulation()
    }
}

/// Whether `events` subscribes to every syscall except `rt_sigreturn` (which
/// the filter always allows).
pub(crate) fn has_full_subscription(events: &reverie::Subscription) -> bool {
    let subscribed = events
        .iter_syscalls()
        .collect::<std::collections::BTreeSet<_>>();
    reverie::syscalls::Sysno::iter()
        .filter(|nr| *nr != reverie::syscalls::Sysno::rt_sigreturn)
        .all(|nr| subscribed.contains(&nr))
}

/// Observer for the trap-only state of a running tracer.
#[derive(Clone, Debug)]
pub struct LiteinstTrapOnlyHandle {
    root_sites: Arc<Mutex<SiteTable>>,
    #[cfg(test)]
    hooks: Arc<TrapOnlyTestHooks>,
}

impl LiteinstTrapOnlyHandle {
    pub(crate) fn from_config(config: &LiteinstTrapOnlyConfig) -> Self {
        Self {
            root_sites: Arc::clone(&config.root_sites),
            #[cfg(test)]
            hooks: Arc::clone(&config.hooks),
        }
    }

    /// The run's test hooks: every non-root table and the lifecycle log.
    #[cfg(test)]
    pub(crate) fn hooks(&self) -> &TrapOnlyTestHooks {
        &self.hooks
    }

    /// Returns the patching state of the root address space.
    pub fn patching(&self) -> SitePatching {
        self.lock().patching()
    }

    /// Returns the number of sites currently patched in the root address space.
    pub fn patched_sites(&self) -> usize {
        self.lock().patched_sites()
    }

    /// Returns whether the root address space still accepts new sites, and
    /// if not, why.
    #[cfg(test)]
    pub(crate) fn table_state(&self) -> TableState {
        self.lock().state()
    }

    /// A copy of the root address space's table.
    #[cfg(test)]
    pub(crate) fn root_table(&self) -> SiteTable {
        self.lock().clone()
    }

    /// Returns the state of one site of the root address space.
    #[cfg(test)]
    pub(crate) fn site_state(&self, site: u64) -> Option<SiteState> {
        self.lock().site_state(site)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, SiteTable> {
        self.root_sites
            .lock()
            .expect("LiteInst trap-only site table lock poisoned")
    }
}

/// Result of probing whether this host services `int 0x80` from 64-bit code.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Ia32EmulationProbe {
    /// An `int 0x80` getpid returned the caller's PID and changed none of
    /// rcx, r8, r9, r10 and r11.
    Available,
    /// An `int 0x80` getpid returned the caller's PID but changed one of rcx,
    /// r8, r9, r10 and r11; the text names the register. The entry is usable
    /// for a run that never patches a site, but not for site patching, which
    /// relies on the entry leaving those registers alone.
    ClobbersRegisters(String),
    /// `int 0x80` is not serviced; the text says what the probe observed.
    Unavailable(String),
}

/// A trap-only LiteInst launch was refused because `int 0x80` is unusable.
///
/// Trap-only patching routes later executions of a site through the IA-32
/// syscall entry. Without `CONFIG_IA32_EMULATION`, or with it disabled by the
/// `ia32_emulation=` boot parameter, that entry faults. The launch fails
/// closed instead of running plain ptrace under the LiteInst label.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error(
    "LiteInst trap-only launch refused: IA-32 syscall emulation (int 0x80) is unavailable \
     on this host, which requires CONFIG_IA32_EMULATION and no ia32_emulation=false boot \
     parameter ({observation})"
)]
pub struct Ia32EmulationUnavailable {
    /// What the probe observed.
    pub observation: String,
}

/// A trap-only LiteInst launch with site patching was refused because this
/// host's `int 0x80` entry changes a register that a patched site needs
/// preserved.
///
/// A patched site runs its syscall through `int 0x80`, and the guest resumes
/// with whatever that entry left in rcx and r8-r11, so site patching needs an
/// IA-32 entry that preserves rcx, r8, r9, r10 and r11, as the probe measures.
/// A launch without site patching never executes a patched site and is not
/// refused for this.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("LiteInst trap-only launch with site patching {patching} refused: {observation}")]
pub struct Ia32EntryClobbersRegisters {
    /// The patching state that needs the registers preserved.
    pub patching: SitePatching,
    /// What the probe observed, starting with the changed register.
    pub observation: String,
}

/// Converts a probe result into the trap-only admission decision for a launch
/// with the given patching state.
///
/// A missing IA-32 entry refuses every trap-only launch
/// ([`Ia32EmulationUnavailable`]). An entry that changes rcx or r8-r11 refuses
/// only a launch that rewrites sites ([`Ia32EntryClobbersRegisters`]).
pub(crate) fn require_ia32_emulation(
    probe: Ia32EmulationProbe,
    patching: SitePatching,
) -> Result<(), anyhow::Error> {
    match probe {
        Ia32EmulationProbe::Available => Ok(()),
        Ia32EmulationProbe::ClobbersRegisters(_) if !patching.rewrites_sites() => Ok(()),
        Ia32EmulationProbe::ClobbersRegisters(observation) => {
            Err(anyhow::Error::new(Ia32EntryClobbersRegisters {
                patching,
                observation,
            }))
        }
        Ia32EmulationProbe::Unavailable(observation) => {
            Err(anyhow::Error::new(Ia32EmulationUnavailable { observation }))
        }
    }
}

/// Probes whether `int 0x80` is serviced for a task created by the calling
/// thread.
///
/// Two things decide the answer. The kernel's IA-32 syscall entry
/// (`CONFIG_IA32_EMULATION` and the `ia32_emulation=` boot parameter) is the
/// same for every thread and cannot change while this process runs. A seccomp
/// filter is per thread, is inherited by every task the thread creates
/// (including the guest), and may allow, fail, trap or kill an IA-32 syscall.
///
/// A thread with no seccomp filter runs the probe itself, on the calling
/// thread, and creates no task: no filter can answer its `int 0x80`, and a
/// fault is caught. (The one way a filter could appear on this thread
/// meanwhile is another thread installing one with
/// `SECCOMP_FILTER_FLAG_TSYNC` between the check and the instruction.) Its
/// first definitive answer is cached for later unfiltered callers.
/// A probe that could not run (for example, because installing its signal
/// handler failed) is reported but not cached, so a later launch probes again.
///
/// A thread under a seccomp filter must not execute `int 0x80` itself: a
/// filter that answers with `SECCOMP_RET_KILL_PROCESS` would kill this process,
/// and `SECCOMP_RET_KILL_THREAD` would kill the calling thread. Such a thread
/// probes in a child instead (see `probe_in_child` below), and its answer is
/// never read from or stored in the cache, because it describes this thread's
/// filter and not the kernel.
///
/// No path takes a PID from the guest's PID sequence. That matters because an
/// embedder may call this from inside the guest's PID namespace: a probe child
/// with an ordinary PID would shift every guest PID by one relative to a
/// plain-ptrace run.
pub fn probe_ia32_emulation() -> Ia32EmulationProbe {
    #[cfg(target_arch = "x86_64")]
    if let Some(filter) = calling_thread_seccomp_filter() {
        return probe_in_child::run(&filter, &boot_parameter_note());
    }
    static PROBE: Mutex<Option<Ia32EmulationProbe>> = Mutex::new(None);
    let mut cached = PROBE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(probe) = cached.as_ref() {
        return probe.clone();
    }
    let (probe, definitive) = probe_ia32_emulation_unfiltered();
    if definitive {
        *cached = Some(probe.clone());
    }
    probe
}

#[cfg(not(target_arch = "x86_64"))]
fn probe_ia32_emulation_unfiltered() -> (Ia32EmulationProbe, bool) {
    (
        Ia32EmulationProbe::Unavailable("int 0x80 exists only on x86_64 hosts".into()),
        true,
    )
}

/// Describes the calling thread's seccomp filter, or returns `None` when it
/// has none.
///
/// `prctl(PR_GET_SECCOMP)` reports the calling thread's own mode. A result
/// other than 0 (disabled), including a failure of the call itself, is treated
/// as filtered: absence of a filter must be proven before `int 0x80` runs in
/// this process.
#[cfg(target_arch = "x86_64")]
fn calling_thread_seccomp_filter() -> Option<String> {
    // SAFETY: PR_GET_SECCOMP reads the calling thread's seccomp mode.
    match unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } {
        0 => None,
        -1 => Some(format!(
            "the calling thread's seccomp mode is unknown (prctl(PR_GET_SECCOMP) failed: {})",
            std::io::Error::last_os_error()
        )),
        mode => Some(format!(
            "the calling thread runs under seccomp (PR_GET_SECCOMP mode {mode})"
        )),
    }
}

/// Executes an IA-32 `getpid` through `int 0x80` on the calling thread, which
/// must have no seccomp filter.
///
/// A missing IA-32 entry raises a general-protection fault (`SIGSEGV`; a
/// not-present gate would raise `SIGBUS`). A temporary handler for these
/// signals catches the fault on this thread only, steps over the instruction,
/// and records the signal. Returns the probe result and whether it is
/// definitive (cacheable).
#[cfg(target_arch = "x86_64")]
fn probe_ia32_emulation_unfiltered() -> (Ia32EmulationProbe, bool) {
    if let Some(filter) = calling_thread_seccomp_filter() {
        // Callers check first; refuse rather than risk this process.
        return (
            Ia32EmulationProbe::Unavailable(format!(
                "the in-process probe refused to run because {filter}"
            )),
            false,
        );
    }
    // SAFETY: `int80_getpid` executes only `int 0x80`, which the guard
    // expects.
    match unsafe { guarded_fault::run(int80_getpid) } {
        Ok((fault, outcome)) => {
            let expected = unsafe { libc::syscall(libc::SYS_getpid) } as u64;
            (
                classify_probe_outcome(fault, outcome, expected, &boot_parameter_note()),
                true,
            )
        }
        Err(reason) => (
            Ia32EmulationProbe::Unavailable(format!("the probe could not run: {reason}")),
            false,
        ),
    }
}

#[cfg(target_arch = "x86_64")]
fn signal_name(signal: libc::c_int) -> &'static str {
    match signal {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGSYS => "SIGSYS",
        libc::SIGKILL => "SIGKILL",
        _ => "a signal",
    }
}

#[cfg(target_arch = "x86_64")]
fn classify_probe_outcome(
    fault: Option<libc::c_int>,
    outcome: Int80Getpid,
    expected: u64,
    boot_note: &str,
) -> Ia32EmulationProbe {
    let result = outcome.rax;
    match fault {
        None if result != expected => Ia32EmulationProbe::Unavailable(format!(
            "int 0x80 getpid returned {result:#x}, not the caller's PID {expected}{boot_note}"
        )),
        None => match outcome.first_clobbered() {
            None => Ia32EmulationProbe::Available,
            Some((name, sentinel, found)) => Ia32EmulationProbe::ClobbersRegisters(format!(
                "int 0x80 getpid changed {name} from {sentinel:#x} to {found:#x}; trap-only \
                 patching needs an IA-32 entry that preserves rcx, r8, r9, r10 and r11{boot_note}"
            )),
        },
        Some(signal) => Ia32EmulationProbe::Unavailable(format!(
            "int 0x80 getpid raised {} ({signal}){boot_note}",
            signal_name(signal)
        )),
    }
}

/// Names of the registers the probe requires `int 0x80` to preserve, in the
/// order of [`Int80Getpid::preserved`].
///
/// Trap-only patching turns a guest `syscall` into `int 0x80`. The guest then
/// continues with whatever the IA-32 entry left in these registers, so the
/// tracer can present the `syscall`-shaped values (rcx = next rip,
/// r11 = rflags) only if the entry itself changes none of them. The probe
/// measures this on the host rather than inferring it from a kernel version,
/// and an entry that changes any of them refuses site patching.
#[cfg(target_arch = "x86_64")]
const PRESERVED_REGISTERS: [&str; 5] = ["rcx", "r8", "r9", "r10", "r11"];

/// Distinct values loaded into [`PRESERVED_REGISTERS`] before the probe's
/// `int 0x80`.
#[cfg(target_arch = "x86_64")]
const PRESERVED_SENTINELS: [u64; 5] = [
    0x5e17_1ce0_0000_0c0c,
    0x5e17_1ce0_0000_0008,
    0x5e17_1ce0_0000_0009,
    0x5e17_1ce0_0000_0010,
    0x5e17_1ce0_0000_0011,
];

/// What the probe's `int 0x80` getpid left behind.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Int80Getpid {
    /// The syscall result (`u64::MAX` if the instruction faulted).
    rax: u64,
    /// rcx, r8, r9, r10 and r11 after the instruction; each held its
    /// [`PRESERVED_SENTINELS`] value before it.
    preserved: [u64; 5],
}

#[cfg(target_arch = "x86_64")]
impl Int80Getpid {
    /// The first preserved register the instruction changed, as its name,
    /// sentinel and the value found.
    fn first_clobbered(&self) -> Option<(&'static str, u64, u64)> {
        (0..PRESERVED_REGISTERS.len())
            .find(|&index| self.preserved[index] != PRESERVED_SENTINELS[index])
            .map(|index| {
                (
                    PRESERVED_REGISTERS[index],
                    PRESERVED_SENTINELS[index],
                    self.preserved[index],
                )
            })
    }

    const SIZE: usize = 8 * 6;

    fn to_bytes(self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..8].copy_from_slice(&self.rax.to_ne_bytes());
        for (index, value) in self.preserved.iter().enumerate() {
            bytes[8 * (index + 1)..8 * (index + 2)].copy_from_slice(&value.to_ne_bytes());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Self {
        let word = |index: usize| {
            u64::from_ne_bytes(bytes[8 * index..8 * (index + 1)].try_into().unwrap())
        };
        Self {
            rax: word(0),
            preserved: [word(1), word(2), word(3), word(4), word(5)],
        }
    }
}

/// The production probe: IA-32 `getpid` (number 20) through `int 0x80`, with
/// [`PRESERVED_SENTINELS`] in rcx and r8-r11 across the instruction.
#[cfg(target_arch = "x86_64")]
unsafe fn int80_getpid() -> Int80Getpid {
    const IA32_NR_GETPID: u64 = 20;
    let rax: u64;
    let mut preserved = PRESERVED_SENTINELS;
    // SAFETY: `int 0x80` either runs the IA-32 getpid, which touches no
    // memory, or faults. In process the fault reaches `guarded_fault`, which
    // steps over it; in the probe child it terminates the child. Every
    // register the entry might change is an operand.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("rax") IA32_NR_GETPID => rax,
            inlateout("rcx") preserved[0],
            inlateout("r8") preserved[1],
            inlateout("r9") preserved[2],
            inlateout("r10") preserved[3],
            inlateout("r11") preserved[4],
            options(nostack),
        );
    }
    Int80Getpid { rax, preserved }
}

/// Probes `int 0x80` in a child whose PID is chosen, for a calling thread
/// under a seccomp filter.
///
/// The child inherits the calling thread's filters, so it observes exactly
/// what the guest would: a kill or trap terminates the child with `SIGSYS`,
/// an errno comes back as a wrong result, and an allowed call returns the
/// child's PID. Nothing it does can reach this process.
///
/// The child is created with `clone3` and `set_tid`, which places it at a
/// caller-chosen PID near `pid_max` in this thread's PID namespace. The kernel
/// allocates a `set_tid` PID without advancing the namespace's next-PID
/// cursor, so the guest's PIDs are the same as if no child had existed.
/// `set_tid` requires `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN` over the PID
/// namespace, which a tracer that created its own user and PID namespace (as
/// Hermit does) has. Without it the probe fails closed with the reason; it
/// never falls back to an ordinary child that would take the next PID.
#[cfg(target_arch = "x86_64")]
mod probe_in_child {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;
    use std::os::fd::OwnedFd;

    use super::Ia32EmulationProbe;
    use super::Int80Getpid;
    use super::classify_probe_outcome;
    use super::signal_name;

    /// `struct clone_args` up to `set_tid_size` (`CLONE_ARGS_SIZE_VER1`, Linux
    /// 5.5), the first version with `set_tid`.
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
    }

    /// PIDs tried, counting down from `pid_max - 1`, before giving up on
    /// finding a free one.
    const CANDIDATE_PIDS: libc::pid_t = 64;

    pub(super) fn run(filter: &str, boot_note: &str) -> Ia32EmulationProbe {
        let refuse = |what: String| {
            Ia32EmulationProbe::Unavailable(format!(
                "{filter}, so int 0x80 must be probed in a child, and {what}"
            ))
        };
        let pid_max = std::fs::read_to_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|text| text.trim().parse::<libc::pid_t>().ok())
            .unwrap_or(32768);
        let mut fds = [0; 2];
        // SAFETY: pipe2 writes two descriptors into `fds`.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return refuse(format!(
                "its result pipe could not be created: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: both descriptors were just created and are owned here.
        let (reader, writer) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

        let mut child = None;
        let lowest = (pid_max - CANDIDATE_PIDS).max(2);
        for tid in (lowest..pid_max).rev() {
            let chosen: libc::pid_t = tid;
            let args = CloneArgs {
                exit_signal: libc::SIGCHLD as u64,
                set_tid: &chosen as *const libc::pid_t as u64,
                set_tid_size: 1,
                ..CloneArgs::default()
            };
            // SAFETY: fork semantics (no CLONE_VM). The child runs only
            // `child_main`, which is async-signal-safe and never returns.
            let pid = unsafe {
                libc::syscall(
                    libc::SYS_clone3,
                    &args as *const CloneArgs,
                    std::mem::size_of::<CloneArgs>(),
                )
            };
            if pid == 0 {
                unsafe { child_main(writer.as_raw_fd()) }
            }
            if pid > 0 {
                child = Some(pid as libc::pid_t);
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return refuse(format!(
                    "creating that child at a chosen PID (clone3 with set_tid {chosen}, which \
                     needs CAP_CHECKPOINT_RESTORE or CAP_SYS_ADMIN over this PID namespace) \
                     failed: {error}"
                ));
            }
        }
        let Some(child) = child else {
            return refuse(format!(
                "no PID in {lowest}..{pid_max} was free for the probe child"
            ));
        };
        drop(writer);

        // The child's `Int80Getpid`, then its own PID from an ordinary getpid.
        let mut bytes = [0u8; Int80Getpid::SIZE + 8];
        let mut filled = 0;
        while filled < bytes.len() {
            // SAFETY: reads into the unfilled tail of `bytes`.
            let n = unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    bytes[filled..].as_mut_ptr().cast(),
                    bytes.len() - filled,
                )
            };
            if n > 0 {
                filled += n as usize;
            } else if n == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break;
            }
        }
        let mut status = 0;
        loop {
            // SAFETY: waits for the child created above.
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            if waited == child {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return refuse(format!("waiting for the probe child failed: {error}"));
            }
        }

        if libc::WIFSIGNALED(status) {
            let signal = libc::WTERMSIG(status);
            return Ia32EmulationProbe::Unavailable(format!(
                "int 0x80 getpid killed the probe child with {} ({signal}); {filter}{boot_note}",
                signal_name(signal)
            ));
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 && filled == bytes.len() {
            let outcome = Int80Getpid::from_bytes(bytes[..Int80Getpid::SIZE].try_into().unwrap());
            let expected = u64::from_ne_bytes(bytes[Int80Getpid::SIZE..].try_into().unwrap());
            return match classify_probe_outcome(None, outcome, expected, boot_note) {
                Ia32EmulationProbe::Available => Ia32EmulationProbe::Available,
                Ia32EmulationProbe::ClobbersRegisters(text) => {
                    Ia32EmulationProbe::ClobbersRegisters(format!("{text}; {filter}"))
                }
                Ia32EmulationProbe::Unavailable(text) => {
                    Ia32EmulationProbe::Unavailable(format!("{text}; {filter}"))
                }
            };
        }
        refuse(format!(
            "the probe child ended with wait status {status:#x} after sending {filled} of {} \
             result bytes",
            bytes.len()
        ))
    }

    /// Runs in the probe child, a fork of a possibly multithreaded process:
    /// only async-signal-safe calls.
    unsafe fn child_main(writer: libc::c_int) -> ! {
        unsafe {
            // A fault or trap must terminate the child with its own signal,
            // neither running an inherited handler nor dumping core.
            let mut unblock: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut unblock);
            for signal in [libc::SIGSEGV, libc::SIGBUS, libc::SIGSYS] {
                libc::signal(signal, libc::SIG_DFL);
                libc::sigaddset(&mut unblock, signal);
            }
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            let outcome = super::int80_getpid();
            let expected = libc::syscall(libc::SYS_getpid) as u64;
            let mut bytes = [0u8; Int80Getpid::SIZE + 8];
            bytes[..Int80Getpid::SIZE].copy_from_slice(&outcome.to_bytes());
            bytes[Int80Getpid::SIZE..].copy_from_slice(&expected.to_ne_bytes());
            libc::write(writer, bytes.as_ptr().cast(), bytes.len());
            libc::_exit(0)
        }
    }
}

/// Runs one `int` instruction on the calling thread with its fault caught.
#[cfg(target_arch = "x86_64")]
mod guarded_fault {
    use std::cell::UnsafeCell;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicI32;
    use std::sync::atomic::AtomicI64;
    use std::sync::atomic::Ordering;

    /// The faults a missing IA-32 entry raises. `SIGSYS` is deliberately
    /// absent: the guard runs only on a thread without a seccomp filter, so no
    /// filter answers its `int 0x80` with a trap, and taking over the process-wide `SIGSYS`
    /// disposition would intercept a seccomp trap meant for another thread.
    /// Such a trap reports the address after the syscall, so it does not
    /// recur when a handler returns, and forwarding it could lose it.
    const SIGNALS: [libc::c_int; 2] = [libc::SIGSEGV, libc::SIGBUS];

    /// Value placed in `rax` when the instruction faults.
    const FAULTED: u64 = u64::MAX;

    /// Thread id of the thread inside `run`'s guarded instruction, or 0.
    static ARMED_TID: AtomicI64 = AtomicI64::new(0);
    /// Signal that interrupted the guarded instruction, or 0.
    static FAULT_SIGNAL: AtomicI32 = AtomicI32::new(0);
    /// Serializes `run`, which swaps process-wide signal dispositions.
    static RUN: Mutex<()> = Mutex::new(());

    struct Previous(UnsafeCell<[libc::sigaction; SIGNALS.len()]>);
    // SAFETY: written only while `RUN` is held and before the handler that
    // reads it is installed; read only by that handler.
    unsafe impl Sync for Previous {}
    static PREVIOUS: Previous = Previous(UnsafeCell::new(unsafe { std::mem::zeroed() }));

    /// Runs `instruction`, which must execute exactly one two-byte `int imm8`
    /// and report `rax` in its result, with `SIGSEGV` and `SIGBUS` caught on
    /// this thread. Returns the signal that interrupted it, if any, and the
    /// instruction's result (whose `rax` is `u64::MAX` after a fault).
    ///
    /// A fault on any other thread in the meantime is passed to the
    /// disposition that was installed before, so this never swallows a real
    /// crash elsewhere in the process.
    pub(super) unsafe fn run<T>(
        instruction: unsafe fn() -> T,
    ) -> Result<(Option<libc::c_int>, T), String> {
        let _serial = RUN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = PREVIOUS.0.get();
        let mut handler: libc::sigaction = unsafe { std::mem::zeroed() };
        handler.sa_sigaction = on_fault as *const () as usize;
        handler.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        unsafe { libc::sigemptyset(&mut handler.sa_mask) };

        let mut installed = 0;
        let mut failure = None;
        for (index, signal) in SIGNALS.into_iter().enumerate() {
            // SAFETY: `previous` is only read by `on_fault`, which cannot run
            // for `signal` until this call installs it.
            let slot = unsafe { &mut (*previous)[index] };
            if unsafe { libc::sigaction(signal, &handler, slot) } != 0 {
                failure = Some(format!(
                    "sigaction({signal}) failed: {}",
                    std::io::Error::last_os_error()
                ));
                break;
            }
            installed += 1;
        }

        let mut outcome: Result<(Option<libc::c_int>, T), String> = Err(String::new());
        if failure.is_none() {
            // A blocked synchronous fault would kill the process instead of
            // reaching the handler.
            let mut unblock: libc::sigset_t = unsafe { std::mem::zeroed() };
            let mut saved_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut unblock);
                for signal in SIGNALS {
                    libc::sigaddset(&mut unblock, signal);
                }
            }
            let masked =
                unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, &mut saved_mask) };
            if masked != 0 {
                failure = Some(format!(
                    "pthread_sigmask failed: {}",
                    std::io::Error::from_raw_os_error(masked)
                ));
            } else {
                FAULT_SIGNAL.store(0, Ordering::SeqCst);
                ARMED_TID.store(unsafe { libc::syscall(libc::SYS_gettid) }, Ordering::SeqCst);
                let result = unsafe { instruction() };
                ARMED_TID.store(0, Ordering::SeqCst);
                let signal = FAULT_SIGNAL.swap(0, Ordering::SeqCst);
                outcome = Ok(((signal != 0).then_some(signal), result));
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &saved_mask, std::ptr::null_mut())
                };
            }
        }

        for (index, signal) in SIGNALS.into_iter().enumerate().take(installed) {
            let slot = unsafe { &(*previous)[index] };
            unsafe { libc::sigaction(signal, slot, std::ptr::null_mut()) };
        }
        match failure {
            Some(reason) => Err(reason),
            None => outcome,
        }
    }

    extern "C" fn on_fault(
        signal: libc::c_int,
        info: *mut libc::siginfo_t,
        context: *mut libc::c_void,
    ) {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        if tid == ARMED_TID.load(Ordering::SeqCst) {
            // SAFETY: the kernel passes a valid ucontext for SA_SIGINFO, and
            // on this thread the interrupted instruction is the guarded
            // `int imm8` in our own text, so reading its first byte is safe.
            unsafe {
                let context = &mut *context.cast::<libc::ucontext_t>();
                let gregs = &mut context.uc_mcontext.gregs;
                let rip = gregs[libc::REG_RIP as usize];
                // A fault reports the address of the `int`.
                if *(rip as *const u8) == 0xcd {
                    gregs[libc::REG_RIP as usize] = rip + 2;
                }
                gregs[libc::REG_RAX as usize] = FAULTED as i64;
            }
            FAULT_SIGNAL.store(signal, Ordering::SeqCst);
            return;
        }
        // SAFETY: the saved disposition was written before this handler
        // was installed.
        unsafe { forward(signal, info, context) };
    }

    /// Passes a fault that is not ours to the disposition saved by `run`.
    unsafe fn forward(signal: libc::c_int, info: *mut libc::siginfo_t, context: *mut libc::c_void) {
        let Some(index) = SIGNALS.iter().position(|&candidate| candidate == signal) else {
            return;
        };
        let previous = unsafe { &(*PREVIOUS.0.get())[index] };
        let action = previous.sa_sigaction;
        if action == libc::SIG_DFL || action == libc::SIG_IGN {
            // Reinstall the old disposition and re-raise the signal (it stays
            // blocked until this handler returns), so that it is not lost. A
            // synchronous fault would also re-execute and meet the old
            // disposition, but not every kernel-generated signal recurs (an
            // asynchronous BUS_MCEERR_AO does not), so under SIG_DFL the
            // signal is always re-raised. Under SIG_IGN a sent signal is
            // discarded as it would have been, and a fault re-executes and is
            // forced by the kernel.
            unsafe {
                libc::sigaction(signal, previous, std::ptr::null_mut());
                if action == libc::SIG_DFL || info.is_null() || (*info).si_code <= 0 {
                    libc::raise(signal);
                }
            }
        } else if previous.sa_flags & libc::SA_SIGINFO != 0 {
            let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                unsafe { std::mem::transmute(action) };
            handler(signal, info, context);
        } else {
            let handler: extern "C" fn(libc::c_int) = unsafe { std::mem::transmute(action) };
            handler(signal);
        }
    }

    /// Test-only instruction: `int 0x81` has no user-accessible gate, so it
    /// always raises a general-protection fault (`SIGSEGV`).
    #[cfg(test)]
    pub(super) unsafe fn int81() -> u64 {
        let result: u64;
        unsafe {
            core::arch::asm!(
                "int 0x81",
                inlateout("rax") 0u64 => result,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r10") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        result
    }
}

/// Names an `ia32_emulation=` boot parameter, when present, for diagnostics.
#[cfg(target_arch = "x86_64")]
fn boot_parameter_note() -> String {
    std::fs::read_to_string("/proc/cmdline")
        .ok()
        .and_then(|cmdline| {
            cmdline
                .split_whitespace()
                .find(|word| word.starts_with("ia32_emulation="))
                .map(|word| format!("; kernel command line has {word}"))
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_table_with_patching_off_starts_and_stays_empty() {
        let table = SiteTable::new(SitePatching::Off);
        assert_eq!(table.patching(), SitePatching::Off);
        assert_eq!(table.patched_sites(), 0);
    }

    #[test]
    fn unavailable_probe_is_a_named_refusal() {
        for patching in [SitePatching::Off, SitePatching::On] {
            let error = require_ia32_emulation(
                Ia32EmulationProbe::Unavailable(
                    "int 0x80 getpid killed the probe with SIGSEGV (11)".into(),
                ),
                patching,
            )
            .expect_err("an unavailable IA-32 entry must refuse trap-only launch");
            let refusal = error
                .downcast_ref::<Ia32EmulationUnavailable>()
                .unwrap_or_else(|| panic!("not Ia32EmulationUnavailable: {error}"));
            assert_eq!(
                refusal.observation,
                "int 0x80 getpid killed the probe with SIGSEGV (11)"
            );
            assert_eq!(
                error.to_string(),
                "LiteInst trap-only launch refused: IA-32 syscall emulation (int 0x80) is \
                 unavailable on this host, which requires CONFIG_IA32_EMULATION and no \
                 ia32_emulation=false boot parameter (int 0x80 getpid killed the probe with \
                 SIGSEGV (11))"
            );
        }
    }

    #[test]
    fn available_probe_admits_launch() {
        for patching in [SitePatching::Off, SitePatching::On] {
            require_ia32_emulation(Ia32EmulationProbe::Available, patching)
                .expect("an available IA-32 entry admits the launch");
        }
    }

    /// An entry that changes rcx or r8-r11 cannot run a patched site, but a
    /// launch that never patches one (patching off) is not refused for it.
    #[test]
    fn a_register_clobbering_entry_refuses_only_site_patching() {
        let observation = "int 0x80 getpid changed r8 from 0x5e171ce000000008 to 0x0; trap-only \
                           patching needs an IA-32 entry that preserves rcx, r8, r9, r10 and r11";
        require_ia32_emulation(
            Ia32EmulationProbe::ClobbersRegisters(observation.into()),
            SitePatching::Off,
        )
        .expect("patching off must not be refused for a register-clobbering entry");

        let error = require_ia32_emulation(
            Ia32EmulationProbe::ClobbersRegisters(observation.into()),
            SitePatching::On,
        )
        .expect_err("site patching must be refused on a register-clobbering entry");
        let refusal = error
            .downcast_ref::<Ia32EntryClobbersRegisters>()
            .unwrap_or_else(|| panic!("not Ia32EntryClobbersRegisters: {error}"));
        assert_eq!(refusal.patching, SitePatching::On);
        assert_eq!(refusal.observation, observation);
        assert!(
            error.downcast_ref::<Ia32EmulationUnavailable>().is_none(),
            "a clobbering entry is not an unavailable one"
        );
        // The register cause comes first; the unavailable wording is absent.
        let message = error.to_string();
        assert_eq!(
            message,
            format!("LiteInst trap-only launch with site patching on refused: {observation}")
        );
        assert!(!message.contains("unavailable"), "{message}");
        assert!(!message.contains("CONFIG_IA32_EMULATION"), "{message}");
    }

    /// An `int 0x80` outcome that preserved every sentinel.
    #[cfg(target_arch = "x86_64")]
    fn preserving(rax: u64) -> Int80Getpid {
        Int80Getpid {
            rax,
            preserved: PRESERVED_SENTINELS,
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_outcome_classification_names_the_fault() {
        assert_eq!(
            classify_probe_outcome(None, preserving(42), 42, ""),
            Ia32EmulationProbe::Available
        );
        let Ia32EmulationProbe::Unavailable(text) = classify_probe_outcome(
            Some(libc::SIGSEGV),
            preserving(u64::MAX),
            42,
            "; kernel command line has ia32_emulation=0",
        ) else {
            panic!("SIGSEGV must classify as unavailable");
        };
        assert!(
            text.contains("SIGSEGV") && text.contains("ia32_emulation=0"),
            "{text}"
        );
        assert!(matches!(
            classify_probe_outcome(Some(libc::SIGSYS), preserving(u64::MAX), 42, ""),
            Ia32EmulationProbe::Unavailable(text) if text.contains("SIGSYS")
        ));
        // A serviced entry that answers wrongly (for example -ENOSYS) is not
        // usable either.
        assert!(matches!(
            classify_probe_outcome(None, preserving(-38i64 as u64), 42, ""),
            Ia32EmulationProbe::Unavailable(text)
                if text.contains("0xffffffffffffffda") && text.contains("PID 42")
        ));
    }

    /// A correct getpid whose entry changed any of rcx, r8, r9, r10 or r11 is
    /// classified as a clobbering entry, naming the register, its sentinel and
    /// the value found. Only site patching refuses that outcome
    /// (`a_register_clobbering_entry_refuses_only_site_patching`).
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_outcome_classifies_an_int80_that_changes_a_preserved_register() {
        for (index, name) in PRESERVED_REGISTERS.into_iter().enumerate() {
            let mut outcome = preserving(42);
            outcome.preserved[index] = 0;
            let Ia32EmulationProbe::ClobbersRegisters(text) =
                classify_probe_outcome(None, outcome, 42, "; kernel command line has x")
            else {
                panic!("a clobbered {name} must classify as a clobbering entry");
            };
            assert!(text.starts_with("int 0x80 getpid changed "), "{text}");
            let sentinel = format!("{:#x}", PRESERVED_SENTINELS[index]);
            assert!(
                text.contains(&format!("changed {name} from {sentinel} to 0x0"))
                    && text.contains("rcx, r8, r9, r10 and r11")
                    && text.contains("kernel command line has x"),
                "{text}"
            );
            // The whole text states only the measured property.
            assert_eq!(
                text,
                format!(
                    "int 0x80 getpid changed {name} from {sentinel} to 0x0; trap-only patching \
                     needs an IA-32 entry that preserves rcx, r8, r9, r10 and r11; kernel \
                     command line has x"
                )
            );
        }
        // The first changed register in rcx, r8, r9, r10, r11 order is named.
        let mut outcome = preserving(42);
        outcome.preserved[4] = 1;
        outcome.preserved[1] = 2;
        assert_eq!(
            classify_probe_outcome(None, outcome, 42, ""),
            Ia32EmulationProbe::ClobbersRegisters(format!(
                "int 0x80 getpid changed r8 from {:#x} to 0x2; trap-only patching needs an \
                 IA-32 entry that preserves rcx, r8, r9, r10 and r11",
                PRESERVED_SENTINELS[1]
            ))
        );
        // A wrong result is reported before a clobber.
        assert_eq!(
            classify_probe_outcome(None, Int80Getpid { rax: 7, ..outcome }, 42, ""),
            Ia32EmulationProbe::Unavailable(
                "int 0x80 getpid returned 0x7, not the caller's PID 42".into()
            )
        );
    }

    /// The probe child's pipe payload round-trips every field.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn int80_outcome_bytes_round_trip() {
        let outcome = Int80Getpid {
            rax: 0x1234,
            preserved: [1, 2, 3, 4, u64::MAX],
        };
        assert_eq!(Int80Getpid::from_bytes(&outcome.to_bytes()), outcome);
    }

    /// The live probe on this host: the in-process `int 0x80` getpid under the
    /// guard returns this PID and leaves every sentinel in place, so the
    /// assertion admits the kernels the design relies on. Like the other live
    /// probe tests, this requires a host with the IA-32 entry.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn live_int80_preserves_rcx_and_r8_through_r11_on_this_host() {
        assert_eq!(
            calling_thread_seccomp_filter(),
            None,
            "the live probe must run on an unfiltered thread"
        );
        let (fault, outcome) = unsafe { guarded_fault::run(int80_getpid) }.expect("guard installs");
        assert_eq!(fault, None, "int 0x80 faulted on this host");
        let pid = unsafe { libc::syscall(libc::SYS_getpid) } as u64;
        assert_eq!(outcome.rax, pid);
        assert_eq!(
            outcome.preserved, PRESERVED_SENTINELS,
            "int 0x80 changed a register the trap-only design needs preserved"
        );
        assert_eq!(
            classify_probe_outcome(None, outcome, pid, ""),
            Ia32EmulationProbe::Available
        );
    }

    #[cfg(target_arch = "x86_64")]
    fn current_disposition(signal: libc::c_int) -> (usize, libc::c_int) {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) },
            0
        );
        // glibc's sigaction(3) adds SA_RESTORER to every action it installs
        // and points it at its own trampoline; the kernel reports it back.
        // It is not part of the disposition a caller chose.
        const SA_RESTORER: libc::c_int = 0x0400_0000;
        (action.sa_sigaction, action.sa_flags & !SA_RESTORER)
    }

    /// The fault path a host without the IA-32 entry takes: a general
    /// protection fault at the `int` instruction, caught on this thread, with
    /// the process surviving and the old dispositions restored.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn guarded_fault_catches_a_general_protection_fault_and_restores_handlers() {
        let before = [
            current_disposition(libc::SIGSEGV),
            current_disposition(libc::SIGBUS),
            current_disposition(libc::SIGSYS),
        ];
        for _ in 0..2 {
            let (fault, result) =
                unsafe { guarded_fault::run(guarded_fault::int81) }.expect("guard installs");
            assert_eq!(fault, Some(libc::SIGSEGV));
            assert_eq!(result, u64::MAX, "the faulting instruction was not skipped");
        }
        let after = [
            current_disposition(libc::SIGSEGV),
            current_disposition(libc::SIGBUS),
            current_disposition(libc::SIGSYS),
        ];
        assert_eq!(before, after, "the probe leaked its signal handlers");
    }

    const AUDIT_ARCH_I386: u32 = 0x4000_0003;
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

    /// Installs, on the calling thread only, a seccomp filter that answers
    /// syscalls of `arch` (and, if given, only number `nr`) with `action` and
    /// allows everything else.
    #[cfg(target_arch = "x86_64")]
    fn install_seccomp_filter(arch: u32, nr: Option<u32>, action: u32) {
        let stmt = |code: u32, k: u32| libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        };
        let jump_unless = |value: u32, skip: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: skip,
            k: value,
        };
        let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        let ret = libc::BPF_RET | libc::BPF_K;
        let mut filter = vec![stmt(load, 4)]; // A = seccomp_data.arch
        match nr {
            None => filter.push(jump_unless(arch, 1)),
            Some(nr) => {
                filter.push(jump_unless(arch, 3));
                filter.push(stmt(load, 0)); // A = seccomp_data.nr
                filter.push(jump_unless(nr, 1));
            }
        }
        filter.push(stmt(ret, action));
        filter.push(stmt(ret, libc::SECCOMP_RET_ALLOW));
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &program as *const libc::sock_fprog,
                ),
                0,
                "install seccomp filter: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    /// Runs `probe_ia32_emulation` on a fresh thread under a filter for IA-32
    /// syscalls, bounded so that a killed or deadlocked probe fails the test
    /// instead of hanging it.
    #[cfg(target_arch = "x86_64")]
    fn probe_on_filtered_thread(action: u32) -> Ia32EmulationProbe {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            install_seccomp_filter(AUDIT_ARCH_I386, None, action);
            let _ = sender.send(probe_ia32_emulation());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the probe on a filtered thread neither returned nor finished in 10 s")
    }

    /// An answer from a filtered thread that names the observed trap, or that
    /// names why the child could not be created. Never Available.
    #[cfg(target_arch = "x86_64")]
    fn assert_filtered_refusal(probe: &Ia32EmulationProbe) {
        let Ia32EmulationProbe::Unavailable(text) = probe else {
            panic!("a filter that traps IA-32 syscalls was reported Available");
        };
        assert!(
            text.contains("runs under seccomp")
                && (text.contains("killed the probe child with SIGSYS (31)")
                    || text.contains("clone3 with set_tid")),
            "{text}"
        );
    }

    /// The seccomp filter is per thread; an answer for one thread must not be
    /// served to another. An unfiltered thread caches Available, a thread
    /// that traps IA-32 syscalls must still see its own refusal, and that
    /// refusal must not replace the cached answer.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_on_a_filtered_thread_neither_uses_nor_fills_the_cache() {
        assert_eq!(probe_ia32_emulation(), Ia32EmulationProbe::Available);
        assert_filtered_refusal(&probe_on_filtered_thread(libc::SECCOMP_RET_TRAP));
        assert_eq!(probe_ia32_emulation(), Ia32EmulationProbe::Available);
    }

    const REEXEC_ARM_ENV: &str = "REVERIE_IA32_PROBE_TEST_ARM";
    const REEXEC_MARK: &str = "@@ia32-probe-arm@@ ";

    /// Re-executes one test of this module in a child process (optionally in
    /// a fresh user, PID and mount namespace, the way Hermit runs the tracer)
    /// and returns its exit status and marked output lines.
    fn reexec(
        test: &str,
        arm: &str,
        fresh_pid_namespace: bool,
    ) -> (std::process::ExitStatus, String) {
        let module = module_path!()
            .split_once("::")
            .map(|(_, rest)| rest)
            .unwrap();
        let mut command = if fresh_pid_namespace {
            let mut command = std::process::Command::new("/usr/bin/unshare");
            command
                .args([
                    "--user",
                    "--map-root-user",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                    "--",
                ])
                .arg(std::env::current_exe().unwrap());
            command
        } else {
            std::process::Command::new(std::env::current_exe().unwrap())
        };
        let mut child = command
            .args([
                "--exact",
                &format!("{module}::{test}"),
                "--nocapture",
                "--test-threads=1",
            ])
            .env(REEXEC_ARM_ENV, arm)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("re-execute the test binary");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let output = child.wait_with_output().unwrap();
                panic!(
                    "{test} arm {arm} exceeded 60 s:\n{}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let record = stdout
            .lines()
            .filter_map(|line| line.strip_prefix(REEXEC_MARK))
            .collect::<Vec<_>>()
            .join("\n");
        eprintln!(
            "{test} arm {arm}: {}\nstdout:\n{stdout}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status, record)
    }

    /// A filter that kills on IA-32 syscalls must not kill the process or
    /// the calling thread, and must not leave the probe deadlocked: a second
    /// probe from another filtered thread answers too. Runs in a child
    /// process so that a regression kills the child, not the test harness.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn probe_survives_seccomp_kill_filters_on_ia32_syscalls() {
        if let Ok(arm) = std::env::var(REEXEC_ARM_ENV) {
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            let action = match arm.as_str() {
                "kill-process" => libc::SECCOMP_RET_KILL_PROCESS,
                "kill-thread" => libc::SECCOMP_RET_KILL_THREAD,
                other => panic!("unknown arm {other}"),
            };
            for attempt in 0..2 {
                let probe = probe_on_filtered_thread(action);
                assert_filtered_refusal(&probe);
                println!("\n{REEXEC_MARK}{arm} attempt {attempt}: {probe:?}");
            }
            let dispositions = [libc::SIGSEGV, libc::SIGBUS, libc::SIGSYS].map(current_disposition);
            println!("{REEXEC_MARK}{arm} dispositions {dispositions:?}");
            return;
        }
        for arm in ["kill-process", "kill-thread"] {
            let (status, record) = reexec(
                "probe_survives_seccomp_kill_filters_on_ia32_syscalls",
                arm,
                false,
            );
            assert!(status.success(), "{arm}: the probe process died: {status}");
            assert_eq!(
                record
                    .lines()
                    .filter(|line| line.contains("attempt"))
                    .count(),
                2,
                "{arm}: {record}"
            );
        }
    }

    /// A child may only probe from a filtered thread if it takes no PID from
    /// the guest's sequence. In a fresh PID namespace, which the test owns as
    /// Hermit owns its own, each filter arm forks once before and once after
    /// the probe; the two PIDs must be consecutive. A control arm that forks
    /// an ordinary child in between shows that one taken PID is visible.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn filtered_probe_takes_no_pid_in_a_fresh_pid_namespace() {
        fn fork_and_reap() -> libc::pid_t {
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                unsafe { libc::_exit(0) };
            }
            assert!(pid > 0, "fork: {}", std::io::Error::last_os_error());
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            pid
        }
        if std::env::var(REEXEC_ARM_ENV).is_ok() {
            // A regression kills this child with SIGSYS; do not dump core.
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            let arms: [(&str, Option<u32>); 6] = [
                ("ordinary-child-control", None),
                ("kill-process", Some(libc::SECCOMP_RET_KILL_PROCESS)),
                ("kill-thread", Some(libc::SECCOMP_RET_KILL_THREAD)),
                ("trap", Some(libc::SECCOMP_RET_TRAP)),
                (
                    "errno-enosys",
                    Some(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
                ),
                ("allow", Some(libc::SECCOMP_RET_ALLOW)),
            ];
            for (label, action) in arms {
                let line = std::thread::spawn(move || {
                    let before = fork_and_reap();
                    let probe = match action {
                        None => {
                            fork_and_reap();
                            None
                        }
                        Some(action) => {
                            install_seccomp_filter(AUDIT_ARCH_I386, None, action);
                            Some(probe_ia32_emulation())
                        }
                    };
                    let after = fork_and_reap();
                    format!("{label} {before} {after} {probe:?}")
                })
                .join()
                .expect("arm thread");
                println!("\n{REEXEC_MARK}{line}");
            }
            return;
        }
        let (status, record) = reexec(
            "filtered_probe_takes_no_pid_in_a_fresh_pid_namespace",
            "all",
            true,
        );
        assert!(
            status.success(),
            "namespace child failed: {status}\n{record}"
        );
        let arm = |label: &str| -> (i32, i32, String) {
            let line = record
                .lines()
                .find(|line| line.starts_with(&format!("{label} ")))
                .unwrap_or_else(|| panic!("no {label} arm in:\n{record}"));
            let mut words = line.splitn(4, ' ').skip(1);
            let before = words.next().unwrap().parse().unwrap();
            let after = words.next().unwrap().parse().unwrap();
            (before, after, words.next().unwrap().to_owned())
        };
        let (before, after, _) = arm("ordinary-child-control");
        assert_eq!(after, before + 2, "an ordinary child's PID was not visible");
        for label in [
            "kill-process",
            "kill-thread",
            "trap",
            "errno-enosys",
            "allow",
        ] {
            let (before, after, probe) = arm(label);
            assert_eq!(after, before + 1, "{label}: the probe took a PID: {probe}");
            match label {
                "allow" => assert_eq!(probe, "Some(Available)"),
                "errno-enosys" => assert!(
                    probe.contains("returned 0xffffffffffffffda")
                        && probe.contains("runs under seccomp"),
                    "{probe}"
                ),
                _ => assert!(
                    probe.contains("killed the probe child with SIGSYS (31)"),
                    "{label}: {probe}"
                ),
            }
        }
    }

    static OTHER_THREAD_GO: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    static OTHER_THREAD_DONE: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    /// A guarded "instruction" that keeps the guard armed until the other
    /// thread has made its trapped syscall (or 5 s pass). It never faults.
    #[cfg(target_arch = "x86_64")]
    unsafe fn hold_guard_armed() -> u64 {
        use std::sync::atomic::Ordering;
        OTHER_THREAD_GO.store(true, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !OTHER_THREAD_DONE.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            std::hint::spin_loop();
        }
        0
    }

    /// A seccomp trap on another thread while the guard is armed must reach
    /// the process's own disposition. Under SIG_DFL, `SIGSYS` terminates the
    /// process, and it must do so with the guard armed as it does without it
    /// (the control arm). Runs in a child process.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_seccomp_trap_on_another_thread_is_not_swallowed_by_the_guard() {
        use std::os::unix::process::ExitStatusExt;
        use std::sync::atomic::Ordering;
        if let Ok(arm) = std::env::var(REEXEC_ARM_ENV) {
            unsafe {
                libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
                libc::signal(libc::SIGSYS, libc::SIG_DFL);
            }
            let other = std::thread::spawn(|| {
                while !OTHER_THREAD_GO.load(Ordering::SeqCst) {
                    std::hint::spin_loop();
                }
                install_seccomp_filter(
                    AUDIT_ARCH_X86_64,
                    Some(libc::SYS_getppid as u32),
                    libc::SECCOMP_RET_TRAP,
                );
                let returned = unsafe { libc::syscall(libc::SYS_getppid) };
                OTHER_THREAD_DONE.store(true, Ordering::SeqCst);
                println!("\n{REEXEC_MARK}other thread survived; getppid returned {returned}");
            });
            match arm.as_str() {
                "control" => OTHER_THREAD_GO.store(true, Ordering::SeqCst),
                "guarded" => {
                    let outcome = unsafe { guarded_fault::run(hold_guard_armed) };
                    println!("\n{REEXEC_MARK}guard returned {outcome:?}");
                }
                other => panic!("unknown arm {other}"),
            }
            let _ = other.join();
            // Give a pending process-directed signal a moment to land.
            std::thread::sleep(std::time::Duration::from_millis(200));
            println!("\n{REEXEC_MARK}process survived");
            return;
        }
        for arm in ["control", "guarded"] {
            let (status, record) = reexec(
                "a_seccomp_trap_on_another_thread_is_not_swallowed_by_the_guard",
                arm,
                false,
            );
            assert_eq!(
                status.signal(),
                Some(libc::SIGSYS),
                "{arm}: the trapped syscall did not terminate the process by SIGSYS \
                 ({status}):\n{record}"
            );
        }
    }
}
