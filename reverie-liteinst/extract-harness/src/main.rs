// Native extraction runner for the byte-identical lazy_promote
// module: flip-and-execute + custody scenarios on AArch64 metal.
#[path = "../../src/lazy_promote.rs"]
mod lazy_promote;

use lazy_promote::{LazyPromoter, PromoteOutcome};
use liteinst_aarch64_patch::PatchError;
use liteinst_aarch64_patch::Patcher;
use liteinst_aarch64_patch::site::{ResumeState, StopControl};
use liteinst_aarch64_patch::store::SiteStore;
use std::sync::atomic::{AtomicBool, Ordering};

struct SingleThreadStop {
    resume_failures: u32,
    acquires: u32,
    resumes: u32,
}
// SAFETY: single-threaded harness; the calling thread is the only
// executor and is stopped at this call by construction.
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

static SYNC_FAIL_ONCE: AtomicBool = AtomicBool::new(false);
unsafe fn sync_fail_once(rw: *mut u8, rx: *mut u8, len: usize) -> Result<(), PatchError> {
    if SYNC_FAIL_ONCE.swap(false, Ordering::SeqCst) {
        return Err(PatchError::Unsupported("injected sync failure"));
    }
    unsafe { liteinst_aarch64_patch::cache::sync_icache(rw, rx, len) }
}

fn svc_page() -> (*mut u8, usize) {
    let page = liteinst_aarch64_patch::page_size().unwrap() as usize;
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
    (p as *mut u8, page)
}

unsafe fn call_getpid_site(site: u64) -> i64 {
    let ret: i64;
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

fn perms_at(addr: u64) -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    for line in maps.lines() {
        let (range, rest) = line.split_once(' ').unwrap();
        let (lo, hi) = range.split_once('-').unwrap();
        if addr >= u64::from_str_radix(lo, 16).unwrap()
            && addr < u64::from_str_radix(hi, 16).unwrap()
        {
            return rest.split_whitespace().next().unwrap().to_string();
        }
    }
    panic!("no mapping for {addr:#x}");
}

fn is_b(word: u32) -> bool {
    matches!(
        liteinst_aarch64::decode(word),
        liteinst_aarch64::Insn::Branch { .. }
    )
}

fn scenario_flip_exec() {
    let (p, _page) = svc_page();
    let site = p as u64;
    let before = unsafe { call_getpid_site(site) };
    assert_eq!(before, std::process::id() as i64);
    assert_eq!(perms_at(site), "r-xp");
    let mut promoter = LazyPromoter::attested(1).unwrap();
    let mut stop = SingleThreadStop {
        resume_failures: 0,
        acquires: 0,
        resumes: 0,
    };
    let outcome = promoter.promote_one(site, &mut stop);
    assert_eq!(outcome, PromoteOutcome::Flipped);
    assert_eq!(stop.acquires, 1, "exactly one acquire settles the flip");
    assert_eq!(
        promoter.promote_one(site, &mut stop),
        PromoteOutcome::Refused
    );
    assert_eq!(promoter.held_sites(), 1);
    let word = unsafe { (site as *const u32).read_volatile() };
    assert!(is_b(word), "word {word:#010x} is not B");
    assert_eq!(perms_at(site), "r-xp", "protection not restored exact");
    let after = unsafe { call_getpid_site(site) };
    assert_eq!(after, before, "call result changed across flip");
    core::mem::forget(promoter);
    println!("PASS flip-exec word={word:#010x} pid={after}");
}

fn scenario_custody_resume() {
    let (p, _page) = svc_page();
    let site = p as u64;
    let mut promoter = LazyPromoter::attested(1).unwrap();
    let mut stop = SingleThreadStop {
        resume_failures: 1,
        acquires: 0,
        resumes: 0,
    };
    assert_eq!(
        promoter.promote_one(site, &mut stop),
        PromoteOutcome::CustodyPending
    );
    assert_eq!(promoter.held_sites(), 1);
    let done = promoter.complete_pending(&mut stop);
    assert_eq!(done, [(site, PromoteOutcome::Flipped)]);
    let after = unsafe { call_getpid_site(site) };
    assert_eq!(after, std::process::id() as i64);
    core::mem::forget(promoter);
    println!("PASS custody-resume");
}

fn scenario_custody_sync() {
    let (p, _page) = svc_page();
    let site = p as u64;
    SYNC_FAIL_ONCE.store(true, Ordering::SeqCst);
    let patcher = Patcher::attested_with_sync(sync_fail_once).unwrap();
    let mut promoter = LazyPromoter::with_patcher(patcher, 1).unwrap();
    let mut stop = SingleThreadStop {
        resume_failures: 0,
        acquires: 0,
        resumes: 0,
    };
    assert_eq!(
        promoter.promote_one(site, &mut stop),
        PromoteOutcome::CustodyPending
    );
    let done = promoter.complete_pending(&mut stop);
    assert_eq!(done, [(site, PromoteOutcome::Flipped)]);
    let after = unsafe { call_getpid_site(site) };
    assert_eq!(after, std::process::id() as i64);
    assert_eq!(perms_at(site), "r-xp");
    core::mem::forget(promoter);
    println!("PASS custody-sync");
}

fn scenario_drain_table() {
    let (p, _page) = svc_page();
    let site = p as u64;
    reverie_inguest::trap::record_pending_promotion_site(site);
    let mut promoter = LazyPromoter::attested(1).unwrap();
    let mut stop = SingleThreadStop {
        resume_failures: 0,
        acquires: 0,
        resumes: 0,
    };
    let out = promoter.drain_pending(&mut stop);
    assert_eq!(out, [(site, PromoteOutcome::Flipped)]);
    // Promoted call re-traps at the ISLAND svc; the denylist must
    // keep that out of the table: call twice, drain again, empty.
    let a = unsafe { call_getpid_site(site) };
    let b = unsafe { call_getpid_site(site) };
    assert_eq!(a, b);
    assert!(promoter.drain_pending(&mut stop).is_empty());
    core::mem::forget(promoter);
    println!("PASS drain-table-denylist");
}

fn perms_at2(addr: u64) -> String {
    perms_at(addr)
}

fn scenario_toctou() {
    // Guest unmaps the site inside acquire: qualification under
    // the lease must refuse cleanly (no deref of unmapped word).
    struct MunmapStop {
        page: u64,
        len: usize,
        acquires: u32,
        resumes: u32,
    }
    unsafe impl StopControl for MunmapStop {
        fn acquire(&mut self) -> Result<(), PatchError> {
            self.acquires += 1;
            unsafe { libc::munmap(self.page as *mut libc::c_void, self.len) };
            Ok(())
        }
        fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
            self.resumes += 1;
            Ok(vec![ResumeState::Released])
        }
    }
    let (p, page) = svc_page();
    let mut promoter = LazyPromoter::attested(1).unwrap();
    let mut stop = MunmapStop {
        page: p as u64,
        len: page,
        acquires: 0,
        resumes: 0,
    };
    assert_eq!(
        promoter.promote_one(p as u64, &mut stop),
        PromoteOutcome::Refused
    );
    assert_eq!((stop.acquires, stop.resumes), (1, 1));
    println!("PASS toctou-munmap");
}

fn scenario_refused_window_no_fallback_by_default() {
    // Default policy: no proc-mem fallback exists to fall into;
    // the flip here uses the window and succeeds. The fallback
    // permission itself is unit-tested in-tree (StoreFallback
    // classification); this scenario pins that the default
    // promoter holds NO proc-mem permission.
    let promoter = LazyPromoter::unattested(1);
    assert_eq!(
        promoter.store_fallback(),
        lazy_promote::StoreFallback::RefuseWindow
    );
    println!("PASS default-policy-refuse-window");
}

static BTI_SKIPPED: AtomicBool = AtomicBool::new(false);
fn scenario_bti_preserved() {
    const PROT_BTI: libc::c_int = 0x10;
    let page = liteinst_aarch64_patch::page_size().unwrap() as usize;
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
    unsafe { (p as *mut u32).write_volatile(0xd65f_03c0) };
    if unsafe { libc::mprotect(p, page, libc::PROT_READ | libc::PROT_EXEC | PROT_BTI) } != 0 {
        BTI_SKIPPED.store(true, Ordering::SeqCst);
        println!("SKIP bti (mmap PROT_BTI unavailable)");
        return;
    }
    let blr_child = |label: &str| {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                core::arch::asm!("blr {site}", site = in(reg) p as u64, options(nostack));
            }
            unsafe { libc::_exit(0) };
        }
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGILL,
            "{label}: expected SIGILL, status={status:#x}"
        );
    };
    blr_child("before store cycle");
    let facts = liteinst_aarch64_patch::mapping::qualify_mapping(p as u64, 1).unwrap();
    assert!(facts.bti, "smaps must report bt for the guarded page");
    let mut store = lazy_promote::MprotectStore::new(p as u64, facts);
    store.begin_write().unwrap();
    store.store_word(0xd65f_03c0).unwrap();
    store.finish_write().unwrap();
    blr_child("after store cycle");
    println!("PASS bti-preserved");
}

fn scenario_custody_blocks_new_work() {
    // RV1: site A in post-store custody (sync injected to fail
    // once) must block site B entirely: no acquire, no resume,
    // while A's page is still RWX.
    SYNC_FAIL_ONCE.store(true, Ordering::SeqCst);
    let patcher = Patcher::attested_with_sync(sync_fail_once).unwrap();
    let mut promoter = LazyPromoter::with_patcher(patcher, 1).unwrap();
    let (pa, _la) = svc_page();
    let (pb, _lb) = svc_page();
    let mut stop = SingleThreadStop {
        resume_failures: 0,
        acquires: 0,
        resumes: 0,
    };
    assert_eq!(
        promoter.promote_one(pa as u64, &mut stop),
        PromoteOutcome::CustodyPending
    );
    assert_eq!(perms_at(pa as u64), "rwxp");
    let (acq, res) = (stop.acquires, stop.resumes);
    assert_eq!(res, 0, "no resume may happen into custody");
    assert_eq!(
        promoter.promote_one(pb as u64, &mut stop),
        PromoteOutcome::CustodyPending
    );
    assert_eq!(
        (stop.acquires, stop.resumes),
        (acq, res),
        "B touched the stop while A in custody"
    );
    let done = promoter.complete_pending(&mut stop);
    assert_eq!(done, [(pa as u64, PromoteOutcome::Flipped)]);
    assert_eq!(perms_at(pa as u64), "r-xp");
    assert_eq!(
        promoter.promote_one(pb as u64, &mut stop),
        PromoteOutcome::Flipped
    );
    core::mem::forget(promoter);
    println!("PASS rv1-custody-blocks");
}

fn scenario_retry_requalifies() {
    // RV2: at acquire #2 the guest munmaps the site; the retry
    // must re-qualify under the second lease and refuse, never
    // store through stale facts.
    struct SecondAcquireMunmap {
        page: u64,
        len: usize,
        acquires: u32,
        resumes: u32,
    }
    unsafe impl StopControl for SecondAcquireMunmap {
        fn acquire(&mut self) -> Result<(), PatchError> {
            self.acquires += 1;
            if self.acquires == 2 {
                unsafe { libc::munmap(self.page as *mut libc::c_void, self.len) };
            }
            Ok(())
        }
        fn resume(&mut self) -> Result<Vec<ResumeState>, PatchError> {
            self.resumes += 1;
            Ok(vec![ResumeState::Released])
        }
    }
    // Window refusal comes from a seccomp filter returning EACCES
    // for W+X mprotect, installed in a forked child so the parent
    // harness stays unfiltered.
    let (p, page) = svc_page();
    let site = p as u64;
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        install_window_refusing_filter();
        let mut promoter = LazyPromoter::attested(1).unwrap();
        promoter.set_store_fallback(lazy_promote::StoreFallback::AllowProcMem);
        let mut stop = SecondAcquireMunmap {
            page: site,
            len: page,
            acquires: 0,
            resumes: 0,
        };
        let outcome = promoter.promote_one(site, &mut stop);
        let code = if outcome == PromoteOutcome::Refused && stop.acquires == 2 {
            0
        } else {
            3
        };
        unsafe { libc::_exit(code) };
    }
    let mut status: libc::c_int = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "retry child status={status:#x} (3=wrong outcome, signal=stale-facts crash)"
    );
    println!("PASS rv2-retry-requalifies");
}

fn install_window_refusing_filter() {
    // BPF: mprotect(226) with prot&(W|X)==(W|X) -> ERRNO EACCES;
    // everything else ALLOW. Installed via prctl+seccomp syscalls.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct SockFilter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_RET_K: u16 = 0x06;
    let stmt = |code, k| SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code, k, jt, jf| SockFilter { code, jt, jf, k };
    let prog = [
        stmt(BPF_LD_W_ABS, 0),          // nr
        jump(BPF_JMP_JEQ_K, 226, 0, 4), // mprotect?
        stmt(BPF_LD_W_ABS, 32),         // args[2] lo (prot)
        stmt(BPF_ALU_AND_K, 0x6),       // W|X
        jump(BPF_JMP_JEQ_K, 0x6, 0, 1),
        stmt(BPF_RET_K, 0x0005_0000 | 13), // ERRNO EACCES
        stmt(BPF_RET_K, 0x7fff_0000),      // ALLOW
    ];
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

fn scenario_refused_window_default_policy() {
    // Same filter: with the DEFAULT policy the refused window is
    // Refused, word unchanged, acquires == resumes == 1.
    let (p, _page) = svc_page();
    let site = p as u64;
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        install_window_refusing_filter();
        let mut promoter = LazyPromoter::attested(1).unwrap();
        let mut stop = SingleThreadStop {
            resume_failures: 0,
            acquires: 0,
            resumes: 0,
        };
        let outcome = promoter.promote_one(site, &mut stop);
        let word = unsafe { (site as *const u32).read_volatile() };
        let ok = outcome == PromoteOutcome::Refused
            && word == 0xd400_0001
            && stop.acquires == 1
            && stop.resumes == 1;
        unsafe { libc::_exit(if ok { 0 } else { 4 }) };
    }
    let mut status: libc::c_int = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "refused-window child status={status:#x}"
    );
    println!("PASS rv2-refused-window-default");
}

fn scenario_two_promoters() {
    // RV9: a second promoter must not resume executors onto the
    // first promoter's unsynced RWX custody page.
    SYNC_FAIL_ONCE.store(true, Ordering::SeqCst);
    let patcher = Patcher::attested_with_sync(sync_fail_once).unwrap();
    let mut first = LazyPromoter::with_patcher(patcher, 1).unwrap();
    let (pa, _la) = svc_page();
    let (pb, _lb) = svc_page();
    let mut stop = SingleThreadStop {
        resume_failures: 0,
        acquires: 0,
        resumes: 0,
    };
    assert_eq!(
        first.promote_one(pa as u64, &mut stop),
        PromoteOutcome::CustodyPending
    );
    assert_eq!(perms_at(pa as u64), "rwxp");
    let mut second = LazyPromoter::attested(1).unwrap();
    let (acq, res) = (stop.acquires, stop.resumes);
    assert_eq!(
        second.promote_one(pb as u64, &mut stop),
        PromoteOutcome::CustodyPending
    );
    assert_eq!(
        (stop.acquires, stop.resumes),
        (acq, res),
        "second promoter touched the stop"
    );
    let done = first.complete_pending(&mut stop);
    assert_eq!(done, [(pa as u64, PromoteOutcome::Flipped)]);
    assert_eq!(
        second.promote_one(pb as u64, &mut stop),
        PromoteOutcome::Flipped
    );
    core::mem::forget(first);
    core::mem::forget(second);
    println!("PASS rv9-two-promoters");
}

fn main() {
    scenario_flip_exec();
    scenario_custody_resume();
    scenario_custody_sync();
    scenario_drain_table();
    scenario_toctou();
    scenario_refused_window_no_fallback_by_default();
    scenario_custody_blocks_new_work();
    scenario_retry_requalifies();
    scenario_refused_window_default_policy();
    scenario_two_promoters();
    scenario_bti_preserved();
    if BTI_SKIPPED.load(Ordering::SeqCst) {
        println!("DONE-WITH-SKIP bti");
    } else {
        println!("ALL PASS");
    }
}
