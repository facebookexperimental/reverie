#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! M1 regression for the liteinst 0.2.0 port: legacy trampoline plans now
//! capture original NOP bytes and emit them byte-exact instead of
//! re-encoding. This test plans, installs and executes replace-first
//! hooks over three windows containing multi-byte NOPs, and cross-checks
//! the trampoline plan's displaced length against the jump patch plan's
//! (the equality `install_unpublished_syscall` relies on). Only the
//! syscall fixture displaces a NOP into the trampoline; the other two
//! resume into their trailing NOPs in the original mapping. The
//! exact-syscall plan shape is planning coverage only: the installed
//! hook is ordinary replace-first. Return values and callback counts
//! establish execution and resumption; the syscall fixture additionally
//! checks the displaced NOP's bytes appear verbatim in the trampoline.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use liteinst::patcher::JumpPatchPlan;
use liteinst::patcher::WORD_PATCH_BYTES;
use liteinst::scanner::InstructionScanner;
use liteinst::trampoline::HookContext;
use liteinst::trampoline::HookSite;
use liteinst::trampoline::InstalledHook;
use liteinst::trampoline::TrampolineArena;
use liteinst::trampoline::TrampolinePlan;

const PAGE_BYTES: usize = 4096;

static HOOK_CALLS: AtomicU64 = AtomicU64::new(0);

/// Emulates the replaced `mov eax, 42`.
unsafe extern "C" fn emulate_mov_42(context: *mut HookContext) {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the trampoline passes a valid context for the hook call.
    unsafe {
        (*context).rax = 42;
    }
}

/// The replaced instruction is a NOP: nothing to emulate.
unsafe extern "C" fn count_only(_context: *mut HookContext) {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
}

/// Emulates the replaced `syscall` for getpid (number already in RAX).
unsafe extern "C" fn emulate_getpid(context: *mut HookContext) {
    HOOK_CALLS.fetch_add(1, Ordering::SeqCst);
    // SAFETY: the trampoline passes a valid context for the hook call.
    unsafe {
        assert_eq!((*context).rax, libc::SYS_getpid as u64);
        (*context).rax = libc::getpid() as u64;
    }
}

struct DualMapping {
    writable: *mut u8,
    executable: *mut u8,
}

impl DualMapping {
    fn new() -> Self {
        let name = b"reverie-liteinst-nop-window\0";
        // SAFETY: the name is NUL terminated and all flags are valid.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr().cast::<libc::c_char>(),
                libc::MFD_CLOEXEC,
            ) as libc::c_int
        };
        assert!(fd >= 0, "memfd_create failed");
        // SAFETY: fd is valid and PAGE_BYTES is representable.
        assert_eq!(unsafe { libc::ftruncate(fd, PAGE_BYTES as libc::off_t) }, 0);
        // SAFETY: maps the complete memfd as a writable shared alias.
        let writable = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE_BYTES,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(writable, libc::MAP_FAILED);
        // SAFETY: maps the same memfd as an executable shared alias.
        let executable = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                PAGE_BYTES,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(executable, libc::MAP_FAILED);
        // SAFETY: both mappings retain their own file-description references.
        assert_eq!(unsafe { libc::close(fd) }, 0);
        Self {
            writable: writable.cast(),
            executable: executable.cast(),
        }
    }

    fn install(&self, offset: usize, bytes: &[u8]) {
        // SAFETY: every fixture range lies within the writable page.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.writable.add(offset), bytes.len());
        }
    }

    fn function(&self, offset: usize) -> extern "C" fn() -> u32 {
        let address = self.executable as usize + offset;
        // SAFETY: the fixture contains a valid function at this address.
        unsafe { core::mem::transmute(address) }
    }

    /// Plan (with the displaced-length cross-check), install quiescently
    /// and activate a replace-first hook at `offset`, and return the
    /// displaced length plus the plan's emitted trampoline image bytes.
    /// The installed hook is leaked so its trampoline outlives the
    /// test's calls. When `also_plan_exact_syscall` is set, an
    /// exact-syscall plan is also constructed (and discarded) as
    /// planning-only coverage; the hook actually installed is ordinary
    /// replace-first either way.
    fn hook_replace_first(
        &self,
        arena: &TrampolineArena,
        offset: usize,
        window: &[u8],
        callback: liteinst::trampoline::HookCallback,
        also_plan_exact_syscall: bool,
    ) -> (usize, Vec<u8>) {
        let site_address = self.executable as u64 + offset as u64;
        let scanner = InstructionScanner::default();
        let scan = scanner
            .scan_prefix(window, site_address, WORD_PATCH_BYTES)
            .expect("prefix scan of the fixture window");
        let reference = TrampolinePlan::from_scan_replacing_first(&scan, site_address, callback)
            .expect("replace-first plan over a NOP window");
        let patch = JumpPatchPlan::from_scan(
            &scanner,
            &scan,
            scan.snapshot(),
            site_address,
            site_address,
            site_address,
        )
        .expect("jump patch plan over a NOP window");
        assert_eq!(
            patch.displaced_len(),
            reference.displaced_len(),
            "trampoline and jump patch displaced lengths must agree"
        );
        assert_eq!(
            reference.return_address(),
            site_address + reference.displaced_len() as u64,
        );
        if also_plan_exact_syscall {
            // Planning-only coverage: the exact-syscall plan must accept
            // this window. It is not the plan installed below.
            let exact =
                TrampolinePlan::from_scan_replacing_exact_syscall(&scan, site_address, callback)
                    .expect("exact-syscall plan over a NOP-tail window");
            // The exact-syscall shape displaces only the two-byte syscall,
            // unlike replace-first, which also displaces the nop8.
            assert_eq!(exact.displaced_len(), 2);
            assert_eq!(exact.return_address(), site_address + 2);
        }
        let site = HookSite::new(
            &scanner,
            &scan,
            scan.snapshot(),
            site_address,
            site_address,
            // SAFETY: offset lies within the writable alias page.
            unsafe { self.writable.add(offset) },
        );
        // SAFETY: no other thread fetches the fixture during installation,
        // and both aliases deliberately remain mapped for the test process.
        let installed = unsafe {
            InstalledHook::install_replacing_first_in_arena_quiescent(site, callback, arena)
        }
        .expect("quiescent replace-first install over a NOP window");
        // SAFETY: quiescent, as above.
        let activated = unsafe { installed.activate_quiescent() }
            .expect("quiescent activation over a NOP window");
        assert!(activated, "first activation must publish the hook");
        Box::leak(Box::new(installed));
        // Emit the same plan at a nominal nearby address so the test can
        // inspect the trampoline image (relocations differ from the
        // installed copy; displaced instruction bytes do not).
        let image = reference
            .emit_at(site_address + 0x1000)
            .expect("emit replace-first trampoline image");
        (reference.displaced_len(), image.bytes().to_vec())
    }
}

#[test]
fn replace_first_over_nop_windows_executes_and_resumes() {
    HOOK_CALLS.store(0, Ordering::SeqCst);
    let mapping = DualMapping::new();
    let arena =
        TrampolineArena::allocate_near(mapping.executable as u64, 8).expect("arena near fixture");

    // Fixture 1: mov eax, 42; nop8; ret. The five-byte mov alone covers
    // the jump, so only it is displaced; after the callback emulates it,
    // execution resumes at the nop8 in the original mapping.
    let mov_nop: &[u8] = &[
        0xB8, 42, 0, 0, 0, // mov eax, 42
        0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, // nop8
        0xC3, // ret
    ];
    mapping.install(0, mov_nop);
    assert_eq!(mapping.function(0)(), 42, "unhooked fixture 1");
    let (displaced, _) = mapping.hook_replace_first(&arena, 0, mov_nop, emulate_mov_42, false);
    assert_eq!(displaced, 5, "fixture 1 displaces only the mov");
    assert_eq!(mapping.function(0)(), 42, "hooked fixture 1 call 1");
    assert_eq!(mapping.function(0)(), 42, "hooked fixture 1 call 2");
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 2);

    // Fixture 2: nop6; nop3; mov eax, 7; ret. The replaced instruction is
    // itself a multi-byte NOP; its six bytes cover the jump, so execution
    // resumes at the nop3 in the original mapping.
    let nop_first: &[u8] = &[
        0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00, // nop6
        0x0F, 0x1F, 0x00, // nop3
        0xB8, 7, 0, 0, 0,    // mov eax, 7
        0xC3, // ret
    ];
    mapping.install(64, nop_first);
    assert_eq!(mapping.function(64)(), 7, "unhooked fixture 2");
    let (displaced, _) = mapping.hook_replace_first(&arena, 64, nop_first, count_only, false);
    assert_eq!(displaced, 6, "fixture 2 displaces only the nop6");
    assert_eq!(mapping.function(64)(), 7, "hooked fixture 2");
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 3);

    // Fixture 3: mov eax, SYS_getpid; syscall; nop8; ret. The two-byte
    // syscall cannot cover the jump alone, so the nop8 is displaced into
    // the trampoline and must be emitted there byte-exact. The hook is
    // installed replace-first; the exact-syscall plan Reverie uses is
    // constructed alongside as planning-only coverage. The callback
    // emulates the syscall and execution resumes past the NOP.
    let syscall_nop: &[u8] = &[
        0xB8, 39, 0, 0, 0, // mov eax, 39 (getpid on x86-64)
        0x0F, 0x05, // syscall
        0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00, // nop8
        0xC3, // ret
    ];
    mapping.install(128, syscall_nop);
    assert_eq!(
        mapping.function(128)(),
        // SAFETY: getpid has no preconditions.
        unsafe { libc::getpid() } as u32,
        "unhooked fixture 3"
    );
    let (displaced, emitted) =
        mapping.hook_replace_first(&arena, 128 + 5, &syscall_nop[5..], emulate_getpid, true);
    assert_eq!(displaced, 10, "fixture 3 displaces syscall + nop8");
    let nop8: [u8; 8] = [0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(
        emitted.windows(nop8.len()).any(|window| window == nop8),
        "displaced nop8 must appear verbatim in the trampoline image"
    );
    assert_eq!(
        mapping.function(128)(),
        // SAFETY: getpid has no preconditions.
        unsafe { libc::getpid() } as u32,
        "hooked fixture 3"
    );
    assert_eq!(HOOK_CALLS.load(Ordering::SeqCst), 4);
}
