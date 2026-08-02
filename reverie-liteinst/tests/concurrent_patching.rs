#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;

use liteinst2::patcher::JumpPatchPlan;
use liteinst2::patcher::LiveJumpPatch;
use liteinst2::patcher::PatchError;
use liteinst2::patcher::StalenessBudget;
use liteinst2::scanner::InstructionScanner;

const PAGE_BYTES: usize = 4096;
const FUNCTION_OFFSET: usize = 56;
const SITE_OFFSET: usize = 60;
const TARGET_OFFSET: usize = 128;

struct DualMapping {
    writable: *mut u8,
    executable: *mut u8,
}

impl DualMapping {
    fn new() -> Self {
        let name = b"reverie-liteinst-concurrent-patch\0";
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

    fn install_fixture(&self) {
        let entry = [0xF3, 0x0F, 0x1E, 0xFA];
        let original = [0xB8, 1, 0, 0, 0, 0xC3, 0x90, 0x90];
        let target = [0xB8, 2, 0, 0, 0, 0xC3];
        // SAFETY: every fixture range lies within the writable page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                entry.as_ptr(),
                self.writable.add(FUNCTION_OFFSET),
                entry.len(),
            );
            core::ptr::copy_nonoverlapping(
                original.as_ptr(),
                self.writable.add(SITE_OFFSET),
                original.len(),
            );
            core::ptr::copy_nonoverlapping(
                target.as_ptr(),
                self.writable.add(TARGET_OFFSET),
                target.len(),
            );
        }
    }

    fn plan(&self) -> JumpPatchPlan {
        let scanner = InstructionScanner::default();
        // SAFETY: the fixture initializes the complete eight-byte patch word.
        let code = unsafe { core::slice::from_raw_parts(self.writable.add(SITE_OFFSET), 8) };
        let site = self.executable as u64 + SITE_OFFSET as u64;
        let target = self.executable as u64 + TARGET_OFFSET as u64;
        let scan = scanner.scan(code, site).unwrap();
        JumpPatchPlan::from_scan(&scanner, &scan, code, site, site, target).unwrap()
    }

    fn function(&self) -> extern "C" fn() -> u32 {
        let address = self.executable as usize + FUNCTION_OFFSET;
        // SAFETY: the fixture contains a valid function at this address.
        unsafe { core::mem::transmute(address) }
    }

    fn writable_site(&self) -> *mut u8 {
        // SAFETY: SITE_OFFSET lies within the writable mapping.
        unsafe { self.writable.add(SITE_OFFSET) }
    }
}

unsafe fn bind_retry(
    plan: JumpPatchPlan,
    writable_address: *mut u8,
    staleness: StalenessBudget,
) -> LiveJumpPatch {
    loop {
        // SAFETY: forwarded from this helper's mapping-lifetime contract.
        match unsafe { LiveJumpPatch::bind(plan.clone(), writable_address, staleness) } {
            Ok(patch) => return patch,
            Err(PatchError::Contended) => thread::yield_now(),
            Err(error) => panic!("bind failed: {error}"),
        }
    }
}

#[test]
fn threaded_clients_keep_guarded_wordpatch_publication() {
    let mapping = DualMapping::new();
    mapping.install_fixture();
    let function = mapping.function();
    // SAFETY: both aliases deliberately remain mapped for the test process.
    let patch = unsafe {
        bind_retry(
            mapping.plan(),
            mapping.writable_site(),
            StalenessBudget::new(20_000).unwrap(),
        )
    };

    let running = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(AtomicU64::new(0));
    let invalid = Arc::new(AtomicBool::new(false));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let running = Arc::clone(&running);
            let calls = Arc::clone(&calls);
            let invalid = Arc::clone(&invalid);
            thread::spawn(move || {
                while running.load(Ordering::Acquire) {
                    let value = function();
                    if value != 1 && value != 2 {
                        invalid.store(true, Ordering::Release);
                    }
                    calls.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();

    for _ in 0..5_000 {
        // SAFETY: the concurrent binding owns the live patch envelope.
        unsafe { patch.apply() }.unwrap();
        // SAFETY: the concurrent binding owns the live patch envelope.
        unsafe { patch.revert() }.unwrap();
    }

    running.store(false, Ordering::Release);
    for worker in workers {
        worker.join().unwrap();
    }
    assert!(!invalid.load(Ordering::Acquire));
    assert!(calls.load(Ordering::Relaxed) > 0);
    assert!(patch.handled_guard_traps() > 0);
    assert_eq!(function(), 1);
}
