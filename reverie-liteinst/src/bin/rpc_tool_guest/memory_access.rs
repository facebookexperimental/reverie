use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;

use reverie::Error;
use reverie::Guest;
use reverie::Stack;
use reverie::Subscription;
use reverie::Tool;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie::syscalls::PathPtr;
use reverie::syscalls::Readlink;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;

static INSPECTION_ADDRESS: AtomicUsize = AtomicUsize::new(0);
static EXECUTABLE: OnceLock<Vec<u8>> = OnceLock::new();
static CALLS: AtomicUsize = AtomicUsize::new(0);
static EXPECTED_RSP: AtomicUsize = AtomicUsize::new(0);
static SITE: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct MemoryTool;

#[reverie::tool]
impl Tool for MemoryTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        let pkru: u32;
        unsafe {
            core::arch::asm!("rdpkru", in("ecx") 0u32, out("eax") pkru, out("edx") _, options(nostack, preserves_flags))
        };
        assert_eq!(pkru, 0, "ordinary Tool buffers must be accessible");
        let registers = guest.regs().await;
        assert_eq!(registers.rsp, EXPECTED_RSP.load(Ordering::Relaxed) as u64);
        assert_eq!(registers.rip, SITE.load(Ordering::Relaxed) as u64);
        let mut stack = guest.stack().await;
        let input = stack.push(*b"Tool scratch\0");
        let path = stack.push(*b"/proc/self/exe\0");
        let input_guard = stack.commit()?;
        // The output fills one LocalStack arena; keep the input allocation in
        // its own committed arena rather than exceeding that fixed capacity.
        let mut stack = guest.stack().await;
        let output = stack.reserve::<[u8; 4096]>().cast::<u8>();
        let guard = stack.commit()?;
        let mut memory = guest.memory();
        assert_eq!(
            memory.read_cstring(input.cast())?.to_bytes(),
            b"Tool scratch"
        );
        memory.write_exact(output, &[0x35; 4096])?;
        let result = guest
            .inject(
                Readlink::new()
                    .with_path(PathPtr::from_ptr(unsafe { path.cast().as_ptr() }))
                    .with_buf(Some(output.cast()))
                    .with_bufsize(4096),
            )
            .await?;
        let expected = EXECUTABLE.get().unwrap();
        assert_eq!(result as usize, expected.len());
        let mut observed = [0; 4096];
        memory.read_exact(output, &mut observed)?;
        assert_eq!(&observed[..expected.len()], expected);
        assert!(observed[expected.len()..].iter().all(|byte| *byte == 0x35));
        let address = INSPECTION_ADDRESS.load(Ordering::Relaxed);
        assert_eq!(
            memory
                .read_cstring(Addr::from_raw(address).unwrap())?
                .to_bytes(),
            b"inspect"
        );
        memory.write_exact(AddrMut::from_raw(address + 16).unwrap(), &[0x47; 16])?;
        assert_eq!(
            memory.write(AddrMut::from_raw(1).unwrap(), &[1; 16]),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            memory.read_cstring(Addr::from_raw(1).unwrap()),
            Err(Errno::EFAULT)
        );
        drop(guard);
        drop(input_guard);
        let (total, senders) = guest.send_rpc(1).await;
        let calls = CALLS.fetch_add(1, Ordering::Relaxed) + 1;
        assert_eq!(total, calls as u64);
        assert_eq!(senders, 1);
        Ok(424_242)
    }
}

// Same ABI as the existing syscall_fallback/xstate.rs test assembly. Reuse
// its full-state save/restore and protected-stack call, without changing its
// existing native, clobber or Tool comparisons.
#[repr(C)]
struct State {
    original: *mut u8,
    before: *mut u8,
    after: *mut u8,
    clear: *mut u8,
    mask: u64,
    site: *mut u8,
    omit_restore: u64,
    pkru: u64,
}

unsafe extern "C" {
    fn fallback_pkey_call(state: *const State, stack: *mut u8) -> i64;
}

pub(super) fn run(path: &Path) {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) }, 0);
    if core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 4) == 0 {
        println!("memory access: OSPKE unavailable");
        std::process::exit(77);
    }
    // As in the existing protected-stack fixture, both native and Tool arms
    // must use a valid rseq registration. Unregister this fixture's own area
    // before denying key0, then restore it after the original PKRU is restored.
    let offset = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_offset".as_ptr()) };
    let size = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_size".as_ptr()) };
    assert!(!offset.is_null() && !size.is_null());
    let size = unsafe { *size.cast::<u32>() };
    let rseq = if size != 0 {
        assert!(size <= 32);
        let mut fs = 0usize;
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1003, &mut fs) },
            0
        );
        let area = fs.wrapping_add_signed(unsafe { *offset.cast::<isize>() });
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_rseq, area, 32, 1, 0x5305_3053u32) },
            0
        );
        Some(area)
    } else {
        None
    };
    EXECUTABLE
        .set(
            std::fs::read_link("/proc/self/exe")
                .unwrap()
                .as_os_str()
                .as_bytes()
                .to_vec(),
        )
        .unwrap();
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let map = |length| {
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(pointer, libc::MAP_FAILED);
        pointer.cast::<u8>()
    };
    let code = map(page);
    let site = unsafe { code.add(page - 3) };
    unsafe { site.copy_from_nonoverlapping([0x0f, 0x05, 0xc3].as_ptr(), 3) };
    assert_eq!(
        unsafe { libc::mprotect(code.cast(), page, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    let inspection = map(page);
    unsafe { inspection.copy_from_nonoverlapping(c"inspect".as_ptr().cast(), 8) };
    INSPECTION_ADDRESS.store(inspection as usize, Ordering::Relaxed);
    let mask = unsafe { core::arch::x86_64::_xgetbv(0) };
    assert_ne!(mask & 512, 0);
    let bytes = core::arch::x86_64::__cpuid_count(0xd, 0).ebx as usize;
    let stride = bytes.div_ceil(page) * page;
    let length = page + 4 * stride + 1024 * 1024;
    let mapping = map(length);
    let key = unsafe { libc::syscall(libc::SYS_pkey_alloc, 0, 0) };
    assert!(key > 0);
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pkey_mprotect,
                mapping,
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                key,
            )
        },
        0
    );
    let state = unsafe { &mut *mapping.cast::<State>() };
    *state = State {
        original: unsafe { mapping.add(page) },
        before: unsafe { mapping.add(page + stride) },
        after: unsafe { mapping.add(page + 2 * stride) },
        clear: unsafe { mapping.add(page + 3 * stride) },
        mask,
        site,
        omit_restore: 0,
        pkru: 0,
    };
    let stack = unsafe { mapping.add(length) };
    // fallback_pkey_call aligns the stack, then fallback_xstate_call saves
    // three words before its call to the page-end syscall site.
    EXPECTED_RSP.store(stack as usize - 40, Ordering::Relaxed);
    SITE.store(site as usize, Ordering::Relaxed);
    let native_pid = unsafe { libc::getpid() } as i64;
    for tool in [false, true] {
        if tool {
            unsafe { reverie_liteinst::install_tool::<MemoryTool>(path) }.unwrap();
        }
        for pkru in [0, 1] {
            state.pkru = pkru;
            unsafe { *libc::__errno_location() = libc::E2BIG };
            assert_eq!(
                unsafe { fallback_pkey_call(state, stack) },
                if tool { 424_242 } else { native_pid }
            );
            assert_eq!(unsafe { *libc::__errno_location() }, libc::E2BIG);
            assert_eq!(
                unsafe { std::slice::from_raw_parts(state.before, bytes) },
                unsafe { std::slice::from_raw_parts(state.after, bytes) }
            );
            if tool {
                assert_eq!(
                    unsafe { std::slice::from_raw_parts(inspection.add(16), 16) },
                    &[0x47; 16]
                );
            }
        }
    }
    assert_eq!(CALLS.load(Ordering::Relaxed), 2);
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_hook_count(site as u64),
        0
    );
    assert_eq!(
        reverie_liteinst::reverie_liteinst_site_trap_count(site as u64),
        2
    );
    assert_eq!(
        unsafe { std::slice::from_raw_parts(site, 3) },
        [0x0f, 0x05, 0xc3]
    );
    println!(
        "memory access: rseq=unregistered native=2 Tool=2 pkru=0,1 xstate-bytes={bytes} scratch=complete readlink=complete inspection=complete faults=EFAULT rpc=2 hooks=0 traps=2"
    );
    assert_eq!(unsafe { libc::syscall(libc::SYS_pkey_free, key) }, 0);
    for (pointer, length) in [(mapping, length), (inspection, page), (code, page)] {
        assert_eq!(unsafe { libc::munmap(pointer.cast(), length) }, 0);
    }
    if let Some(area) = rseq {
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_rseq, area, 32, 0, 0x5305_3053u32) },
            0
        );
    }
}
