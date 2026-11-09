//! Real Guest::memory transfers under the installed FullTool callback scope.

use std::io;
use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Guest;
use reverie::syscalls::Addr;
use reverie::syscalls::AddrMut;
use reverie::syscalls::Errno;
use reverie::syscalls::MemoryAccess;
use reverie_inguest::guest::support::tool_callback_active;
use reverie_inguest::stats::rpc_io_counter_test;
use reverie_liteinst::LiteinstDispatchPath;

use super::SharedTool;

static MAPPING: OnceLock<Mapping> = OnceLock::new();
static CALLBACK_CHECKS: AtomicUsize = AtomicUsize::new(0);

struct Mapping {
    base: usize,
    page: usize,
}

impl Mapping {
    fn bytes<const N: usize>(&self, offset: usize) -> [u8; N] {
        assert!(offset.checked_add(N).unwrap() <= self.page);
        // SAFETY: only the permanently readable first page is inspected, after
        // the synchronous kernel transfer returned. No guest slice is retained.
        unsafe { ((self.base + offset) as *const [u8; N]).read() }
    }
}

pub(super) fn run() {
    assert!(!tool_callback_active());
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page > 0 && page <= 1 << 20);
    let page = page as usize;
    assert!(page.is_power_of_two());
    let base = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    unsafe { base.cast::<u8>().write_bytes(0x5a, page * 2) };
    assert_eq!(
        unsafe { libc::mprotect(base.cast::<u8>().add(page).cast(), page, libc::PROT_NONE) },
        0
    );
    // The fixture process owns these two pages until exit. Preparation precedes
    // installation; no mapping, allocation, or guard setup enters a measurement.
    assert!(
        MAPPING
            .set(Mapping {
                base: base as usize,
                page,
            })
            .is_ok()
    );
    super::run(false);
}

fn nested() -> u64 {
    rpc_io_counter_test(LiteinstDispatchPath::InGuestNestedSigsys)
}

fn vector(address: usize, length: usize) -> libc::iovec {
    libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: length,
    }
}

// As in reverie-memory's native differential tests, borrow only the numeric
// Unix iovec descriptors, never Rust slices over inaccessible remote bytes.
unsafe fn remote_reads(vectors: &[libc::iovec]) -> &[io::IoSlice<'_>] {
    unsafe { core::slice::from_raw_parts(vectors.as_ptr().cast(), vectors.len()) }
}

unsafe fn remote_writes(vectors: &mut [libc::iovec]) -> &mut [io::IoSliceMut<'_>] {
    unsafe { core::slice::from_raw_parts_mut(vectors.as_mut_ptr().cast(), vectors.len()) }
}

pub(super) fn check_actual_callback<G: Guest<SharedTool>>(guest: &mut G, count: u64) {
    let Some(mapping) = MAPPING.get() else {
        return;
    };
    if count != 1 {
        return;
    }
    // Called by SharedTool's actual installed getpid handler, never by a
    // fabricated guard or a direct ToolHost dispatch in the test runner.
    assert!(tool_callback_active());
    let before = nested();
    let pid = unsafe { libc::getpid() };
    assert_eq!(nested(), before + 1, "libc getpid control must trap");
    assert_eq!(pid, guest.pid().as_raw());
    let mut control = [0_u8; 4];
    let local = vector(control.as_mut_ptr() as usize, control.len());
    let remote = vector(b"ctrl".as_ptr() as usize, 4);
    let before = nested();
    let copied = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    assert_eq!(
        nested(),
        before + 1,
        "libc process_vm_readv control must trap"
    );
    assert_eq!(copied, 4);
    assert_eq!(&control, b"ctrl");

    let mut memory = guest.memory();
    let mut observations = [("", 0_u64); 13];
    let mut next = 0;
    macro_rules! copy {
        ($name:literal, $operation:expr) => {{
            let before = nested();
            let result = $operation;
            observations[next] = ($name, nested().checked_sub(before).unwrap());
            next += 1;
            result
        }};
    }
    let address = |offset| Addr::from_raw(mapping.base + offset).unwrap();
    let address_mut = |offset| AddrMut::from_raw(mapping.base + offset).unwrap();
    let mut bytes = [0xa7; 5];
    assert_eq!(
        copy!("scalar read", memory.read(address(0), &mut bytes)),
        Ok(5)
    );
    assert_eq!(bytes, [0x5a; 5]);
    assert_eq!(
        copy!("scalar write", memory.write(address_mut(8), b"write")),
        Ok(5)
    );
    assert_eq!(&mapping.bytes::<5>(8), b"write");
    assert_eq!(
        copy!(
            "user write",
            memory.write_with_user_access(address_mut(16), b"usr")
        ),
        Ok(3)
    );
    assert_eq!(&mapping.bytes::<3>(16), b"usr");

    // A later fault must retain the completed first vector and stop before the
    // final accessible vector. The remote descriptors contain no Rust pointee.
    let mut remote = [
        vector(mapping.base + 32, 3),
        vector(mapping.base + mapping.page, 4),
        vector(mapping.base + 48, 3),
    ];
    let mut bytes = [0xa7; 10];
    assert_eq!(
        copy!("vector read partial", unsafe {
            memory.read_vectored(
                remote_reads(&remote),
                &mut [io::IoSliceMut::new(&mut bytes)],
            )
        }),
        Ok(3)
    );
    assert_eq!(
        bytes,
        [0x5a, 0x5a, 0x5a, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7]
    );
    assert_eq!(
        copy!("vector write partial", unsafe {
            memory.write_vectored(
                &[io::IoSlice::new(b"vecFAULT!!")],
                remote_writes(&mut remote),
            )
        }),
        Ok(3)
    );
    assert_eq!(&mapping.bytes::<3>(32), b"vec");
    assert_eq!(mapping.bytes::<3>(48), [0x5a; 3]);

    let mut bytes = [0xa7; 8];
    assert_eq!(
        copy!(
            "scalar read partial",
            memory.read(address(mapping.page - 3), &mut bytes)
        ),
        Ok(3)
    );
    assert_eq!(bytes, [0x5a, 0x5a, 0x5a, 0xa7, 0xa7, 0xa7, 0xa7, 0xa7]);
    assert_eq!(
        copy!(
            "scalar write partial",
            memory.write(address_mut(mapping.page - 3), b"partial!")
        ),
        Ok(3)
    );
    assert_eq!(&mapping.bytes::<3>(mapping.page - 3), b"par");
    let mut bytes = [0xa7; 8];
    assert_eq!(
        copy!(
            "scalar read fault",
            memory.read(address(mapping.page), &mut bytes)
        ),
        Err(Errno::EFAULT)
    );
    assert_eq!(bytes, [0xa7; 8]);
    assert_eq!(
        copy!(
            "scalar write fault",
            memory.write(address_mut(mapping.page), b"fault")
        ),
        Err(Errno::EFAULT)
    );
    let mut remote = [vector(mapping.base + mapping.page, 5)];
    assert_eq!(
        copy!("vector read fault", unsafe {
            memory.read_vectored(
                remote_reads(&remote),
                &mut [io::IoSliceMut::new(&mut bytes)],
            )
        }),
        Ok(0)
    );
    assert_eq!(bytes, [0xa7; 8]);
    assert_eq!(
        copy!("vector write fault", unsafe {
            memory.write_vectored(&[io::IoSlice::new(b"fault")], remote_writes(&mut remote))
        }),
        Ok(0)
    );
    assert_eq!(
        copy!("empty vector read", memory.read_vectored(&[], &mut [])),
        Ok(0)
    );
    assert_eq!(
        copy!("empty vector write", memory.write_vectored(&[], &mut [])),
        Ok(0)
    );

    // Scalar empty/overflow shortcuts must remain syscall-free. Empty exact
    // copies preserve the existing trait's success without calling a primitive.
    let before = nested();
    let invalid = Addr::from_raw(usize::MAX).unwrap();
    let invalid_mut = AddrMut::from_raw(usize::MAX).unwrap();
    assert_eq!(memory.read(invalid, &mut []), Ok(0));
    assert_eq!(memory.write(invalid_mut, &[]), Ok(0));
    assert_eq!(memory.read_exact(invalid, &mut []), Ok(()));
    assert_eq!(memory.write_exact(invalid_mut, &[]), Ok(()));
    assert_eq!(
        memory.read(Addr::from_raw(usize::MAX - 3).unwrap(), &mut bytes),
        Err(Errno::EFAULT)
    );
    assert_eq!(
        memory.write(AddrMut::from_raw(usize::MAX - 3).unwrap(), &bytes),
        Err(Errno::EFAULT)
    );
    assert_eq!(bytes, [0xa7; 8]);
    assert_eq!(nested(), before);

    assert_eq!(next, observations.len());
    for (operation, delta) in observations {
        assert_eq!(
            delta, 0,
            "actual Guest::memory {operation} must not add nested SIGSYS"
        );
    }
    assert!(tool_callback_active());
    assert_eq!(CALLBACK_CHECKS.fetch_add(1, Ordering::Relaxed), 0);
}

pub(super) fn after_actual_callbacks() {
    if MAPPING.get().is_some() {
        assert!(!tool_callback_active());
        assert_eq!(CALLBACK_CHECKS.load(Ordering::Relaxed), 1);
        println!("memory io: libc_nested=1,1 copies=13 nested=0 partial=3 faults=EFAULT,0");
        std::io::stdout().flush().unwrap();
    }
}
