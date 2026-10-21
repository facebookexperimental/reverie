//! Public Tool syscalls under the real installed FullTool callback authority.

use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Guest;
use reverie::syscalls::Errno;
use reverie::syscalls::Sysno;
use reverie_inguest::guest::support::tool_callback_active;
use reverie_inguest::stats::rpc_io_counter_test;
use reverie_liteinst::LiteinstDispatchPath;

use super::SharedTool;

static FIXTURE: OnceLock<Fixture> = OnceLock::new();
static CALLBACK_CHECKS: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    file: File,
    path: CString,
    link: [u8; 4096],
    link_length: usize,
    stat: libc::stat,
}

pub(super) fn run() {
    assert!(!tool_callback_active());
    // All ownership and path preparation precedes installation. The callback
    // uses only this live physical descriptor and fixed Tool-owned buffers.
    let file = File::open("/dev/null").unwrap();
    let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    let mut link = [0xa7; 4096];
    let length = unsafe {
        libc::readlinkat(
            libc::AT_FDCWD,
            path.as_ptr(),
            link.as_mut_ptr().cast(),
            link.len(),
        )
    };
    assert!(length > 0 && (length as usize) < link.len());
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    assert_eq!(
        unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) },
        0
    );
    assert!(
        FIXTURE
            .set(Fixture {
                file,
                path,
                link,
                link_length: length as usize,
                // SAFETY: successful fstat initialized the zeroed output.
                stat: unsafe { stat.assume_init() },
            })
            .is_ok()
    );
    super::run(false);
}

fn nested() -> u64 {
    rpc_io_counter_test(LiteinstDispatchPath::InGuestNestedSigsys)
}

pub(super) fn check_actual_callback<G: Guest<SharedTool>>(guest: &mut G, count: u64) {
    let Some(fixture) = FIXTURE.get() else {
        return;
    };
    if count != 1 {
        return;
    }
    // Only SharedTool's installed getpid callback reaches this function. It
    // never creates a callback guard or obtains authority through a mock.
    assert!(tool_callback_active());
    assert!(fixture.file.as_raw_fd() >= 0);
    let before = nested();
    let pid = unsafe { libc::getpid() };
    assert_eq!(pid, guest.pid().as_raw());
    assert_eq!(nested(), before + 1, "ordinary libc getpid must trap");
    println!("tool syscall: actual_callback=1 libc_nested=1");
    std::io::stdout().flush().unwrap();

    let mut observations = [("", 0_u64); 4];
    let mut next = 0;
    macro_rules! call {
        ($name:literal, $number:expr, $args:expr) => {{
            let before = nested();
            // SAFETY: each operation returns synchronously on this stack;
            // its physical descriptors and fixed buffers are Tool-owned.
            let result = unsafe { guest.tool_syscall($number, $args) };
            observations[next] = ($name, nested().checked_sub(before).unwrap());
            next += 1;
            result
        }};
    }
    assert_eq!(call!("getpid", Sysno::getpid, [0; 6]), Ok(pid as usize));
    assert_eq!(
        call!("close", Sysno::close, [usize::MAX, 0, 0, 0, 0, 0]),
        Err(Errno::EBADF)
    );
    let mut link = [0xa7; 4096];
    assert_eq!(
        call!(
            "readlinkat",
            Sysno::readlinkat,
            [
                libc::AT_FDCWD as usize,
                fixture.path.as_ptr() as usize,
                link.as_mut_ptr() as usize,
                link.len(),
                0,
                0,
            ]
        ),
        Ok(fixture.link_length)
    );
    assert_eq!(link, fixture.link, "readlink bytes and untouched tail");
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    assert_eq!(
        call!(
            "newfstatat",
            Sysno::newfstatat,
            [
                libc::AT_FDCWD as usize,
                fixture.path.as_ptr() as usize,
                stat.as_mut_ptr() as usize,
                0,
                0,
                0,
            ]
        ),
        Ok(0)
    );
    // SAFETY: successful newfstatat initialized the zeroed output.
    let stat = unsafe { stat.assume_init() };
    assert_eq!(stat.st_dev, fixture.stat.st_dev);
    assert_eq!(stat.st_ino, fixture.stat.st_ino);
    assert_eq!(stat.st_mode, fixture.stat.st_mode);
    assert_eq!(stat.st_rdev, fixture.stat.st_rdev);
    assert_eq!(stat.st_size, fixture.stat.st_size);
    assert_eq!(stat.st_uid, fixture.stat.st_uid);
    assert_eq!(stat.st_gid, fixture.stat.st_gid);
    assert_eq!(stat.st_nlink, fixture.stat.st_nlink);
    assert_eq!(next, observations.len());
    for (operation, delta) in observations {
        assert_eq!(
            delta, 0,
            "actual Guest::tool_syscall {operation} must not add nested SIGSYS"
        );
    }
    assert!(tool_callback_active());
    assert_eq!(CALLBACK_CHECKS.fetch_add(1, Ordering::Relaxed), 0);
}

pub(super) fn after_actual_callbacks() {
    if FIXTURE.get().is_some() {
        assert!(!tool_callback_active());
        assert_eq!(CALLBACK_CHECKS.load(Ordering::Relaxed), 1);
        println!("tool syscall: calls=4 nested=0 errno=EBADF link=matched stat=matched");
        std::io::stdout().flush().unwrap();
    }
}
