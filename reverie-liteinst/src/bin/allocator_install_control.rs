//! A caller with System must be refused before Tool construction or activation.

use std::path::Path;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use reverie::Pid;
use reverie::Subscription;
use reverie::Tool;

// Keep the compiler's default System allocator and the original refusal test.
reverie_liteinst::declare_legacy_tool_backing!();

static TOOL_CALLS: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct MustNotStart;

#[reverie::tool]
impl Tool for MustNotStart {
    type GlobalState = ();
    type ThreadState = ();

    fn new(_: Pid, _: &()) -> Self {
        TOOL_CALLS.fetch_add(1, Ordering::Relaxed);
        Self
    }

    fn subscriptions(_: &()) -> Subscription {
        TOOL_CALLS.fetch_add(1, Ordering::Relaxed);
        Subscription::none()
    }
}

fn seccomp_state() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").expect("read seccomp state");
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .expect("kernel must expose seccomp mode and filter count")
            .trim()
            .parse::<u64>()
            .expect("numeric seccomp state")
    };
    (field("Seccomp:"), field("Seccomp_filters:"))
}

fn main() {
    let mode = std::env::args()
        .nth(1)
        .expect("install, quiescent or bootstrap");
    // Merely mentioning the core must not install its former global allocator.
    let layout = std::alloc::Layout::from_size_align(64, 16).unwrap();
    let pointer = unsafe { std::alloc::alloc(layout) };
    assert!(!pointer.is_null());
    assert_eq!(
        reverie_liteinst::allocator_fixture::m1_probe_private(pointer),
        0
    );
    unsafe { std::alloc::dealloc(pointer, layout) };
    let before = seccomp_state();
    let missing_coordinator = Path::new("/reverie-m1-no-such-coordinator/socket");
    // SAFETY: this fresh process is single-threaded, has installed no Tool and
    // keeps every other application thread quiescent. The actual System
    // allocator is intentionally unsupported; installation must refuse it.
    let result = unsafe {
        match mode.as_str() {
            "install" => reverie_liteinst::install_tool::<MustNotStart>(missing_coordinator),
            "quiescent" => {
                reverie_liteinst::install_tool_quiescent::<MustNotStart>(missing_coordinator)
            }
            "bootstrap" => {
                reverie_liteinst::install_tool_from_bootstrap::<MustNotStart>(missing_coordinator)
            }
            _ => panic!("unknown installation control"),
        }
    };
    let error = result.expect_err("System-only root must not be admitted");
    assert_eq!(error.raw_os_error(), Some(libc::EOPNOTSUPP));
    assert_eq!(TOOL_CALLS.load(Ordering::Relaxed), 0);
    assert_eq!(
        seccomp_state(),
        before,
        "installation activated a seccomp filter"
    );
    println!("M1_INSTALL_CONTROL mode={mode} refused=EOPNOTSUPP tool_calls=0 filter_unchanged=1");
}
