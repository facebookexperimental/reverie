//! Socket routing observations under the actual installed shared Tool owner.

use std::io::Read;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::syscalls::Sysno;
use reverie_inguest::guest::rpc::GuestRpcStream;
use reverie_inguest::guest::support::tool_callback_active;
use reverie_inguest::stats::rpc_io_counter_test;
use reverie_liteinst::LiteinstDispatchPath;

use super::SharedGlobal;
use super::SharedRequest;

const MECHANISM: usize = 1;
const OUTSIDE_SHARED: usize = 2;
const OUTSIDE_LITEINST: usize = 3;
static MODE: AtomicUsize = AtomicUsize::new(0);
static CALLBACK_CHECKS: AtomicUsize = AtomicUsize::new(0);
static SOCKETS: OnceLock<Mutex<Sockets>> = OnceLock::new();

struct Sockets {
    client: GuestRpcStream,
    peer: UnixStream,
}

pub(super) fn run(mode: &str) {
    assert!(!tool_callback_active());
    let mode = match mode {
        "shared-handler-rpc-io" => MECHANISM,
        "shared-handler-outside-shared" => OUTSIDE_SHARED,
        "shared-handler-outside-liteinst" => OUTSIDE_LITEINST,
        _ => panic!("unknown RPC I/O mode"),
    };
    if mode == MECHANISM {
        // All sockets and timeout state exist before real installation; the
        // measured operations use fixed stack buffers without allocation.
        let (client, mut peer) = UnixStream::pair().unwrap();
        for socket in [&client, &peer] {
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
        }
        peer.write_all(b"abcdefghi").unwrap();
        assert!(
            SOCKETS
                .set(Mutex::new(Sockets {
                    client: client.into(),
                    peer,
                }))
                .is_ok()
        );
    }
    MODE.store(mode, Ordering::Relaxed);
    super::run(false);
}

pub(super) fn subscribe_socket_controls() -> bool {
    matches!(
        MODE.load(Ordering::Relaxed),
        OUTSIDE_SHARED | OUTSIDE_LITEINST
    )
}

pub(super) fn refuse_unexpected_socket_callback(number: Sysno) {
    if subscribe_socket_controls() && matches!(number, Sysno::sendto | Sysno::recvfrom) {
        // Descriptor protection must refuse the guest's coordinator socket
        // before Tool dispatch. This distinct terminal status cannot satisfy
        // the expected transport-failure status 123.
        unsafe {
            reverie_inguest::trap::raw_syscall6(libc::SYS_exit_group, [124, 0, 0, 0, 0, 0]);
        }
        unreachable!("unexpected socket callback exit returned");
    }
}

fn nested() -> u64 {
    rpc_io_counter_test(LiteinstDispatchPath::InGuestNestedSigsys)
}

fn guest() -> u64 {
    rpc_io_counter_test(LiteinstDispatchPath::InGuestSigsys)
}

pub(super) fn check_actual_callback(count: u64) {
    if MODE.load(Ordering::Relaxed) != MECHANISM || count != 1 {
        return;
    }
    // This is called only from SharedTool's real installed getpid callback.
    // Never manufacture ToolCallbackGuard authority in this fixture.
    assert!(tool_callback_active());
    let mut sockets = SOCKETS.get().unwrap().lock().unwrap();
    let fd = sockets.client.as_raw_fd();
    let mut libc_buffer = [0_u8; 3];
    let mut adapter_buffer = [0_u8; 3];

    let before = nested();
    let sent = unsafe {
        libc::sendto(
            fd,
            b"L".as_ptr().cast(),
            1,
            libc::MSG_NOSIGNAL,
            core::ptr::null(),
            0,
        )
    };
    let after = nested();
    assert_eq!(sent, 1);
    assert_eq!(after, before + 1, "libc sendto must trap outside the gate");

    let before = nested();
    let received = unsafe {
        libc::recvfrom(
            fd,
            libc_buffer.as_mut_ptr().cast(),
            libc_buffer.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    let after = nested();
    assert_eq!(received, 3);
    assert_eq!(&libc_buffer, b"abc");
    assert_eq!(
        after,
        before + 1,
        "libc recvfrom must trap outside the gate"
    );

    let before = nested();
    let sent = sockets.client.write(b"A");
    let after = nested();
    assert_eq!(sent.unwrap(), 1);
    assert_eq!(
        after, before,
        "actual callback adapter write must use the gate"
    );

    let before = nested();
    let received = sockets.client.read(&mut adapter_buffer);
    let after = nested();
    assert_eq!(received.unwrap(), 3);
    assert_eq!(&adapter_buffer, b"def");
    assert_eq!(
        after, before,
        "actual callback adapter read must use the gate"
    );
    assert!(tool_callback_active());
    assert_eq!(CALLBACK_CHECKS.fetch_add(1, Ordering::Relaxed), 0);
}

pub(super) fn after_actual_callbacks() {
    match MODE.load(Ordering::Relaxed) {
        0 => {}
        MECHANISM => check_outside_callback(),
        OUTSIDE_SHARED => {
            assert!(!tool_callback_active());
            let _ = reverie_inguest::guest::installed_tool::blocking_global_rpc::<SharedGlobal>(
                SharedRequest {
                    tag: 7001,
                    reenter: false,
                },
            );
            panic!("outside-callback shared accessor returned");
        }
        OUTSIDE_LITEINST => {
            assert!(!tool_callback_active());
            let _ = reverie_liteinst::blocking_global_rpc::<SharedGlobal>(SharedRequest {
                tag: 7002,
                reenter: false,
            });
            panic!("outside-callback LiteInst accessor returned");
        }
        _ => unreachable!(),
    }
}

fn check_outside_callback() {
    assert!(!tool_callback_active());
    assert_eq!(CALLBACK_CHECKS.load(Ordering::Relaxed), 1);
    let mut sockets = SOCKETS.get().unwrap().lock().unwrap();
    let mut buffer = [0_u8; 3];

    let before_guest = guest();
    let before_nested = nested();
    let sent = sockets.client.write(b"O");
    let after_guest = guest();
    let after_nested = nested();
    assert_eq!(sent.unwrap(), 1);
    assert_eq!(
        after_guest,
        before_guest + 1,
        "outside adapter write is a guest trap"
    );
    assert_eq!(after_nested, before_nested);

    let before_guest = guest();
    let before_nested = nested();
    let received = sockets.client.read(&mut buffer);
    let after_guest = guest();
    let after_nested = nested();
    assert_eq!(received.unwrap(), 3);
    assert_eq!(&buffer, b"ghi");
    assert_eq!(
        after_guest,
        before_guest + 1,
        "outside adapter read is a guest trap"
    );
    assert_eq!(after_nested, before_nested);
    assert!(!tool_callback_active());

    let mut sent_bytes = [0_u8; 3];
    sockets.peer.read_exact(&mut sent_bytes).unwrap();
    assert_eq!(&sent_bytes, b"LAO");
    println!("rpc io: libc_nested=1,1 callback_nested=0,0 outside_guest=1,1");
    std::io::stdout().flush().unwrap();
}
