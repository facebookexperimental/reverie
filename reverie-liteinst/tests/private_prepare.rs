//! Private straddler validation ordering: the caller validates
//! before constructing any admitted owner (plain returned error),
//! and errors after ownership transfer into a validated prepare
//! entry terminate before generic teardown. One serialized test
//! owns the single Drop witness and the environment for its whole
//! run; fork children use fabricated transports over socket pairs
//! and a modeled gate page, redeeming no real launch authorization.

reverie_liteinst::declare_legacy_scoped_tool_allocator!();

use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicPtr;
use std::sync::atomic::Ordering;

static CONFIG_DROP_WITNESS: AtomicPtr<u64> = AtomicPtr::new(core::ptr::null_mut());

fn witness_page() -> *mut u64 {
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    let page = page.cast::<u64>();
    unsafe {
        page.write_volatile(0);
        page.add(1).write_volatile(0);
    }
    page
}

/// A Config whose Drop marks shared cell 0, proving whether generic
/// owned teardown ran in a fork child.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
struct WitnessConfig {
    marker: u64,
}

impl Drop for WitnessConfig {
    fn drop(&mut self) {
        let page = CONFIG_DROP_WITNESS.load(Ordering::SeqCst);
        if !page.is_null() {
            unsafe { page.write_volatile(7) };
        }
    }
}

#[derive(Default)]
struct StraddlerGlobal;

#[reverie::global_tool]
impl reverie::GlobalTool for StraddlerGlobal {
    type Request = ();
    type Response = ();
    type Config = WitnessConfig;

    async fn receive_rpc(&self, _from: reverie::Pid, _message: ()) {
        panic!("selector validation must precede any RPC in this fixture");
    }
}

#[derive(Default)]
struct StraddlerTool;

#[reverie::tool]
impl reverie::Tool for StraddlerTool {
    type GlobalState = StraddlerGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<G: reverie::Guest<Self>>(
        &self,
        _guest: &mut G,
        _syscall: reverie::syscalls::Syscall,
    ) -> Result<i64, reverie::Error> {
        panic!("selector validation must precede any dispatch in this fixture");
    }
}

fn write_frame(peer: &mut UnixStream, payload: &[u8]) {
    use std::io::Write;
    peer.write_all(&(payload.len() as u32).to_be_bytes())
        .unwrap();
    peer.write_all(payload).unwrap();
    peer.flush().unwrap();
}

fn read_frame(peer: &mut UnixStream) -> Vec<u8> {
    use std::io::Read;
    let mut header = [0_u8; 4];
    peer.read_exact(&mut header).unwrap();
    let mut payload = vec![0_u8; u32::from_be_bytes(header) as usize];
    peer.read_exact(&mut payload).unwrap();
    payload
}

fn socket_pair() -> (UnixStream, UnixStream) {
    let (stream, peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    peer.set_write_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    (stream, peer)
}

fn clear_straddler_and_validate()
-> Result<reverie_liteinst::ValidatedStraddlerStaleness, std::io::Error> {
    // SAFETY: fork child is single-threaded before any other work.
    unsafe {
        std::env::remove_var(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV);
    }
    if unsafe { reverie_inguest::trap::prepare_fixed_gates() }.is_err() {
        unsafe { libc::_exit(95) };
    }
    reverie_liteinst::validate_straddler_selector()
}

/// One serialized test owns the witness page and the environment:
/// parser refusal, then initial and successor ownership phases in
/// order. Each phase's parent half proves its witnesses trip before
/// forking and retires the pointer before unmapping.
#[test]
fn private_prepare_ordering_is_serialized() {
    parser_phase();
    initial_phase();
    #[cfg(feature = "exec-native-injection")]
    successor_phase();
}

fn parser_phase() {
    let page = witness_page();
    CONFIG_DROP_WITNESS.store(page, Ordering::SeqCst);
    drop(WitnessConfig { marker: 0 });
    assert_eq!(unsafe { page.read_volatile() }, 7, "witness must trip");
    unsafe { page.write_volatile(0) };
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // SAFETY: fork child is single-threaded before any other work.
        unsafe {
            std::env::set_var(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV, "banana");
        }
        let refused = match reverie_liteinst::validate_straddler_selector() {
            Err(error) => {
                error.kind() == std::io::ErrorKind::InvalidInput
                    && error.to_string()
                        == "REVERIE_LITEINST_STRADDLER_STALENESS_TICKS must be a nonzero \
                            decimal TSC-tick count"
            }
            Ok(_) => false,
        };
        if !refused {
            unsafe { libc::_exit(44) };
        }
        // SAFETY: still the single-threaded fork child.
        unsafe {
            std::env::set_var(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV, "17000");
        }
        if reverie_liteinst::validate_straddler_selector().is_err() {
            unsafe { libc::_exit(45) };
        }
        // SAFETY: still the single-threaded fork child.
        unsafe {
            std::env::remove_var(reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV);
        }
        if reverie_liteinst::validate_straddler_selector().is_err() {
            unsafe { libc::_exit(46) };
        }
        // Caller-side teardown after the plain returns above is
        // ordinary and observable; nothing was handed over.
        drop(WitnessConfig { marker: 73 });
        unsafe { libc::_exit(42) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    let witnessed = unsafe { page.read_volatile() };
    CONFIG_DROP_WITNESS.store(core::ptr::null_mut(), Ordering::SeqCst);
    assert_eq!(unsafe { libc::munmap(page.cast(), 4096) }, 0);
    assert!(libc::WIFEXITED(status), "child status {status}");
    assert_eq!(libc::WEXITSTATUS(status), 42);
    assert_eq!(witnessed, 7, "only the caller's own post-return drop ran");
}

/// Valid token first, then client construction, then an error after
/// ownership transfer into the validated prepare entry: terminal 127
/// with the admitted client's generic Config Drop never run. The
/// null native control is rejected only at publication, so this
/// proves post-transfer teardown ordering at the new boundary, not
/// the old late parser.
fn initial_phase() {
    let (stream, mut peer) = socket_pair();
    let config = reverie_rpc_transport::codec::encode(&WitnessConfig { marker: 73 }).unwrap();
    let digest = reverie_rpc_transport::initial_image::config_digest(&config);
    let page = witness_page();
    CONFIG_DROP_WITNESS.store(page, Ordering::SeqCst);
    drop(WitnessConfig { marker: 0 });
    assert_eq!(unsafe { page.read_volatile() }, 7, "witness must trip");
    unsafe { page.write_volatile(0) };
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(peer);
        let token = match clear_straddler_and_validate() {
            Ok(token) => token,
            Err(_) => unsafe { libc::_exit(97) },
        };
        let stream = reverie_inguest::guest::rpc::GuestRpcStream::from(stream);
        let client = match reverie_rpc_transport::BlockingRpcClient::<
            StraddlerGlobal,
            reverie_inguest::guest::rpc::GuestRpcStream,
        >::initial_image_from_connected_stream(
            stream,
            reverie::Tid::from_raw(17),
            b"prepare-fixture-nonce",
            digest,
        ) {
            Ok(client) => client,
            Err(_) => unsafe { libc::_exit(96) },
        };
        match unsafe {
            reverie_liteinst::prepare_tool_initial_image_validated::<StraddlerTool>(
                token,
                client,
                core::ptr::null_mut(),
            )
        } {
            Err(_) => unsafe { libc::_exit(44) },
            Ok(_) => unsafe { libc::_exit(43) },
        }
    }
    drop(stream);
    // Serve exactly the redemption + ack + Config exchange that
    // fabricates the client; this is transport data, not adoption.
    let _request = read_frame(&mut peer);
    let mut ack = Vec::from(*b"RVINITAK");
    ack.extend_from_slice(&1_u16.to_be_bytes());
    ack.extend_from_slice(&digest);
    write_frame(&mut peer, &ack);
    write_frame(&mut peer, &config);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    let config_dropped = unsafe { page.read_volatile() };
    CONFIG_DROP_WITNESS.store(core::ptr::null_mut(), Ordering::SeqCst);
    assert_eq!(unsafe { libc::munmap(page.cast(), 4096) }, 0);
    assert!(libc::WIFEXITED(status), "child status {status}");
    assert_eq!(
        libc::WEXITSTATUS(status),
        127,
        "post-transfer error must take the terminal path"
    );
    assert_eq!(config_dropped, 0, "generic Config Drop ran in the child");
}

/// The successor validated entry after ownership transfer: terminal
/// 127 with neither the generic Config Drop (cell 0) nor the boxed
/// consumer Drop (cell 1) run.
#[cfg(feature = "exec-native-injection")]
fn successor_phase() {
    struct WitnessConsumer {
        page: *mut u64,
    }
    // SAFETY: test-only; the shared page outlives the fork child.
    unsafe impl Send for WitnessConsumer {}
    impl Drop for WitnessConsumer {
        fn drop(&mut self) {
            unsafe { self.page.add(1).write_volatile(9) };
        }
    }
    // SAFETY: fixture only proves teardown ordering; callbacks
    // above decode run, publication then fails on the null control.
    unsafe impl reverie_liteinst::NativeSuccessorConsumer<StraddlerTool> for WitnessConsumer {
        fn qualify_config(&self, _config: &WitnessConfig) -> std::io::Result<()> {
            Ok(())
        }

        fn decode_verified(
            &mut self,
            _config: &WitnessConfig,
            _state: &reverie_rpc_transport::successor::VerifiedSuccessorState,
            _binding: reverie_inguest::guest::exec_private::SuccessorBinding,
        ) -> std::io::Result<(StraddlerTool, ())> {
            Ok((StraddlerTool, ()))
        }

        fn restore_fresh_runtime(
            &mut self,
            _binding: reverie_inguest::guest::exec_private::SuccessorBinding,
        ) -> std::io::Result<()> {
            Ok(())
        }

        fn complete(
            &mut self,
            _rpc: &reverie_liteinst::rpc::CoordinatorRpc<StraddlerGlobal>,
            _binding: reverie_inguest::guest::exec_private::SuccessorBinding,
        ) -> std::io::Result<reverie_inguest::guest::exec_private::SuccessorBinding> {
            Err(std::io::Error::other(
                "unreachable in straddler terminal fixture",
            ))
        }
    }

    let (stream, mut peer) = socket_pair();
    let config = reverie_rpc_transport::codec::encode(&WitnessConfig { marker: 73 }).unwrap();
    let state: &[u8] = b"successor-state";
    let expected = reverie_rpc_transport::successor::ExpectedSuccessor {
        config: reverie_rpc_transport::initial_image::config_digest(&config),
        state: reverie_rpc_transport::initial_image::config_digest(state),
    };
    let page = witness_page();
    CONFIG_DROP_WITNESS.store(page, Ordering::SeqCst);
    drop(WitnessConfig { marker: 0 });
    drop(WitnessConsumer { page });
    assert_eq!(
        unsafe { page.read_volatile() },
        7,
        "config witness must trip"
    );
    assert_eq!(
        unsafe { page.add(1).read_volatile() },
        9,
        "consumer witness must trip"
    );
    unsafe {
        page.write_volatile(0);
        page.add(1).write_volatile(0);
    }
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        drop(peer);
        let token = match clear_straddler_and_validate() {
            Ok(token) => token,
            Err(_) => unsafe { libc::_exit(97) },
        };
        let request = reverie_rpc_transport::successor::SuccessorRequest {
            ticket: b"prepare-fixture-ticket",
            expected,
        };
        let stream = reverie_inguest::guest::rpc::GuestRpcStream::from(stream);
        let client = match reverie_rpc_transport::BlockingRpcClient::<
            StraddlerGlobal,
            reverie_inguest::guest::rpc::GuestRpcStream,
        >::successor_from_connected_stream(
            stream, reverie::Tid::from_raw(17), request
        ) {
            Ok(client) => client,
            Err(_) => unsafe { libc::_exit(96) },
        };
        let binding = reverie_inguest::guest::exec_private::SuccessorBinding {
            generation: 1,
            ticket: client.state().ticket_digest(),
            state: expected.state,
            config: expected.config,
        };
        match unsafe {
            reverie_liteinst::prepare_tool_successor_image_validated::<StraddlerTool>(
                token,
                client,
                core::ptr::null_mut(),
                binding,
                Box::new(WitnessConsumer { page }),
            )
        } {
            Err(_) => unsafe { libc::_exit(44) },
            Ok(_) => unsafe { libc::_exit(43) },
        }
    }
    drop(stream);
    let _request = read_frame(&mut peer);
    let mut ack = Vec::from(*b"RVSUCCAK");
    ack.extend_from_slice(&1_u16.to_be_bytes());
    ack.extend_from_slice(&expected.config);
    ack.extend_from_slice(&expected.state);
    ack.extend_from_slice(&reverie_rpc_transport::initial_image::config_digest(
        b"prepare-fixture-ticket",
    ));
    write_frame(&mut peer, &ack);
    write_frame(&mut peer, &config);
    write_frame(&mut peer, state);
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    let config_dropped = unsafe { page.read_volatile() };
    let consumer_dropped = unsafe { page.add(1).read_volatile() };
    CONFIG_DROP_WITNESS.store(core::ptr::null_mut(), Ordering::SeqCst);
    assert_eq!(unsafe { libc::munmap(page.cast(), 4096) }, 0);
    assert!(libc::WIFEXITED(status), "child status {status}");
    assert_eq!(libc::WEXITSTATUS(status), 127);
    assert_eq!(config_dropped, 0, "generic Config Drop ran in the child");
    assert_eq!(consumer_dropped, 0, "boxed consumer Drop ran in the child");
}
