/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Actual configured int3 interception, without a LiteInst preload or rewriter.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::AtomicU64;

use reverie::Guest;
use reverie::process::Stdio;
use reverie::syscalls::Addr;
use reverie::syscalls::Syscall;
use serde::Deserialize;
use serde::Serialize;
use tokio::io::AsyncReadExt;

use super::*;

#[tokio::test(flavor = "current_thread")]
async fn unbound_cleanup_retention_survives_attachment_and_tls_storage_refusal() {
    const NAME: &str = "tracer::injected_error_tests::unbound_cleanup_retention_survives_attachment_and_tls_storage_refusal";
    const ROLE: &str = "REVERIE_UNBOUND_TLS_CHILD";
    const DEADLINE: &str = "REVERIE_UNBOUND_TLS_DEADLINE";
    fn now_ns() -> u64 {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
            0
        );
        now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
    }
    if std::env::var(ROLE).as_deref() != Ok(NAME) {
        let deadline = now_ns() + 5_000_000_000;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(ROLE, NAME)
            .env(DEADLINE, deadline.to_string())
            .spawn()
            .unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "isolated TLS resource fixture failed: {status}"
                );
                assert!(now_ns() < deadline, "original five-second deadline expired");
                return;
            }
            if now_ns() >= deadline {
                let signal = child.kill();
                let rescue_deadline = Instant::now() + Duration::from_secs(2);
                let rescue = loop {
                    let status = child.try_wait().unwrap();
                    if status.is_some() || Instant::now() >= rescue_deadline {
                        break status;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                };
                panic!(
                    "original TLS fixture deadline failed; separate rescue only: {signal:?}, {rescue:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    assert!(std::env::args().any(|arg| arg == NAME));
    assert!(std::env::args().any(|arg| arg == "--exact"));
    assert!(OrdinaryAdmission::acquire().is_ok());
    struct Resource {
        drops: Arc<std::sync::atomic::AtomicUsize>,
        _original: Box<u64>,
    }
    impl PtraceCleanupResource for Resource {
        fn cleanup(&mut self) -> Result<(), Error> {
            panic!("unbound resource acquired cleanup authority")
        }
    }
    impl Drop for Resource {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn resource(drops: &Arc<std::sync::atomic::AtomicUsize>) -> Resource {
        Resource {
            drops: drops.clone(),
            _original: Box::new(71),
        }
    }
    fn storage_marker() -> CleanupUnconfirmed {
        // White-box marker for the entry-before-lookup boundary, with an actual
        // live process identity. No fabricated traced tree or cleanup success.
        CleanupUnconfirmed {
            id: u64::MAX,
            thread: std::thread::current().id(),
            primary: Arc::new(anyhow::Error::new(AfterEffect(Box::new(71))).into()),
            origin: reverie::BackendFailure {
                pid: Pid::from_raw(unsafe { libc::getpid() }),
                tid: Pid::from_raw(unsafe { libc::gettid() }),
                phase: "test attachment storage refusal",
            },
            owner_identity: Arc::new(Ok(CleanupOwnerIdentity::capture().unwrap())),
        }
    }
    let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let marker = storage_marker();
    CLEANUP_QUARANTINE.with(|owners| {
        let _borrow = owners.borrow_mut();
        assert!(matches!(
            marker.retain_cleanup_resource::<(), ExitStatus, _>(resource(&drops)),
            Err(CleanupLookupError::StorageUnavailable)
        ));
        quarantine_cleanup_resource(resource(&drops));
    });
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(*UNCONFIRMED_QUARANTINES.lock().unwrap(), 2);
    struct Teardown {
        marker: CleanupUnconfirmed,
        drops: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl Drop for Teardown {
        fn drop(&mut self) {
            assert!(
                CLEANUP_QUARANTINE.try_with(|_| ()).is_err(),
                "registry was not actually torn down"
            );
            assert!(matches!(
                self.marker
                    .retain_cleanup_resource::<(), ExitStatus, _>(resource(&self.drops)),
                Err(CleanupLookupError::StorageUnavailable)
            ));
            quarantine_cleanup_resource(resource(&self.drops));
        }
    }
    thread_local! {
        static TEARDOWN: std::cell::RefCell<Option<Teardown>> = const { std::cell::RefCell::new(None) };
    }
    let thread_drops = drops.clone();
    std::thread::spawn(move || {
        TEARDOWN.with(|slot| {
            *slot.borrow_mut() = Some(Teardown {
                marker: storage_marker(),
                drops: thread_drops,
            })
        });
        // Initialized last, destroyed first: exercise real unavailable TLS,
        // not a returned-error seam or a borrowed-registry approximation.
        CLEANUP_QUARANTINE.with(|_| ());
    })
    .join()
    .unwrap();
    assert_eq!(
        drops.load(Ordering::SeqCst),
        0,
        "storage refusal destroyed an original guard"
    );
    assert_eq!(*UNCONFIRMED_QUARANTINES.lock().unwrap(), 4);
    let refused = spawn_fn::<(), _>(|| panic!("refused admission executed guest work")).await;
    assert!(
        matches!(refused, Err(Error::Tool(error)) if error.downcast_ref::<CleanupAdmissionRefused>().is_some())
    );
    assert!(now_ns() < std::env::var(DEADLINE).unwrap().parse::<u64>().unwrap());
    // These four unbound allocations intentionally remain until isolated process
    // exit. They are not called reaped, rescued, or recoverable product owners.
}

const ENTRY: u64 = 0x401000;
const DATA: u64 = 0x402000;
const MARKER: u64 = 0x5452415054455354;
const EFFECT: &[u8] = b"committed-effect";
const AFTER: &[u8] = b"guest-continued";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
enum Mode {
    #[default]
    Success,
    Errno,
    ToolError,
    ChildToolError,
}

#[derive(Default)]
struct Log {
    events: Arc<StdMutex<Vec<&'static str>>>,
    effect_tid: Arc<AtomicI32>,
}

#[reverie::global_tool]
impl GlobalTool for Log {
    type Config = Mode;
    type Request = ();
    type Response = ();

    async fn receive_rpc(&self, from: Pid, _: ()) {
        self.effect_tid.store(from.as_raw(), Ordering::SeqCst);
        self.events.lock().unwrap().push("effect");
        static_before_failure(from, &self.events);
        refusal_before_failure(from, &self.events);
    }

    fn report_backend_failure(&self, _: reverie::BackendFailure) {
        self.events.lock().unwrap().push("failed");
    }
}

#[derive(Debug, thiserror::Error)]
#[error("typed injected failure after effect {0}")]
struct AfterEffect(Box<u64>);

#[derive(Default)]
struct TrapTool;

#[reverie::tool]
impl Tool for TrapTool {
    type GlobalState = Log;
    type ThreadState = ();

    fn subscriptions(_: &Mode) -> Subscription {
        let mut events = Subscription::none();
        events.syscalls([Sysno::getpid]);
        events
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        call: Syscall,
    ) -> Result<i64, Error> {
        assert!(matches!(call, Syscall::Getpid(_)));
        // A real injected write completes before the callback returns its error.
        assert_eq!(
            guest
                .inject(
                    reverie::syscalls::Write::default()
                        .with_fd(1)
                        .with_buf(Addr::from_raw(DATA as usize + 256))
                        .with_len(EFFECT.len()),
                )
                .await?,
            EFFECT.len() as i64,
        );
        guest.send_rpc(()).await;
        match guest.config() {
            Mode::Success => Ok(71),
            Mode::Errno => Err(Errno::EBADF.into()),
            Mode::ToolError | Mode::ChildToolError => {
                Err(anyhow::Error::new(AfterEffect(Box::new(71))).into())
            }
        }
    }
}

struct Fixture {
    path: PathBuf,
    trap_rip: u64,
}

impl Fixture {
    fn new(child: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "reverie-injected-error-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        let mut code = Vec::new();
        if child {
            // The parent blocks in wait4. If a failed child were detached or
            // encoded EIO, it and then its parent would both emit AFTER.
            code.extend_from_slice(&[0xb8, 57, 0, 0, 0, 0x0f, 0x05]); // fork
            code.extend_from_slice(&[0x48, 0x85, 0xc0, 0x0f, 0x84]); // test rax; je child
            let branch = code.len();
            code.extend_from_slice(&[0; 4]);
            code.extend_from_slice(&[0x48, 0x89, 0xc7, 0x31, 0xf6, 0x31, 0xd2, 0x45, 0x31, 0xd2]);
            code.extend_from_slice(&[0xb8, 61, 0, 0, 0, 0x0f, 0x05]); // wait4
            write(&mut code, DATA + 320, AFTER.len());
            code.extend_from_slice(&[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
            let delta = i32::try_from(code.len() - (branch + 4)).unwrap();
            code[branch..branch + 4].copy_from_slice(&delta.to_le_bytes());
        }
        // Save the actual stack in the logical frame, then invoke the configured
        // marker/RDI/frame/int3 ABI. This is not a mocked handler call.
        code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, frame
        code.extend_from_slice(&DATA.to_le_bytes());
        code.extend_from_slice(&[0x48, 0x89, 0xa7, 128, 0, 0, 0]); // mov [rdi+128],rsp
        code.extend_from_slice(&[0x48, 0xb8]); // movabs rax, marker
        code.extend_from_slice(&MARKER.to_le_bytes());
        code.push(0xcc);
        let trap_rip = ENTRY + code.len() as u64;
        fn write(code: &mut Vec<u8>, buf: u64, len: usize) {
            code.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0xbf, 1, 0, 0, 0, 0xbe]);
            code.extend_from_slice(&(buf as u32).to_le_bytes());
            code.push(0xba);
            code.extend_from_slice(&(len as u32).to_le_bytes());
            code.extend_from_slice(&[0x0f, 0x05]);
        }
        write(&mut code, DATA + 120, 8); // exact returned frame RAX
        write(&mut code, DATA + 320, AFTER.len());
        code.extend_from_slice(&[0xb8, 60, 0, 0, 0, 0x31, 0xff, 0x0f, 0x05]);
        let mut elf = vec![0u8; 0x3000];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&ENTRY.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&2u16.to_le_bytes());
        for (header, flags, offset, address, length) in [
            (64, 5u32, 0u64, 0x400000u64, 0x1000 + code.len() as u64),
            (120, 6u32, 0x2000u64, DATA, 0x1000),
        ] {
            elf[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
            elf[header + 4..header + 8].copy_from_slice(&flags.to_le_bytes());
            elf[header + 8..header + 16].copy_from_slice(&offset.to_le_bytes());
            elf[header + 16..header + 24].copy_from_slice(&address.to_le_bytes());
            elf[header + 24..header + 32].copy_from_slice(&address.to_le_bytes());
            elf[header + 32..header + 40].copy_from_slice(&length.to_le_bytes());
            elf[header + 40..header + 48].copy_from_slice(&length.to_le_bytes());
            elf[header + 48..header + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        }
        elf[0x1000..0x1000 + code.len()].copy_from_slice(&code);
        elf[0x2078..0x2080].copy_from_slice(&(libc::SYS_getpid as u64).to_le_bytes());
        elf[0x2088..0x2090].copy_from_slice(&ENTRY.to_le_bytes());
        elf[0x2100..0x2100 + EFFECT.len()].copy_from_slice(EFFECT);
        elf[0x2140..0x2140 + AFTER.len()].copy_from_slice(AFTER);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(&elf).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o700))
            .unwrap();
        Self { path, trap_rip }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_file(&self.path).unwrap();
    }
}

async fn run(mode: Mode, legacy_guard: bool) {
    run_with_transient_refusal(mode, legacy_guard, None).await;
}

async fn run_with_transient_refusal(
    mode: Mode,
    legacy_guard: bool,
    refusal: Option<Arc<AtomicBool>>,
) {
    let fixture = Fixture::new(matches!(mode, Mode::ChildToolError));
    let mut command = Command::new(&fixture.path);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut builder = TracerBuilder::<TrapTool>::new(command)
        .config(mode)
        .injected_syscall_trap(MARKER, fixture.trap_rip);
    if legacy_guard {
        // Exercise the production legacy cleanup owner, using the maintained
        // activation bypass. This does not validate a real LiteInst preload.
        builder = builder
            .liteinst_runtime("/not/used.so", 1, 2, 3, 4, 5)
            .activate_liteinst_without_handshake_for_test();
    }
    if let Some(refusal) = refusal {
        builder = builder.fail_liteinst_discovery_once_for_test(refusal);
    }
    let mut tracer = builder.spawn().await.unwrap();
    let root = tracer.guest_pid();
    let mut stdout = tracer.stdout.take().unwrap();
    let mut stderr = tracer.stderr.take().unwrap();
    // Keep diagnostics without retaining the GlobalTool itself: completion
    // must be allowed to consume its sole Arc after all tasks actually join.
    let observations = Arc::downgrade(&tracer.gref);
    let events = tracer.gref.events.clone();
    let effect_tid = tracer.gref.effect_tid.clone();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let (result, out_result, err_result) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            tracer.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        )
    })
    .await
    .expect("configured injected syscall did not finish within five seconds");
    out_result.unwrap();
    err_result.unwrap();
    // Do not keep an argument temporary's MutexGuard across static_boundary:
    // its read-only observation also locks the same event vector.
    let boundary_events = {
        let guard = events.lock().unwrap();
        guard.iter().map(|event| (*event).to_owned()).collect()
    };
    static_boundary(
        "plain-before-absence",
        root,
        StaticDetails::Plain {
            stdout: out.clone(),
            stderr: err.clone(),
            events: boundary_events,
            failure: result.as_ref().err().map(ToString::to_string),
            original_after_effect: matches!(&result, Err(Error::Tool(error)) if error.downcast_ref::<AfterEffect>().is_some()),
        },
    );
    assert!(err.is_empty(), "unexpected guest stderr: {err:?}");
    assert!(
        !PathBuf::from(format!("/proc/{root}")).exists(),
        "root was not actually reaped"
    );
    assert!(
        observations.upgrade().is_none(),
        "Tool state still has a backend owner"
    );
    let effect_tid = effect_tid.load(Ordering::SeqCst);
    assert!(effect_tid > 0, "actual callback effect was never observed");
    assert!(
        !PathBuf::from(format!("/proc/{effect_tid}")).exists(),
        "effect task was not reaped"
    );
    if matches!(mode, Mode::ChildToolError) {
        assert_ne!(root.as_raw(), effect_tid);
    }
    match mode {
        Mode::ToolError | Mode::ChildToolError => {
            assert_eq!(*events.lock().unwrap(), ["effect", "failed"]);
            let Error::Tool(error) = result.err().expect("tool failure became a guest result")
            else {
                panic!("typed Tool error was lost");
            };
            assert_eq!(
                *error
                    .downcast_ref::<AfterEffect>()
                    .expect("original typed payload")
                    .0,
                71
            );
            assert_eq!(
                out, EFFECT,
                "guest continued or result frame was exposed after failure"
            );
        }
        Mode::Success | Mode::Errno => {
            let (status, log) = result.unwrap();
            assert_eq!(status, ExitStatus::Exited(0));
            assert_eq!(*log.events.lock().unwrap(), ["effect"]);
            let value: i64 = if matches!(mode, Mode::Success) {
                71
            } else {
                -(libc::EBADF as i64)
            };
            let expected = [EFFECT, value.to_le_bytes().as_slice(), AFTER].concat();
            assert_eq!(out, expected);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn injected_success_preserves_result_and_continuation() {
    run(Mode::Success, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn injected_errno_preserves_result_and_continuation() {
    run(Mode::Errno, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn injected_tool_error_after_effect_is_terminal() {
    run(Mode::ToolError, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn injected_child_tool_error_does_not_resume_child_or_parent() {
    const NAME: &str =
        "tracer::injected_error_tests::injected_child_tool_error_does_not_resume_child_or_parent";
    if static_fixture_natural_reaper("plain", NAME).await {
        return;
    }
    static_diagnostic_init();
    run(Mode::ChildToolError, false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_guard_preserves_injected_success_and_errno() {
    run(Mode::Success, true).await;
    run(Mode::Errno, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_guard_reaps_injected_root_and_child_tool_failures() {
    run(Mode::ToolError, true).await;
    run(Mode::ChildToolError, true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_guard_refusal_retains_original_owner_and_typed_cause() {
    const NAME: &str =
        "tracer::injected_error_tests::legacy_guard_refusal_retains_original_owner_and_typed_cause";
    refusal_fixture("original", NAME).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_guard_refusal_retry_retains_original_owner() {
    const NAME: &str =
        "tracer::injected_error_tests::legacy_guard_refusal_retry_retains_original_owner";
    refusal_fixture("once", NAME).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_guard_refusal_held_natural_parent_stays_unconfirmed() {
    const NAME: &str =
        "tracer::injected_error_tests::legacy_guard_refusal_held_natural_parent_stays_unconfirmed";
    refusal_fixture("held", NAME).await;
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_guard_refusal_ipc_failure_keeps_registered_owner_without_drop_budget() {
    const NAME: &str = "tracer::injected_error_tests::legacy_guard_refusal_ipc_failure_keeps_registered_owner_without_drop_budget";
    refusal_fixture("ipc", NAME).await;
}

async fn refusal_body(mode: &str, name: &str, deadline_ns: u64) {
    assert!(std::env::args().any(|arg| arg == "--exact"));
    assert!(std::env::args().any(|arg| arg == name));
    let deadline = tokio::time::Instant::now() + static_remaining(deadline_ns);
    let fixture = Fixture::new(true);
    let mut command = Command::new(&fixture.path);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let refused = Arc::new(AtomicBool::new(true));
    let mut tracer = TracerBuilder::<TrapTool>::new(command)
        .config(Mode::ChildToolError)
        .injected_syscall_trap(MARKER, fixture.trap_rip)
        .liteinst_runtime("/not/used.so", 1, 2, 3, 4, 5)
        .activate_liteinst_without_handshake_for_test()
        .spawn()
        .await
        .unwrap();
    tracer
        .liteinst_cleanup
        .as_mut()
        .unwrap()
        .fail_discovery_while = Some(refused.clone());
    let root = tracer.guest_pid();
    let global = Arc::downgrade(&tracer.gref);
    let events = tracer.gref.events.clone();
    let effect_tid = tracer.gref.effect_tid.clone();
    let result = tokio::time::timeout_at(deadline, tracer.wait_with_output())
        .await
        .expect("injected cleanup refusal exceeded five seconds");
    let error = match result {
        Err(Error::Tool(error)) => error,
        _ => panic!("missing typed refusal"),
    };
    let diagnostic = error
        .downcast_ref::<InjectedCleanupUnconfirmed>()
        .expect("cleanup-unconfirmed type");
    let Error::Tool(original) = diagnostic.failure().primary() else {
        panic!("original Tool cause lost")
    };
    assert_eq!(
        *original
            .downcast_ref::<AfterEffect>()
            .expect("typed original")
            .0,
        71
    );
    assert!(
        refused.load(Ordering::SeqCst),
        "persistent refusal was lifted before the product bound"
    );
    assert!(diagnostic.failure().secondary().iter().any(|failure| {
        failure.origin().phase == "injected tracee cleanup confirmation"
            && matches!(failure.error(), Error::Io(error) if error.raw_os_error() == Some(libc::EIO))
    }));
    assert!(
        diagnostic.failure().secondary().len() > 1,
        "persistent refusal was not retried"
    );
    assert_eq!(*events.lock().unwrap(), ["effect", "failed"]);
    assert!(
        global.upgrade().is_some(),
        "refusal dropped the original global owner"
    );
    assert!(
        matches!(TracerBuilder::<()>::new(Command::new("/bin/true")).spawn().await,
        Err(Error::Tool(error)) if error.downcast_ref::<CleanupAdmissionRefused>().is_some())
    );
    let id = diagnostic.id;
    CLEANUP_QUARANTINE.with(|owners| {
        let owners = owners.borrow();
        let owner = owners
            .get(&id)
            .unwrap()
            .downcast_ref::<LegacyInjectedOwner<Log>>()
            .unwrap();
        assert!(
            Arc::ptr_eq(owner.failure.as_ref().unwrap(), &diagnostic.failure),
            "quarantined owner must retain the exact original failure/prefix allocation"
        );
    });
    // Discard the public marker while the owner is still quarantined. Its
    // complete prefix and original typed cause must survive independently.
    drop(error);
    refused.store(false, Ordering::SeqCst);
    // Register the same original box in a return slot before releasing registry
    // borrows. Unwind restores it without cleanup or an additional allowance.
    let mut retained = RefusalOwnerScope::enter(id);
    refusal_owned(&mut retained, |owner| {
        assert_eq!(owner.tracer.guest_pid(), root);
        assert!(Arc::ptr_eq(&owner.tracer.gref, &global.upgrade().unwrap()));
    });
    let mut owner = refusal_rescue(retained, mode, deadline_ns);
    // Restore the exact captured prefix, then read from the original retained
    // reader after rescue. No after-error guest bytes may have appeared, even
    // when the failure was published before the capture driver read EFFECT.
    let retained = owner.failure.as_ref().expect("original retained failure");
    let Error::Tool(original) = retained.primary() else {
        panic!("retained Tool cause lost")
    };
    assert_eq!(
        *original
            .downcast_ref::<AfterEffect>()
            .expect("retained typed original")
            .0,
        71
    );
    let prefix = retained.captured_prefix().expect("capture was requested");
    owner
        .stdout
        .restore_prefix(Some(prefix.stdout().to_vec()))
        .unwrap();
    owner
        .stderr
        .restore_prefix(Some(prefix.stderr().to_vec()))
        .unwrap();
    tokio::time::timeout_at(
        deadline,
        future::poll_fn(|cx| {
            for drain in [&mut owner.stdout, &mut owner.stderr] {
                match drain.poll(cx) {
                    std::task::Poll::Ready(crate::capture::DrainEvent::Error(error)) => {
                        panic!("rescue reader: {error}")
                    }
                    std::task::Poll::Ready(crate::capture::DrainEvent::Progress) => {
                        cx.waker().wake_by_ref()
                    }
                    _ => {}
                }
            }
            if owner.stdout.is_finished() && owner.stderr.is_finished() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        }),
    )
    .await
    .expect("original readers did not finish within the same five-second bound");
    assert_eq!(owner.stdout.take_prefix().unwrap().unwrap(), EFFECT);
    assert!(owner.stderr.take_prefix().unwrap().unwrap().is_empty());
    let permit = owner.permit.take().unwrap();
    drop(owner);
    permit.complete();
    assert!(global.upgrade().is_none());
    assert!(!PathBuf::from(format!("/proc/{root}")).exists());
    assert!(!PathBuf::from(format!("/proc/{}", effect_tid.load(Ordering::SeqCst))).exists());
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_guard_capture_and_discard_preserve_success() {
    for discard in [false, true] {
        let fixture = Fixture::new(false);
        let mut command = Command::new(&fixture.path);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        let tracer = TracerBuilder::<TrapTool>::new(command)
            .config(Mode::Success)
            .injected_syscall_trap(MARKER, fixture.trap_rip)
            .liteinst_runtime("/not/used.so", 1, 2, 3, 4, 5)
            .activate_liteinst_without_handshake_for_test()
            .spawn()
            .await
            .unwrap();
        let root = tracer.guest_pid();
        tokio::time::timeout(Duration::from_secs(5), async {
            if discard {
                let (status, log) = tracer.wait_discarding_output().await.unwrap();
                assert_eq!(status, ExitStatus::Exited(0));
                assert_eq!(*log.events.lock().unwrap(), ["effect"]);
            } else {
                let (output, log) = tracer.wait_with_output().await.unwrap();
                assert_eq!(output.status, ExitStatus::Exited(0));
                assert_eq!(
                    output.stdout,
                    [EFFECT, 71i64.to_le_bytes().as_slice(), AFTER].concat()
                );
                assert!(output.stderr.is_empty());
                assert_eq!(*log.events.lock().unwrap(), ["effect"]);
            }
        })
        .await
        .expect("legacy capture/discard exceeded five seconds");
        assert!(!PathBuf::from(format!("/proc/{root}")).exists());
    }
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_fatal_external_reaper_refusal_keeps_terminal_observation_and_owner() {
    use std::io::Read;
    use std::os::unix::net::UnixStream;

    const NAME: &str = "tracer::injected_error_tests::legacy_fatal_external_reaper_refusal_keeps_terminal_observation_and_owner";
    const ROLE: &str = "REVERIE_INJECTED_EXTERNAL_REAPER_ROLE";
    const DEADLINE: &str = "REVERIE_INJECTED_EXTERNAL_REAPER_DEADLINE";
    fn now_ns() -> u64 {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
            0
        );
        now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
    }
    fn remaining(deadline: u64) -> Duration {
        let ns = deadline
            .checked_sub(now_ns())
            .expect("single five-second fixture deadline expired");
        assert_ne!(ns, 0);
        Duration::from_nanos(ns)
    }
    fn command(role: &str, deadline: u64) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(ROLE, role)
            .env(DEADLINE, deadline.to_string());
        command
    }
    async fn wait_child(child: &mut std::process::Child, deadline: u64) {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "isolated external-reaper fixture failed: {status}"
                );
                remaining(deadline);
                return;
            }
            if now_ns() >= deadline {
                let signal = child.kill();
                let rescue_deadline = Instant::now() + Duration::from_secs(2);
                let reaped = loop {
                    let status = child.try_wait().unwrap();
                    if status.is_some() || Instant::now() >= rescue_deadline {
                        break status;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                };
                panic!(
                    "single five-second deadline failed; separate subprocess rescue: signal={signal:?}, reaped={reaped:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    let role = std::env::var(ROLE).unwrap_or_default();
    if role.is_empty() {
        let deadline = now_ns() + 5_000_000_000;
        let mut child = command("natural-parent", deadline).spawn().unwrap();
        wait_child(&mut child, deadline).await;
        return;
    }
    assert!(std::env::args().any(|arg| arg == "--exact"));
    assert!(std::env::args().any(|arg| arg == NAME));
    let deadline = std::env::var(DEADLINE).unwrap().parse::<u64>().unwrap();
    if role == "natural-parent" {
        // Only this isolated supervisor becomes a subreaper. The ptracer is a
        // separate descendant and has no natural-parent wait authority here.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let (mut channel, child_channel) = UnixStream::pair().unwrap();
        channel.set_read_timeout(Some(remaining(deadline))).unwrap();
        channel
            .set_write_timeout(Some(remaining(deadline)))
            .unwrap();
        let mut child = command("ptracer", deadline)
            .stdin(std::process::Stdio::from(OwnedFd::from(child_channel)))
            .spawn()
            .unwrap();
        // Deliberately do not perform a natural wait until the backend has
        // returned its typed timeout. This is an actual retained zombie, not a
        // fake procfs answer or a live process relabelled as terminal.
        let mut words = [0u64; 3];
        for word in &mut words {
            let mut bytes = [0; 8];
            channel.read_exact(&mut bytes).unwrap();
            *word = u64::from_ne_bytes(bytes);
        }
        let pid = Pid::from_raw(i32::try_from(words[0]).unwrap());
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
        assert!(
            raw >= 0,
            "open exact adopted child pidfd: {}",
            std::io::Error::last_os_error()
        );
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        let snapshot = tracee_snapshot(pid).unwrap();
        assert_eq!(snapshot.start_time, words[1]);
        assert_eq!(
            fs::metadata(format!("/proc/{pid}")).unwrap().ino(),
            words[2]
        );
        assert_eq!(snapshot.ppid.as_raw(), std::process::id() as i32);
        assert_eq!(snapshot.tracer_pid.as_raw(), 0);
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pidfd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            0
        );
        assert_eq!(unsafe { info.si_pid() }, pid.as_raw());
        assert_eq!(info.si_code, libc::CLD_KILLED);
        assert_eq!(unsafe { info.si_status() }, libc::SIGKILL);
        assert!(PathBuf::from(format!("/proc/{pid}")).exists());
        // Separate test rescue by the proven natural parent, using its pidfd.
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    pidfd.as_raw_fd() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG,
                )
            },
            0
        );
        assert_eq!(unsafe { info.si_pid() }, pid.as_raw());
        assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
        channel.write_all(&[1]).unwrap();
        wait_child(&mut child, deadline).await;
        return;
    }
    assert_eq!(role, "ptracer");
    let raw = unsafe { libc::dup(libc::STDIN_FILENO) };
    assert!(raw >= 0);
    let mut channel = UnixStream::from(unsafe { OwnedFd::from_raw_fd(raw) });
    channel.set_read_timeout(Some(remaining(deadline))).unwrap();
    channel
        .set_write_timeout(Some(remaining(deadline)))
        .unwrap();
    let fixture = Fixture::new(true);
    let mut guest = Command::new(&fixture.path);
    guest
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let tracer = TracerBuilder::<TrapTool>::new(guest)
        .config(Mode::ChildToolError)
        .injected_syscall_trap(MARKER, fixture.trap_rip)
        .liteinst_runtime("/not/used.so", 1, 2, 3, 4, 5)
        .activate_liteinst_without_handshake_for_test()
        .spawn()
        .await
        .unwrap();
    let root = tracer.guest_pid();
    let global = Arc::downgrade(&tracer.gref);
    let events = tracer.gref.events.clone();
    let effect_tid = tracer.gref.effect_tid.clone();
    let before = Instant::now();
    let result = tokio::time::timeout(remaining(deadline), tracer.wait_with_output())
        .await
        .unwrap();
    assert!(
        before.elapsed() >= Duration::from_secs(2),
        "external wait was not withheld through the cleanup bound"
    );
    remaining(deadline);
    let Err(Error::Tool(error)) = result else {
        panic!("terminal observation falsely confirmed")
    };
    let diagnostic = error
        .downcast_ref::<InjectedCleanupUnconfirmed>()
        .expect("typed cleanup refusal");
    assert!(
        matches!(diagnostic.failure().primary(), Error::Tool(original) if original.downcast_ref::<AfterEffect>().is_some())
    );
    assert!(diagnostic.failure().secondary().iter().any(|failure| failure.origin().phase == "injected tracee cleanup confirmation" && matches!(failure.error(), Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut)));
    assert_eq!(*events.lock().unwrap(), ["effect", "failed"]);
    assert!(global.upgrade().is_some());
    assert!(!PathBuf::from(format!("/proc/{root}")).exists());
    let pid = Pid::from_raw(effect_tid.load(Ordering::SeqCst));
    let id = diagnostic.id;
    let identity_words = CLEANUP_QUARANTINE.with(|owners| {
        let owners = owners.borrow();
        let owner = owners
            .get(&id)
            .unwrap()
            .downcast_ref::<LegacyInjectedOwner<Log>>()
            .unwrap();
        assert!(Arc::ptr_eq(
            owner.failure.as_ref().unwrap(),
            &diagnostic.failure
        ));
        let guard = owner.tracer.liteinst_cleanup.as_ref().unwrap();
        assert!(guard.retained_descendants.is_empty());
        assert!(guard.retained_terminal_descendants.is_empty());
        let observations = guard.fatal_terminal_observations.as_ref().unwrap();
        assert_eq!(observations.len(), 1);
        let identity = observations
            .get(&pid)
            .expect("exact terminal generation retained");
        assert!(identity.observe_same_process().unwrap());
        assert!(
            !terminal_descendant_remains_owned(identity),
            "observation acquired ownership"
        );
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(status.lines().any(|line| line.starts_with("State:\tZ")));
        [
            pid.as_raw() as u64,
            identity.snapshot.start_time,
            identity.proc_inode,
        ]
    });
    assert!(
        matches!(TracerBuilder::<()>::new(Command::new("/bin/true")).spawn().await, Err(Error::Tool(error)) if error.downcast_ref::<CleanupAdmissionRefused>().is_some())
    );
    // Marker disposal cannot discard the captured prefix or original cause.
    drop(error);
    for word in identity_words {
        channel.write_all(&word.to_ne_bytes()).unwrap();
    }
    let mut ack = [0];
    channel.read_exact(&mut ack).unwrap();
    assert_eq!(ack, [1]);
    let mut owner = CLEANUP_QUARANTINE.with(|owners| {
        let owner = std::mem::ManuallyDrop::into_inner(owners.borrow_mut().remove(&id).unwrap());
        *owner
            .downcast::<LegacyInjectedOwner<Log>>()
            .unwrap_or_else(|_| panic!("wrong retained owner"))
    });
    owner
        .tracer
        .liteinst_cleanup
        .as_mut()
        .unwrap()
        .terminate_and_confirm()
        .expect("separate test rescue after natural-parent reap");
    let retained = owner.failure.as_ref().unwrap();
    assert!(
        matches!(retained.primary(), Error::Tool(original) if original.downcast_ref::<AfterEffect>().is_some())
    );
    let prefix = retained.captured_prefix().unwrap();
    owner
        .stdout
        .restore_prefix(Some(prefix.stdout().to_vec()))
        .unwrap();
    owner
        .stderr
        .restore_prefix(Some(prefix.stderr().to_vec()))
        .unwrap();
    tokio::time::timeout(
        remaining(deadline),
        future::poll_fn(|cx| {
            for drain in [&mut owner.stdout, &mut owner.stderr] {
                match drain.poll(cx) {
                    std::task::Poll::Ready(crate::capture::DrainEvent::Error(error)) => {
                        panic!("retained reader: {error}")
                    }
                    std::task::Poll::Ready(crate::capture::DrainEvent::Progress) => {
                        cx.waker().wake_by_ref()
                    }
                    _ => {}
                }
            }
            if owner.stdout.is_finished() && owner.stderr.is_finished() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(owner.stdout.take_prefix().unwrap().unwrap(), EFFECT);
    assert!(owner.stderr.take_prefix().unwrap().unwrap().is_empty());
    let permit = owner.permit.take().unwrap();
    drop(owner);
    permit.complete();
    assert!(global.upgrade().is_none());
    assert!(!PathBuf::from(format!("/proc/{pid}")).exists());
    remaining(deadline);
}

#[tokio::test(flavor = "current_thread")]
async fn legacy_transient_cleanup_refusal_recovers_with_admission_open() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let refusal = Arc::new(AtomicBool::new(true));
        run_with_transient_refusal(Mode::ChildToolError, true, Some(refusal.clone())).await;
        assert!(
            !refusal.load(Ordering::SeqCst),
            "one-shot refusal was not exercised"
        );
        let tracer = TracerBuilder::<()>::new(Command::new("/bin/true"))
            .spawn()
            .await
            .expect("confirmed transient cleanup must leave admission open");
        assert_eq!(tracer.wait().await.unwrap().0, ExitStatus::Exited(0));
    })
    .await
    .expect("transient cleanup and new admission exceeded five seconds");
}

#[tokio::test(flavor = "current_thread")]
async fn static_injected_cleanup_resource_follows_original_pending_owner() {
    static_diagnostic_init();
    const NAME: &str = "tracer::injected_error_tests::static_injected_cleanup_resource_follows_original_pending_owner";
    if static_fixture_natural_reaper("resource", NAME).await {
        return;
    }
    const ROLE: &str = "REVERIE_STATIC_RESOURCE_CHILD";
    const DEADLINE: &str = "REVERIE_STATIC_RESOURCE_DEADLINE";
    fn now_ns() -> u64 {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
            0
        );
        now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
    }
    if std::env::var(ROLE).as_deref() != Ok(NAME) {
        let deadline = now_ns() + 5_000_000_000;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(ROLE, NAME)
            .env(DEADLINE, deadline.to_string())
            .spawn()
            .unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "isolated resource fixture failed: {status}"
                );
                assert!(now_ns() < deadline, "original five-second deadline expired");
                return;
            }
            if now_ns() >= deadline {
                let signal = child.kill();
                let rescue_deadline = Instant::now() + Duration::from_secs(2);
                let rescue = loop {
                    let status = child.try_wait().unwrap();
                    if status.is_some() || Instant::now() >= rescue_deadline {
                        break status;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                };
                panic!(
                    "five-second resource fixture deadline failed; separate rescue: {signal:?}, {rescue:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    assert!(std::env::args().any(|arg| arg == NAME));
    assert!(std::env::args().any(|arg| arg == "--exact"));
    let deadline = tokio::time::Instant::now()
        + Duration::from_nanos(
            std::env::var(DEADLINE)
                .unwrap()
                .parse::<u64>()
                .unwrap()
                .saturating_sub(now_ns()),
        );

    struct Resource {
        attempts: Arc<std::sync::atomic::AtomicUsize>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
        root: Pid,
        effect: Arc<AtomicI32>,
    }
    impl PtraceCleanupResource for Resource {
        fn cleanup(&mut self) -> Result<(), Error> {
            static_boundary(
                "resource-before-absence",
                self.root,
                StaticDetails::Resource {
                    attempts: self.attempts.load(Ordering::SeqCst),
                    drops: self.drops.load(Ordering::SeqCst),
                    effect: self.effect.load(Ordering::SeqCst),
                    admission_closed: OrdinaryAdmission::acquire().is_err(),
                },
            );
            assert!(!PathBuf::from(format!("/proc/{}", self.root)).exists());
            assert!(
                !PathBuf::from(format!("/proc/{}", self.effect.load(Ordering::SeqCst))).exists()
            );
            assert!(
                OrdinaryAdmission::acquire().is_err(),
                "admission reopened before resource cleanup"
            );
            if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(std::io::Error::from_raw_os_error(libc::EIO).into())
            } else {
                Ok(())
            }
        }
    }
    impl Drop for Resource {
        fn drop(&mut self) {
            assert!(
                OrdinaryAdmission::acquire().is_err(),
                "resource dropped after admission reopened"
            );
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }
    async fn check<R: 'static>(error: Error, root: Pid, effect: Arc<AtomicI32>, capture: bool) {
        let Error::Tool(error) = error else {
            panic!("static cleanup marker lost")
        };
        let marker = error
            .downcast_ref::<CleanupUnconfirmed>()
            .expect("existing public recovery route");
        assert!(
            matches!(marker.primary(), Error::Tool(error) if error.downcast_ref::<AfterEffect>().is_some())
        );
        assert!(matches!(
            marker.take_cleanup::<(), R>(),
            Err(CleanupLookupError::WrongType)
        ));
        // Verify an actual original pidfd plus active namespace, and its refusal
        // before registry access for a foreign numeric process identity.
        marker.verify_owner().unwrap();
        let mut foreign = CleanupOwnerIdentity::capture().unwrap();
        foreign.pid = if foreign.pid == 1 { 2 } else { 1 };
        assert!(matches!(
            foreign.verify(),
            Err(CleanupLookupError::WrongProcess)
        ));
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refused_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refused_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let unbound = if !capture {
            assert!(matches!(
                marker.retain_cleanup_resource::<(), R, _>(Resource {
                    attempts: refused_attempts.clone(),
                    drops: refused_drops.clone(),
                    root,
                    effect: effect.clone(),
                }),
                Err(CleanupLookupError::WrongType)
            ));
            assert_eq!(
                refused_drops.load(Ordering::SeqCst),
                0,
                "lookup refusal dropped exact resource"
            );
            Some(CLEANUP_QUARANTINE.with(|owners| {
                *owners
                    .borrow()
                    .iter()
                    .find(|(_, owner)| owner.is::<UnboundCleanupResource>())
                    .expect("separate retained unbound owner")
                    .0
            }))
        } else {
            None
        };
        marker
            .retain_cleanup_resource::<Log, R, _>(Resource {
                attempts: attempts.clone(),
                drops: drops.clone(),
                root,
                effect,
            })
            .unwrap();
        let id = marker.id;
        let pending = if capture {
            // Marker disposal while still quarantined must retain the guard.
            // Removal below is explicitly white-box test rescue, not a promised
            // recovery API for a caller which discarded its diagnostic.
            drop(error);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            CLEANUP_QUARANTINE.with(|owners| {
                let owner =
                    std::mem::ManuallyDrop::into_inner(owners.borrow_mut().remove(&id).unwrap());
                *owner
                    .downcast::<PendingPtraceCleanup<Log, R>>()
                    .unwrap_or_else(|_| panic!("wrong original owner"))
            })
        } else {
            let owner = marker.take_cleanup::<Log, R>().unwrap();
            drop(error);
            owner
        };
        assert_eq!(pending.driver.resources.len(), 1);
        let ToolRunOutcome::CleanupPending(pending) = pending.resume_cleanup().await else {
            panic!("actual resource cleanup error was hidden")
        };
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(pending.failure().secondary().iter().any(|failure| failure.origin().phase == "ptrace retained cleanup resource" && matches!(failure.error(), Error::Io(error) if error.raw_os_error() == Some(libc::EIO))));
        if capture {
            assert_eq!(
                pending.failure().captured_prefix().unwrap().stdout(),
                EFFECT
            );
            assert!(
                pending
                    .failure()
                    .captured_prefix()
                    .unwrap()
                    .stderr()
                    .is_empty()
            );
        } else {
            assert!(pending.failure().captured_prefix().is_none());
        }
        let error = pending.quarantine();
        let Error::Tool(error) = error else {
            unreachable!()
        };
        let marker = error.downcast_ref::<CleanupUnconfirmed>().unwrap();
        assert_eq!(
            marker.recovery_key(),
            id,
            "repeat quarantine changed original owner key"
        );
        let pending = marker.take_cleanup::<Log, R>().unwrap();
        assert_eq!(
            pending.driver.resources.len(),
            1,
            "repeat quarantine duplicated/lost guard"
        );
        drop(error);
        let ToolRunOutcome::Complete(completion) = pending.resume_cleanup().await else {
            panic!("same retained resource did not recover")
        };
        let failure = completion
            .result
            .err()
            .expect("original Tool failure became success");
        assert!(
            matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<AfterEffect>().is_some())
        );
        assert!(
            failure
                .secondary()
                .iter()
                .any(|failure| failure.origin().phase == "ptrace retained cleanup resource")
        );
        if capture {
            assert_eq!(failure.captured_prefix().unwrap().stdout(), EFFECT);
        } else {
            assert!(failure.captured_prefix().is_none());
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        if let Some(id) = unbound {
            assert!(
                OrdinaryAdmission::acquire().is_err(),
                "original completion reopened admission over an unbound guard"
            );
            assert_eq!(refused_drops.load(Ordering::SeqCst), 0);
            assert_eq!(
                refused_attempts.load(Ordering::SeqCst),
                0,
                "unbound guard acquired cleanup authority"
            );
            // Explicit white-box test rescue only; production deliberately has
            // no lookup/recovery API for an unbound attachment.
            let owner = CLEANUP_QUARANTINE.with(|owners| {
                let owner =
                    std::mem::ManuallyDrop::into_inner(owners.borrow_mut().remove(&id).unwrap());
                *owner
                    .downcast::<UnboundCleanupResource>()
                    .unwrap_or_else(|_| panic!("wrong unbound owner"))
            });
            let UnboundCleanupResource {
                _resource: resource,
                _permit: permit,
            } = owner;
            drop(resource);
            permit.complete();
            assert_eq!(refused_drops.load(Ordering::SeqCst), 1);
        }
        assert!(OrdinaryAdmission::acquire().is_ok());
    }

    tokio::time::timeout_at(deadline, async {
        for capture in [true, false] {
            static_diagnostic_before_spawn();
            let control = Arc::new(crate::task::FatalFreezeControl::default());
            crate::task::FATAL_FREEZE_CONTROL.with(|slot| *slot.borrow_mut() = Some(control));
            let fixture = Fixture::new(true);
            let mut command = Command::new(&fixture.path);
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            let tracer = TracerBuilder::<TrapTool>::new(command)
                .config(Mode::ChildToolError)
                .injected_syscall_trap(MARKER, fixture.trap_rip)
                .spawn()
                .await
                .unwrap();
            assert!(
                tracer.termination_handle().is_none(),
                "normal public supervisor support changed"
            );
            let root = tracer.guest_pid();
            let effect = tracer.gref.effect_tid.clone();
            let global = Arc::downgrade(&tracer.gref);
            if capture {
                let error = tracer
                    .wait_with_output()
                    .await
                    .err()
                    .expect("missing failed captured cleanup");
                crate::task::FATAL_FREEZE_CONTROL.with(|slot| *slot.borrow_mut() = None);
                check::<Output>(error, root, effect, true).await;
            } else {
                let error = tracer
                    .wait_discarding_output()
                    .await
                    .err()
                    .expect("missing failed discarded cleanup");
                crate::task::FATAL_FREEZE_CONTROL.with(|slot| *slot.borrow_mut() = None);
                check::<ExitStatus>(error, root, effect, false).await;
            }
            assert!(global.upgrade().is_none());
        }
    })
    .await
    .expect("static retained resource cleanup exceeded original five-second deadline");
}

// RUN191 diagnostic: the original ptracer and a distinct natural wait owner.
// Every branch uses the same static guest and the original absence assertions.
const STATIC_REAPER_ROLE: &str = "REVERIE_STATIC_REAPER_ROLE";
const STATIC_REAPER_MODE: &str = "REVERIE_STATIC_REAPER_MODE";
const STATIC_REAPER_DEADLINE: &str = "REVERIE_STATIC_REAPER_DEADLINE";

#[derive(Debug, Serialize, Deserialize)]
struct StaticOwnerObservation {
    tid: i32,
    terminal: String,
    sigkill: bool,
    retired: bool,
    held: bool,
    frozen: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StaticDriverObservation {
    failure: Option<String>,
    original_after_effect: bool,
    stdout: Option<Vec<u8>>,
    stderr: Option<Vec<u8>>,
    drains_finished: bool,
}
#[derive(Debug, Serialize, Deserialize)]
enum StaticDetails {
    Live {
        injected_write: usize,
    },
    Plain {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        events: Vec<String>,
        failure: Option<String>,
        original_after_effect: bool,
    },
    Resource {
        attempts: usize,
        drops: usize,
        effect: i32,
        admission_closed: bool,
    },
}
#[derive(Debug, Serialize, Deserialize)]
struct StaticObservation {
    boundary: String,
    root: i32,
    root_absent: bool,
    root_start: u64,
    root_inode: u64,
    root_pidfd_ready: bool,
    effect: i32,
    start: u64,
    inode: u64,
    ppid: i32,
    tracer: i32,
    state: String,
    pidfd_ready: bool,
    owners: Vec<StaticOwnerObservation>,
    events: Vec<String>,
    driver: Option<StaticDriverObservation>,
    details: StaticDetails,
}
struct StaticReaperProbe {
    channel: std::os::unix::net::UnixStream,
    deadline: u64,
    identity: Option<TraceeIdentity>,
    root_identity: Option<TraceeIdentity>,
    events: Option<Arc<StdMutex<Vec<&'static str>>>>,
    driver: Option<StaticDriverObservation>,
}
thread_local! {
    static STATIC_REAPER_PROBE: std::cell::RefCell<Option<StaticReaperProbe>> = const { std::cell::RefCell::new(None) };
}

fn static_now_ns() -> u64 {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) },
        0
    );
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}
fn static_remaining(deadline: u64) -> Duration {
    let remaining = deadline
        .checked_sub(static_now_ns())
        .expect("shared five-second diagnostic deadline expired");
    assert_ne!(remaining, 0);
    Duration::from_nanos(remaining)
}
// These guards belong only to diagnostic supervisor processes, never guests.
// Install on the process leader before exec: libtest later creates a test
// thread, whose PR_GET_PDEATHSIG would not observe this leader's state.
const STATIC_REAPER_PARENT: &str = "REVERIE_STATIC_REAPER_PARENT";
fn static_contained_command(name: &str, role: &str, deadline: u64) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    let expected_parent = std::process::id() as libc::pid_t;
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(STATIC_REAPER_ROLE, role)
        .env(STATIC_REAPER_DEADLINE, deadline.to_string())
        .env(STATIC_REAPER_PARENT, expected_parent.to_string());
    // Only allocation-free Linux syscalls and fixed OS-error construction run
    // between fork and exec. The synchronous spawning parent thread cannot
    // return/unwind before Command::spawn's exec handshake has completed.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut installed = 0;
            if libc::prctl(libc::PR_GET_PDEATHSIG, &mut installed, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if installed != libc::SIGKILL || libc::getppid() != expected_parent {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    command
}
fn static_verify_parent_after_exec() {
    let expected = std::env::var(STATIC_REAPER_PARENT)
        .unwrap()
        .parse::<libc::pid_t>()
        .unwrap();
    assert_eq!(unsafe { libc::getppid() }, expected);
    // Deliberately do not SET again or claim that GET in this new test thread
    // can verify the original leader's value. The forced-parent-death control
    // exercises that original guard through this actual self-exec path.
}

fn static_abort_containment() {
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 0);
    eprintln!(
        "static diagnostic local abort containment: pid={}, dumpable=0",
        std::process::id()
    );
}
fn static_identity(pid: Pid) -> TraceeIdentity {
    let snapshot = tracee_snapshot(pid).unwrap();
    let proc_dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}"))
        .unwrap();
    let proc_inode = proc_dir.metadata().unwrap().ino();
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
    assert!(fd >= 0, "original process pidfd: {}", Errno::last());
    assert_eq!(
        tracee_snapshot(pid).unwrap().start_time,
        snapshot.start_time
    );
    TraceeIdentity {
        tid: pid,
        snapshot,
        proc_dir: proc_dir.into(),
        proc_inode,
        pidfd: Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }),
        parent: None,
    }
}
fn static_pidfd_ready(identity: &TraceeIdentity) -> bool {
    let mut fd = libc::pollfd {
        fd: identity.pidfd.as_ref().unwrap().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut fd, 1, 0) };
    assert!(rc >= 0, "pidfd observation: {}", Errno::last());
    assert_eq!(fd.revents & (libc::POLLNVAL | libc::POLLERR), 0);
    rc == 1 && fd.revents & libc::POLLIN != 0
}
fn static_send<T: Serialize>(
    channel: &mut std::os::unix::net::UnixStream,
    value: &T,
    deadline: u64,
) {
    use std::io::Write;
    channel
        .set_write_timeout(Some(static_remaining(deadline)))
        .unwrap();
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::legacy()).unwrap();
    assert!(bytes.len() < 65536);
    channel
        .write_all(&(bytes.len() as u32).to_ne_bytes())
        .unwrap();
    channel.write_all(&bytes).unwrap();
}
fn static_read<T: serde::de::DeserializeOwned>(
    channel: &mut std::os::unix::net::UnixStream,
    deadline: u64,
) -> Option<T> {
    use std::io::Read;
    channel
        .set_read_timeout(Some(static_remaining(deadline)))
        .unwrap();
    let mut length = [0; 4];
    if channel.read(&mut length[..1]).unwrap() == 0 {
        return None;
    }
    channel.read_exact(&mut length[1..]).unwrap();
    let length = u32::from_ne_bytes(length) as usize;
    assert!(length < 65536);
    let mut bytes = vec![0; length];
    channel.read_exact(&mut bytes).unwrap();
    let (value, consumed) =
        bincode::serde::decode_from_slice(&bytes, bincode::config::legacy()).unwrap();
    assert_eq!(consumed, length, "trailing diagnostic frame bytes");
    Some(value)
}
fn static_observe(
    probe: &StaticReaperProbe,
    boundary: &str,
    root: Pid,
    details: StaticDetails,
) -> StaticObservation {
    let identity = probe
        .identity
        .as_ref()
        .expect("capture before callback failure");
    let pid = identity.tid;
    let snapshot = tracee_snapshot(pid).unwrap();
    assert_eq!(snapshot.start_time, identity.snapshot.start_time);
    assert_eq!(
        fs::metadata(format!("/proc/{pid}")).unwrap().ino(),
        identity.proc_inode
    );
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let state = status
        .lines()
        .find_map(|line| line.strip_prefix("State:\t"))
        .unwrap();
    let owners = FATAL_REAP_OBSERVATIONS.with(|slot| {
        slot.borrow()
            .as_ref()
            .unwrap()
            .iter()
            .map(|stop| {
                let exit = stop.terminal.observed_exit_status();
                StaticOwnerObservation {
                    tid: stop.tid.as_raw(),
                    terminal: format!("{exit:?}"),
                    sigkill: matches!(
                        exit,
                        Ok(Some(safeptrace::ExitStatus::Signaled(Signal::SIGKILL, _)))
                    ),
                    retired: stop.terminal.wait(Duration::ZERO),
                    held: stop.held.lock().unwrap().is_some(),
                    frozen: stop.frozen.load(Ordering::Acquire),
                }
            })
            .collect()
    });
    StaticObservation {
        boundary: boundary.to_owned(),
        root: root.as_raw(),
        root_absent: !PathBuf::from(format!("/proc/{root}")).exists(),
        root_start: probe.root_identity.as_ref().unwrap().snapshot.start_time,
        root_inode: probe.root_identity.as_ref().unwrap().proc_inode,
        root_pidfd_ready: static_pidfd_ready(probe.root_identity.as_ref().unwrap()),
        effect: pid.as_raw(),
        start: snapshot.start_time,
        inode: identity.proc_inode,
        ppid: snapshot.ppid.as_raw(),
        tracer: snapshot.tracer_pid.as_raw(),
        state: state.to_owned(),
        pidfd_ready: static_pidfd_ready(identity),
        owners,
        events: probe
            .events
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .iter()
            .map(|event| (*event).to_owned())
            .collect(),
        driver: probe.driver.clone(),
        details,
    }
}
fn static_before_failure(pid: Pid, events: &Arc<StdMutex<Vec<&'static str>>>) {
    STATIC_REAPER_PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(probe) = slot.as_mut() else { return };
        probe.identity = Some(static_identity(pid));
        probe.events = Some(events.clone());
        let root = probe.identity.as_ref().unwrap().snapshot.ppid;
        probe.root_identity = Some(static_identity(root));
        // P and G already initialized their real timers. This changes only T's
        // mm, before the intentional Tool failure or any negative assertion.
        static_abort_containment();
        let observation = static_observe(
            probe,
            "live-before-failure",
            root,
            StaticDetails::Live {
                injected_write: EFFECT.len(),
            },
        );
        static_send(&mut probe.channel, &observation, probe.deadline);
        let response: bool = static_read(&mut probe.channel, probe.deadline).unwrap();
        assert!(response);
    });
}
pub(super) fn static_driver_observation(
    failure: Option<&crate::PtraceRunFailure>,
    stdout: Option<&[u8]>,
    stderr: Option<&[u8]>,
    finished: bool,
) {
    STATIC_REAPER_PROBE.with(|slot| {
        if let Some(probe) = slot.borrow_mut().as_mut() {
            probe.driver = Some(StaticDriverObservation {
                failure: failure.map(ToString::to_string),
                original_after_effect: failure.is_some_and(|failure| matches!(failure.primary(), Error::Tool(error) if error.downcast_ref::<AfterEffect>().is_some())),
                stdout: stdout.map(<[u8]>::to_vec), stderr: stderr.map(<[u8]>::to_vec), drains_finished: finished,
            });
        }
    });
}
fn static_boundary(boundary: &str, root: Pid, details: StaticDetails) {
    STATIC_REAPER_PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(probe) = slot.as_mut() else { return };
        // A successful earlier natural wait is observable as absence. Do not
        // invent a second proc snapshot or require a second natural wait.
        if !PathBuf::from(format!("/proc/{}", probe.identity.as_ref().unwrap().tid)).exists() {
            eprintln!("static diagnostic subsequent boundary: {boundary}, exact previously observed child now absent, details={details:?}");
            return;
        }
        let observation = static_observe(probe, boundary, root, details);
        static_send(&mut probe.channel, &observation, probe.deadline);
        let response: bool = static_read(&mut probe.channel, probe.deadline).unwrap();
        assert!(response);
    });
}
fn static_natural_wait(identity: &TraceeIdentity) {
    let mut observed: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let fd = identity.pidfd.as_ref().unwrap().as_raw_fd() as u32;
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd,
                &mut observed,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        },
        0
    );
    assert_eq!(unsafe { observed.si_pid() }, identity.tid.as_raw());
    assert_eq!(observed.si_code, libc::CLD_KILLED);
    assert_eq!(unsafe { observed.si_status() }, libc::SIGKILL);
    assert!(PathBuf::from(format!("/proc/{}", identity.tid)).exists());
    let mut reaped: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd,
                &mut reaped,
                libc::WEXITED | libc::WNOHANG,
            )
        },
        0
    );
    assert_eq!(unsafe { reaped.si_pid() }, identity.tid.as_raw());
    assert_eq!(reaped.si_code, libc::CLD_KILLED);
    assert_eq!(unsafe { reaped.si_status() }, libc::SIGKILL);
    assert!(!PathBuf::from(format!("/proc/{}", identity.tid)).exists());
    eprintln!(
        "static diagnostic actual natural wait: child={}, SIGKILL, final_absent=true",
        identity.tid
    );
}
// The fixture owns the distinct natural-reaper operation; the backend still
// owns only its original ptrace wait/notifier lifecycle. The original test body
// and its final /proc checks run unchanged in T, after R's exact natural wait.
async fn static_fixture_natural_reaper(route: &str, name: &str) -> bool {
    match std::env::var(STATIC_REAPER_ROLE).as_deref() {
        Ok("ptracer") => false,
        Ok("reaper") | Err(_) => {
            static_reaper_diagnostic("positive", name, &[route]).await;
            true
        }
        Ok(role) => panic!("unexpected fixture supervisor role {role}"),
    }
}
async fn static_reaper_diagnostic(mode: &str, name: &str, routes: &[&str]) {
    let role = std::env::var(STATIC_REAPER_ROLE).unwrap_or_default();
    if role.is_empty() {
        // Controls exercise both routes; each original fixture selects only
        // its own route. One deadline covers creation and all selected work.
        let deadline = static_now_ns() + 5_000_000_000;
        for route in routes {
            let mut child = static_contained_command(name, "reaper", deadline)
                .env(STATIC_REAPER_MODE, mode)
                .env("REVERIE_STATIC_REAPER_ROUTE", route)
                .spawn()
                .unwrap();
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "isolated diagnostic failed: {status}");
                    static_remaining(deadline);
                    break;
                }
                if static_now_ns() >= deadline {
                    let signal = child.kill();
                    let rescue = Instant::now() + Duration::from_secs(2);
                    while child.try_wait().unwrap().is_none() && Instant::now() < rescue {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    panic!(
                        "shared five-second diagnostic failed; separate supervisor rescue={signal:?}"
                    );
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        return;
    }
    static_verify_parent_after_exec();
    static_abort_containment();
    let deadline = std::env::var(STATIC_REAPER_DEADLINE)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let route = std::env::var("REVERIE_STATIC_REAPER_ROUTE").unwrap();
    assert_eq!(std::env::var(STATIC_REAPER_MODE).unwrap(), mode);
    if role == "reaper" {
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let (mut channel, child_channel) = std::os::unix::net::UnixStream::pair().unwrap();
        let original = if route == "plain" {
            "tracer::injected_error_tests::injected_child_tool_error_does_not_resume_child_or_parent"
        } else {
            "tracer::injected_error_tests::static_injected_cleanup_resource_follows_original_pending_owner"
        };
        let mut child = static_contained_command(original, "ptracer", deadline)
            .env("REVERIE_STATIC_RESOURCE_CHILD", "tracer::injected_error_tests::static_injected_cleanup_resource_follows_original_pending_owner")
            .env("REVERIE_STATIC_RESOURCE_DEADLINE", deadline.to_string()).stdin(std::process::Stdio::from(OwnedFd::from(child_channel)))
            .spawn().unwrap();
        let mut held = None;
        let mut active: Option<TraceeIdentity> = None;
        let mut live_refused = 0;
        let mut terminal_observations = 0;
        while let Some(observation) = static_read::<StaticObservation>(&mut channel, deadline) {
            eprintln!("STATIC_REAPER_SEALED {observation:?}");
            let pid = Pid::from_raw(observation.effect);
            if observation.boundary == "live-before-failure" {
                active = Some(static_identity(pid));
            }
            let identity = active.as_ref().expect("original live generation");
            let actual = tracee_snapshot(pid).unwrap();
            assert_eq!(actual.start_time, identity.snapshot.start_time);
            assert_eq!(identity.snapshot.start_time, observation.start);
            assert_eq!(identity.proc_inode, observation.inode);
            let state = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            let effect = observation
                .owners
                .iter()
                .find(|owner| owner.tid == pid.as_raw())
                .unwrap();
            let root_owner = observation
                .owners
                .iter()
                .find(|owner| owner.tid == observation.root)
                .unwrap();
            let ready = effect.sigkill
                && effect.retired
                && !effect.held
                && root_owner.sigkill
                && root_owner.retired
                && !root_owner.held
                && observation.root_pidfd_ready
                && observation.root_absent
                && observation.pidfd_ready
                && observation.tracer == 0
                && observation.state.starts_with('Z')
                && actual.tracer_pid.as_raw() == 0
                && static_pidfd_ready(identity)
                && state.lines().any(|line| line.starts_with("State:\tZ"));
            if observation.boundary == "live-before-failure" {
                assert!(!ready, "terminal predicate accepted actual live stop");
                assert!(!static_pidfd_ready(identity));
                assert!(state.lines().any(|line| line.starts_with("State:\tt")));
                assert_ne!(identity.snapshot.tracer_pid.as_raw(), 0);
                assert!(!effect.retired);
                live_refused += 1;
            } else {
                terminal_observations += 1;
                assert!(
                    ready,
                    "backend was not actually retired before absence assertion"
                );
                assert_eq!(actual.ppid.as_raw(), std::process::id() as i32);
                assert_eq!(observation.ppid, std::process::id() as i32);
                assert_eq!(observation.events, ["effect", "failed"]);
                if mode == "held" {
                    held = active.take();
                } else {
                    // Product observations above are sealed before this natural wait.
                    static_natural_wait(identity);
                }
            }
            static_send(&mut channel, &true, deadline);
        }
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            static_remaining(deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        };
        assert!(live_refused > 0);
        assert!(terminal_observations > 0);
        if mode == "held" {
            eprintln!(
                "STATIC_REAPER_ORIGINAL_ASSERTION_RESULT route={route} status={status}; verdict sealed before natural teardown"
            );
            use std::os::unix::process::ExitStatusExt;
            assert!(
                status.code() == Some(101) || status.signal() == Some(libc::SIGABRT),
                "original absence failure must be a Rust assertion/abort, got {status}"
            );
            static_natural_wait(held.as_ref().unwrap());
        } else {
            assert!(
                status.success(),
                "reaped positive/live-stop companion failed: {status}"
            );
        }
        static_remaining(deadline);
        return;
    }
    panic!("unexpected diagnostic role {role}");
}
fn static_diagnostic_before_spawn() {
    STATIC_REAPER_PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(probe) = slot.as_mut() else { return };
        if let Some(identity) = probe.identity.as_ref() {
            let root = probe.root_identity.as_ref().unwrap();
            assert!(static_pidfd_ready(identity) && static_pidfd_ready(root));
            assert!(!PathBuf::from(format!("/proc/{}", identity.tid)).exists());
            assert!(!PathBuf::from(format!("/proc/{}", root.tid)).exists());
            // The previous captured case is fully retired and naturally reaped.
            // Restore T's original setting for the next guest's pre-exec timer.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) }, 0);
        }
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 1);
        // Only after the prior case is confirmed terminal and naturally reaped,
        // start a fresh diagnostic epoch. Do not match a reused numeric PID to
        // an earlier case's retired notifier or attribute its prefix to discard.
        FATAL_REAP_OBSERVATIONS.with(|owners| *owners.borrow_mut() = Some(Vec::new()));
        probe.driver = None;
    });
}
fn static_diagnostic_init() {
    if std::env::var(STATIC_REAPER_ROLE).as_deref() != Ok("ptracer") {
        return;
    }
    static_verify_parent_after_exec();
    // Initial guest timer admission must observe the unchanged inherited mm.
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 1);
    let deadline = std::env::var(STATIC_REAPER_DEADLINE)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let mut subreaper = -1;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper, 0, 0, 0) },
        0
    );
    assert_eq!(subreaper, 0);
    FATAL_REAP_OBSERVATIONS.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    STATIC_REAPER_PROBE.with(|slot| {
        *slot.borrow_mut() = Some(StaticReaperProbe {
            channel: unsafe { std::os::unix::net::UnixStream::from_raw_fd(libc::STDIN_FILENO) },
            deadline,
            identity: None,
            root_identity: None,
            events: None,
            driver: None,
        })
    });
}
#[tokio::test(flavor = "current_thread")]
async fn static_reaper_diagnostic_held() {
    static_reaper_diagnostic(
        "held",
        "tracer::injected_error_tests::static_reaper_diagnostic_held",
        &["plain", "resource"],
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn static_reaper_diagnostic_positive() {
    static_reaper_diagnostic(
        "positive",
        "tracer::injected_error_tests::static_reaper_diagnostic_positive",
        &["plain", "resource"],
    )
    .await;
}
#[tokio::test(flavor = "current_thread")]
async fn static_reaper_diagnostic_live() {
    static_reaper_diagnostic(
        "live",
        "tracer::injected_error_tests::static_reaper_diagnostic_live",
        &["plain", "resource"],
    )
    .await;
}

// Harness-only control: no guest or backend completion is fabricated here.
// An isolated natural subreaper owns the forced-death experiment; the parent
// libtest process never becomes a subreaper. The leaf blocks after self-exec,
// and has only the guard installed on its leader by static_contained_command.
#[tokio::test(flavor = "current_thread")]
async fn static_reaper_diagnostic_parent_death() {
    const NAME: &str = "tracer::injected_error_tests::static_reaper_diagnostic_parent_death";
    let role = std::env::var(STATIC_REAPER_ROLE).unwrap_or_default();
    if role.is_empty() {
        let deadline = static_now_ns() + 5_000_000_000;
        let mut child = static_contained_command(NAME, "containment-supervisor", deadline)
            .spawn()
            .unwrap();
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "parent-death control failed: {status}");
                static_remaining(deadline);
                return;
            }
            if static_now_ns() >= deadline {
                let signal = child.kill();
                let rescue = Instant::now() + Duration::from_secs(2);
                while child.try_wait().unwrap().is_none() && Instant::now() < rescue {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                panic!(
                    "parent-death control exceeded original five seconds; separate rescue={signal:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    static_verify_parent_after_exec();
    static_abort_containment();
    let deadline = std::env::var(STATIC_REAPER_DEADLINE)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    if role == "containment-leaf" {
        let mut channel =
            unsafe { std::os::unix::net::UnixStream::from_raw_fd(libc::STDIN_FILENO) };
        static_send(&mut channel, &true, deadline);
        // Keep the process and inherited output FDs alive until the real
        // parent-death signal. Do not consume EOF, panic, or re-arm a signal.
        loop {
            unsafe {
                libc::pause();
            }
        }
    }
    if role == "containment-parent" {
        let mut upstream =
            unsafe { std::os::unix::net::UnixStream::from_raw_fd(libc::STDIN_FILENO) };
        let (mut channel, child_channel) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = static_contained_command(NAME, "containment-leaf", deadline)
            .stdin(std::process::Stdio::from(OwnedFd::from(child_channel)))
            .spawn()
            .unwrap();
        assert!(static_read::<bool>(&mut channel, deadline).unwrap());
        let identity = static_identity(Pid::from_raw(child.id() as i32));
        assert_eq!(identity.snapshot.ppid.as_raw(), std::process::id() as i32);
        assert!(!static_pidfd_ready(&identity));
        static_send(
            &mut upstream,
            &(
                child.id() as i32,
                identity.snapshot.start_time,
                identity.proc_inode,
            ),
            deadline,
        );
        // The isolated supervisor kills this exact original Child owner.
        // Keeping it live until then proves the leaf did not exit on its own.
        loop {
            let status = child.try_wait().unwrap();
            assert!(
                status.is_none(),
                "leaf exited before forced parent death: {status:?}"
            );
            static_remaining(deadline);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    assert_eq!(role, "containment-supervisor");
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let (mut channel, child_channel) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut parent = static_contained_command(NAME, "containment-parent", deadline)
        .stdin(std::process::Stdio::from(OwnedFd::from(child_channel)))
        .spawn()
        .unwrap();
    let (leaf, start, inode): (i32, u64, u64) = static_read(&mut channel, deadline).unwrap();
    let identity = static_identity(Pid::from_raw(leaf));
    assert_eq!(identity.snapshot.ppid.as_raw(), parent.id() as i32);
    assert_eq!(identity.snapshot.start_time, start);
    assert_eq!(identity.proc_inode, inode);
    assert!(!static_pidfd_ready(&identity));
    eprintln!(
        "STATIC_PARENT_DEATH_LIVE parent={}, leaf={leaf}, start={start}, inode={inode}, pidfd_ready=false",
        parent.id()
    );
    parent.kill().unwrap();
    let parent_status = loop {
        if let Some(status) = parent.try_wait().unwrap() {
            break status;
        }
        static_remaining(deadline);
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(parent_status.signal(), Some(libc::SIGKILL));
    // Reserve the final second of this same five-second budget for exact
    // leaf rescue if the guard under test fails. Rescue cannot make it pass.
    let observation_end = deadline.saturating_sub(1_000_000_000);
    while !static_pidfd_ready(&identity) {
        if static_now_ns() >= observation_end {
            let fd = identity.pidfd.as_ref().unwrap().as_raw_fd();
            let signal = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    fd,
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            let signal_errno = if signal == -1 {
                Some(Errno::last())
            } else {
                None
            };
            while !static_pidfd_ready(&identity) && static_now_ns() < deadline {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let ready = static_pidfd_ready(&identity);
            eprintln!(
                "STATIC_PARENT_DEATH_FAILED leaf={leaf}: no terminal result before final rescue reserve; separate exact-pidfd signal={signal}, errno={signal_errno:?}, ready={ready}"
            );
            if ready {
                static_natural_wait(&identity);
            }
            panic!("parent-death guard failed; separate rescue cannot satisfy control");
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(
        tracee_snapshot(identity.tid).unwrap().ppid.as_raw(),
        std::process::id() as i32
    );
    static_natural_wait(&identity);
    static_remaining(deadline);
    eprintln!(
        "STATIC_PARENT_DEATH_CONFIRMED leaf={leaf}, original_pidfd_ready=true, actual_natural_wait=SIGKILL, final_absent=true; no rescue"
    );
}

// All potentially failing diagnostic work returns before it can unwind through
// the original cleanup transaction. No production cleanup call is caught here.
thread_local! {
    static REFUSAL_OBSERVER_PANICKED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static REFUSAL_ARMED_DROPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
fn refusal_observer<T>(body: impl FnOnce() -> T) -> Option<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => Some(value),
        Err(_) => {
            let _ = REFUSAL_OBSERVER_PANICKED.try_with(|flag| flag.set(true));
            None
        }
    }
}
fn refusal_hook(body: impl FnOnce() -> std::io::Result<()>) -> std::io::Result<()> {
    refusal_observer(body).unwrap_or_else(|| {
        Err(std::io::Error::other(
            "diagnostic observer panicked; cleanup remains unconfirmed",
        ))
    })
}
fn refusal_require(condition: bool, detail: &'static str) -> std::io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidData, detail))
    }
}
fn refusal_now_ns() -> std::io::Result<u64> {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64)
}
fn refusal_remaining(deadline: u64) -> std::io::Result<Duration> {
    let remaining = deadline.saturating_sub(refusal_now_ns()?);
    if remaining == 0 {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "original refusal diagnostic deadline expired",
        ))
    } else {
        Ok(Duration::from_nanos(remaining))
    }
}
fn refusal_pidfd_ready(identity: &TraceeIdentity) -> std::io::Result<bool> {
    let handle = identity
        .pidfd
        .as_ref()
        .ok_or_else(|| std::io::Error::other("original process pidfd missing"))?;
    let mut fd = libc::pollfd {
        fd: handle.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut fd, 1, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    refusal_require(
        fd.revents & (libc::POLLNVAL | libc::POLLERR) == 0,
        "original pidfd observation refused",
    )?;
    Ok(rc == 1 && fd.revents & libc::POLLIN != 0)
}
fn refusal_send<T: Serialize>(
    channel: &mut std::os::unix::net::UnixStream,
    value: &T,
    deadline: u64,
) -> std::io::Result<()> {
    use std::io::Write;
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::legacy())
        .map_err(std::io::Error::other)?;
    refusal_require(
        bytes.len() < 65536,
        "diagnostic frame exceeds original bound",
    )?;
    let length = (bytes.len() as u32).to_ne_bytes();
    for part in [length.as_slice(), bytes.as_slice()] {
        let mut remaining = part;
        while !remaining.is_empty() {
            channel.set_write_timeout(Some(refusal_remaining(deadline)?))?;
            match channel.write(remaining) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "diagnostic frame write returned zero",
                    ));
                }
                Ok(written) => remaining = &remaining[written..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}
fn refusal_read<T: serde::de::DeserializeOwned>(
    channel: &mut std::os::unix::net::UnixStream,
    deadline: u64,
) -> std::io::Result<T> {
    use std::io::Read;
    fn read_part(
        channel: &mut std::os::unix::net::UnixStream,
        mut part: &mut [u8],
        deadline: u64,
    ) -> std::io::Result<()> {
        while !part.is_empty() {
            channel.set_read_timeout(Some(refusal_remaining(deadline)?))?;
            match channel.read(part) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "natural parent reply closed",
                    ));
                }
                Ok(read) => part = &mut part[read..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    let mut length = [0; 4];
    read_part(channel, &mut length, deadline)?;
    let length = u32::from_ne_bytes(length) as usize;
    refusal_require(length < 65536, "diagnostic frame exceeds original bound")?;
    let mut bytes = vec![0; length];
    read_part(channel, &mut bytes, deadline)?;
    let (value, consumed) = bincode::serde::decode_from_slice(&bytes, bincode::config::legacy())
        .map_err(std::io::Error::other)?;
    refusal_require(consumed == length, "trailing diagnostic frame bytes")?;
    Ok(value)
}
pub(super) fn refusal_armed_drop(_tid: Pid) {
    let _ = REFUSAL_ARMED_DROPS.try_with(|count| count.set(count.get().saturating_add(1)));
}
#[derive(Clone, Debug)]
struct RefusalHookFailure {
    kind: std::io::ErrorKind,
    errno: Option<i32>,
    detail: String,
    origin_attempt: u64,
    actual_reply_eof: bool,
}
impl RefusalHookFailure {
    fn of(error: &std::io::Error, origin_attempt: u64, actual_reply_eof: bool) -> Self {
        Self {
            kind: error.kind(),
            errno: error.raw_os_error(),
            detail: error.to_string(),
            origin_attempt,
            actual_reply_eof,
        }
    }
    fn error(&self) -> std::io::Error {
        self.errno
            .map(std::io::Error::from_raw_os_error)
            .unwrap_or_else(|| std::io::Error::new(self.kind, self.detail.clone()))
    }
}

// RUN192: observation-only legacy cleanup probe. The terminal handle is always
// borrowed from its real owner; this module never creates a notifier handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct RefusalGeneration {
    tid: i32,
    tgid: i32,
    start: u64,
    inode: u64,
}
impl RefusalGeneration {
    pub(super) fn of(identity: &TraceeIdentity) -> Self {
        Self {
            tid: identity.tid.as_raw(),
            tgid: identity.snapshot.tgid.as_raw(),
            start: identity.snapshot.start_time,
            inode: identity.proc_inode,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RefusalTerminal {
    generation: RefusalGeneration,
    event_parent: Option<i32>,
    event_fork: bool,
    terminal: String,
    sigkill: bool,
    retired: bool,
    pending_empty: bool,
}
impl RefusalTerminal {
    fn borrow_original(
        identity: &TraceeIdentity,
        terminal: &TerminalCleanup,
        link: Option<EventChildLink>,
    ) -> Self {
        let status = terminal.observed_exit_status();
        Self {
            generation: RefusalGeneration::of(identity),
            event_parent: link.map(|link| link.parent_tid.as_raw()),
            event_fork: link.is_some_and(|link| link.op == ChildOp::Fork),
            terminal: format!("{status:?}"),
            sigkill: matches!(
                status,
                Ok(Some(safeptrace::ExitStatus::Signaled(
                    Signal::SIGKILL,
                    false
                )))
            ),
            retired: terminal.wait(Duration::ZERO),
            pending_empty: terminal.pending_is_empty(),
        }
    }
    fn ready(&self) -> bool {
        self.sigkill && self.retired && self.pending_empty
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RefusalErrorObservation {
    at_ns: u64,
    // Checked at this observation against the exact Instant passed to the guard.
    // The separate monotonic-nanosecond log is not treated as an exact conversion.
    after_rescue_deadline: bool,
    attempt: u64,
    rescue: bool,
    teardown: bool,
    phase: String,
    tid: i32,
    generation: Option<RefusalGeneration>,
    original_root: Option<RefusalGeneration>,
    original_effect: Option<RefusalGeneration>,
    raw_errno: Option<i32>,
    kind: String,
    display: String,
    // This exact branch is known to handle signal-delivery ESRCH. False does
    // not assert propagation of other site errors: only RefusalReturned records
    // an actual error leaving the restored cleanup transaction.
    handled_delivery_esrch: bool,
}
// Only observations already handled by the exact original branch enter this
// aggregate. Attempt is deliberately NOT part of the key. Each occurrence is
// counted; every returned attempt separately records its aggregate count delta.
const REFUSAL_HANDLED_GROUPS: usize = 32;
#[derive(Clone, Debug)]
struct RefusalHandled {
    first: RefusalErrorObservation,
    last_at_ns: u64,
    last_attempt: u64,
    occurrences: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RefusalHookProvenance {
    origin_attempt: u64,
    actual_reply_eof: bool,
    replayed: bool,
}
struct RefusalProbe {
    channel: std::rc::Rc<std::cell::Cell<Option<std::os::unix::net::UnixStream>>>,
    deadline: u64,
    rescue_deadline: u64,
    rescue_deadline_instant: Option<Instant>,
    root: Option<TraceeIdentity>,
    effect: Option<TraceeIdentity>,
    events: Option<Arc<StdMutex<Vec<&'static str>>>>,
    terminal: Option<RefusalTerminal>,
    errors: Vec<RefusalErrorObservation>,
    returned: Vec<RefusalReturned>,
    nonrescue_sites_omitted: u64,
    nonrescue_returns: u64,
    nonrescue_returns_omitted: u64,
    rescue_returns: usize,
    handled: Vec<RefusalHandled>,
    handled_at_attempt_start: [u64; REFUSAL_HANDLED_GROUPS],
    handled_total: u64,
    ready_attempt: Option<u64>,
    actual_reply_eofs: u64,
    attempt_hook_provenance: Option<RefusalHookProvenance>,
    overflow: bool,
    attempts: u64,
    rescue: bool,
    teardown: bool,
    ready_sent: bool,
    ready_acknowledged: bool,
    hook_failure: Option<RefusalHookFailure>,
    product: Option<RefusalProductSeal>,
    phase_stack: Vec<(String, i32, Option<RefusalGeneration>)>,
}
thread_local! {
    static REFUSAL_PROBE: std::cell::RefCell<Option<RefusalProbe>> = const { std::cell::RefCell::new(None) };
}
pub(super) struct RefusalPhase {
    entered: bool,
}
impl RefusalPhase {
    pub(super) fn enter(
        phase: &'static str,
        tid: Pid,
        generation: Option<RefusalGeneration>,
    ) -> Self {
        let entered = refusal_observer(|| {
            REFUSAL_PROBE
                .try_with(|slot| {
                    // Observation's own proc reads can call instrumented helpers. They
                    // never recursively borrow the probe or claim a cleanup phase.
                    let mut slot = slot.try_borrow_mut().ok()?;
                    let probe = slot.as_mut()?;
                    if probe.phase_stack.len() >= 16 {
                        probe.overflow = true;
                        return None;
                    }
                    probe
                        .phase_stack
                        .push((phase.to_owned(), tid.as_raw(), generation));
                    Some(())
                })
                .ok()
                .flatten()
        })
        .flatten()
        .is_some();
        Self { entered }
    }
    pub(super) fn finish<T, E: std::fmt::Display + std::fmt::Debug + 'static>(
        &self,
        result: &Result<T, E>,
    ) {
        if let (true, Err(error)) = (self.entered, result) {
            refusal_leaf_error(None, error, None);
        }
    }
}
impl Drop for RefusalPhase {
    fn drop(&mut self) {
        if self.entered {
            let _ = refusal_observer(|| {
                REFUSAL_PROBE.try_with(|slot| {
                    if let Ok(mut slot) = slot.try_borrow_mut()
                        && let Some(probe) = slot.as_mut()
                        && probe.phase_stack.pop().is_none()
                    {
                        probe.overflow = true;
                    }
                })
            });
        }
    }
}
fn refusal_count_handled(probe: &mut RefusalProbe, record: RefusalErrorObservation) {
    let key_matches = |group: &RefusalHandled| {
        let first = &group.first;
        first.rescue == record.rescue
            && first.teardown == record.teardown
            && first.phase == record.phase
            && first.tid == record.tid
            && first.generation == record.generation
            && first.original_root == record.original_root
            && first.original_effect == record.original_effect
            && first.raw_errno == record.raw_errno
            && first.kind == record.kind
            && first.display == record.display
            && first.handled_delivery_esrch == record.handled_delivery_esrch
    };
    let index = probe.handled.iter().position(key_matches);
    let Some(total) = probe.handled_total.checked_add(1) else {
        probe.overflow = true;
        return;
    };
    if let Some(index) = index {
        let group = &mut probe.handled[index];
        let Some(count) = group.occurrences.checked_add(1) else {
            probe.overflow = true;
            return;
        };
        group.occurrences = count;
        group.last_at_ns = record.at_ns;
        group.last_attempt = record.attempt;
    } else {
        if probe.handled.len() == REFUSAL_HANDLED_GROUPS {
            probe.overflow = true;
            return;
        }
        probe.handled.push(RefusalHandled {
            last_at_ns: record.at_ns,
            last_attempt: record.attempt,
            occurrences: 1,
            first: record,
        });
    }
    probe.handled_total = total;
}

// Called only inside direct_children's original handled-NotFound branch, after
// its original process-absence condition has evaluated true. No new probe or
// reinterpretation of ENOENT decides product behavior.
pub(super) fn refusal_handled_children_absence(tid: Pid, error: &std::io::Error) {
    let phase = RefusalPhase::enter("children-task-directory-open", tid, None);
    if phase.entered {
        refusal_site_error(None, error, true);
    }
}

pub(super) fn refusal_leaf_error<E: std::fmt::Display + std::fmt::Debug + 'static>(
    leaf: Option<&'static str>,
    error: &E,
    _prior: Option<usize>,
) {
    refusal_site_error(leaf, error, false);
}
fn refusal_site_error<E: std::fmt::Display + std::fmt::Debug + 'static>(
    leaf: Option<&'static str>,
    error: &E,
    handled_children_absence: bool,
) {
    let _ = refusal_observer(|| {
        REFUSAL_PROBE.try_with(|slot| {
            let Ok(mut slot) = slot.try_borrow_mut() else { return };
            let Some(probe) = slot.as_mut() else { return };
            let Some((phase, tid, generation)) = probe.phase_stack.last().cloned() else {
                probe.overflow = true;
                return;
            };
            let any = error as &dyn std::any::Any;
            let raw_errno = if let Some(error) = any.downcast_ref::<std::io::Error>() {
                error.raw_os_error()
            } else if let Some(error) = any.downcast_ref::<Errno>() {
                Some(error.into_raw())
            } else if let Some(error) = any.downcast_ref::<nix::errno::Errno>() {
                Some(*error as i32)
            } else if let Some(TraceError::Errno(error)) = any.downcast_ref::<TraceError>() {
                Some(error.into_raw())
            } else {
                None
            };
            let phase = leaf.map_or(phase.clone(), |leaf| format!("{phase}/{leaf}"));
            let at_ns = match refusal_now_ns() {
                Ok(now) => now,
                Err(_) => { probe.overflow = true; return; }
            };
            let record = RefusalErrorObservation {
                at_ns,
                after_rescue_deadline: probe
                    .rescue_deadline_instant
                    .is_some_and(|deadline| Instant::now() >= deadline),
                attempt: probe.attempts,
                rescue: probe.rescue,
                teardown: probe.teardown,
                // These exact match arms accept ESRCH; site1/site2 callers
                // receive send_identity_sigkill's Ok rather than its leaf Err.
                handled_delivery_esrch: matches!(phase.as_str(),
                    "root-stop-signal-delivery"
                    | "root-kill-signal-delivery"
                    | "descendant-kill-signal-delivery-site3")
                    && raw_errno == Some(libc::ESRCH),
                phase,
                tid,
                generation,
                original_root: probe.root.as_ref().map(RefusalGeneration::of),
                original_effect: probe.effect.as_ref().map(RefusalGeneration::of),
                raw_errno,
                kind: any.downcast_ref::<std::io::Error>()
                    .map(|error| format!("{:?}", error.kind()))
                    .unwrap_or_else(|| "typed non-io leaf".to_owned()),
                display: error.to_string(),
            };
            if record.handled_delivery_esrch || handled_children_absence {
                refusal_count_handled(probe, record);
                return;
            }
            // The original failure retains its ordered product secondaries.
            // Sample only diagnostic product sites, with an exact omitted count.
            if !probe.rescue && probe.errors.iter().filter(|site| !site.rescue).count() >= 8 {
                match probe.nonrescue_sites_omitted.checked_add(1) {
                    Some(count) => probe.nonrescue_sites_omitted = count,
                    None => probe.overflow = true,
                }
                return;
            }
            if probe.errors.len() == 4096 {
                probe.overflow = true;
                return;
            }
            use std::io::Write;
            let _ = writeln!(std::io::stderr().lock(),
                "REFUSAL_ACTUAL_SITE attempt={} rescue={} phase={} tid={} raw={:?} kind={} error={}",
                record.attempt, record.rescue, record.phase, record.tid, record.raw_errno,
                record.kind, record.display.chars().take(120).collect::<String>());
            probe.errors.push(record);
        })
    });
}
#[derive(Clone, Debug)]
struct RefusalReturned {
    attempt: u64,
    rescue: bool,
    teardown: bool,
    tid: i32,
    raw_errno: Option<i32>,
    kind: std::io::ErrorKind,
    display: String,
    observed_sites: Vec<usize>,
    handled_occurrences: Vec<(usize, u64)>,
    hook_provenance: Option<RefusalHookProvenance>,
    callback_seen: bool,
}
// These are actual return observations at the transaction boundary AFTER its
// existing Err path restores moved maps. They are never inferred from leaves.
pub(super) fn refusal_attempt_result(tid: Pid, result: &std::io::Result<()>) {
    let Err(error) = result else { return };
    let _ = refusal_observer(|| {
        REFUSAL_PROBE.try_with(|slot| {
            let Ok(mut slot) = slot.try_borrow_mut() else {
                return;
            };
            let Some(probe) = slot.as_mut() else { return };
            if !probe.rescue {
                let Some(count) = probe.nonrescue_returns.checked_add(1) else {
                    probe.overflow = true;
                    return;
                };
                probe.nonrescue_returns = count;
                if count > 8 {
                    probe.nonrescue_returns_omitted += 1;
                    return;
                }
            } else {
                if probe.rescue_returns == 4096 {
                    probe.overflow = true;
                    return;
                }
                probe.rescue_returns += 1;
            }
            let handled_occurrences = probe.handled.iter().enumerate()
                .filter_map(|(index, group)| {
                    let count = group.occurrences - probe.handled_at_attempt_start[index];
                    (count != 0).then_some((index, count))
                }).collect();
            let record = RefusalReturned {
                attempt: probe.attempts,
                rescue: probe.rescue,
                teardown: probe.teardown,
                tid: tid.as_raw(),
                raw_errno: error.raw_os_error(),
                kind: error.kind(),
                display: error.to_string(),
                observed_sites: probe
                    .errors
                    .iter()
                    .enumerate()
                    .filter_map(|(index, site)| {
                        (site.attempt == probe.attempts && site.rescue == probe.rescue)
                            .then_some(index)
                    })
                    .collect(),
                handled_occurrences,
                hook_provenance: probe.attempt_hook_provenance,
                callback_seen: false,
            };
            // Bounded rescue-only output; all exact values remain in `returned`.
            // Site errors (including handled ones) do not suppress this return.
            if probe.rescue {
                use std::io::Write;
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "REFUSAL_ACTUAL_ATTEMPT_RETURN attempt={} tid={} raw={:?} kind={:?} hook={:?} handled={:?} error={}",
                    record.attempt,
                    record.tid,
                    record.raw_errno,
                    record.kind,
                    record.hook_provenance,
                    record.handled_occurrences,
                    record.display.chars().take(240).collect::<String>()
                );
            }
            probe.returned.push(record);
        })
    });
}
fn refusal_callback(error: &std::io::Error) {
    let _ = refusal_observer(|| {
        REFUSAL_PROBE.try_with(|slot| {
            let Ok(mut slot) = slot.try_borrow_mut() else {
                return;
            };
            let Some(probe) = slot.as_mut() else { return };
            let Some(record) = probe.returned.last_mut() else {
                probe.overflow = true;
                return;
            };
            if record.attempt != probe.attempts
                || !record.rescue
                || record.callback_seen
                || record.raw_errno != error.raw_os_error()
                || record.kind != error.kind()
                || record.display != error.to_string()
            {
                probe.overflow = true;
                return;
            }
            record.callback_seen = true;
        })
    });
}
pub(super) fn refusal_attempt() {
    let _ = refusal_observer(|| {
        REFUSAL_PROBE.try_with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut()
                && let Some(probe) = slot.as_mut()
            {
                match probe.attempts.checked_add(1) {
                    Some(count) => probe.attempts = count,
                    None => probe.overflow = true,
                }
                probe.attempt_hook_provenance = None;
                probe.handled_at_attempt_start.fill(0);
                for (index, group) in probe.handled.iter().enumerate() {
                    probe.handled_at_attempt_start[index] = group.occurrences;
                }
            }
        })
    });
}
pub(super) fn refusal_borrow_retired(tracee: &RegisteredTraceeCleanup) -> std::io::Result<()> {
    refusal_hook(|| {
        REFUSAL_PROBE
            .try_with(|slot| {
                let mut slot = slot
                    .try_borrow_mut()
                    .map_err(|_| std::io::Error::other("retirement probe already borrowed"))?;
                let Some(probe) = slot.as_mut() else {
                    return Ok(());
                };
                let expected = probe.effect.as_ref().ok_or_else(|| {
                    std::io::Error::other("effect was not captured before cleanup")
                })?;
                if tracee.identity.tid != expected.tid {
                    return Ok(());
                }
                let observation = RefusalTerminal::borrow_original(
                    &tracee.identity,
                    &tracee.terminal,
                    tracee.event_link,
                );
                refusal_require(
                    observation.generation == RefusalGeneration::of(expected),
                    "retired observation generation mismatch",
                )?;
                refusal_require(
                    observation.retired,
                    "pre-removal borrow did not observe actual retirement",
                )?;
                probe.terminal = Some(observation);
                Ok(())
            })
            .map_err(|_| std::io::Error::other("retirement probe TLS unavailable"))?
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RefusalProductSeal {
    original_after_effect: bool,
    secondary_eio_count: usize,
    prefix_stdout: Vec<u8>,
    prefix_stderr: Vec<u8>,
    original_failure_allocation: bool,
}
fn refusal_physical_ready(
    root_absent: bool,
    root_ready: bool,
    effect_ready: bool,
    ppid: i32,
    expected_reaper: i32,
    tracer: i32,
    state: &str,
) -> bool {
    root_absent
        && root_ready
        && effect_ready
        && ppid == expected_reaper
        && tracer == 0
        && state.starts_with('Z')
}
// The first real reply EOF and the last returned guard error are distinct.
// This record does not manufacture another EOF when the unchanged retry loop's
// last attempt reaches the actual disappearance deadline without calling the hook.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct RefusalIpcSeal {
    first_eof_attempt: u64,
    actual_reply_eofs: u64,
    first_failure: String,
    eof_returns: u64,
    last_attempt: u64,
    last_kind: String,
    last_raw_errno: Option<i32>,
    last_display: String,
    last_hook: Option<RefusalHookProvenance>,
    final_timeout_site: Option<RefusalErrorObservation>,
}
fn refusal_assert_actual_timeout(
    site: &RefusalErrorObservation,
    root: RefusalGeneration,
    effect: RefusalGeneration,
    attempt: u64,
    display: &str,
) {
    assert_eq!(site.phase, "cleanup-confirmation-timeout");
    assert_eq!(site.tid, root.tid);
    assert_eq!(site.generation, Some(root));
    assert_eq!(site.original_root, Some(root));
    assert_eq!(site.original_effect, Some(effect));
    assert_eq!(site.attempt, attempt);
    assert!(site.rescue && !site.teardown);
    assert_eq!(site.kind, "TimedOut");
    assert_eq!(site.raw_errno, None);
    assert!(!site.handled_delivery_esrch);
    assert_eq!(site.display, display);
    assert_eq!(
        display,
        format!(
            "LiteInst tracee {} cleanup or fatal terminal-disappearance confirmation timed out",
            root.tid
        )
    );
    assert!(
        site.at_ns > 0 && site.after_rescue_deadline,
        "actual guard timeout must be observed at/after its unchanged Instant deadline"
    );
}
impl RefusalIpcSeal {
    fn assert_exact(&self, root: RefusalGeneration, effect: RefusalGeneration) {
        assert!(self.first_eof_attempt > 0 && self.eof_returns > 0);
        assert_eq!(self.actual_reply_eofs, 1);
        assert_eq!(self.first_failure, "natural parent reply closed");
        assert_eq!(self.last_raw_errno, None);
        if let Some(site) = &self.final_timeout_site {
            assert_eq!(self.last_kind, "TimedOut");
            assert_eq!(self.last_attempt, self.first_eof_attempt + self.eof_returns);
            assert!(self.last_hook.is_none());
            refusal_assert_actual_timeout(
                site,
                root,
                effect,
                self.last_attempt,
                &self.last_display,
            );
        } else {
            assert_eq!(self.last_kind, "UnexpectedEof");
            assert_eq!(
                self.last_attempt,
                self.first_eof_attempt + self.eof_returns - 1
            );
            assert_eq!(self.last_display, "natural parent reply closed");
            assert_eq!(
                self.last_hook,
                Some(RefusalHookProvenance {
                    origin_attempt: self.first_eof_attempt,
                    actual_reply_eof: true,
                    replayed: self.eof_returns > 1,
                })
            );
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
enum RefusalWire {
    Live {
        root: RefusalGeneration,
        effect: RefusalGeneration,
        injected_write: usize,
    },
    Ready {
        root: Box<RefusalTerminal>,
        effect: Box<RefusalTerminal>,
        product: RefusalProductSeal,
        root_absent: bool,
        root_ready: bool,
        effect_ready: bool,
        ppid: i32,
        tracer: i32,
        state: String,
        root_lease_empty: bool,
        events: Vec<String>,
        admission_closed: bool,
    },
    HeldTimeout {
        effect: RefusalGeneration,
        timed_out: bool,
        retained: bool,
        timeout_display: String,
    },
    IpcFailure {
        effect: RefusalGeneration,
        retained: bool,
        armed_drop_delta: u64,
        elapsed_ns: u64,
        outcome: Box<RefusalIpcSeal>,
    },
    Finished,
}
fn refusal_before_failure(pid: Pid, events: &Arc<StdMutex<Vec<&'static str>>>) {
    let result = refusal_hook(|| {
        let prepared = REFUSAL_PROBE
            .try_with(|slot| -> std::io::Result<_> {
                let mut slot = slot
                    .try_borrow_mut()
                    .map_err(|_| std::io::Error::other("live probe already borrowed"))?;
                let Some(probe) = slot.as_mut() else {
                    return Ok(None);
                };
                refusal_require(probe.effect.is_none(), "one original injected effect")?;
                probe.effect = Some(static_identity(pid));
                let root = probe.effect.as_ref().unwrap().snapshot.ppid;
                probe.root = Some(static_identity(root));
                probe.events = Some(events.clone());
                // After the actual live guest identities and timers exist, contain
                // only T's intentional assertion aborts; P/G mm remain unchanged.
                assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 1);
                static_abort_containment();
                let message = RefusalWire::Live {
                    root: RefusalGeneration::of(probe.root.as_ref().unwrap()),
                    effect: RefusalGeneration::of(probe.effect.as_ref().unwrap()),
                    injected_write: EFFECT.len(),
                };
                Ok(Some((
                    RefusalChannel::take(probe)?,
                    message,
                    probe.deadline,
                )))
            })
            .map_err(|_| std::io::Error::other("live probe TLS unavailable"))??;
        if let Some((mut channel, message, deadline)) = prepared {
            // No registry/probe borrow or mutex spans either exchange.
            refusal_send(channel.stream(), &message, deadline)?;
            refusal_require(
                refusal_read::<bool>(channel.stream(), deadline)?,
                "live identity acknowledgement refused",
            )?;
        }
        Ok(())
    });
    if let Err(error) = result {
        refusal_retain_hook_error(&error);
    }
}
fn refusal_retain_hook_error(error: &std::io::Error) {
    let _ = refusal_observer(|| {
        REFUSAL_PROBE.try_with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut()
                && let Some(probe) = slot.as_mut()
                && probe.hook_failure.is_none()
            {
                probe.hook_failure = Some(RefusalHookFailure::of(error, probe.attempts, false));
            }
        })
    });
}
pub(super) fn refusal_cleanup_progress(guard: &LiteinstTraceeCleanup) -> std::io::Result<()> {
    // Catch only diagnostic work before an unwind can cross the hook into the
    // caller's moved maps. Err then follows its existing map restoration.
    let result = refusal_hook(|| {
        let prepared = REFUSAL_PROBE
            .try_with(|slot| -> std::io::Result<_> {
                let mut slot = slot
                    .try_borrow_mut()
                    .map_err(|_| std::io::Error::other("progress probe already borrowed"))?;
                let Some(probe) = slot.as_mut() else {
                    return Ok(None);
                };
                if !probe.rescue {
                    return Ok(None);
                }
                if REFUSAL_OBSERVER_PANICKED.with(|flag| flag.get()) {
                    return Err(std::io::Error::other("diagnostic observer panic retained"));
                }
                refusal_require(!probe.overflow, "incomplete bounded phase observations")?;
                if let Some(failure) = &probe.hook_failure {
                    probe.attempt_hook_provenance = Some(RefusalHookProvenance {
                        origin_attempt: failure.origin_attempt,
                        actual_reply_eof: failure.actual_reply_eof,
                        replayed: true,
                    });
                    return Err(failure.error());
                }
                if probe.ready_acknowledged {
                    return Ok(None);
                }
                let Some(message) = refusal_progress_inner(probe, guard)? else {
                    return Ok(None);
                };
                Ok(Some((
                    RefusalChannel::take(probe)?,
                    message,
                    probe.rescue_deadline,
                )))
            })
            .map_err(|_| std::io::Error::other("progress probe TLS unavailable"))??;
        if let Some((mut channel, message, deadline)) = prepared {
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "REFUSAL_PRODUCT_TERMINAL_SEALED {message:?}"
            );
            refusal_send(channel.stream(), &message, deadline)?;
            REFUSAL_PROBE.with(|slot| {
                let mut slot = slot.borrow_mut();
                let probe = slot.as_mut().unwrap();
                probe.ready_sent = true;
                probe.ready_attempt = Some(probe.attempts);
            });
            // The only actual reply read. Retained replays never read again.
            let acknowledged = refusal_read::<bool>(channel.stream(), deadline);
            if let Err(error) = &acknowledged {
                REFUSAL_PROBE.with(|slot| {
                    let mut slot = slot.borrow_mut();
                    let probe = slot.as_mut().unwrap();
                    let actual_reply_eof = error.kind() == std::io::ErrorKind::UnexpectedEof
                        && error.raw_os_error().is_none()
                        && error.to_string() == "natural parent reply closed";
                    if actual_reply_eof {
                        match probe.actual_reply_eofs.checked_add(1) {
                            Some(count) => probe.actual_reply_eofs = count,
                            None => probe.overflow = true,
                        }
                    }
                    probe.attempt_hook_provenance = Some(RefusalHookProvenance {
                        origin_attempt: probe.attempts,
                        actual_reply_eof,
                        replayed: false,
                    });
                    if probe.hook_failure.is_none() {
                        probe.hook_failure = Some(RefusalHookFailure::of(
                            error,
                            probe.attempts,
                            actual_reply_eof,
                        ));
                    }
                });
            }
            refusal_require(
                acknowledged?,
                "natural reaper refused readiness acknowledgement",
            )?;
            REFUSAL_PROBE
                .with(|slot| slot.borrow_mut().as_mut().unwrap().ready_acknowledged = true);
        }
        Ok(())
    });
    if let Err(error) = &result {
        refusal_retain_hook_error(error);
    }
    result
}
fn refusal_progress_inner(
    probe: &mut RefusalProbe,
    guard: &LiteinstTraceeCleanup,
) -> std::io::Result<Option<RefusalWire>> {
    let Some(effect_terminal) = probe.terminal.as_ref() else {
        return Ok(None);
    };
    let terminal = guard
        .terminal
        .as_ref()
        .ok_or_else(|| std::io::Error::other("original root handle missing"))?;
    let root_terminal = RefusalTerminal::borrow_original(&guard.identity, terminal, None);
    let root = probe
        .root
        .as_ref()
        .ok_or_else(|| std::io::Error::other("root not captured"))?;
    let effect = probe
        .effect
        .as_ref()
        .ok_or_else(|| std::io::Error::other("effect not captured"))?;
    refusal_require(
        root_terminal.generation == RefusalGeneration::of(root),
        "root generation mismatch",
    )?;
    refusal_require(
        effect_terminal.generation == RefusalGeneration::of(effect),
        "effect generation mismatch",
    )?;
    if !root_terminal.ready() || !effect_terminal.ready() {
        return Ok(None);
    }
    refusal_require(
        effect_terminal.event_parent == Some(root.tid.as_raw()) && effect_terminal.event_fork,
        "actual fork event link missing",
    )?;
    let root_absent = !root.observe_same_process()?;
    let root_ready = refusal_pidfd_ready(root)?;
    let root_lease_empty = guard
        .held_root_stop
        .try_lock()
        .map_err(|_| std::io::Error::other("root lease observation unavailable"))?
        .is_none();
    if !root_absent || !root_ready || !root_lease_empty {
        return Ok(None);
    }
    refusal_require(
        !PathBuf::from(format!("/proc/{}", root.tid)).exists(),
        "original root path still present",
    )?;
    refusal_require(
        effect.observe_same_process()?,
        "original effect generation missing before natural wait",
    )?;
    let snapshot = tracee_snapshot(effect.tid)?;
    let status = fs::read_to_string(format!("/proc/{}/status", effect.tid))?;
    let state = status
        .lines()
        .find_map(|line| line.strip_prefix("State:\t"))
        .ok_or_else(|| std::io::Error::other("effect State missing"))?
        .to_owned();
    let effect_ready = refusal_pidfd_ready(effect)?;
    let reaper = unsafe { libc::getppid() };
    refusal_require(
        effect_ready && state.starts_with('Z'),
        "effect not actually terminal zombie",
    )?;
    refusal_require(
        snapshot.ppid.as_raw() == reaper && snapshot.tracer_pid.as_raw() == 0,
        "effect not owned by original natural parent",
    )?;
    let retained = guard
        .fatal_terminal_observations
        .as_ref()
        .and_then(|map| map.get(&effect.tid))
        .ok_or_else(|| std::io::Error::other("original terminal observation not retained"))?;
    refusal_require(
        RefusalGeneration::of(retained) == RefusalGeneration::of(effect),
        "retained effect generation mismatch",
    )?;
    let events = probe
        .events
        .as_ref()
        .ok_or_else(|| std::io::Error::other("events not captured"))?
        .try_lock()
        .map_err(|_| std::io::Error::other("events observation unavailable"))?
        .iter()
        .map(|s| (*s).to_owned())
        .collect::<Vec<_>>();
    refusal_require(
        events == ["effect", "failed"],
        "original event sequence changed",
    )?;
    let admission_closed = OrdinaryAdmission::acquire().is_err();
    refusal_require(admission_closed, "failed-owner admission reopened")?;
    let message = RefusalWire::Ready {
        root: Box::new(root_terminal),
        effect: Box::new(effect_terminal.clone()),
        product: probe
            .product
            .as_ref()
            .ok_or_else(|| std::io::Error::other("product refusal not sealed"))?
            .clone(),
        root_absent,
        root_ready,
        effect_ready,
        ppid: snapshot.ppid.as_raw(),
        tracer: snapshot.tracer_pid.as_raw(),
        state,
        root_lease_empty,
        events,
        admission_closed,
    };
    Ok(Some(message))
}

// The existing quarantine entry stays occupied by this registered return slot.
// It is test-only and offers no public recovery. All storage/Rc allocation occurs
// before replacing the original entry. The original Box allocation never moves.
struct RefusalReturnSlot {
    owner: std::cell::Cell<Option<std::mem::ManuallyDrop<Box<dyn std::any::Any>>>>,
}
struct RefusalOwnerScope {
    id: u64,
    registered: std::rc::Rc<RefusalReturnSlot>,
    owner: Option<std::mem::ManuallyDrop<Box<dyn std::any::Any>>>,
}
impl RefusalOwnerScope {
    fn enter(id: u64) -> Self {
        let registered = std::rc::Rc::new(RefusalReturnSlot {
            owner: std::cell::Cell::new(None),
        });
        let replacement =
            std::mem::ManuallyDrop::new(Box::new(registered.clone()) as Box<dyn std::any::Any>);
        let owner = CLEANUP_QUARANTINE.with(|owners| {
            let mut owners = owners.borrow_mut();
            let entry = owners.get_mut(&id).expect("original registered owner");
            assert!(entry.downcast_ref::<LegacyInjectedOwner<Log>>().is_some());
            std::mem::replace(entry, replacement)
        });
        // No fallible operation lies between the replacement and this guard.
        Self {
            id,
            registered,
            owner: Some(owner),
        }
    }
    fn resume(id: u64) -> Self {
        let registered = CLEANUP_QUARANTINE.with(|owners| {
            owners
                .borrow()
                .get(&id)
                .expect("same registered return slot")
                .downcast_ref::<std::rc::Rc<RefusalReturnSlot>>()
                .expect("same return slot type")
                .clone()
        });
        let owner = registered.owner.take().expect("exact parked owner");
        Self {
            id,
            registered,
            owner: Some(owner),
        }
    }
    fn allocation(&self) -> *const () {
        let owner: &dyn std::any::Any = &***self.owner.as_ref().unwrap();
        std::ptr::from_ref(owner).cast::<()>()
    }
    fn borrow(&mut self) -> &mut LegacyInjectedOwner<Log> {
        self.owner
            .as_mut()
            .unwrap()
            .downcast_mut::<LegacyInjectedOwner<Log>>()
            .unwrap()
    }
    fn registered(&self) -> bool {
        CLEANUP_QUARANTINE.with(|owners| {
            owners
                .borrow()
                .get(&self.id)
                .and_then(|entry| entry.downcast_ref::<std::rc::Rc<RefusalReturnSlot>>())
                .is_some_and(|entry| std::rc::Rc::ptr_eq(entry, &self.registered))
        })
    }
    fn take_confirmed(mut self) -> LegacyInjectedOwner<Log> {
        assert!(self.registered(), "same original quarantine registration");
        assert!(
            !self
                .borrow()
                .tracer
                .liteinst_cleanup
                .as_ref()
                .unwrap()
                .armed,
            "unconfirmed owner must remain registered"
        );
        // Both type and disarm were checked before removal. Only the confirmed
        // value can be exposed to ordinary Drop after this point.
        let registration =
            CLEANUP_QUARANTINE.with(|owners| owners.borrow_mut().remove(&self.id).unwrap());
        drop(std::mem::ManuallyDrop::into_inner(registration));
        let owner = std::mem::ManuallyDrop::into_inner(self.owner.take().unwrap());
        *owner
            .downcast::<LegacyInjectedOwner<Log>>()
            .unwrap_or_else(|_| unreachable!("checked before removal"))
    }
}
impl Drop for RefusalOwnerScope {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            // Infallible Cell transfer: no registry/RefCell borrow, allocation,
            // observer, cleanup call, deadline, or ordinary armed-owner Drop.
            // The original entry already owns this exact Rc return slot.
            self.registered.owner.set(Some(owner));
        }
    }
}

// IPC temporarily owns the stream without a RefCell borrow. Its original slot
// remains in the probe and receives the stream back even if diagnostic code
// unwinds. A nested acquisition fails closed; it cannot alias the stream.
struct RefusalChannel {
    slot: std::rc::Rc<std::cell::Cell<Option<std::os::unix::net::UnixStream>>>,
    stream: Option<std::os::unix::net::UnixStream>,
}
impl RefusalChannel {
    fn take(probe: &RefusalProbe) -> std::io::Result<Self> {
        let slot = probe.channel.clone();
        let stream = slot
            .take()
            .ok_or_else(|| std::io::Error::other("diagnostic channel already leased"))?;
        Ok(Self {
            slot,
            stream: Some(stream),
        })
    }
    fn stream(&mut self) -> &mut std::os::unix::net::UnixStream {
        self.stream.as_mut().unwrap()
    }
}
impl Drop for RefusalChannel {
    fn drop(&mut self) {
        self.slot.set(self.stream.take());
    }
}

fn refusal_owned<T>(
    retained: &mut RefusalOwnerScope,
    body: impl FnOnce(&mut LegacyInjectedOwner<Log>) -> T,
) -> T {
    body(retained.borrow())
}

fn refusal_rescue(
    mut retained: RefusalOwnerScope,
    mode: &str,
    deadline_ns: u64,
) -> LegacyInjectedOwner<Log> {
    let armed_drops = REFUSAL_ARMED_DROPS.with(|count| count.get());
    let (original_failure, product) = refusal_owned(&mut retained, |owner| {
        let failure = owner.failure.as_ref().unwrap().clone();
        let prefix = failure
            .captured_prefix()
            .expect("original captured prefix retained");
        let product = RefusalProductSeal {
            original_after_effect: matches!(failure.primary(), Error::Tool(error)
                if error.downcast_ref::<AfterEffect>().is_some_and(|cause| *cause.0 == 71)),
            secondary_eio_count: failure
                .secondary()
                .iter()
                .filter(|failure| {
                    failure.origin().phase == "injected tracee cleanup confirmation"
                        && matches!(failure.error(), Error::Io(error)
                        if error.raw_os_error() == Some(libc::EIO))
                })
                .count(),
            prefix_stdout: prefix.stdout().to_vec(),
            prefix_stderr: prefix.stderr().to_vec(),
            original_failure_allocation: Arc::ptr_eq(owner.failure.as_ref().unwrap(), &failure),
        };
        (failure, product)
    });
    assert!(
        product.original_after_effect
            && product.secondary_eio_count > 1
            && product.original_failure_allocation
    );
    assert!(EFFECT.starts_with(&product.prefix_stdout) && product.prefix_stderr.is_empty());
    let rescue_start = static_now_ns();
    let rescue_ns = deadline_ns.min(rescue_start + 2_000_000_000);
    let rescue_deadline = Instant::now() + static_remaining(rescue_ns);
    if mode == "once" {
        refusal_owned(&mut retained, |owner| {
            owner
                .tracer
                .liteinst_cleanup
                .as_mut()
                .unwrap()
                .fail_discovery_once = Some(Arc::new(AtomicBool::new(true)))
        });
    }
    REFUSAL_PROBE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let probe = slot.as_mut().unwrap();
        probe.rescue = true;
        probe.rescue_deadline = rescue_ns;
        probe.rescue_deadline_instant = Some(rescue_deadline);
        probe.product = Some(product);
    });
    let (attempts_before, returned_before, handled_before) = REFUSAL_PROBE.with(|slot| {
        let slot = slot.borrow();
        let probe = slot.as_ref().unwrap();
        (probe.attempts, probe.returned.len(), probe.handled_total)
    });
    let mut refusals = Vec::new();
    let confirmed = refusal_owned(&mut retained, |owner| {
        owner
            .tracer
            .liteinst_cleanup
            .as_mut()
            .unwrap()
            .terminate_fatal_and_confirm(rescue_deadline, |error| {
                refusal_callback(&error);
                refusals.push(error);
            })
    });
    let mut ipc_seal = None;
    REFUSAL_PROBE.with(|slot| {
        let slot = slot.borrow();
        let probe = slot.as_ref().unwrap();
        let returned = &probe.returned[returned_before..];
        assert!(!probe.overflow);
        assert_eq!(returned.len(), refusals.len());
        assert_eq!(probe.rescue_returns, refusals.len());
        let original_root = probe.root.as_ref().unwrap().tid.as_raw();
        let mut returned_handled = 0u64;
        for (offset, (record, error)) in returned.iter().zip(&refusals).enumerate() {
            assert!(record.callback_seen && record.rescue && !record.teardown);
            assert_eq!(record.tid, original_root);
            assert_eq!(record.attempt, attempts_before + offset as u64 + 1);
            assert_eq!(record.raw_errno, error.raw_os_error());
            assert_eq!(record.kind, error.kind());
            assert_eq!(record.display, error.to_string());
            for &(index, count) in &record.handled_occurrences {
                let group = &probe.handled[index];
                assert!(group.first.rescue && !group.first.teardown && count > 0);
                assert!(group.first.attempt <= record.attempt);
                assert!(record.attempt <= group.last_attempt);
                returned_handled = returned_handled.checked_add(count).unwrap();
            }
        }
        let successful_attempt_handled = if confirmed {
            probe.handled.iter().enumerate().map(|(index, group)| {
                group.occurrences - probe.handled_at_attempt_start[index]
            }).sum::<u64>()
        } else {
            0
        };
        assert_eq!(
            probe.handled_total - handled_before,
            returned_handled + successful_attempt_handled,
            "every handled rescue occurrence belongs to its actual attempt"
        );
        assert_eq!(
            probe.handled_total,
            probe.handled.iter().map(|group| group.occurrences).sum::<u64>()
        );
        let attempts = probe.attempts - attempts_before;
        match mode {
            "original" => {
                assert!(refusals.is_empty());
                assert_eq!(attempts, 1);
            }
            "once" => {
                assert_eq!(refusals.len(), 1);
                assert_eq!(attempts, 2);
                assert_eq!(refusals[0].raw_os_error(), Some(libc::EIO));
                let exact = returned[0].observed_sites.iter().filter(|&&index| {
                    let site = &probe.errors[index];
                    site.phase == "discovery-one-shot-refusal"
                        && site.raw_errno == Some(libc::EIO)
                        && !site.handled_delivery_esrch
                        && site.attempt == returned[0].attempt
                        && site.rescue
                        && site.tid == original_root
                }).count();
                assert_eq!(exact, 1, "one-shot site and actual callback correlation");
            }
            "held" => {
                assert!(!refusals.is_empty());
                assert_eq!(attempts as usize, refusals.len());
                for (record, error) in returned.iter().zip(&refusals) {
                    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                    assert_eq!(error.raw_os_error(), None);
                    assert!(error.to_string().contains(
                        "fatal terminal-disappearance confirmation timed out"
                    ));
                    assert!(record.hook_provenance.is_none());
                    let exact = record.observed_sites.iter().filter(|&&index| {
                        let site = &probe.errors[index];
                        site.phase == "cleanup-confirmation-timeout"
                            && site.kind == "TimedOut"
                            && site.raw_errno.is_none()
                            && site.rescue
                            && site.tid == original_root
                            && site.attempt == record.attempt
                    }).count();
                    assert_eq!(exact, 1, "actual guard disappearance timeout site");
                }
            }
            "ipc" => {
                assert!(!refusals.is_empty());
                assert_eq!(attempts as usize, refusals.len());
                assert_eq!(probe.actual_reply_eofs, 1, "exactly one actual read EOF");
                let origin = probe.ready_attempt.expect("actual Ready attempt");
                assert_eq!(origin, attempts_before + 1);
                let root = RefusalGeneration::of(probe.root.as_ref().unwrap());
                let effect = RefusalGeneration::of(probe.effect.as_ref().unwrap());
                let mut eof_returns = 0u64;
                let mut final_timeout_site = None;
                for (index, (record, error)) in returned.iter().zip(&refusals).enumerate() {
                    if error.kind() == std::io::ErrorKind::UnexpectedEof {
                        assert_eq!(error.raw_os_error(), None);
                        assert_eq!(error.to_string(), "natural parent reply closed");
                        assert_eq!(record.hook_provenance, Some(RefusalHookProvenance {
                            origin_attempt: origin,
                            actual_reply_eof: true,
                            replayed: index != 0,
                        }));
                        eof_returns = eof_returns.checked_add(1).unwrap();
                    } else {
                        // Only the last actual returned error may be the guard's
                        // own timeout; the first return must still be the real EOF.
                        assert!(index > 0 && index + 1 == returned.len());
                        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
                        assert_eq!(error.raw_os_error(), None);
                        assert!(record.hook_provenance.is_none());
                        let sites: Vec<_> = record.observed_sites.iter()
                            .map(|&site| &probe.errors[site])
                            .filter(|site| site.phase == "cleanup-confirmation-timeout")
                            .collect();
                        assert_eq!(sites.len(), 1, "one actual final guard timeout site");
                        refusal_assert_actual_timeout(sites[0], root, effect, record.attempt,
                            &error.to_string());
                        assert!(final_timeout_site.replace(sites[0].clone()).is_none());
                    }
                }
                assert_eq!(eof_returns as usize + usize::from(final_timeout_site.is_some()),
                    returned.len());
                let last = returned.last().unwrap();
                let seal = RefusalIpcSeal {
                    first_eof_attempt: origin,
                    actual_reply_eofs: probe.actual_reply_eofs,
                    first_failure: refusals[0].to_string(),
                    eof_returns,
                    last_attempt: last.attempt,
                    last_kind: format!("{:?}", last.kind),
                    last_raw_errno: last.raw_errno,
                    last_display: last.display.clone(),
                    last_hook: last.hook_provenance,
                    final_timeout_site,
                };
                seal.assert_exact(root, effect);
                ipc_seal = Some(seal);
            }
            _ => panic!("unknown diagnostic mode"),
        }
        if mode != "ipc" {
            assert_eq!(probe.actual_reply_eofs, 0);
            assert!(returned.iter().all(|record| record.hook_provenance.is_none()));
        }
        for (index, group) in probe.handled.iter().enumerate() {
            let first = &group.first;
            assert!(group.occurrences > 0);
            assert!(first.attempt <= group.last_attempt && first.at_ns <= group.last_at_ns);
            if first.phase == "children-task-directory-open" {
                assert_eq!(first.raw_errno, Some(libc::ENOENT));
                assert_eq!(first.kind, "NotFound");
                assert!(!first.handled_delivery_esrch);
            } else {
                assert!(matches!(first.phase.as_str(),
                    "root-stop-signal-delivery"
                    | "root-kill-signal-delivery"
                    | "descendant-kill-signal-delivery-site3"));
                assert_eq!(first.raw_errno, Some(libc::ESRCH));
                assert!(first.handled_delivery_esrch);
            }
            eprintln!(
                "REFUSAL_HANDLED_COUNT index={index} phase={} tid={} generation={:?} rescue={} teardown={} raw={:?} kind={} occurrences={} first_attempt={} last_attempt={} first_ns={} last_ns={} error={}",
                first.phase, first.tid, first.generation, first.rescue, first.teardown,
                first.raw_errno, first.kind, group.occurrences, first.attempt,
                group.last_attempt, first.at_ns, group.last_at_ns, first.display
            );
        }
        eprintln!(
            "REFUSAL_EXACT_CORRELATION mode={mode} attempts={attempts} returned={} callbacks={} handled={} product_site_samples_omitted={} nonrescue_returns={} product_return_samples_omitted={} actual_reply_eofs={}",
            returned.len(), refusals.len(), probe.handled_total - handled_before,
            probe.nonrescue_sites_omitted, probe.nonrescue_returns,
            probe.nonrescue_returns_omitted, probe.actual_reply_eofs
        );
    });
    assert!(retained.registered());
    // The exact original allocation remains registered even on false.
    // No assertions below can start an armed-owner Drop or a fresh allowance.
    assert_eq!(REFUSAL_ARMED_DROPS.with(|count| count.get()), armed_drops);
    refusal_owned(&mut retained, |owner| {
        assert!(Arc::ptr_eq(
            owner.failure.as_ref().unwrap(),
            &original_failure
        ))
    });
    if !confirmed {
        let refusal = refusals.last().expect("actual guard refusal");
        let timed_out = refusal.kind() == std::io::ErrorKind::TimedOut;
        let unexpected_eof = refusal.kind() == std::io::ErrorKind::UnexpectedEof;
        eprintln!(
            "REFUSAL_ORIGINAL_RESCUE_RESULT confirmed=false mode={mode} timed_out={timed_out} unexpected_eof={unexpected_eof} armed_drop_delta=0 error={refusal}; separate teardown follows only after this seal"
        );
        assert!(
            matches!(mode, "held" | "ipc"),
            "unexpected original guard rescue refusal"
        );
        assert!(
            Instant::now() >= rescue_deadline,
            "original bounded retry returned early"
        );
        if mode == "held" {
            assert!(timed_out && !unexpected_eof);
            assert!(ipc_seal.is_none());
        } else {
            let seal = ipc_seal
                .as_ref()
                .expect("complete actual EOF/final-return seal");
            assert_eq!(seal.last_kind, format!("{:?}", refusal.kind()));
            assert_eq!(seal.last_raw_errno, refusal.raw_os_error());
            assert_eq!(seal.last_display, refusal.to_string());
            eprintln!(
                "REFUSAL_IPC_FAILED_SEAL {seal:?}; first EOF remains separate from last returned error"
            );
        }
        refusal_owned(&mut retained, |owner| {
            assert!(Arc::ptr_eq(
                owner.failure.as_ref().unwrap(),
                &original_failure
            ));
            let guard = owner.tracer.liteinst_cleanup.as_ref().unwrap();
            assert!(guard.armed && owner.permit.is_some());
            let effect = REFUSAL_PROBE
                .with(|slot| slot.borrow().as_ref().unwrap().effect.as_ref().unwrap().tid);
            assert!(
                guard
                    .fatal_terminal_observations
                    .as_ref()
                    .unwrap()
                    .get(&effect)
                    .unwrap()
                    .observe_same_process()
                    .unwrap()
            );
            assert!(
                guard.retained_descendants.is_empty()
                    && guard.retained_terminal_descendants.is_empty()
            );
        });
        if mode == "ipc" {
            // Exercise the same infallible return operation used on unwind.
            // It does not remove the existing registration or run cleanup.
            let id = retained.id;
            let allocation = retained.allocation();
            drop(retained);
            retained = RefusalOwnerScope::resume(id);
            assert!(retained.registered());
            assert_eq!(retained.allocation(), allocation);
            assert_eq!(REFUSAL_ARMED_DROPS.with(|count| count.get()), armed_drops);
        }
        let (mut channel, message) = REFUSAL_PROBE.with(|slot| {
            let mut slot = slot.borrow_mut();
            let probe = slot.as_mut().unwrap();
            assert!(probe.ready_sent);
            assert_eq!(probe.ready_acknowledged, mode == "held");
            if mode == "ipc" {
                let failure = probe
                    .hook_failure
                    .as_ref()
                    .expect("actual first IPC failure retained");
                assert_eq!(failure.kind, std::io::ErrorKind::UnexpectedEof);
                assert!(failure.errno.is_none());
            } else {
                assert!(probe.hook_failure.is_none());
            }
            let message = if mode == "held" {
                RefusalWire::HeldTimeout {
                    effect: RefusalGeneration::of(probe.effect.as_ref().unwrap()),
                    timed_out,
                    retained: true,
                    timeout_display: refusal.to_string(),
                }
            } else {
                RefusalWire::IpcFailure {
                    effect: RefusalGeneration::of(probe.effect.as_ref().unwrap()),
                    retained: true,
                    armed_drop_delta: 0,
                    elapsed_ns: static_now_ns() - rescue_start,
                    outcome: Box::new(ipc_seal.take().expect("actual IPC outcome already sealed")),
                }
            };
            (
                RefusalChannel::take(probe).expect("separate failure-seal channel"),
                message,
            )
        });
        refusal_send(channel.stream(), &message, deadline_ns).expect("separate failure-seal IPC");
        if mode == "held" {
            assert!(
                refusal_read::<bool>(channel.stream(), deadline_ns)
                    .expect("separate held teardown acknowledgement")
            );
        }
        drop(channel);
        REFUSAL_PROBE.with(|slot| {
            // Disable only this failed diagnostic hook for separate teardown.
            // The original failure and retained hook failure remain unchanged.
            let mut slot = slot.borrow_mut();
            let probe = slot.as_mut().unwrap();
            probe.rescue = false;
            probe.teardown = true;
        });
        // Compute BEFORE borrowing; even expiration leaves the owner registered.
        let remaining_deadline = Instant::now() + static_remaining(deadline_ns);
        let mut teardown_refusals = 0usize;
        let rescued = refusal_owned(&mut retained, |owner| {
            owner
                .tracer
                .liteinst_cleanup
                .as_mut()
                .unwrap()
                .terminate_fatal_and_confirm(remaining_deadline, |error| {
                    teardown_refusals += 1;
                    use std::io::Write;
                    let _ = writeln!(
                        std::io::stderr().lock(),
                        "REFUSAL_POST_FAILED_VERDICT_TEARDOWN {error}"
                    );
                })
        });
        eprintln!(
            "REFUSAL_SEPARATE_TEARDOWN confirmed={rescued} refusals={teardown_refusals}; original rescue remains FAILED"
        );
        assert!(
            rescued,
            "separate teardown failed; original return slot retains owner and original rescue remains FAILED"
        );
    } else {
        assert!(
            !matches!(mode, "held" | "ipc"),
            "held/refused natural parent falsely confirmed without reaping"
        );
        eprintln!(
            "REFUSAL_ORIGINAL_RESCUE_RESULT confirmed=true; separate test rescue, not product cleanup"
        );
    }
    if mode == "once" {
        assert!(
            refusals
                .iter()
                .any(|error| error.raw_os_error() == Some(libc::EIO)),
            "actual retained refusal did not reach retry callback"
        );
        REFUSAL_PROBE.with(|slot| {
            assert!(
                slot.borrow()
                    .as_ref()
                    .unwrap()
                    .errors
                    .iter()
                    .any(|error| error.rescue
                        && error.phase == "discovery-one-shot-refusal"
                        && error.raw_errno == Some(libc::EIO))
            )
        });
        refusal_owned(&mut retained, |owner| {
            assert!(
                !owner
                    .tracer
                    .liteinst_cleanup
                    .as_ref()
                    .unwrap()
                    .fail_discovery_once
                    .as_ref()
                    .unwrap()
                    .load(Ordering::SeqCst)
            )
        });
    }
    REFUSAL_PROBE.with(|slot| {
        let slot = slot.borrow();
        let probe = slot.as_ref().unwrap();
        assert!(
            probe.ready_sent && !probe.overflow,
            "incomplete/overflowed original-owner observations"
        );
        assert!(probe.phase_stack.is_empty());
        assert_eq!(probe.handled_total,
            probe.handled.iter().map(|group| group.occurrences).sum::<u64>());
        let sampled_nonrescue = probe.returned.iter().filter(|record| !record.rescue).count();
        assert_eq!(probe.nonrescue_returns,
            sampled_nonrescue as u64 + probe.nonrescue_returns_omitted);
        for (index, group) in probe.handled.iter().enumerate() {
            eprintln!("REFUSAL_FINAL_HANDLED_COUNT index={index} first={:?} last_ns={} last_attempt={} occurrences={}",
                group.first, group.last_at_ns, group.last_attempt, group.occurrences);
        }
        eprintln!("REFUSAL_FINAL_NONRESCUE_RETURNS total={} samples={} omitted={}; includes explicitly marked separate teardown",
            probe.nonrescue_returns, sampled_nonrescue, probe.nonrescue_returns_omitted);
    });
    assert!(
        !REFUSAL_OBSERVER_PANICKED.with(|flag| flag.get()),
        "unexpected diagnostic panic cannot qualify this control"
    );
    assert_eq!(
        REFUSAL_ARMED_DROPS.with(|count| count.get()),
        armed_drops,
        "no fresh Drop cleanup budget allowed"
    );
    refusal_owned(&mut retained, |owner| {
        assert!(Arc::ptr_eq(
            owner.failure.as_ref().unwrap(),
            &original_failure
        ))
    });
    static_remaining(deadline_ns);
    retained.take_confirmed()
}

async fn refusal_wait_child(child: &mut std::process::Child, deadline: u64) {
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(
                status.success(),
                "isolated refusal fixture failed: {status}"
            );
            static_remaining(deadline);
            return;
        }
        if static_now_ns() >= deadline {
            let signal = child.kill();
            let reaped = child.try_wait();
            // No new allowance. An absent terminal observation remains explicit
            // for the existing owned outer containment, never successful reap.
            panic!(
                "original five-second refusal deadline expired; exact-child emergency signal={signal:?}, actual_reap_observation={reaped:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
async fn refusal_fixture(mode: &str, name: &str) {
    let role = std::env::var(STATIC_REAPER_ROLE).unwrap_or_default();
    if role.is_empty() {
        let deadline = static_now_ns() + 5_000_000_000;
        let mut reaper = static_contained_command(name, "refusal-reaper", deadline)
            .env("REVERIE_REFUSAL_MODE", mode)
            .spawn()
            .unwrap();
        refusal_wait_child(&mut reaper, deadline).await;
        return;
    }
    assert_eq!(std::env::var("REVERIE_REFUSAL_MODE").unwrap(), mode);
    assert!(std::env::args().any(|arg| arg == "--exact"));
    assert!(std::env::args().any(|arg| arg == name));
    static_verify_parent_after_exec();
    let deadline = std::env::var(STATIC_REAPER_DEADLINE)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    if role == "refusal-reaper" {
        static_abort_containment();
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut is_subreaper = 0;
        assert_eq!(
            unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut is_subreaper, 0, 0, 0) },
            0
        );
        assert_eq!(is_subreaper, 1);
        let (mut channel, child_channel) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = static_contained_command(name, "refusal-ptracer", deadline)
            .stdin(std::process::Stdio::from(OwnedFd::from(child_channel)))
            .spawn()
            .unwrap();
        let mut identities: Option<(TraceeIdentity, TraceeIdentity)> = None;
        let mut ready_seen = false;
        let mut natural_reaped = false;
        let mut finished = false;
        while let Some(message) = static_read::<RefusalWire>(&mut channel, deadline) {
            eprintln!("REFUSAL_NATURAL_PARENT_SEALED {message:?}");
            match message {
                RefusalWire::Live {
                    root,
                    effect,
                    injected_write,
                } => {
                    assert!(identities.is_none());
                    assert_eq!(injected_write, EFFECT.len());
                    assert!(root.tid > 0 && effect.tid > 0 && root.tid != effect.tid);
                    let p = static_identity(Pid::from_raw(root.tid));
                    let g = static_identity(Pid::from_raw(effect.tid));
                    assert_eq!(RefusalGeneration::of(&p), root);
                    assert_eq!(RefusalGeneration::of(&g), effect);
                    assert_eq!(g.snapshot.ppid, p.tid);
                    assert!(!static_pidfd_ready(&p) && !static_pidfd_ready(&g));
                    assert_ne!(g.snapshot.tracer_pid.as_raw(), 0);
                    let status = fs::read_to_string(format!("/proc/{}/status", g.tid)).unwrap();
                    assert!(
                        status.lines().any(|line| line.starts_with("State:\tt")),
                        "real live held signal stop required"
                    );
                    let state = status
                        .lines()
                        .find_map(|line| line.strip_prefix("State:\t"))
                        .unwrap();
                    assert!(
                        !refusal_physical_ready(
                            !p.observe_same_process().unwrap(),
                            static_pidfd_ready(&p),
                            static_pidfd_ready(&g),
                            g.snapshot.ppid.as_raw(),
                            std::process::id() as i32,
                            g.snapshot.tracer_pid.as_raw(),
                            state
                        ),
                        "same physical-ready predicate accepted a real live stop"
                    );
                    // The required physical predicate rejects this live generation
                    // without inventing any live notifier status or retirement.
                    identities = Some((p, g));
                }
                RefusalWire::Ready {
                    root,
                    effect,
                    product,
                    root_absent,
                    root_ready,
                    effect_ready,
                    ppid,
                    tracer,
                    state,
                    root_lease_empty,
                    events,
                    admission_closed,
                } => {
                    assert!(!ready_seen);
                    assert!(
                        product.original_after_effect
                            && product.secondary_eio_count > 1
                            && product.original_failure_allocation
                    );
                    assert!(
                        EFFECT.starts_with(&product.prefix_stdout)
                            && product.prefix_stderr.is_empty()
                    );
                    let (p, g) = identities.as_ref().unwrap();
                    assert_eq!(root.generation, RefusalGeneration::of(p));
                    assert_eq!(effect.generation, RefusalGeneration::of(g));
                    assert!(root.ready() && effect.ready() && root_lease_empty);
                    assert_eq!(effect.event_parent, Some(p.tid.as_raw()));
                    assert!(effect.event_fork);
                    assert!(root_absent && root_ready && effect_ready && admission_closed);
                    assert!(static_pidfd_ready(p) && !p.observe_same_process().unwrap());
                    assert!(!PathBuf::from(format!("/proc/{}", p.tid)).exists());
                    assert!(g.observe_same_process().unwrap() && static_pidfd_ready(g));
                    let actual = tracee_snapshot(g.tid).unwrap();
                    assert_eq!(actual.ppid.as_raw(), std::process::id() as i32);
                    assert_eq!(ppid, std::process::id() as i32);
                    assert_eq!(actual.tracer_pid.as_raw(), 0);
                    assert_eq!(tracer, 0);
                    assert!(refusal_physical_ready(
                        root_absent,
                        root_ready,
                        effect_ready,
                        ppid,
                        std::process::id() as i32,
                        tracer,
                        &state
                    ));
                    assert!(state.starts_with('Z'));
                    assert!(
                        fs::read_to_string(format!("/proc/{}/status", g.tid))
                            .unwrap()
                            .lines()
                            .any(|line| line.starts_with("State:\tZ"))
                    );
                    assert_eq!(events, ["effect", "failed"]);
                    ready_seen = true;
                    if mode == "ipc" {
                        // Actual EOF at T's unchanged bounded read; keep our
                        // read half for its failed-verdict/separate-reap request.
                        channel.shutdown(std::net::Shutdown::Write).unwrap();
                    } else if mode != "held" {
                        static_natural_wait(g);
                        natural_reaped = true;
                    }
                }
                RefusalWire::HeldTimeout {
                    effect,
                    timed_out,
                    retained,
                    timeout_display,
                } => {
                    assert_eq!(mode, "held");
                    assert!(ready_seen && !natural_reaped && timed_out && retained);
                    assert!(
                        timeout_display
                            .contains("fatal terminal-disappearance confirmation timed out")
                    );
                    let (_, g) = identities.as_ref().unwrap();
                    assert_eq!(effect, RefusalGeneration::of(g));
                    assert!(g.observe_same_process().unwrap() && static_pidfd_ready(g));
                    let actual = tracee_snapshot(g.tid).unwrap();
                    assert_eq!(actual.ppid.as_raw(), std::process::id() as i32);
                    assert_eq!(actual.tracer_pid.as_raw(), 0);
                    eprintln!(
                        "REFUSAL_HELD_FAILED_VERDICT_CONFIRMED; beginning separate natural teardown"
                    );
                    static_natural_wait(g);
                    natural_reaped = true;
                }
                RefusalWire::IpcFailure {
                    effect,
                    retained,
                    armed_drop_delta,
                    elapsed_ns,
                    outcome,
                } => {
                    assert_eq!(mode, "ipc");
                    assert!(ready_seen && !natural_reaped && retained);
                    assert_eq!(armed_drop_delta, 0);
                    assert!(elapsed_ns > 0);
                    let (p, g) = identities.as_ref().unwrap();
                    assert_eq!(effect, RefusalGeneration::of(g));
                    outcome.assert_exact(RefusalGeneration::of(p), effect);
                    assert!(g.observe_same_process().unwrap() && static_pidfd_ready(g));
                    let actual = tracee_snapshot(g.tid).unwrap();
                    assert_eq!(actual.ppid.as_raw(), std::process::id() as i32);
                    assert_eq!(actual.tracer_pid.as_raw(), 0);
                    assert!(
                        fs::read_to_string(format!("/proc/{}/status", g.tid))
                            .unwrap()
                            .lines()
                            .any(|line| line.starts_with("State:\tZ"))
                    );
                    eprintln!(
                        "REFUSAL_IPC_FAILED_VERDICT_CONFIRMED; original owner retained without Drop; separate natural teardown starts now"
                    );
                    static_natural_wait(g);
                    natural_reaped = true;
                }
                RefusalWire::Finished => {
                    assert!(ready_seen && natural_reaped && !finished);
                    finished = true;
                }
            }
            if !(mode == "ipc" && ready_seen) {
                static_send(&mut channel, &true, deadline);
            }
        }
        assert!(finished && ready_seen && natural_reaped);
        refusal_wait_child(&mut child, deadline).await;
        return;
    }
    assert_eq!(role, "refusal-ptracer");
    let mut subreaper = -1;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut subreaper, 0, 0, 0) },
        0
    );
    assert_eq!(subreaper, 0);
    assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) }, 1);
    let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
    assert!(fd >= 0);
    REFUSAL_PROBE.with(|slot| {
        *slot.borrow_mut() = Some(RefusalProbe {
            channel: std::rc::Rc::new(std::cell::Cell::new(Some(unsafe {
                std::os::unix::net::UnixStream::from_raw_fd(fd)
            }))),
            deadline,
            rescue_deadline: deadline,
            rescue_deadline_instant: None,
            root: None,
            effect: None,
            events: None,
            terminal: None,
            errors: Vec::new(),
            returned: Vec::new(),
            nonrescue_sites_omitted: 0,
            nonrescue_returns: 0,
            nonrescue_returns_omitted: 0,
            rescue_returns: 0,
            handled: Vec::new(),
            handled_at_attempt_start: [0; REFUSAL_HANDLED_GROUPS],
            handled_total: 0,
            ready_attempt: None,
            actual_reply_eofs: 0,
            attempt_hook_provenance: None,
            overflow: false,
            attempts: 0,
            rescue: false,
            teardown: false,
            ready_sent: false,
            ready_acknowledged: false,
            hook_failure: None,
            product: None,
            phase_stack: Vec::new(),
        });
    });
    refusal_body(mode, name, deadline).await;
    let mut channel = REFUSAL_PROBE.with(|slot| {
        let slot = slot.borrow();
        let probe = slot.as_ref().unwrap();
        assert!(!probe.overflow && probe.ready_sent);
        RefusalChannel::take(probe).expect("final diagnostic channel")
    });
    refusal_send(channel.stream(), &RefusalWire::Finished, deadline)
        .expect("final diagnostic write");
    if mode != "ipc" {
        assert!(refusal_read::<bool>(channel.stream(), deadline).expect("final diagnostic reply"));
    }
    drop(channel);
    REFUSAL_PROBE.with(|slot| *slot.borrow_mut() = None);
}
