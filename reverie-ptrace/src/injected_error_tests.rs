/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
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

async fn run(mode: Mode) {
    let fixture = Fixture::new(matches!(mode, Mode::ChildToolError));
    let mut command = Command::new(&fixture.path);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut tracer = TracerBuilder::<TrapTool>::new(command)
        .config(mode)
        .injected_syscall_trap(MARKER, fixture.trap_rip)
        .spawn()
        .await
        .unwrap();
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
    run(Mode::Success).await;
}

#[tokio::test(flavor = "current_thread")]
async fn injected_errno_preserves_result_and_continuation() {
    run(Mode::Errno).await;
}

#[tokio::test(flavor = "current_thread")]
async fn injected_tool_error_after_effect_is_terminal() {
    run(Mode::ToolError).await;
}

#[tokio::test(flavor = "current_thread")]
async fn injected_child_tool_error_does_not_resume_child_or_parent() {
    const NAME: &str =
        "tracer::injected_error_tests::injected_child_tool_error_does_not_resume_child_or_parent";
    if static_fixture_natural_reaper("plain", NAME).await {
        return;
    }
    static_diagnostic_init();
    run(Mode::ChildToolError).await;
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
