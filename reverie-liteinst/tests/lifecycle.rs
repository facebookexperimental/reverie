use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Backend;
use reverie::BackendStatsSnapshot;
use reverie::Error;
use reverie::ExitStatus;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_liteinst::LiteinstBackend;
use reverie_liteinst::LiteinstDispatchPath;
use reverie_liteinst::SITE_PATCHING_ENV;
use reverie_liteinst::TOOL_PRELOAD_ENV;

#[cfg(feature = "rpc-io-fixture")]
#[path = "lifecycle/rpc_io.rs"]
mod rpc_io;

// These controls use the fully installed lifecycle executable, never a
// pre-activation fabricated dispatch or a parallel registry.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SharedHandlerRequest {
    tag: u64,
    reenter: bool,
}

#[derive(Default)]
struct SharedHandlerGlobal {
    requests: std::sync::Mutex<Vec<(i32, u64)>>,
}

#[reverie::global_tool]
impl GlobalTool for SharedHandlerGlobal {
    type Request = SharedHandlerRequest;
    type Response = (i32, u64, u64);
    type Config = ();

    async fn receive_rpc(&self, from: Tid, request: SharedHandlerRequest) -> (i32, u64, u64) {
        let mut requests = self.requests.lock().unwrap();
        requests.push((from.as_raw(), request.tag));
        (from.as_raw(), requests.len() as u64, request.tag)
    }
}

#[derive(Default)]
struct SharedHandlerCoordinatorTool;

#[reverie::tool]
impl Tool for SharedHandlerCoordinatorTool {
    type GlobalState = SharedHandlerGlobal;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        panic!(
            "host dispatch is not installed guest dispatch: {:?}",
            syscall.number()
        );
    }
}

/// Counts actual accepted ordinary RPC connections from their SO_PEERPIDFD.
/// This observes connection ownership; it is not native InitialImage admission.
#[derive(Default)]
struct SharedHandlerAdmission {
    peers: std::sync::Mutex<Vec<i32>>,
}

impl reverie_rpc_transport::ConnectionAdmission for SharedHandlerAdmission {
    fn admit(
        &self,
        peer: std::os::fd::OwnedFd,
    ) -> std::io::Result<reverie_rpc_transport::Admitted> {
        use std::os::fd::AsRawFd;
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", peer.as_raw_fd()))?;
        let pid = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("Pid:"))
            .ok_or_else(|| std::io::Error::other("actual peer pidfd has no Pid"))?
            .trim()
            .parse::<i32>()
            .map_err(std::io::Error::other)?;
        if pid <= 0 {
            return Err(std::io::Error::other("actual peer pidfd is not live"));
        }
        self.peers.lock().unwrap().push(pid);
        Ok(reverie_rpc_transport::Admitted { process_id: pid })
    }
}

async fn run_shared_handler_control(
    mode: &str,
) -> (std::process::Output, SharedHandlerGlobal, Vec<i32>) {
    let (_preload_directory, preload) = compile_noop_preload();
    let admission = std::sync::Arc::new(SharedHandlerAdmission::default());
    let (result, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::with_connection_admission(
            admission.clone(),
            LiteinstBackend::run_with_output_and_preload::<SharedHandlerCoordinatorTool>(
                guest_command(mode),
                (),
                preload,
            ),
        ),
    )
    .await
    .expect("shared-handler installed control hung")
    .unwrap();
    let peers = admission.peers.lock().unwrap().clone();
    (result, global, peers)
}

fn assert_shared_handler_owner(result: &std::process::Output, global: &SharedHandlerGlobal) {
    assert_eq!(
        result.stdout,
        b"shared handler: callbacks=2 owner=stable LI=2 shared=2 wrong-global=4 reentry=2 outer=1\n",
        "{result:?}",
    );
    assert!(result.stderr.is_empty(), "{result:?}");
    let requests = global.requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        5,
        "wrong-global/reentrant requests must not send: {requests:?}"
    );
    let source = requests[0].0;
    assert!(source > 0);
    assert_eq!(
        *requests,
        [1001, 2001, 3001, 1002, 2002].map(|tag| (source, tag)),
        "both accessors must observe the actual same sender and request order",
    );
}

#[tokio::test(flavor = "current_thread")]
async fn installed_shared_and_liteinst_accessors_retain_the_real_tool_and_rpc_owner() {
    let (result, global, peers) = run_shared_handler_control("shared-handler-owner").await;
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_shared_handler_owner(&result, &global);
    let source = global.requests.lock().unwrap()[0].0;
    assert_eq!(
        peers,
        [source],
        "the actual owner uses one accepted RPC connection"
    );
}

#[cfg(feature = "fixed-syscall-gates")]
#[tokio::test(flavor = "current_thread")]
async fn whole_fixed_install_duplicate_is_terminal_after_actual_first_owner_observations() {
    let (result, global, peers) = run_shared_handler_control("shared-handler-duplicate").await;
    assert_eq!(result.status.code(), Some(127), "{result:?}");
    assert_shared_handler_owner(&result, &global);
    let source = global.requests.lock().unwrap()[0].0;
    assert_eq!(peers.first(), Some(&source));
    // A later duplicate attempt may connect before its terminal refusal.
    // Do not claim it reached registry rejection or constructed nothing.
}

const RPC_GETPID: u64 = 1;
const RPC_CLOCK_GETTIME: u64 = 2;
const RPC_GETTIMEOFDAY: u64 = 3;
const RPC_FORK: u64 = 4;
const RPC_CLOSE_RANGE: u64 = 5;
const RPC_BLOCKING: u64 = 6;
const RPC_PARK: u64 = 7;
const RPC_FAIL: u64 = 8;
/// Tags a process's exit-time count of its Tool callbacks.
const RPC_CALLBACK_COUNT: u64 = 1 << 32;
/// The lifecycle observations the fixture Tool sends (`lifecycle_event` in
/// `src/bin/lifecycle_guest.rs`: tag in the top byte, id in bits 16 to 47,
/// value in the low 16 bits), and the physical exits an admission observes,
/// each numbered from [`OBSERVATION_SEQUENCE`] when it is recorded, so the
/// two sources merge into one ordered stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Observed {
    /// `handle_signal_event` was shown this signal.
    Signal(u16),
    /// `on_exit_thread` reported a signal death with this raw wait status.
    ExitThread(u16),
    /// `on_exit_process` reported a signal death with this raw wait status.
    ExitProcess(u16),
    /// The tgkill handler went on after its injection, which returned this.
    TgkillReturned(u16),
    /// `handle_post_exec` ran.
    PostExec,
    /// Tool code ran after the Tool's own SIGKILL injection (never expected).
    AfterSigkill,
    /// The process's pidfd polled readable: it is physically gone.
    PhysicallyExited,
}

/// Numbers every lifecycle observation in the order it is recorded.
static OBSERVATION_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const BACKEND_OUTPUT_CHILD_ENV: &str = "REVERIE_LITEINST_BACKEND_OUTPUT_TEST_CHILD";

#[derive(Debug, Default)]
struct LifecycleGlobal {
    getpid: AtomicU64,
    clock_gettime: AtomicU64,
    gettimeofday: AtomicU64,
    fork: AtomicU64,
    /// Guest `close_range` calls the in-guest Tool saw.
    close_range: AtomicU64,
    /// Requests sent with `blocking_global_rpc`.
    blocking: AtomicU64,
    /// Every in-guest Tool syscall callback, counted in guest memory
    /// independently of the backend's statistics and reported once per
    /// process at exit.
    callbacks: AtomicU64,
    /// Pids reported through `on_backend_process_exited`.
    exited: std::sync::Mutex<Vec<i32>>,
    /// Lifecycle observations: sequence number, the process or thread id
    /// they name, and what was observed.
    observed: std::sync::Mutex<Vec<(u64, i32, Observed)>>,
    /// Calls of `report_backend_failure`.
    backend_failures: AtomicU64,
    /// Processes parked by `RPC_PARK`.
    parked: AtomicU64,
    /// Backend failures this fixture's own tool published, refusing an
    /// `RPC_FAIL` request: these, and only these, complete
    /// `wait_for_backend_failure`. A failure an admission forwards through
    /// the exit reporter is only counted, so a test can check the forwarding
    /// without ending its run.
    published_failures: AtomicU64,
}

/// What `LifecycleGlobal::backend_pending_process_exits` returns, so a test can
/// tell the global's answer from the reporter's empty one after the run.
const PENDING_EXIT_SENTINEL: i32 = 4242;

#[reverie::global_tool]
impl GlobalTool for LifecycleGlobal {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, from: Tid, event: u64) {
        if event == RPC_PARK {
            self.parked.fetch_add(1, Ordering::Relaxed);
            std::future::pending::<()>().await;
        }
        if event == RPC_FAIL {
            while self.parked.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            self.report_backend_failure(reverie::BackendFailure {
                pid: reverie::Pid::from_raw(from.as_raw()),
                tid: from,
                phase: "lifecycle fixture refusal",
            });
            self.published_failures.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if event >> 56 != 0 {
            let id = (event >> 16) as u32 as i32;
            let value = event as u16;
            let observed = match event >> 56 {
                1 => Observed::Signal(value),
                2 => Observed::ExitThread(value),
                3 => Observed::ExitProcess(value),
                4 => Observed::TgkillReturned(value),
                5 => Observed::PostExec,
                6 => Observed::AfterSigkill,
                tag => panic!("unknown lifecycle observation tag {tag}"),
            };
            let sequence = OBSERVATION_SEQUENCE.fetch_add(1, Ordering::SeqCst);
            self.observed.lock().unwrap().push((sequence, id, observed));
            return;
        }
        if event & RPC_CALLBACK_COUNT != 0 {
            self.callbacks
                .fetch_add(event & !RPC_CALLBACK_COUNT, Ordering::Relaxed);
            return;
        }
        let counter = match event {
            RPC_GETPID => &self.getpid,
            RPC_CLOCK_GETTIME => &self.clock_gettime,
            RPC_GETTIMEOFDAY => &self.gettimeofday,
            RPC_FORK => &self.fork,
            RPC_CLOSE_RANGE => &self.close_range,
            RPC_BLOCKING => &self.blocking,
            _ => panic!("unknown lifecycle fixture RPC {event}"),
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn on_backend_process_exited(&self, pid: i32) {
        self.exited.lock().unwrap().push(pid);
    }

    fn backend_pending_process_exits(&self) -> Vec<i32> {
        vec![PENDING_EXIT_SENTINEL]
    }

    fn report_backend_failure(&self, _event: reverie::BackendFailure) {
        self.backend_failures.fetch_add(1, Ordering::Relaxed);
    }

    async fn wait_for_backend_failure(&self) {
        while self.published_failures.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[derive(Default)]
struct CoordinatorOnlyTool;

#[reverie::tool]
impl Tool for CoordinatorOnlyTool {
    type GlobalState = LifecycleGlobal;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid, Sysno::clock_gettime, Sysno::gettimeofday]
            .into_iter()
            .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        panic!(
            "coordinator-only Tool reached host syscall dispatch for {:?}",
            syscall.number()
        );
    }
}

fn compile_noop_preload() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lifecycle_preload.c");
    let output = directory.path().join("lifecycle-preload.so");
    let result = std::process::Command::new("cc")
        .args(["-shared", "-fPIC", "-Wl,--build-id=none"])
        .arg(source)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile lifecycle preload:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    (directory, output)
}

fn guest_command(mode: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-lifecycle-guest"));
    command.arg(mode);
    command
}

/// Only the precise CPU capability absence is unmeasured. Syscall errors,
/// missing rows and failed allocation/access assertions never take this branch.
fn pkey_hardware_unmeasured(output: &std::process::Output) -> bool {
    if output.status.code() != Some(77) {
        return false;
    }
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{output:?}");
    assert!(
        lines[0].starts_with("pkey hardware: leaf7_ecx=0x") && lines[0].ends_with(" ospke=false"),
        "{output:?}"
    );
    assert_eq!(lines[1], "pkey hardware unmeasured: OSPKE unavailable");
    eprintln!("OSPKE unavailable; pkey hardware cases were not measured");
    true
}

fn assert_pkey_permission_rows(stdout: &str) {
    assert!(
        stdout.contains("ospke=true\n"),
        "OSPKE hardware was not measured: {stdout}"
    );
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("allocation rights="))
            .count(),
        4,
        "{stdout}"
    );
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("free rights="))
            .count(),
        4,
        "{stdout}"
    );
    for rights in 0..4 {
        assert!(
            stdout.lines().any(
                |line| line.starts_with(&format!("allocation rights={rights} "))
                    && line.ends_with("other_bits_equal=true ok=true")
            ),
            "{stdout}"
        );
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with(&format!("free rights={rights} "))
                    && line.ends_with("ok=true")),
            "{stdout}"
        );
    }
    for label in ["flags", "rights", "free"] {
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with(&format!("invalid {label}: "))
                    && line.ends_with("ok=true")),
            "{stdout}"
        );
    }
    assert!(
        stdout.contains("first_access status=0x0 signal=0 exit=0\n"),
        "first keyed access must succeed without compensating WRPKRU: {stdout}"
    );
    assert!(
        stdout.ends_with("allocations=4 invalid=3 first_access=1 failures=0\n"),
        "{stdout}"
    );
}

#[test]
fn pkey_permission_effects_native_control() {
    use std::process::Stdio;
    use std::time::Instant;

    let mut child =
        std::process::Command::new(env!("CARGO_BIN_EXE_reverie-liteinst-lifecycle-guest"))
            .arg("pkey-native")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("native pkey control timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "native pkey stdout:\n{stdout}stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    if pkey_hardware_unmeasured(&output) {
        return;
    }
    assert!(
        output.status.success(),
        "native pkey control failed: {output:?}"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_pkey_permission_rows(&stdout);
}

async fn pkey_permission_effects_in_guest(mode: &str, patching: bool) {
    let (_preload_directory, preload) = compile_noop_preload();
    let mut command = guest_command(mode);
    command.env(SITE_PATCHING_ENV, if patching { "1" } else { "0" });
    command.env(reverie_liteinst::SIGALRM_HANDLERS_ENV, "0");
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            command,
            (),
            preload,
        ),
    )
    .await
    .expect("pkey permission-effect admission hung")
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "pkey mode={mode} patching={patching} status={:?}\nstdout:\n{stdout}stderr:\n{}\nstats:\n{stats}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    if pkey_hardware_unmeasured(&output) {
        return;
    }
    // An explicit refusal elsewhere never satisfies this native-semantic
    // permission and first-access oracle.
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_pkey_permission_rows(&stdout);
    assert_eq!(
        global.getpid.load(Ordering::Relaxed),
        8,
        "the guest Tool must receive the warmup calls"
    );
    let snapshot = stats.snapshot();
    let record = snapshot
        .dispatch_stats()
        .expect("pkey admission must report actual paths");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    let paths = stats.dispatch_path_counts();
    if patching {
        assert!(
            stdout.contains("pkey marked_site traps=1 hooks=14\n"),
            "scalar allocations must run after installation of their actual site: {stdout}"
        );
        assert!(
            paths.count(&LiteinstDispatchPath::DirectHook) >= 14,
            "{stats}"
        );
    } else {
        assert!(
            stdout.contains("pkey marked_site traps=0 hooks=0\n"),
            "{stdout}"
        );
        assert_eq!(snapshot.patch_shapes().patched_rips(), 0, "{stats}");
        assert_eq!(paths.count(&LiteinstDispatchPath::DirectHook), 0, "{stats}");
        assert_eq!(
            paths.count(&LiteinstDispatchPath::PtraceInstallation),
            0,
            "{stats}"
        );
        assert!(
            paths.count(&LiteinstDispatchPath::PatchingDisabledFallback) >= 14,
            "{stats}"
        );
    }
    assert_physical_signals_agree(&stats, &record);
    assert_tool_callbacks_were_delivered(&global, &stats);
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_permission_effects_forward_fallback() {
    pkey_permission_effects_in_guest("pkey-forward", false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_permission_effects_inject_fallback() {
    pkey_permission_effects_in_guest("pkey-inject", false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_permission_effects_tail_fallback() {
    pkey_permission_effects_in_guest("pkey-tail", false).await;
}

// Installed syscall hooks do not own saved guest PKRU. These tests measure
// their explicit pre-effect refusal boundary, not native allocation equivalence.
// The native/fallback tests separately require full permission and access effects.
async fn pkey_alloc_boundary_in_guest(mode: &str, patching: bool) {
    let (_preload_directory, preload) = compile_noop_preload();
    let mut command = guest_command(mode);
    command.env(SITE_PATCHING_ENV, if patching { "1" } else { "0" });
    command.env(reverie_liteinst::SIGALRM_HANDLERS_ENV, "0");
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            command,
            (),
            preload,
        ),
    )
    .await
    .expect("pkey boundary admission hung")
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!(
        "pkey boundary mode={mode} patching={patching} status={:?}\nstdout:\n{stdout}stderr:\n{}\nstats:\n{stats}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    if pkey_hardware_unmeasured(&output) {
        return;
    }
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(stdout.contains("ospke=true\n"), "{stdout}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
    let snapshot = stats.snapshot();
    let record = snapshot
        .dispatch_stats()
        .expect("pkey boundary must report actual paths");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    let paths = stats.dispatch_path_counts();
    assert_eq!(
        paths.count(&LiteinstDispatchPath::PtraceInstallation),
        0,
        "{stats}"
    );
    if patching {
        assert!(
            stdout.contains("refusal marked_site traps=1 hooks=5\n"),
            "{stdout}"
        );
        assert!(
            stdout.contains("owned control_site traps=2 hooks=0\n"),
            "{stdout}"
        );
        for rights in 0..4 {
            assert!(
                stdout.lines().any(|line| line
                    .starts_with(&format!("installed refusal rights={rights} result=-95 "))),
                "{stdout}"
            );
        }
        assert!(
            paths.count(&LiteinstDispatchPath::DirectHook) >= 5,
            "{stats}"
        );
        assert_eq!(
            paths.count(&LiteinstDispatchPath::PatchingDisabledFallback),
            0,
            "{stats}"
        );
        assert!(
            paths.count(&LiteinstDispatchPath::UnpatchableOrOtherFallback) >= 2,
            "{stats}"
        );
        assert!(
            stdout
                .lines()
                .any(|line| line.starts_with("no key consumed: expected=")
                    && line.contains(" observed=")),
            "{stdout}"
        );
        assert!(
            stdout.ends_with("refusal measured; native installed parity remains unsupported\n"),
            "{stdout}"
        );
    } else {
        assert_eq!(snapshot.patch_shapes().patched_rips(), 0, "{stats}");
        assert_eq!(paths.count(&LiteinstDispatchPath::DirectHook), 0, "{stats}");
        if mode == "pkey-composition" {
            assert!(
                stdout
                    .lines()
                    .any(|line| line.starts_with("composition scalar=424242 ")
                        && line.ends_with("other_bits_equal=true")),
                "{stdout}"
            );
            assert!(stdout.ends_with("two rewritten allocations, two errors, final scalar override; rights preserved\n"), "{stdout}");
        } else {
            assert!(
                stdout
                    .lines()
                    .any(|line| line.starts_with("instruction inject: result=-95 ")),
                "{stdout}"
            );
            assert!(
                stdout.contains("owned control_site traps=0 hooks=0\n"),
                "{stdout}"
            );
            assert!(
                stdout
                    .lines()
                    .any(|line| line.starts_with("no key consumed: expected=")),
                "{stdout}"
            );
            assert!(
                stdout.ends_with("refusal measured; native installed parity remains unsupported\n"),
                "{stdout}"
            );
        }
    }
    assert_physical_signals_agree(&stats, &record);
    assert_tool_callbacks_were_delivered(&global, &stats);
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_alloc_installed_pre_effect_refusal_forward() {
    pkey_alloc_boundary_in_guest("pkey-refusal-forward", true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_alloc_installed_pre_effect_refusal_inject() {
    pkey_alloc_boundary_in_guest("pkey-refusal-inject", true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_alloc_installed_pre_effect_refusal_tail() {
    pkey_alloc_boundary_in_guest("pkey-refusal-tail", true).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_alloc_owned_event_composes_rewrites_errors_and_scalar_override() {
    pkey_alloc_boundary_in_guest("pkey-composition", false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_alloc_instruction_without_owned_pkru_refuses_before_effect() {
    pkey_alloc_boundary_in_guest("pkey-instruction-refusal", false).await;
}

/// A guest for a `*_preload_data` launcher: it fails unless its coordinator
/// came through the bootstrap descriptor rather than the environment.
fn bootstrap_guest_command(mode: &str) -> Command {
    let mut command = guest_command(mode);
    command.env("REVERIE_LITEINST_LIFECYCLE_EXPECT_BOOTSTRAP", "1");
    command
}

fn assert_reaped(pid: u32) {
    // Once the root exits this descendant is reparented to the host's subreaper.
    // Closing its inherited coordinator connection proves it has exited, but
    // procfs may expose the zombie briefly before that independent reaper gets
    // scheduled (notably on the GitHub-hosted runner). Bound the observation
    // instead of racing a single procfs lookup against reaping.
    let proc_entry = PathBuf::from(format!("/proc/{pid}"));
    for _ in 0..100 {
        if !proc_entry.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !proc_entry.exists(),
        "LiteInst descendant {pid} remains in procfs"
    );
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn supervisor_preserves_root_status_and_drains_outliving_child() {
    let (_preload_directory, preload) = compile_noop_preload();
    let marker_directory = tempfile::tempdir().unwrap();
    let marker = marker_directory.path().join("descendant.marker");
    let mut command = guest_command("root-exits-first");
    command.arg(&marker);

    let (status, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_preload::<CoordinatorOnlyTool>(command, (), preload),
    )
    .await
    .expect("lifecycle supervisor hung while draining an outliving child")
    .unwrap();

    assert_eq!(status, ExitStatus::Exited(23));
    assert_eq!(std::fs::read(&marker).unwrap(), b"descendant-finished\n");
    assert_eq!(global.fork.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn supervisor_observes_and_reaps_signaled_descendant() {
    let (_preload_directory, preload) = compile_noop_preload();
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("descendant.pid");
    let mut command = guest_command("signaled-descendant");
    command.arg(&pid_file);

    let (status, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_preload::<CoordinatorOnlyTool>(command, (), preload),
    )
    .await
    .expect("lifecycle supervisor hung after descendant signal death")
    .unwrap();

    assert_eq!(status, ExitStatus::Exited(29));
    let pid = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    assert_reaped(pid);
    assert_eq!(global.fork.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn supervisor_keeps_patchable_syscalls_in_guest() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("fast-path"),
            (),
            preload,
        ),
    )
    .await
    .expect("lifecycle supervisor hung on the in-guest fast path")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"calls=8 traps=1 hooks=8\n", "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
}

#[tokio::test(flavor = "current_thread")]
async fn in_guest_run_reports_typed_instrumentation_stats() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            guest_command("fast-path"),
            (),
            preload,
        ),
    )
    .await
    .expect("stats-enabled in-guest run hung")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"calls=8 traps=1 hooks=8\n", "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
    assert_fast_path_stats(&global, &stats);
}

/// A guest command that does not inherit `ADDR_NO_RANDOMIZE` from the test
/// runner (for example one started under `setarch -R`), so only the backend
/// can set it. Caller `pre_exec` hooks run before the backend's.
fn randomized_guest_command(mut command: Command) -> Command {
    // SAFETY: the hook makes only async-signal-safe `personality` calls.
    unsafe {
        command.pre_exec(|| {
            let current = libc::personality(0xffff_ffff);
            if current == -1 {
                return Err(reverie::syscalls::Errno::new(libc::EINVAL));
            }
            let randomized = current as libc::c_ulong & !(libc::ADDR_NO_RANDOMIZE as libc::c_ulong);
            if libc::personality(randomized) == -1 {
                return Err(reverie::syscalls::Errno::new(libc::EINVAL));
            }
            Ok(())
        });
    }
    command
}

/// Both launchers start the guest with address-space randomization disabled,
/// as Reverie's ptrace and DBT launchers do, so its stack, heap and mapping
/// addresses are the same in every run.
#[tokio::test(flavor = "current_thread")]
async fn in_guest_runs_disable_address_space_randomization() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            randomized_guest_command(guest_command("address-randomization")),
            (),
            preload.clone(),
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        output.stdout, b"address randomization=disabled\n",
        "{output:?}"
    );

    let (output, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_data::<CoordinatorOnlyTool>(
            randomized_guest_command(bootstrap_guest_command("address-randomization")),
            (),
            preload,
            b"lifecycle".to_vec(),
        ),
    )
    .await
    .expect("bootstrap run hung")
    .unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(
        output.stdout, b"address randomization=disabled\n",
        "{output:?}"
    );
}

/// A socket the in-guest Tool reserves for its own output is kept from the guest
/// exactly as the coordinator connection is: the guest cannot close, write,
/// shut down, configure, query, truncate, map or reopen it; a guest dup2 or
/// dup3 onto its number succeeds and moves the socket instead; and the Tool's
/// own write reaches it (the fixture checks its peer end receives exactly the
/// Tool's message). With the descriptor table full, a dup onto it still
/// succeeds and the runtime retires the socket; its retirement message reaches
/// the reader even through a full queue and with a forked child holding the
/// socket. Other calls that name it in a register argument (epoll, sendfile's
/// input, timerfd, inotify, ...) fail with EBADF as for a closed number. A
/// regular file is refused.
#[tokio::test(flavor = "current_thread")]
async fn a_reserved_tool_output_fd_is_protected_from_the_guest() {
    let (_preload_directory, preload) = compile_noop_preload();
    let directory = tempfile::tempdir().unwrap();
    let mut command = guest_command("tool-output-fd");
    command.arg(directory.path().join("regular-file"));
    let (result, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(command, (), preload),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(result.stdout, b"tool output fd: protected\n", "{result:?}");
}

/// A guest `close_range` whose range covers the runtime's own descriptors
/// reaches a Tool that subscribes to it, so the Tool can account for the guest
/// descriptors it closes; the runtime still spares its own descriptors at
/// physical execution, so the guest-visible result is unchanged and the
/// coordinator connection survives.
#[tokio::test(flavor = "current_thread")]
async fn a_close_range_over_runtime_descriptors_reaches_the_tool() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (result, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("close-range-through-tool"),
            (),
            preload,
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        result.stdout, b"close range through tool: ok\n",
        "{result:?}"
    );
    assert_eq!(global.close_range.load(Ordering::Relaxed), 1);
    assert!(global.getpid.load(Ordering::Relaxed) >= 1);
}

/// With a creation hook registered, the runtime performs every creation
/// form (fork, the copying vfork, legacy clone, clone3) as clone3 with its
/// own CLONE_PIDFD output, reports each once with the child's pid and pidfs
/// inode, and leaves no pidfd in the guest's table.
#[tokio::test(flavor = "current_thread")]
async fn a_creation_hook_receives_each_childs_birth_identity() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (result, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("creation-identity"),
            (),
            preload,
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    if !creation_hook_supported(&result) {
        return;
    }
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(result.stdout, b"creation identity: ok\n", "{result:?}");
}

/// A creation hook that fails after a real creation (a child with an
/// identity) ends the creating process with status 125 before the creation
/// returns to the guest.
#[tokio::test(flavor = "current_thread")]
async fn a_failing_creation_hook_ends_the_creating_process() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (result, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("creation-hook-fails"),
            (),
            preload,
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    if !creation_hook_supported(&result) {
        return;
    }
    assert_eq!(result.status.code(), Some(125), "{result:?}");
    // The hook saw a real creation (a child with an identity) before its
    // error ended the process; the guest's own line after the fork never
    // printed.
    assert_eq!(result.stdout, b"created, hook failing\n", "{result:?}");
}

/// A clone3 whose record tail Linux can read but the runtime cannot (a
/// write-only page) is refused: no child exists, the hook hears why, and the
/// creating process ends with status 125 before the call returns.
#[tokio::test(flavor = "current_thread")]
async fn a_creation_the_runtime_cannot_perform_faithfully_is_refused() {
    let (result, stdout) = run_lifecycle_mode("creation-write-only-args").await;
    if !creation_hook_supported(&result) {
        return;
    }
    assert_eq!(result.status.code(), Some(125), "{result:?}");
    assert_eq!(
        stdout, "refused: arguments unreadable, no child\n",
        "{result:?}"
    );
}

/// Once a creation hook is registered, a guest seccomp filter is refused
/// with EOPNOTSUPP while creations keep working. (That no other filter is
/// attached when the hook is registered is the registering side's
/// prerequisite, established from outside the process.)
#[tokio::test(flavor = "current_thread")]
async fn a_creation_hook_excludes_guest_seccomp_filters() {
    let (result, stdout) = run_lifecycle_mode("guest-filter-after-hook").await;
    if !creation_hook_supported(&result) {
        return;
    }
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        stdout,
        format!(
            "filter=-1 errno=Some({}) created=true waited=0\n",
            libc::EOPNOTSUPP
        ),
        "{result:?}"
    );
}

/// Whether this kernel gives each process a pidfs inode (Linux 6.9 and
/// later), decided from the release, independently of the runtime. Without
/// it, registering a creation hook is correctly refused.
fn kernel_has_pidfs() -> bool {
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut name) }, 0);
    let release = unsafe { std::ffi::CStr::from_ptr(name.release.as_ptr()) }.to_string_lossy();
    let mut numbers = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|part| part.parse::<u32>().unwrap_or(0));
    (numbers.next().unwrap_or(0), numbers.next().unwrap_or(0)) >= (6, 9)
}

/// On a kernel without pidfs, a creation-hook mode must report the refusal
/// and end normally; returns true when the caller's positive checks apply.
fn creation_hook_supported(result: &std::process::Output) -> bool {
    if kernel_has_pidfs() {
        return true;
    }
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        result.stdout, b"creation hook refused: pidfs unavailable\n",
        "{result:?}"
    );
    false
}

async fn run_lifecycle_mode(mode: &str) -> (std::process::Output, String) {
    let (_preload_directory, preload) = compile_noop_preload();
    let (result, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command(mode),
            (),
            preload,
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    (result, stdout)
}

/// A backend failure the coordinator's tool reports, while another guest
/// process is parked in a request the tool never answers, ends the run at once
/// with an error. Before, the launch waited for the root guest, which was the
/// parked process, forever.
#[tokio::test(flavor = "current_thread")]
async fn a_backend_failure_ends_the_run_while_a_process_is_parked() {
    let (_preload_directory, preload) = compile_noop_preload();
    let error = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("backend-failure"),
            (),
            preload,
        ),
    )
    .await
    .expect("a backend failure left the run hanging")
    .unwrap_err();
    assert!(error.to_string().contains("backend failure"), "{error}");
}

/// Admits every guest connection and records each admitted process's
/// physical exit, observed on its pidfd by a thread the test joins after the
/// run, so no observation can arrive after the test reads them.
#[derive(Default)]
struct ExitObservingAdmission {
    physical: std::sync::Arc<std::sync::Mutex<Vec<(u64, i32, Observed)>>>,
    observers: std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl ExitObservingAdmission {
    /// Waits for every observer and returns what they recorded.
    fn finish(&self) -> Vec<(u64, i32, Observed)> {
        for observer in self.observers.lock().unwrap().drain(..) {
            observer.join().unwrap();
        }
        self.physical.lock().unwrap().clone()
    }
}

impl reverie_rpc_transport::ConnectionAdmission for ExitObservingAdmission {
    fn admit(
        &self,
        peer: std::os::fd::OwnedFd,
    ) -> std::io::Result<reverie_rpc_transport::Admitted> {
        use std::os::fd::AsRawFd;
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", peer.as_raw_fd()))?;
        let pid: i32 = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("Pid:"))
            .and_then(|pid| pid.trim().parse().ok())
            .ok_or_else(|| std::io::Error::other("pidfd names no pid"))?;
        let physical = self.physical.clone();
        self.observers
            .lock()
            .unwrap()
            .push(std::thread::spawn(move || {
                let mut poll = libc::pollfd {
                    fd: peer.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // A pidfd polls readable once its process has exited.
                while unsafe { libc::poll(&mut poll, 1, -1) } != 1 {}
                let sequence = OBSERVATION_SEQUENCE.fetch_add(1, Ordering::SeqCst);
                physical
                    .lock()
                    .unwrap()
                    .push((sequence, pid, Observed::PhysicallyExited));
            }));
        Ok(reverie_rpc_transport::Admitted { process_id: pid })
    }
}

/// A process that sends itself a signal that would end it dies at a point of
/// its own program order, so the in-guest host reports it as it reports an
/// exit, before it happens: one ordered stream per process shows, for an
/// abort (a `tgkill` the Tool subscribes to), that the Tool's tgkill handler
/// runs to its end after its injection, then the signal callback, then
/// `on_exit_thread` and `on_exit_process` with the complete status the
/// parent's wait returns (including the core-dump bit, with and without a
/// core limit), then the physical exit. A `kill` of its own pid, which the
/// Tool does not subscribe to, is reported the same way; a SIGKILL is never
/// shown to the signal callback. Where the signal callback ignores, blocks or
/// suppresses the signal, the process goes on and exits with its own code,
/// with no exit callback: the host decides the death after the callback.
///
/// A `raise(SIGTRAP)` is judged by the guest's own SIGTRAP action
/// (SIG_DFL, so a death), not by LiteInst's guard router, which the kernel
/// has as its action and which hands such a SIGTRAP back to the guest's
/// action; a guest that ignores SIGTRAP is not killed.
///
/// Before, such a process died without any callback, and the in-guest Tool
/// (Detcore) never learned of the exit. A `raise(SIGTRAP)` still did, after
/// the rest was fixed: the router made SIGTRAP look caught.
#[tokio::test(flavor = "current_thread")]
async fn a_process_that_ends_itself_with_a_signal_reports_it_and_its_exit_first() {
    let (_preload_directory, preload) = compile_noop_preload();
    let admission = std::sync::Arc::new(ExitObservingAdmission::default());
    let (result, global) = tokio::time::timeout(
        Duration::from_secs(30),
        LiteinstBackend::with_connection_admission(
            admission.clone(),
            LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
                guest_command("self-signal-deaths"),
                (),
                preload,
            ),
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    let children: Vec<(String, i32, u16)> = stdout
        .lines()
        .map(|line| {
            let mut words = line.split(' ');
            let label = words.next().unwrap().to_owned();
            let pid = words.next().unwrap().strip_prefix("pid=").unwrap();
            let status = words.next().unwrap().strip_prefix("status=0x").unwrap();
            (
                label,
                pid.parse().unwrap(),
                u16::from_str_radix(status, 16).unwrap(),
            )
        })
        .collect();
    let labels: Vec<&str> = children.iter().map(|(label, ..)| label.as_str()).collect();
    assert_eq!(
        labels,
        [
            "abort",
            "abort-core-limit-1",
            "kill-sigterm",
            "kill-sigkill",
            "raise-sigusr1",
            "raise-sigusr2",
            "raise-sighup",
            "raise-sigvtalrm",
            "raise-sigprof",
            "cpuid-sigterm",
            "thread-start-sigterm",
            "abort-pending-unreadable",
            "raise-sigstkflt",
            "raise-sigpwr",
            "raise-sigxfsz",
            "raise-sigint",
            "raise-sigquit",
            "raise-sigio",
            "raise-sigxcpu",
            "raise-sigfpe",
            "raise-sigbus",
            "raise-sigtrap",
            "raise-sigtrap-ignored",
        ],
        "{stdout}"
    );
    // Every guest process has exited by now (the run ends when they have),
    // so every observer finishes.
    let mut observed = global.observed.lock().unwrap().clone();
    observed.extend(admission.finish());
    observed.sort_by_key(|(sequence, ..)| *sequence);
    eprintln!("guest stdout:\n{stdout}observed: {observed:?}");
    use Observed::*;
    let term = libc::SIGTERM as u16;
    let kill = libc::SIGKILL as u16;
    for (label, pid, status) in &children {
        let of_child: Vec<Observed> = observed
            .iter()
            .filter(|(_, id, _)| id == pid)
            .map(|(.., what)| *what)
            .collect();
        let status = *status;
        let expected = match label.as_str() {
            "abort" | "abort-core-limit-1" => {
                assert_eq!(status & 0x7f, libc::SIGABRT as u16, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGABRT as u16),
                    ExitThread(status),
                    ExitProcess(status),
                    PhysicallyExited,
                ]
            }
            // The guest's SIGTRAP action is SIG_DFL, though the kernel's is
            // LiteInst's guard router: a death, reported first like abort's.
            "raise-sigtrap" => {
                assert_eq!(status & 0x7f, libc::SIGTRAP as u16, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGTRAP as u16),
                    ExitThread(status),
                    ExitProcess(status),
                    PhysicallyExited,
                ]
            }
            // The guest ignores SIGTRAP: not a death, nothing to report.
            "raise-sigtrap-ignored" => {
                assert_eq!(status, 45 << 8, "{label}");
                vec![TgkillReturned(0), PhysicallyExited]
            }
            "kill-sigterm" => {
                assert_eq!(status, libc::SIGTERM as u16, "{label}");
                vec![
                    Signal(libc::SIGTERM as u16),
                    ExitThread(status),
                    ExitProcess(status),
                    PhysicallyExited,
                ]
            }
            "kill-sigkill" => {
                assert_eq!(status, libc::SIGKILL as u16, "{label}");
                vec![ExitThread(status), ExitProcess(status), PhysicallyExited]
            }
            "raise-sigusr1" => {
                assert_eq!(status, 41 << 8, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGUSR1 as u16),
                    PhysicallyExited,
                ]
            }
            "raise-sigusr2" => {
                assert_eq!(status, 42 << 8, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGUSR2 as u16),
                    PhysicallyExited,
                ]
            }
            "raise-sighup" => {
                assert_eq!(status, 43 << 8, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGHUP as u16),
                    PhysicallyExited,
                ]
            }
            // The signal callback sent SIGKILL, then suppressed SIGVTALRM.
            "raise-sigvtalrm" => {
                assert_eq!(status, kill, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGVTALRM as u16),
                    ExitThread(kill),
                    ExitProcess(kill),
                    PhysicallyExited,
                ]
            }
            // The handler forwarded SIGPROF, then sent SIGKILL: SIGKILL
            // ends the process there, so the handler's fork, error and
            // record never happen and SIGPROF is never delivered.
            "raise-sigprof" => {
                assert_eq!(status, kill, "{label}");
                vec![ExitThread(kill), ExitProcess(kill), PhysicallyExited]
            }
            // The signal callback ended itself with a tail injection of
            // SIGKILL.
            "raise-sigstkflt" => {
                assert_eq!(status, kill, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGSTKFLT as u16),
                    ExitThread(kill),
                    ExitProcess(kill),
                    PhysicallyExited,
                ]
            }
            // The signal callback tail-injected getpid: refused by name as
            // a Tool error (exit 125), with no exit callback.
            "raise-sigpwr" => {
                assert_eq!(status, 125 << 8, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGPWR as u16),
                    PhysicallyExited,
                ]
            }
            // The signal callback staged a SIGKILL in a future it abandoned:
            // its later write (SIGINT) is never made, and its return
            // (SIGQUIT) does not save the guest.
            "raise-sigint" | "raise-sigquit" => {
                let signal = if label == "raise-sigint" {
                    libc::SIGINT
                } else {
                    libc::SIGQUIT
                };
                assert_eq!(status, kill, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(signal as u16),
                    ExitThread(kill),
                    ExitProcess(kill),
                    PhysicallyExited,
                ]
            }
            // The tgkill handler staged a SIGKILL in a future it abandoned,
            // then returned 0: the guest still dies by SIGKILL.
            "raise-sigio" => {
                assert_eq!(status, kill, "{label}");
                vec![ExitThread(kill), ExitProcess(kill), PhysicallyExited]
            }
            // The signal callback staged a SIGKILL in a future it abandoned,
            // then awaited a coordinator request (SIGFPE) or wrote guest
            // memory (SIGBUS): the request is never sent, the writes are
            // never made, and the guest dies by SIGKILL.
            "raise-sigfpe" | "raise-sigbus" => {
                let signal = if label == "raise-sigfpe" {
                    libc::SIGFPE
                } else {
                    libc::SIGBUS
                };
                assert_eq!(status, kill, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(signal as u16),
                    ExitThread(kill),
                    ExitProcess(kill),
                    PhysicallyExited,
                ]
            }
            // The signal callback injected a plain fork: refused as a Tool
            // error before the fork is made (no other process appears).
            "raise-sigxcpu" => {
                assert_eq!(status, 125 << 8, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGXCPU as u16),
                    PhysicallyExited,
                ]
            }
            // SIGXFSZ and SIGUSR1 held; the SIGXFSZ callback sent SIGUSR1
            // again while it was still waiting, so SIGUSR1 is delivered
            // once (its callback ignores it), and the child goes on.
            "raise-sigxfsz" => {
                assert_eq!(status, 48 << 8, "{label}");
                vec![
                    TgkillReturned(0),
                    Signal(libc::SIGXFSZ as u16),
                    Signal(libc::SIGUSR1 as u16),
                    PhysicallyExited,
                ]
            }
            // Sent by the CPUID callback, and by the thread-start callback.
            "cpuid-sigterm" | "thread-start-sigterm" => {
                assert_eq!(status, term, "{label}");
                vec![
                    Signal(term),
                    ExitThread(term),
                    ExitProcess(term),
                    PhysicallyExited,
                ]
            }
            // An admitted guest filter excludes self-death staging even when
            // it only denies rt_sigpending. SIGABRT is a raw death without
            // signal/exit callbacks, which Hermit records as a loss.
            "abort-pending-unreadable" => {
                assert_eq!(status & 0x7f, libc::SIGABRT as u16, "{label}");
                vec![PhysicallyExited]
            }
            other => panic!("unexpected case {other}"),
        };
        assert_eq!(of_child, expected, "{label} (pid {pid}): {observed:?}");
    }
    // With a core limit of 1 the kernel writes no core, and the reported
    // status says so.
    assert_eq!(children[1].2 & 0x80, 0, "{stdout}");
    // The admitted-filter child no longer enters the staging confirmation
    // path: its raw SIGABRT death remains excluded, rather than a Tool error.
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !stderr.contains("SIGABRT, which ends this process, could not be made pending"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "tail_inject of syscall 39, a call that does not end the guest, outside a syscall handler is unsupported"
        ),
        "{stderr}"
    );
    assert!(
        !observed.iter().any(|(.., what)| *what == AfterSigkill),
        "{observed:?}"
    );
    assert!(!stderr.contains("after-abandoned-sigkill"), "{stderr}");
    assert!(
        stderr.contains(
            "a process creation (syscall 57) injected outside a syscall handler is unsupported"
        ),
        "{stderr}"
    );
    // Only the root and its listed children ever connected: the refused
    // fork made no process.
    let mut pids: Vec<i32> = observed.iter().map(|(_, pid, _)| *pid).collect();
    pids.sort_unstable();
    pids.dedup();
    assert_eq!(pids.len(), children.len() + 1, "{observed:?}");
    // The SIGFPE callback's request, made after it abandoned its SIGKILL,
    // never reached the coordinator.
    assert_eq!(global.parked.load(Ordering::Relaxed), 0);
    // The SIGBUS callback's write before its SIGKILL reached the shared
    // page; both writes after it, through the handle obtained before and a
    // new one, failed with ESRCH and changed nothing.
    let sigbus = stdout
        .lines()
        .find(|line| line.starts_with("raise-sigbus "))
        .unwrap();
    assert!(
        sigbus.ends_with(&format!(" shared=1 refused={0},{0}", libc::ESRCH)),
        "{sigbus}"
    );
}

/// A Tool-injected clone3 outside a syscall handler is refused by number
/// before reading its changing record or creating a child. The guest's own
/// clone3 classifier is unchanged from main and is not claimed repaired.
#[tokio::test(flavor = "current_thread")]
async fn a_changing_clone3_record_is_not_read_for_an_outside_handler_refusal() {
    let (result, stdout) = run_lifecycle_mode("clone3-flip").await;
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        stdout, "trials=64 statuses=0x7d00x64 created=0\n",
        "{stderr}"
    );
    assert_eq!(
        stderr
            .matches(
                "a process creation (syscall 435) injected outside a syscall handler is unsupported"
            )
            .count(),
        64,
        "{stderr}"
    );
}

/// Runs the filter boundary probes with the coordinator's lifecycle stream.
async fn run_filter_probe(mode: &str) -> (std::process::Output, LifecycleGlobal) {
    let (_preload_directory, preload) = compile_noop_preload();
    tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command(mode),
            (),
            preload,
        ),
    )
    .await
    .expect("filter boundary probe hung")
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn an_admitted_guest_filter_keeps_denied_self_kill_errno_and_survival() {
    let (result, global) = run_filter_probe("filter-denied-self-kill").await;
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(
        result.stdout,
        format!("kill=-1 errno={} survived\n", libc::EPERM).as_bytes(),
        "{result:?}"
    );
    assert!(global.observed.lock().unwrap().is_empty(), "{global:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn an_admitted_permissive_filter_keeps_self_death_without_exit_callbacks() {
    use std::os::unix::process::ExitStatusExt;
    let (result, global) = run_filter_probe("filter-permissive-self-death").await;
    assert_eq!(result.status.signal(), Some(libc::SIGTERM), "{result:?}");
    assert!(result.stdout.is_empty(), "{result:?}");
    assert!(global.observed.lock().unwrap().is_empty(), "{global:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn a_filter_install_during_staging_or_delivery_is_refused_before_installation() {
    use std::os::unix::process::ExitStatusExt;
    // If installed, this exact filter kills on the refusal's exit_group.
    let (control, _) = run_filter_probe("filter-exit-control").await;
    assert_eq!(control.status.signal(), Some(libc::SIGSYS), "{control:?}");
    for mode in [
        "filter-after-staged-inject",
        "filter-after-staged-tail",
        "filter-in-signal-inject",
        "filter-in-signal-tail",
    ] {
        let (result, global) = run_filter_probe(mode).await;
        assert_eq!(result.status.code(), Some(125), "{mode}: {result:?}");
        assert!(result.stdout.is_empty(), "{mode}: {result:?}");
        assert!(String::from_utf8_lossy(&result.stderr).contains("a seccomp filter installation while a self-signal is staged or being delivered is unsupported"), "{mode}: {result:?}");
        let events: Vec<Observed> = global
            .observed
            .lock()
            .unwrap()
            .iter()
            .map(|(.., event)| *event)
            .collect();
        if mode.starts_with("filter-in-signal") {
            assert_eq!(
                events,
                vec![
                    Observed::TgkillReturned(0),
                    Observed::Signal(libc::SIGTERM as u16)
                ],
                "{mode}"
            );
        } else {
            assert!(events.is_empty(), "{mode}: {events:?}");
        }
    }
}

/// A signal callback that replaces the guest's own fatal signal with
/// SIGALRM, while the guest's SIGALRM handler is kept virtual (admitted
/// SIGALRM handlers, site patching off), is refused by name as a Tool error
/// before anything is sent: a raw SIGALRM would stay physically blocked and
/// the handler would never run. The handler is observed not to run, and the
/// guest does not go on past its `raise`.
#[tokio::test(flavor = "current_thread")]
async fn replacing_a_signal_with_a_virtual_sigalrm_is_refused_by_name() {
    let (_preload_directory, preload) = compile_noop_preload();
    let mut command = guest_command("sigalrm-replacement");
    command
        .env(reverie_liteinst::SIGALRM_HANDLERS_ENV, "1")
        .env(SITE_PATCHING_ENV, "0");
    let (result, _global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(command, (), preload),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(125), "{result:?}");
    // The handler was admitted, and neither it nor the code after `raise`
    // ran.
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "sigaction=0\n",
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "replacing SIGTERM with SIGALRM while the guest's SIGALRM handler is virtual is unsupported"
        ),
        "{stderr}"
    );
}

/// The guest raises SIGALRM while it has no handler, so the default action
/// would end it; its signal callback installs the guest's SIGALRM handler
/// (kept virtual: admitted SIGALRM handlers, site patching off) and lets the
/// SIGALRM be delivered. That is refused by name as a Tool error before
/// anything is sent: a raw SIGALRM would stay physically blocked behind the
/// virtual handler, which would never run. (Before, the same signal number
/// went out raw, and the guest went on past its `raise` with SIGALRM
/// pending.) The handler is observed not to run, and the guest does not go on
/// past its `raise`.
#[tokio::test(flavor = "current_thread")]
async fn a_sigalrm_whose_handler_its_signal_callback_installed_is_refused_by_name() {
    let (_preload_directory, preload) = compile_noop_preload();
    let mut command = guest_command("sigalrm-installed-by-callback");
    command
        .env(reverie_liteinst::SIGALRM_HANDLERS_ENV, "1")
        .env(SITE_PATCHING_ENV, "0");
    let (result, _global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(command, (), preload),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert_eq!(result.status.code(), Some(125), "{result:?}");
    assert_eq!(
        String::from_utf8_lossy(&result.stdout),
        "sigaction=0 reset=0\n",
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "delivering the guest's own SIGALRM after the Tool made the guest's SIGALRM handler virtual is unsupported"
        ),
        "{stderr}"
    );
}

/// The root process's thread-start callback sends it SIGTERM, and its
/// post-exec callback would ignore SIGTERM: the SIGTERM ends the process
/// before the post-exec callback runs, as a tracer delivers it when the
/// thread resumes from its start. Before, the held signal was delivered only
/// after both callbacks, found ignored, and the process survived.
#[tokio::test(flavor = "current_thread")]
async fn a_signal_from_a_thread_start_callback_is_delivered_before_post_exec() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (result, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("root-startup-signal"),
            (),
            preload,
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(result.status.signal(), Some(libc::SIGTERM), "{result:?}");
    assert_eq!(result.stdout, b"", "{result:?}");
    let observed: Vec<Observed> = global
        .observed
        .lock()
        .unwrap()
        .iter()
        .map(|(.., what)| *what)
        .collect();
    let term = libc::SIGTERM as u16;
    assert_eq!(
        observed,
        [
            Observed::Signal(term),
            Observed::ExitThread(term),
            Observed::ExitProcess(term),
        ]
    );
}

/// Synchronous Tool code inside a callback, outside the callback's own
/// send_rpc, sends a request to the global state through the process's
/// existing coordinator connection with `blocking_global_rpc`, and a request
/// for another global state type is refused without sending.
#[tokio::test(flavor = "current_thread")]
async fn synchronous_tool_code_inside_a_callback_reaches_the_global_state() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (result, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("blocking-global-rpc"),
            (),
            preload,
        ),
    )
    .await
    .expect("in-guest run hung")
    .unwrap();
    assert_eq!(result.status.code(), Some(0), "{result:?}");
    assert_eq!(result.stdout, b"blocking global rpc: ok\n", "{result:?}");
    assert_eq!(global.blocking.load(Ordering::Relaxed), 1);
}

/// Asserts the statistics of one `fast-path` guest run.
fn assert_fast_path_stats(
    global: &LifecycleGlobal,
    stats: &reverie_liteinst::LiteinstBackendStatsSource,
) {
    assert_eq!(stats.snapshot().process_reports(), 1, "{stats}");
    assert!(stats.distinct_rips() >= 1, "{stats}");
    assert!(stats.patch_candidates() >= 1, "{stats}");
    let paths = stats.dispatch_path_counts();
    assert!(
        paths.count(&LiteinstDispatchPath::InGuestSigsys) >= 1,
        "expected an in-guest SIGSYS: {stats}"
    );
    assert!(
        paths.count(&LiteinstDispatchPath::DirectHook) >= 8,
        "expected installed-hook dispatches: {stats}"
    );
    let record = stats
        .snapshot()
        .dispatch_stats()
        .expect("in-guest LiteInst reports a dispatch record");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    assert_eq!(record.counters.ptrace_seccomp_stops, Some(0), "{record}");
    assert_eq!(record.counters.ptrace_sigtrap_stops, Some(0), "{record}");
    assert_eq!(
        record.counters.patched_direct_calls,
        Some(paths.count(&LiteinstDispatchPath::DirectHook)),
        "{record}"
    );
    // A site is patched only after its first call trapped, so there is at
    // least one SIGSYS per patched site.
    assert!(record.sites.patched >= Some(1), "{record}");
    assert!(
        record.counters.signal_traps >= record.sites.patched,
        "{record}"
    );
    assert_physical_signals_agree(stats, &record);
    // The getpid site's first call trapped once and then entered through the
    // hook it installed; every call after that was a hook entry.
    assert!(
        record.counters.patched_direct_calls >= Some(8),
        "{record}\n{stats}"
    );
    assert_tool_callbacks_were_delivered(global, stats);
}

/// The handler's count of every `SIGSYS` it received equals the dispatcher's
/// classified signals, counted at a different point, plus each fallback's
/// completion signal, less the entries a fork child re-attributed to itself.
fn assert_physical_signals_agree(
    stats: &reverie_liteinst::LiteinstBackendStatsSource,
    record: &reverie::DispatchStats,
) {
    let paths = stats.dispatch_path_counts();
    let classified = paths.count(&LiteinstDispatchPath::InGuestSigsys)
        + paths.count(&LiteinstDispatchPath::InGuestNestedSigsys)
        + paths.count(&LiteinstDispatchPath::FallbackCompletionSigsys)
        - stats.snapshot().fork_child_entries().sigsys;
    assert_eq!(
        record.counters.signal_traps,
        Some(classified),
        "{record}\n{stats}"
    );
}

/// Every Tool callback the guest counted was entered by a guest event: a
/// top-level `SIGSYS` or a patched-site hook entry the Tool's own syscalls did
/// not make. The guest counts one callback per entry, so a callback re-run for
/// an `ERESTARTSYS` restart is not counted twice. The Tool's own syscalls are
/// excluded, so its RPC traffic cannot pad the count. It is still a bound, not
/// an equality: a lazily patched site's first call counts
/// a signal and then a hook entry for one callback, and a signal for an
/// unsubscribed syscall makes no callback.
///
/// Both sides are raw per-process sums. A fork child counts the callback it
/// returns from as its own, and so does its re-attributed first event.
fn assert_tool_callbacks_were_delivered(
    global: &LifecycleGlobal,
    stats: &reverie_liteinst::LiteinstBackendStatsSource,
) {
    let callbacks = global.callbacks.load(Ordering::Relaxed);
    assert!(callbacks > 0, "the guest Tool reported no callbacks");
    let paths = stats.dispatch_path_counts();
    let guest_entries = paths.count(&LiteinstDispatchPath::InGuestSigsys)
        + paths.count(&LiteinstDispatchPath::DirectHook)
        - paths.count(&LiteinstDispatchPath::InGuestNestedHook);
    assert!(
        callbacks <= guest_entries,
        "{callbacks} callbacks, {guest_entries} guest entries\n{stats}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn in_guest_tool_refuses_an_unsupported_site_patching_value() {
    let (_preload_directory, preload) = compile_noop_preload();
    let mut command = guest_command("patching-off");
    command.env(SITE_PATCHING_ENV, "2");
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(command, (), preload),
    )
    .await
    .expect("in-guest run with an unsupported site-patching value hung")
    .unwrap();

    // The fixture unwraps the installation result, so the refusal is a panic
    // before the fixture's workload: no output and no getpid RPC.
    assert_eq!(output.status.code(), Some(101), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unsupported REVERIE_LITEINST_SITE_PATCHING value"),
        "{output:?}"
    );
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn bootstrap_run_with_output_reports_typed_instrumentation_stats() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_data_and_stats::<CoordinatorOnlyTool>(
            bootstrap_guest_command("fast-path"),
            (),
            preload,
            b"lifecycle".to_vec(),
        ),
    )
    .await
    .expect("stats-enabled bootstrap run hung")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"calls=8 traps=1 hooks=8\n", "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
    assert_fast_path_stats(&global, &stats);
}

#[tokio::test(flavor = "current_thread")]
async fn bootstrap_run_with_inherited_stdio_reports_typed_instrumentation_stats() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_inherited_stdio_and_preload_data_and_stats::<CoordinatorOnlyTool>(
            bootstrap_guest_command("fast-path"),
            (),
            preload,
            b"lifecycle".to_vec(),
        ),
    )
    .await
    .expect("stats-enabled inherited-stdio bootstrap run hung")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    // The guest wrote to the inherited stdout, not to a captured buffer.
    assert!(output.stdout.is_empty(), "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
    assert_fast_path_stats(&global, &stats);
}

/// The status-only bootstrap launchers keep the caller's stdio: a guest whose
/// stdout the caller pointed at a file writes there.
#[tokio::test(flavor = "current_thread")]
async fn bootstrap_status_run_keeps_caller_stdio_and_reports_stats() {
    let (_preload_directory, preload) = compile_noop_preload();
    let stdout_file = tempfile::NamedTempFile::new().unwrap();
    let mut command = bootstrap_guest_command("fast-path");
    command.stdout(reverie::process::Stdio::from(stdout_file.reopen().unwrap()));
    let (status, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_preload_data_and_stats::<CoordinatorOnlyTool>(
            command,
            (),
            preload.clone(),
            b"lifecycle".to_vec(),
        ),
    )
    .await
    .expect("stats-enabled bootstrap status run hung")
    .unwrap();

    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(
        std::fs::read(stdout_file.path()).unwrap(),
        b"calls=8 traps=1 hooks=8\n"
    );
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
    assert_fast_path_stats(&global, &stats);

    let stdout_file = tempfile::NamedTempFile::new().unwrap();
    let mut command = bootstrap_guest_command("fast-path");
    command.stdout(reverie::process::Stdio::from(stdout_file.reopen().unwrap()));
    let (status, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_preload_data::<CoordinatorOnlyTool>(
            command,
            (),
            preload,
            b"lifecycle".to_vec(),
        ),
    )
    .await
    .expect("bootstrap status run hung")
    .unwrap();

    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(
        std::fs::read(stdout_file.path()).unwrap(),
        b"calls=8 traps=1 hooks=8\n"
    );
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
}

#[tokio::test(flavor = "current_thread")]
async fn site_patching_off_runs_every_call_through_the_in_guest_fallback() {
    let (_preload_directory, preload) = compile_noop_preload();
    let mut command = guest_command("patching-off");
    command.env(SITE_PATCHING_ENV, "0");
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            command,
            (),
            preload,
        ),
    )
    .await
    .expect("patching-off in-guest run hung")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    // No site is claimed, so the site keeps no trap or hook count; every
    // getpid and every vDSO clock_gettime and gettimeofday reached the
    // fallback, and no tracer is attached to the guest.
    assert_eq!(
        output.stdout,
        b"calls=8 traps=0 hooks=0 fallback_getpid=8 fallback_clock_gettime=8 \
          fallback_gettimeofday=8 tracer_pid=0\n",
        "{output:?}"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
    assert_eq!(global.clock_gettime.load(Ordering::Relaxed), 8);
    assert_eq!(global.gettimeofday.load(Ordering::Relaxed), 8);
    assert_eq!(stats.snapshot().process_reports(), 1, "{stats}");
    assert_eq!(stats.snapshot().patch_shapes().patched_rips(), 0, "{stats}");
    let paths = stats.dispatch_path_counts();
    for (path, expected) in [
        (LiteinstDispatchPath::DirectHook, 0),
        (LiteinstDispatchPath::FirstSiteSeccomp, 0),
        (LiteinstDispatchPath::PtraceInstallation, 0),
        (LiteinstDispatchPath::CachelineStraddlerFallback, 0),
        (LiteinstDispatchPath::UnpatchableOrOtherFallback, 0),
        (LiteinstDispatchPath::FallbackRefusal, 0),
    ] {
        assert_eq!(paths.count(&path), expected, "{path}: {stats}");
    }
    let disabled = paths.count(&LiteinstDispatchPath::PatchingDisabledFallback);
    assert!(
        disabled >= 24,
        "expected every getpid, clock_gettime and gettimeofday on the fallback: {stats}"
    );
    // Every fallback completes except the guest's final exit_group: it is
    // dispatched through the fallback like any other call, but the Tool host
    // submits the process statistics before that call exits the process, so
    // its completion is never counted.
    assert_eq!(
        paths.count(&LiteinstDispatchPath::FallbackCompletionSigsys),
        disabled - 1,
        "every fallback but the final exit_group must complete: {stats}"
    );
    let record = stats
        .snapshot()
        .dispatch_stats()
        .expect("in-guest LiteInst reports a dispatch record");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    assert_eq!(record.counters.ptrace_seccomp_stops, Some(0), "{record}");
    assert_eq!(record.counters.ptrace_sigtrap_stops, Some(0), "{record}");
    assert_eq!(record.counters.patched_direct_calls, Some(0), "{record}");
    assert_physical_signals_agree(&stats, &record);
    assert_tool_callbacks_were_delivered(&global, &stats);
    println!("{stats}");
}

#[tokio::test(flavor = "current_thread")]
async fn in_guest_timer_requests_fail_closed_with_enosys() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("timer-refused"),
            (),
            preload,
        ),
    )
    .await
    .expect("timer-refused in-guest run hung")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    // Nothing in the guest delivers a timer event, so both requests must be
    // refused rather than accepted and never fired.
    assert_eq!(
        output.stdout, b"set_timer=ENOSYS set_timer_precise=ENOSYS\n",
        "{output:?}"
    );
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn fallback_fork_reports_both_process_dispatch_paths() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            guest_command("fallback-fork-stats"),
            (),
            preload,
        ),
    )
    .await
    .expect("fallback fork statistics run hung")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"fallback fork stats: child=finished\n");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(global.fork.load(Ordering::Relaxed), 1);
    assert_eq!(stats.snapshot().process_reports(), 2, "{stats}");
    assert_eq!(
        stats
            .dispatch_path_counts()
            .count(&LiteinstDispatchPath::UnpatchableOrOtherFallback),
        2,
        "{stats}"
    );
    assert_eq!(
        stats
            .dispatch_path_counts()
            .count(&LiteinstDispatchPath::CachelineStraddlerFallback),
        0,
        "{stats}"
    );
    assert_eq!(
        stats
            .dispatch_path_counts()
            .count(&LiteinstDispatchPath::FallbackRefusal),
        0,
        "{stats}"
    );
    assert!(
        stats
            .dispatch_path_counts()
            .count(&LiteinstDispatchPath::InGuestSigsys)
            >= 2,
        "{stats}"
    );
    // The child reports the parent's fork entry as its own first event; the
    // shared record still counts that physical signal once.
    assert_eq!(
        stats.snapshot().fork_child_entries(),
        reverie_liteinst::InheritedEntries {
            sigsys: 1,
            hooks: 0
        },
        "{stats}"
    );
    let record = stats
        .snapshot()
        .dispatch_stats()
        .expect("in-guest LiteInst reports a dispatch record");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    assert_physical_signals_agree(&stats, &record);
    assert_tool_callbacks_were_delivered(&global, &stats);
    println!("{stats}");
}

#[tokio::test(flavor = "current_thread")]
async fn tool_syscall_through_a_patched_site_is_a_nested_hook_entry() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            guest_command("nested-hook"),
            (),
            preload,
        ),
    )
    .await
    .expect("nested hook statistics run hung")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    // The guest's own counts of the getppid site: its own call trapped and
    // patched the site, then the Tool's call entered through the hook.
    assert_eq!(
        output.stdout, b"nested getppid traps=1 hooks=2\n",
        "{output:?}"
    );
    assert_eq!(global.getpid.load(Ordering::Relaxed), 1);
    let paths = stats.dispatch_path_counts();
    assert_eq!(
        paths.count(&LiteinstDispatchPath::InGuestNestedHook),
        1,
        "{stats}"
    );
    let record = stats
        .snapshot()
        .dispatch_stats()
        .expect("in-guest LiteInst reports a dispatch record");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    // The nested entry is a physical patched call like any other.
    assert_eq!(
        record.counters.patched_direct_calls,
        Some(paths.count(&LiteinstDispatchPath::DirectHook)),
        "{record}"
    );
    assert_physical_signals_agree(&stats, &record);
    assert_tool_callbacks_were_delivered(&global, &stats);
}

#[tokio::test(flavor = "current_thread")]
async fn hooked_fork_counts_the_inherited_hook_entry_once() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload_and_stats::<CoordinatorOnlyTool>(
            guest_command("hooked-fork-stats"),
            (),
            preload,
        ),
    )
    .await
    .expect("hooked fork statistics run hung")
    .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"hooked fork stats: child=finished\n");
    assert_eq!(global.fork.load(Ordering::Relaxed), 1);
    assert_eq!(stats.snapshot().process_reports(), 2, "{stats}");
    // The fork entered through the hook its first call installed; the child
    // reports that entry again as its own first event.
    assert_eq!(
        stats.snapshot().fork_child_entries(),
        reverie_liteinst::InheritedEntries {
            sigsys: 0,
            hooks: 1
        },
        "{stats}"
    );
    let paths = stats.dispatch_path_counts();
    let record = stats
        .snapshot()
        .dispatch_stats()
        .expect("in-guest LiteInst reports a dispatch record");
    assert_eq!(record.inconsistencies(), Vec::<String>::new(), "{record}");
    assert_eq!(
        record.counters.patched_direct_calls,
        Some(paths.count(&LiteinstDispatchPath::DirectHook) - 1),
        "{record}\n{stats}"
    );
    assert_physical_signals_agree(&stats, &record);
    assert_tool_callbacks_were_delivered(&global, &stats);
}

#[tokio::test(flavor = "current_thread")]
async fn backend_trait_output_capture_reports_bytes_status_and_stats() {
    if std::env::var_os(BACKEND_OUTPUT_CHILD_ENV).is_none() {
        let (_preload_directory, preload) = compile_noop_preload();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "backend_trait_output_capture_reports_bytes_status_and_stats",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(BACKEND_OUTPUT_CHILD_ENV, "1")
            .env(TOOL_PRELOAD_ENV, preload)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "isolated Backend::run_with_output test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        return;
    }

    let (output, global, stats) = tokio::time::timeout(
        Duration::from_secs(10),
        <LiteinstBackend as Backend>::run_with_output::<CoordinatorOnlyTool>(
            guest_command("fast-path"),
            (),
        ),
    )
    .await
    .expect("Backend::run_with_output hung on the LiteInst path")
    .unwrap();

    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(output.stdout, b"calls=8 traps=1 hooks=8\n", "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(global.getpid.load(Ordering::Relaxed), 8);
    assert_eq!(stats.process_reports(), 1, "{stats}");
    assert!(stats.patch_shapes().patched_rips() >= 1, "{stats}");
    assert!(stats.patch_shapes().candidate_rips() >= 1, "{stats}");
}

#[tokio::test(flavor = "current_thread")]
async fn supervisor_restarts_wait4_without_leaking_private_errno() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("restart-wait4"),
            (),
            preload,
        ),
    )
    .await
    .expect("supervised wait4 hung")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"wait4-restart-ok\n", "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn supervisor_restarts_read_without_leaking_private_errno() {
    let (_preload_directory, preload) = compile_noop_preload();
    let (output, _) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::run_with_output_and_preload::<CoordinatorOnlyTool>(
            guest_command("restart-read"),
            (),
            preload,
        ),
    )
    .await
    .expect("supervised read hung")
    .unwrap();

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(output.stdout, b"read-result=4243 calls=3\n", "{output:?}");
}

/// Admits every guest connection and records the pid each pidfd names, and
/// whether the launcher attached an exit reporter before the first admission.
/// At the first admission, mid-run, it uses each of the reporter's methods
/// once.
#[derive(Default)]
struct RecordingAdmission {
    seen: std::sync::Mutex<Vec<i32>>,
    reporter_before_first_admission: std::sync::atomic::AtomicBool,
    reporter: std::sync::Mutex<Option<std::sync::Arc<dyn reverie_rpc_transport::ExitReporter>>>,
    pending_at_first_admission: std::sync::Mutex<Option<Vec<i32>>>,
}

impl reverie_rpc_transport::ConnectionAdmission for RecordingAdmission {
    fn attach_exit_reporter(
        &self,
        reporter: std::sync::Arc<dyn reverie_rpc_transport::ExitReporter>,
    ) {
        if self.seen.lock().unwrap().is_empty() {
            self.reporter_before_first_admission
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
        *self.reporter.lock().unwrap() = Some(reporter);
    }

    fn admit(
        &self,
        peer: std::os::fd::OwnedFd,
    ) -> std::io::Result<reverie_rpc_transport::Admitted> {
        use std::os::fd::AsRawFd;
        let fdinfo =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{}", peer.as_raw_fd())).unwrap();
        let pid: i32 = fdinfo
            .lines()
            .find_map(|line| line.strip_prefix("Pid:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let mut seen = self.seen.lock().unwrap();
        if seen.is_empty()
            && let Some(reporter) = self.reporter.lock().unwrap().as_ref()
        {
            *self.pending_at_first_admission.lock().unwrap() =
                Some(reporter.pending_process_exits());
            reporter.process_exited(pid);
            reporter.backend_failed(reverie::BackendFailure {
                pid: reverie::Pid::from_raw(pid),
                tid: reverie::Tid::from_raw(pid),
                phase: "lifecycle test",
            });
        }
        seen.push(pid);
        Ok(reverie_rpc_transport::Admitted { process_id: pid })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn connection_admission_sees_each_guest_process_before_it_is_served() {
    let (_preload_directory, preload) = compile_noop_preload();
    let marker_directory = tempfile::tempdir().unwrap();
    let marker = marker_directory.path().join("descendant.marker");
    let mut command = guest_command("root-exits-first");
    command.arg(&marker);
    let admission = std::sync::Arc::new(RecordingAdmission::default());

    let (status, global) = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::with_connection_admission(
            admission.clone(),
            LiteinstBackend::run_with_preload::<CoordinatorOnlyTool>(command, (), preload),
        ),
    )
    .await
    .expect("an admitted run hung")
    .unwrap();

    // Admission did not change the run, and every admitted connection was a
    // guest process, never the coordinator itself, each admitted once.
    assert_eq!(status, ExitStatus::Exited(23));
    assert_eq!(std::fs::read(&marker).unwrap(), b"descendant-finished\n");
    assert_eq!(global.fork.load(Ordering::Relaxed), 1);
    let seen = admission.seen.lock().unwrap().clone();
    assert!(!seen.is_empty(), "no guest connection was admitted");
    let me = std::process::id() as i32;
    assert!(seen.iter().all(|&pid| pid > 0 && pid != me), "{seen:?}");
    let mut unique = seen.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        seen.len(),
        "a process was admitted twice: {seen:?}"
    );
    assert!(
        admission
            .reporter_before_first_admission
            .load(std::sync::atomic::Ordering::SeqCst),
        "the launcher must attach the exit reporter before admitting a connection"
    );
    // During the run each reporter method reached the global tool's hook.
    assert_eq!(
        *admission.pending_at_first_admission.lock().unwrap(),
        Some(vec![PENDING_EXIT_SENTINEL])
    );
    assert_eq!(*global.exited.lock().unwrap(), [seen[0]]);
    assert_eq!(global.backend_failures.load(Ordering::Relaxed), 1);
    // After the run the reporter holds no global, so it reaches nothing.
    let reporter = admission.reporter.lock().unwrap().clone().unwrap();
    assert!(reporter.pending_process_exits().is_empty());
    reporter.process_exited(seen[0]);
}

struct RefusingAdmission;

impl reverie_rpc_transport::ConnectionAdmission for RefusingAdmission {
    fn admit(
        &self,
        _peer: std::os::fd::OwnedFd,
    ) -> std::io::Result<reverie_rpc_transport::Admitted> {
        Err(std::io::Error::other("refused by the test"))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn refused_guest_connection_fails_the_run() {
    let (_preload_directory, preload) = compile_noop_preload();
    let marker_directory = tempfile::tempdir().unwrap();
    let marker = marker_directory.path().join("descendant.marker");
    let mut command = guest_command("root-exits-first");
    command.arg(&marker);

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        LiteinstBackend::with_connection_admission(
            std::sync::Arc::new(RefusingAdmission),
            LiteinstBackend::run_with_preload::<CoordinatorOnlyTool>(command, (), preload),
        ),
    )
    .await
    .expect("a refused run hung");

    // The guest never reaches its program: the run fails or the guest exits
    // with something other than the fixture's own status.
    match result {
        Err(_) => {}
        Ok((status, _global)) => assert_ne!(status, ExitStatus::Exited(23)),
    }
    assert!(!marker.exists(), "the refused guest ran its program");
}

#[cfg(feature = "allocator-fixture")]
#[path = "lifecycle/mapping_routes.rs"]
mod mapping_routes;
