use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

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

const RPC_GETPID: u64 = 1;
const RPC_FORK: u64 = 4;

#[derive(Debug, Default)]
struct LifecycleGlobal {
    getpid: AtomicU64,
    fork: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for LifecycleGlobal {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, event: u64) {
        let counter = match event {
            RPC_GETPID => &self.getpid,
            RPC_FORK => &self.fork,
            _ => panic!("unknown lifecycle fixture RPC {event}"),
        };
        counter.fetch_add(1, Ordering::Relaxed);
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
    assert_eq!(stats.snapshot().process_reports(), 1, "{stats}");
    assert!(stats.distinct_rips() >= 1, "{stats}");
    assert!(stats.patch_candidates() >= 1, "{stats}");
    let paths = stats.dispatch_path_counts();
    assert!(paths[2] >= 1, "expected an in-guest SIGSYS: {stats}");
    assert!(paths[6] >= 8, "expected installed-hook dispatches: {stats}");
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
