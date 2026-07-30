use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::Duration;

use reverie::Error;
use reverie::GlobalTool;
use reverie::Guest;
use reverie::Subscription;
use reverie::Tid;
use reverie::Tool;
use reverie::process::Command;
use reverie::syscalls::Syscall;
use reverie::syscalls::SyscallArgs;
use reverie::syscalls::SyscallInfo;
use reverie::syscalls::Sysno;
use reverie_liteinst::LiteinstBackend;

#[derive(Debug, Default)]
struct EventCounter {
    delivered: AtomicU64,
    last_getpid_rip: AtomicU64,
    last_getpid_r12: AtomicU64,
    helper_mprotect_callbacks: AtomicU64,
}

#[reverie::global_tool]
impl GlobalTool for EventCounter {
    type Request = u64;
    type Response = ();
    type Config = ();

    async fn receive_rpc(&self, _from: Tid, increment: u64) {
        if increment & (1_u64 << 63) != 0 {
            self.last_getpid_rip
                .store(increment & ((1_u64 << 62) - 1), Ordering::SeqCst);
            self.delivered.fetch_add(1, Ordering::SeqCst);
        } else if increment & (1_u64 << 62) != 0 {
            self.last_getpid_r12
                .store(increment & ((1_u64 << 62) - 1), Ordering::SeqCst);
        } else if increment & (1_u64 << 61) != 0 {
            self.helper_mprotect_callbacks
                .fetch_add(1, Ordering::SeqCst);
        } else {
            self.delivered.fetch_add(increment, Ordering::SeqCst);
        }
    }
}

#[derive(Default)]
struct CountSyscalls;

#[reverie::tool]
impl Tool for CountSyscalls {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getrandom, Sysno::getpid, Sysno::mprotect]
            .into_iter()
            .collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert!(matches!(
            syscall.number(),
            Sysno::getrandom | Sysno::getpid | Sysno::mprotect
        ));
        if syscall.number() == Sysno::getpid {
            let regs = guest.regs().await;
            guest.send_rpc((1_u64 << 62) | regs.r12).await;
            guest.send_rpc((1_u64 << 63) | regs.rip).await;
        } else if syscall.number() == Sysno::mprotect {
            guest.send_rpc(1_u64 << 61).await;
        } else {
            guest.send_rpc(1).await;
        }
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct PassthroughGetpid;

#[reverie::tool]
impl Tool for PassthroughGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct ObservePkey;

#[reverie::tool]
impl Tool for ObservePkey {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid, Sysno::pkey_mprotect].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        guest.send_rpc(1).await;
        Ok(guest.inject(syscall).await?)
    }
}

#[derive(Default)]
struct ReplaceGetpid;

#[reverie::tool]
impl Tool for ReplaceGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        let replacement = Syscall::from_raw(Sysno::getppid, SyscallArgs::new(0, 0, 0, 0, 0, 0));
        Ok(guest.inject(replacement).await?)
    }
}

#[derive(Default)]
struct DoubleInjectGetpid;

#[reverie::tool]
impl Tool for DoubleInjectGetpid {
    type GlobalState = EventCounter;
    type ThreadState = ();

    fn subscriptions(_config: &()) -> Subscription {
        [Sysno::getpid].into_iter().collect()
    }

    async fn handle_syscall_event<G: Guest<Self>>(
        &self,
        guest: &mut G,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        assert_eq!(syscall.number(), Sysno::getpid);
        guest.send_rpc(1).await;
        let _ = guest.inject(syscall).await?;
        Ok(guest.inject(syscall).await?)
    }
}

fn preload_path() -> PathBuf {
    let launcher = PathBuf::from(env!("CARGO_BIN_EXE_reverie-liteinst-strace"));
    let target = launcher.parent().unwrap();
    [
        target.join("libreverie_liteinst.so"),
        target.join("deps/libreverie_liteinst.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build the LiteInst preload cdylib")
}

fn compile_fixture(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let output = directory.path().join(name.trim_end_matches(".c"));
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args(["-std=gnu11", "-O0", "-fno-pie", "-no-pie"])
        .arg(&source)
        .arg("-o")
        .arg(&output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    (directory, output)
}

fn symbol_address(binary: &std::path::Path, symbol: &str) -> u64 {
    let output = ProcessCommand::new("nm").arg(binary).output().unwrap();
    assert!(output.status.success(), "nm failed: {output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            let _kind = fields.next()?;
            (fields.next()? == symbol).then(|| u64::from_str_radix(address, 16).unwrap())
        })
        .unwrap_or_else(|| panic!("missing symbol {symbol}"))
}

fn processes_named(name: &str) -> Vec<u32> {
    let mut found = Vec::new();
    for entry in fs::read_dir("/proc").unwrap() {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(comm) = fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        if comm.trim() == name {
            found.push(pid);
        }
    }
    found
}

fn assert_pid_reaped(pid: u32) {
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "failed LiteInst process {pid} remains stopped or unreaped"
    );
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) },
        -1,
        "failed LiteInst process {pid} still has a waitable state"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD),
        "failed LiteInst process {pid} was not fully reaped"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn host_lifecycle_observes_allocator_and_explicit_getrandom() {
    let (_directory, guest) = compile_fixture("allocator_getrandom.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<CountSyscalls>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        global.delivered.load(Ordering::SeqCst),
        3,
        "host lifecycle missed allocator/pre-constructor entropy: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn first_site_is_installed_once_and_hot_calls_use_liteinst() {
    let (_baseline_directory, baseline_guest) = compile_fixture("allocator_getrandom.c");
    let (baseline_output, baseline_global) = LiteinstBackend::run_host_with_output_and_preload::<
        CountSyscalls,
    >(Command::new(baseline_guest), (), preload_path())
    .await
    .unwrap();
    assert!(baseline_output.status.success(), "{baseline_output:?}");

    let (_directory, guest) = compile_fixture("hybrid_hot_site.c");
    let site = symbol_address(&guest, "reverie_liteinst_hybrid_getpid_site");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<CountSyscalls>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"calls=32 traps=1 hooks=31 ac=0 simd=1 spoofs=3\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 33, "{output:?}");
    assert_eq!(
        global.last_getpid_rip.load(Ordering::SeqCst),
        site + 2,
        "the host Tool must see the original logical post-syscall RIP"
    );
    assert_eq!(
        global.last_getpid_r12.load(Ordering::SeqCst),
        0x0012_3456_789a_bcde,
        "logical guest R12 must remain distinct from the controller HookContext base"
    );
    assert_eq!(
        global.helper_mprotect_callbacks.load(Ordering::SeqCst)
            - baseline_global
                .helper_mprotect_callbacks
                .load(Ordering::SeqCst),
        0,
        "the patch helper must add zero mprotect Tool callbacks above the loader baseline"
    );
    assert!(output.status.success(), "{output:?}");
}

async fn run_cpuid_policy_mode(
    mode: Option<&str>,
) -> Option<(reverie::process::Output, EventCounter)> {
    let (_directory, guest) = compile_fixture("hybrid_cpuid_policy.c");
    let mut command = Command::new(guest);
    if let Some(mode) = mode {
        command.arg(mode);
    }
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
    .unwrap();
    if output.status.code() == Some(77) {
        eprintln!("skipping: this host does not support ARCH_GET_CPUID");
        return None;
    }
    Some((output, global))
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_disabled_cpuid_after_installing_a_site() {
    let Some((output, global)) = run_cpuid_policy_mode(None).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=active calls=32 traps=1 hooks=31 cpuid=0\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_disabled_cpuid_after_fallback() {
    let Some((output, global)) = run_cpuid_policy_mode(Some("fallback")).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=fallback calls=2 traps=1 hooks=0 cpuid=0\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 2, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

async fn run_tsc_policy_mode(
    mode: Option<&str>,
) -> Option<(reverie::process::Output, EventCounter)> {
    let (_directory, guest) = compile_fixture("hybrid_tsc_policy.c");
    let mut command = Command::new(guest);
    if let Some(mode) = mode {
        command.arg(mode);
    }
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
    .unwrap();
    if output.status.code() == Some(77) {
        eprintln!("skipping: this host does not support PR_GET_TSC/PR_SET_TSC");
        return None;
    }
    Some((output, global))
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_faulting_tsc_after_installing_a_site() {
    let Some((output, global)) = run_tsc_policy_mode(None).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=active calls=32 traps=1 hooks=31 tsc=2\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn patch_helper_restores_faulting_tsc_after_fallback() {
    let Some((output, global)) = run_tsc_policy_mode(Some("fallback")).await else {
        return;
    };
    assert_eq!(
        output.stdout, b"mode=fallback calls=2 traps=1 hooks=0 tsc=2\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 2, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn first_discovery_event_can_replace_the_syscall() {
    let (_directory, guest) = compile_fixture("hybrid_hot_site.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<ReplaceGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"calls=32 traps=1 hooks=31 ac=0 simd=1 spoofs=3\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn first_discovery_event_can_inject_more_than_once() {
    let (_directory, guest) = compile_fixture("hybrid_hot_site.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<DoubleInjectGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(
        output.stdout, b"calls=32 traps=1 hooks=31 ac=0 simd=1 spoofs=3\n",
        "{output:?}"
    );
    assert_eq!(global.delivered.load(Ordering::SeqCst), 32, "{output:?}");
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn hybrid_fails_closed_when_the_guest_forks() {
    let (_directory, guest) = compile_fixture("hybrid_fork.c");
    let marker = format!("li{:x}", std::process::id());
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("root.pid");
    let mut command = Command::new(guest);
    command.arg(&marker).arg(&pid_file);
    let result = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await;

    let _error = result.expect_err("hybrid unexpectedly followed a child");
    let root_pid: u32 = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_pid_reaped(root_pid);
    assert!(
        processes_named(&marker).is_empty(),
        "failed LiteInst root/child remains stopped or as a zombie"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn reused_mapping_invalidates_and_rediscovers_the_syscall_site() {
    let (_directory, guest) = compile_fixture("hybrid_mapping_churn.c");
    let (output, global) = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        Command::new(guest),
        (),
        preload_path(),
    )
    .await
    .unwrap();

    assert_eq!(output.stdout, b"reuse traps=2 hooks=0\n", "{output:?}");
    assert_eq!(
        global.delivered.load(Ordering::SeqCst),
        4,
        "both generations must use the correct ptrace fallback: {output:?}"
    );
    assert!(output.status.success(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn moving_a_patched_mapping_rejects_stale_hot_provenance() {
    let (_directory, guest) = compile_fixture("hybrid_mremap_patched.c");
    let command = Command::new(guest);
    let error = LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
    .expect_err("mremap unexpectedly moved a live patched site");

    assert!(
        error
            .to_string()
            .contains("mremap overlaps an active LiteInst hook footprint"),
        "mapping was not rejected by the pre-mutation provenance check: {error}"
    );
}

async fn run_active_footprint_mode(
    mode: &str,
) -> Result<(reverie::process::Output, EventCounter), Error> {
    let (_directory, guest) = compile_fixture("hybrid_active_footprint.c");
    let mut command = Command::new(guest);
    command.arg(mode);
    LiteinstBackend::run_host_with_output_and_preload::<PassthroughGetpid>(
        command,
        (),
        preload_path(),
    )
    .await
}

#[tokio::test(flavor = "current_thread")]
async fn active_hook_noop_mprotect_preserves_the_hook() {
    for (mode, stdout) in [
        ("noop", "active no-op protection preserved\n"),
        ("short-noop", "active short no-op protection preserved\n"),
    ] {
        let (output, global) = run_active_footprint_mode(mode).await.unwrap();
        assert_eq!(output.stdout, stdout.as_bytes());
        assert_eq!(global.delivered.load(Ordering::SeqCst), 3);
        assert!(output.status.success(), "{output:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn active_hook_mapping_footprints_reject_mprotect_before_mutation() {
    for (mode, syscall) in [
        ("site", "mprotect"),
        ("trampoline", "mprotect"),
        ("arena-rw", "mprotect"),
        ("short-site", "mprotect"),
        ("short-trampoline", "mprotect"),
        ("short-arena-rw", "mprotect"),
        ("short-munmap", "munmap"),
        ("short-map-fixed", "mmap"),
        ("short-mremap", "mremap"),
        ("short-mremap-fixed", "mremap"),
        ("zero-old-mremap-fixed", "mremap"),
    ] {
        let error = run_active_footprint_mode(mode)
            .await
            .expect_err("active footprint mutation unexpectedly completed");
        assert!(
            error.to_string().contains(&format!(
                "{syscall} overlaps an active LiteInst hook footprint"
            )),
            "{mode} footprint was not rejected before mutation: {error}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pkey_mprotect_is_controller_owned_unless_subscribed() {
    let (_directory, guest) = compile_fixture("hybrid_active_footprint.c");
    let mut command = Command::new(&guest);
    command.arg("pkey-noop");
    let (unsubscribed_output, unsubscribed) = LiteinstBackend::run_host_with_output_and_preload::<
        PassthroughGetpid,
    >(command, (), preload_path())
    .await
    .unwrap();

    let mut command = Command::new(guest);
    command.arg("pkey-noop");
    let (subscribed_output, subscribed) = LiteinstBackend::run_host_with_output_and_preload::<
        ObservePkey,
    >(command, (), preload_path())
    .await
    .unwrap();
    assert_eq!(unsubscribed_output.stdout, subscribed_output.stdout);
    assert_eq!(
        subscribed.delivered.load(Ordering::SeqCst),
        unsubscribed.delivered.load(Ordering::SeqCst) + 1,
        "pkey_mprotect must reach the Tool exactly when subscribed"
    );

    let error = run_active_footprint_mode("pkey-site")
        .await
        .expect_err("destructive pkey_mprotect unexpectedly completed");
    assert!(
        error
            .to_string()
            .contains("pkey_mprotect overlaps an active LiteInst hook footprint"),
        "pkey_mprotect was not rejected before mutation: {error}"
    );
}

async fn cancel_host_wait(capture_output: bool) {
    let (_directory, guest) = compile_fixture("hybrid_wait_cancel.c");
    let pid_directory = tempfile::tempdir().unwrap();
    let pid_file = pid_directory.path().join("guest.pid");
    let mut command = Command::new(guest);
    command.arg(&pid_file);

    let mut run = if capture_output {
        Box::pin(LiteinstBackend::run_host_with_output_and_preload::<
            PassthroughGetpid,
        >(command, (), preload_path()))
            as std::pin::Pin<Box<dyn std::future::Future<Output = _>>>
    } else {
        Box::pin(async move {
            LiteinstBackend::run_host_with_preload::<PassthroughGetpid>(command, (), preload_path())
                .await
                .map(|(status, global)| {
                    (
                        reverie::process::Output {
                            status,
                            stdout: Vec::new(),
                            stderr: Vec::new(),
                        },
                        global,
                    )
                })
        })
    };
    let wait_for_pid = async {
        loop {
            if let Ok(contents) = fs::read_to_string(&pid_file)
                && let Ok(pid) = contents.trim().parse::<u32>()
            {
                break pid;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let pid = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = &mut run => panic!("wait completed before cancellation: {result:?}"),
            pid = wait_for_pid => pid,
        }
    })
    .await
    .expect("guest did not enter the wait phase");
    drop(run);
    assert_pid_reaped(pid);
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_wait_reaps_and_unregisters_liteinst_root() {
    cancel_host_wait(false).await;
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_wait_with_output_reaps_and_unregisters_liteinst_root() {
    cancel_host_wait(true).await;
}
