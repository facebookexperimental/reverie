/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * This source code is licensed under the BSD-style license in LICENSE.
 */

//! Actual caller Tool/native lifecycle checks. Build the independent caller
//! artifact for this profile with the documented producer before running these
//! nonignored tests. Missing or stale artifacts are failures.

use std::fs;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;
use std::process::Output;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use reverie_dbt::CallerArtifact;
use reverie_dbt::DbtRunner;
use reverie_dbt::bundled_drrun_path;
use reverie_dbt::failed_run_output;
use tempfile::TempDir;

#[path = "fixtures/caller-lifecycle-runtime/src/lifecycle.rs"]
mod lifecycle;
#[path = "fixtures/caller-lifecycle-runtime/src/protocol.rs"]
pub mod protocol;

use lifecycle::raw_call;
use protocol as tool;
use tool::Config;
use tool::Event;
use tool::LifecycleGlobal;
use tool::Mode;
use tool::Terminal;

const CHILD_CASE: &str = "REVERIE_DBT_CALLER_LIFECYCLE_CASE";
const CHILD_SELECTOR: &str = "REVERIE_DBT_CALLER_LIFECYCLE_SELECTOR";
const CHILD_GUEST: &str = "REVERIE_DBT_CALLER_LIFECYCLE_GUEST";
const WITNESS: &str = "CALLER_LIFECYCLE_NATIVE_COMPLETED";
const GUEST_SOURCE: &str = include_str!("fixtures/caller-lifecycle-runtime/guest.S");

fn temporary_directory(prefix: &str) -> TempDir {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(root).unwrap();
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(root)
        .unwrap()
}

fn guest_binary() -> PathBuf {
    static GUEST: OnceLock<TempDir> = OnceLock::new();
    let directory = GUEST.get_or_init(|| {
        let checked_source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/caller-lifecycle-runtime/guest.S");
        assert_eq!(fs::read_to_string(checked_source).unwrap(), GUEST_SOURCE);
        let directory = temporary_directory("caller-lifecycle-guest-");
        let source = directory.path().join("guest.S");
        fs::write(&source, GUEST_SOURCE).unwrap();
        // Like the existing native fixtures, use the configured C toolchain.
        // Compile once before starting any case's ten-second execution bound.
        let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
        let output = Command::new(compiler)
            .args([
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,-e,_start",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(directory.path().join("guest"))
            .arg(source)
            .output()
            .unwrap();
        assert!(output.status.success(), "guest compiler failed: {output:?}");
        directory
    });
    directory.path().join("guest")
}

fn caller_manifest() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let deps = executable.parent().unwrap();
    assert_eq!(deps.file_name().unwrap(), "deps");
    deps.parent()
        .unwrap()
        .join("reverie-dbt-callers/caller-lifecycle/manifest.json")
}

fn launch_native(
    config: &Config,
    guest: &Path,
) -> (std::io::Result<(Output, LifecycleGlobal)>, Vec<u8>) {
    config.validate();
    // This exact manifest is required; no older image or prototype fallback.
    let artifact = CallerArtifact::load(caller_manifest()).unwrap();
    let diagnostics = temporary_directory("caller-lifecycle-diagnostics-");
    let diagnostic_path = diagnostics.path().join("native.log");
    let diagnostic_file = fs::File::create(&diagnostic_path).unwrap();
    let runner = DbtRunner::new(bundled_drrun_path(), artifact.native_client())
        .unwrap()
        .diagnostic_file(&diagnostic_file)
        .unwrap();
    let mut command = Command::new(guest);
    command.args([
        config.mode.guest_argument().to_owned(),
        config.terminal.number().id().to_string(),
        config.args[0].to_string(),
    ]);
    // Inherit the helper's supervised process group. A Tokio timeout cannot
    // stop the launcher's blocking wait; the parent enforces the real bound.
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(runner.output_with_caller_tool::<LifecycleGlobal>(&command, config.clone()));
    (result, fs::read(&diagnostic_path).unwrap())
}

fn run_native(config: Config, guest: &Path) {
    let (result, native_diagnostics) = launch_native(&config, guest);
    let (output, global) = result.unwrap_or_else(|error| {
        panic!(
            "native caller failed: {error}; output: {:?}; diagnostic: {}",
            failed_run_output(&error),
            String::from_utf8_lossy(&native_diagnostics),
        );
    });
    assert_eq!(output.status.code(), Some(config.exit_code()), "{output:?}");
    let expected_stdout: &[u8] = if config.mode.continues() {
        b"before\ncontinued\n"
    } else {
        b"before\n"
    };
    assert_eq!(output.stdout, expected_stdout, "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert!(
        native_diagnostics.is_empty(),
        "{}",
        String::from_utf8_lossy(&native_diagnostics)
    );

    let (received_config, rows) = global.snapshot();
    assert_eq!(received_config, config);
    if config.mode == Mode::NoApplicationRpc {
        assert_eq!(LifecycleGlobal::no_application_rpc_requests(), 0);
        assert!(rows.is_empty(), "unexpected application request: {rows:?}");
        let witness = fs::read_to_string(config.witness.as_ref().unwrap()).unwrap();
        let first = witness.lines().next().expect("missing constructor witness");
        let pid: i32 = first.split_whitespace().next().unwrap().parse().unwrap();
        assert!(pid > 0);
        assert_ne!(pid as u32, std::process::id());
        let expected = [
            "Constructed selections=1".to_owned(),
            "ThreadState".to_owned(),
            format!("{:?}", Event::StartHook),
            format!("{:?}", Event::PostExecHook),
            format!(
                "{:?}",
                Event::ThreadExit {
                    code: 23,
                    attempts: 0,
                    drops: 0,
                    continued: false,
                }
            ),
            format!("{:?}", Event::ProcessExit { code: 23 }),
        ]
        .map(|event| format!("{pid} {} {event}\n", config.nonce))
        .concat();
        assert_eq!(witness, expected);
        return;
    }
    let pid = rows.first().expect("startup RPC was not received").0;
    assert!(pid > 0);
    assert_ne!(pid as u32, std::process::id());
    assert!(rows.iter().all(|(from, _)| *from == pid));
    let attempts = usize::from(config.mode != Mode::OriginalExit);
    let mut expected = vec![Event::StartHook, Event::PostExecHook];
    if attempts == 1 {
        expected.push(Event::Attempt {
            observed: raw_call(config.trigger_call()),
            requested_replacement: config.replacement().map(raw_call),
        });
    }
    if config.mode.continues() {
        expected.push(Event::Continued {
            result: if config.mode == Mode::SuppressOnce {
                0
            } else {
                i64::from(pid)
            },
        });
    }
    expected.push(Event::ThreadExit {
        code: config.exit_code(),
        attempts,
        drops: attempts,
        continued: config.mode.continues(),
    });
    expected.push(Event::ProcessExit {
        code: config.exit_code(),
    });
    assert_eq!(
        rows.into_iter().map(|(_, event)| event).collect::<Vec<_>>(),
        expected
    );
    // The real wait and complete event order cover ordinary physical cleanup.
    // They do not manufacture or claim a forced duplicate native notification.
}

struct SupervisedChild(Option<Child>);

impl SupervisedChild {
    fn kill_group(&mut self) {
        if let Some(child) = &mut self.0 {
            let process_group = i32::try_from(child.id()).unwrap();
            // SAFETY: pre_exec creates this child's own process group.
            let _ = unsafe { libc::kill(-process_group, libc::SIGKILL) };
            let _ = child.kill();
        }
    }

    fn finish(mut self) -> Output {
        self.0.take().unwrap().wait_with_output().unwrap()
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        self.kill_group();
        if let Some(mut child) = self.0.take() {
            let _ = child.wait();
        }
    }
}

fn output_with_timeout(command: &mut Command) -> Output {
    // Match the original Strace/LiteInst helper's ten-second group kill/reap
    // mechanism; the guard also reaps if the parent encounters another error.
    // SAFETY: this pre-exec closure only calls async-signal-safe setpgid.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = SupervisedChild(Some(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            return child.finish();
        }
        if Instant::now() >= deadline {
            child.kill_group();
            let output = child.finish();
            panic!("caller lifecycle case timed out: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn run_cases(selector: &str, cases: &[Config]) {
    run_cases_using(selector, cases, run_native);
}

fn run_cases_using(selector: &str, cases: &[Config], run: fn(Config, &Path)) {
    if let Some(index) = std::env::var_os(CHILD_CASE) {
        assert_eq!(std::env::var(CHILD_SELECTOR).unwrap(), selector);
        let index: usize = index.to_str().unwrap().parse().unwrap();
        let config = cases.get(index).expect("unknown fixture case").clone();
        let guest = PathBuf::from(std::env::var_os(CHILD_GUEST).unwrap());
        assert!(guest.is_file());
        run(config, &guest);
        println!("{WITNESS}:{selector}:{index}");
        return;
    }
    assert!(std::env::var_os(CHILD_SELECTOR).is_none());
    assert!(std::env::var_os(CHILD_GUEST).is_none());
    let guest = guest_binary();
    for index in 0..cases.len() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", selector, "--nocapture", "--test-threads=1"])
            .env(CHILD_CASE, index.to_string())
            .env(CHILD_SELECTOR, selector)
            .env(CHILD_GUEST, &guest);
        let output = output_with_timeout(&mut command);
        assert!(output.status.success(), "{selector}[{index}]: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            stdout.matches("test result: ok. 1 passed;").count(),
            1,
            "missing/duplicate exact-selector harness result: {stdout}"
        );
        assert_eq!(
            stdout
                .matches(&format!("{WITNESS}:{selector}:{index}\n"))
                .count(),
            1,
            "missing/duplicate native completion witness: {stdout}"
        );
    }
}

fn terminal_cases(mode: Mode) -> Vec<Config> {
    [Terminal::Exit, Terminal::ExitGroup]
        .into_iter()
        .flat_map(|terminal| [23, 0x117].map(|code| Config::new(mode, terminal, code)))
        .collect()
}

#[test]
fn caller_selected_terminal_tail_preserves_actual_status() {
    run_cases(
        "caller_selected_terminal_tail_preserves_actual_status",
        &terminal_cases(Mode::SelectedTail),
    );
}

#[test]
fn caller_original_nonzero_and_masked_status_match_wait() {
    run_cases(
        "caller_original_nonzero_and_masked_status_match_wait",
        &terminal_cases(Mode::OriginalExit),
    );
}

#[test]
fn caller_suppressed_exit_resumes_before_later_consumption() {
    run_cases(
        "caller_suppressed_exit_resumes_before_later_consumption",
        &[Config::new(Mode::SuppressOnce, Terminal::Exit, 23)],
    );
}

#[test]
fn caller_rewrite_away_from_exit_resumes_before_later_consumption() {
    run_cases(
        "caller_rewrite_away_from_exit_resumes_before_later_consumption",
        &[Config::new(Mode::RewriteAway, Terminal::Exit, 23)],
    );
}

#[test]
fn caller_rewrite_to_terminal_preserves_actual_status() {
    run_cases(
        "caller_rewrite_to_terminal_preserves_actual_status",
        &[23, 0x117].map(|code| Config::new(Mode::RewriteToTerminal, Terminal::ExitGroup, code)),
    );
}

#[test]
fn caller_without_application_rpc_constructs_and_consumes_the_real_tool() {
    let directory = temporary_directory("caller-no-rpc-witness-");
    run_cases(
        "caller_without_application_rpc_constructs_and_consumes_the_real_tool",
        &[Config::without_application_rpc(
            directory.path().join("hooks"),
        )],
    );
}

fn inherit_query_spoof_filter() {
    let before = fs::read_to_string("/proc/thread-self/status").unwrap();
    assert!(
        reverie::pidfd_self::status_has_exactly_seccomp_filters(&before, 0),
        "query-spoof setup requires an initially unfiltered helper"
    );
    let statement = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let mut filter = [
        statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0),
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 3,
            k: libc::SYS_prctl as u32,
        },
        // seccomp_data.args[0], the low 32 bits of prctl's int option.
        statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 16),
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::PR_GET_SECCOMP as u32,
        },
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ERRNO),
        statement(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: this exec-isolated helper owns the filter; only its prctl query
    // is spoofed. Normal launch, I/O, wait, cleanup and exit remain allowed.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &program
            ),
            0
        );
        assert_eq!(libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0), 0);
    }
    let status = fs::read_to_string("/proc/thread-self/status").unwrap();
    assert!(reverie::pidfd_self::status_has_exactly_seccomp_filters(
        &status, 1
    ));
    println!("CALLER_QUERY_SPOOF_ESTABLISHED:query=0:mode=2:filters=1");
}

fn run_query_spoofed_native(config: Config, guest: &Path) {
    assert_eq!(config.mode, Mode::NoApplicationRpc);
    inherit_query_spoof_filter();
    // Install before creating any server/runner threads, so the actual native
    // root inherits this filter. The supervising test parent is unfiltered.
    let (result, diagnostics) = launch_native(&config, guest);
    // The public runner must reap its actual child even when admission fails.
    // This helper created no other child (the guest was compiled by its parent).
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    let error = match result {
        Err(error) => error,
        Ok((output, global)) => panic!(
            "filtered caller unexpectedly completed: {output:?}; application_requests={}; global={:?}; witness={:?}; diagnostics={}",
            LifecycleGlobal::no_application_rpc_requests(),
            global.snapshot(),
            fs::read_to_string(config.witness.as_ref().unwrap()),
            String::from_utf8_lossy(&diagnostics),
        ),
    };
    assert!(
        error
            .to_string()
            .contains("caller-inherited-seccomp-unsupported"),
        "wrong refusal: {error}; output={:?}; diagnostics={}",
        failed_run_output(&error),
        String::from_utf8_lossy(&diagnostics),
    );
    assert_eq!(LifecycleGlobal::no_application_rpc_requests(), 0);
    let captured = failed_run_output(&error).expect("refusal retains actual cleanup output/status");
    let status = captured.status.expect("actual reaped root status");
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    assert_eq!(status.code(), None);
    assert!(
        captured.stdout.is_empty(),
        "guest ran before refusal: {captured:?}"
    );
    assert!(
        captured.stderr.is_empty(),
        "unexpected guest stderr: {captured:?}"
    );
    assert!(
        diagnostics.is_empty(),
        "unexpected native diagnostic: {diagnostics:?}"
    );
    assert!(
        !config.witness.as_ref().unwrap().exists(),
        "Tool was constructed before refusal"
    );
}

#[test]
fn caller_refuses_inherited_filter_that_spoofs_its_self_query() {
    let directory = temporary_directory("caller-query-spoof-witness-");
    run_cases_using(
        "caller_refuses_inherited_filter_that_spoofs_its_self_query",
        &[Config::without_application_rpc(
            directory.path().join("hooks"),
        )],
        run_query_spoofed_native,
    );
}
