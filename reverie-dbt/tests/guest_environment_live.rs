/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! A DBT guest sees the environment it was given, before and after an exec,
//! and the runtime still finds its private variables.
//!
//! DynamoRIO's early injection runs the guest on the stack the kernel built for
//! drrun's exec, so the guest's initial environment used to carry DynamoRIO's
//! variables (`DYNAMORIO_CONFIGDIR`, `DYNAMORIO_EXE_PATH`, ...) and the
//! caller's private ones, including a coordinator socket path that is random
//! per run. The bundled DynamoRIO removes the selected variables before the
//! guest's first instruction, and passes them on to the children it follows,
//! which remove them again. The client keeps its own copy for the runtime.
//! Arbitrary `HERMIT_DBT_*` application variables remain guest-visible.
//!
//! This runs [`tests/fixtures/guest_environment.c`] natively with an exact
//! environment, and under the client with the same environment plus
//! `HERMIT_DBT_COUNTER2`, coordinated by [`Counter2Global`]. The parent forks a
//! child that execs the fixture again by its path, and that child execs it
//! once more through `/proc/self/exe`; then the parent forks a child that
//! execs it with a NULL argv, and one that execs it with a read-only argv
//! whose `argv[0]` is `/proc/self/exe` (DynamoRIO fixes that argument up when
//! it redirects the exec). Every image must print the native `environ`, the
//! native non-empty `/proc/self/environ` entries, the native `AT_EXECFN`, and
//! whether that string is on the stack, and all four processes must report to
//! the coordinator at exit: the parent reaches it only through the client's
//! copy of the socket variable, and each exec'd child only through DynamoRIO
//! passing the hidden variables on (a child that escaped the client would not
//! report at all).
//!
//! The second test runs a copy of the fixture under a path longer than
//! DynamoRIO's own library path, so `AT_EXECFN` cannot reuse the kernel's exec
//! filename storage and DynamoRIO places it in a private mapping instead: the
//! one expected difference is "execfn-on-stack 0" where native prints 1.
//!
//! `/proc/self/environ` is compared without its empty entries: the kernel's
//! range still covers the removed strings' bytes, which are erased to NULs, so
//! its length differs from native (a known residual). The non-empty entries
//! carry every non-NUL byte, so no private byte can pass unseen.
//!
//! `#[ignore]`d like the other live tests; run it with:
//!
//! ```text
//! DYNAMORIO_HOME=<...> REVERIE_DBT_CLIENT=<...>/libreverie_dbt_client.so \
//!   cargo test -p reverie-dbt --test guest_environment_live -- --ignored --nocapture \
//!     --skip executable_frontend::supervised_launch_worker --test-threads=1
//! ```
//!
//! Only the private self-exec worker is excluded; it is not an assurance case.
//! Its owned-specification assertions still apply when the tests invoke it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;
use std::sync::OnceLock;

use reverie_dbt::Counter2Global;
use reverie_dbt::DbtRunner;

/// Compiles the fixture once; both tests use it, and they may run at once.
fn compile_fixture() -> PathBuf {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(compile_fixture_now).clone()
}

fn compile_fixture_now() -> PathBuf {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/guest_environment.c");
    let binary = Path::new(env!("CARGO_TARGET_TMPDIR")).join("guest_environment");
    let compile = Command::new(std::env::var("CC").unwrap_or_else(|_| "cc".into()))
        .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap_or_else(|error| panic!("failed to start the C compiler: {error}"));
    assert!(
        compile.status.success(),
        "failed to compile {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&compile.stderr)
    );
    binary
}

fn stdout_of(label: &str, output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{label} exited with {}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

/// Runs `fixture` natively and under the client; returns both stdouts after
/// checking the native control and the coordinator's process count.
async fn native_and_dbt(fixture: &Path) -> (String, String) {
    native_and_dbt_with_privacy(fixture, &[], &[], |runner| runner).await
}

async fn native_and_dbt_with_privacy(
    fixture: &Path,
    extra_public: &[(&str, &str)],
    extra_private: &[(&str, &str)],
    configure: impl FnOnce(DbtRunner) -> DbtRunner,
) -> (String, String) {
    let mut given = BTreeMap::from([
        (OsString::from("GUEST_A"), OsString::from("1")),
        (OsString::from("GUEST_B"), OsString::from("two words")),
        (
            OsString::from("HERMIT_APP_VISIBLE"),
            OsString::from("public"),
        ),
        (
            OsString::from("HERMIT_DBT_APP_VISIBLE"),
            OsString::from("public"),
        ),
        (
            OsString::from("HERMIT_DBT_RPC_SOCKET_USER"),
            OsString::from("public"),
        ),
    ]);
    given.extend(
        extra_public
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );

    let native = Command::new(fixture)
        .env_clear()
        .envs(&given)
        .output()
        .unwrap_or_else(|error| panic!("failed to run the fixture natively: {error}"));
    let native = stdout_of("native run", &native);
    // The control: the fixture printed both entries in every image.
    for image in ["parent", "child", "grandchild", "emptyargv", "readonly"] {
        for kind in ["env", "procenv"] {
            let line = format!("{image} {kind} GUEST_B=two words");
            assert!(
                native.lines().any(|printed| printed == line),
                "the native run did not print `{line}`:\n{native}"
            );
        }
    }

    let mut private = given.clone();
    private.insert(OsString::from("HERMIT_DBT_COUNTER2"), OsString::from("1"));
    private.extend(
        extra_private
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    // The exec leaves the pre-exec image's background thread behind (it
    // predates this test); terminating the process group keeps it from holding
    // stdout open.
    let runner = DbtRunner::from_env()
        .expect("DYNAMORIO_HOME (or DynamoRIO_DIR) and REVERIE_DBT_CLIENT must be set")
        .private_environment_key("HERMIT_DBT_COUNTER2")
        .expect("valid Tool environment key")
        .terminate_process_group_on_exit(true);
    let (dbt, global) = configure(runner)
        .output_with_environment_and_global::<Counter2Global>(&Command::new(fixture), &private, ())
        .await
        .unwrap_or_else(|error| panic!("the DBT run failed: {error}"));
    let dbt = stdout_of("DBT run", &dbt);
    let (_, processes, _) = global.snapshot();
    assert_eq!(
        processes, 4,
        "the parent and its three exec'd children must all report to the \
         coordinator through their private variables\n{dbt}"
    );
    (native, dbt)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
async fn selected_private_keys_and_prefixes_preserve_public_neighbors_across_exec() {
    let fixture = compile_fixture();
    let (native, dbt) = native_and_dbt_with_privacy(
        &fixture,
        &[("TOOL_SECRET_SUFFIX", "public"), ("TOOL_PUBLIC", "public")],
        &[
            ("TOOL_SECRET", "private key"),
            ("TOOL_PRIVATE_ONE", "private prefix one"),
            ("TOOL_PRIVATE_TWO", "private prefix two"),
        ],
        |runner| {
            runner
                .private_environment_key("TOOL_SECRET")
                .unwrap()
                .private_environment_prefix("TOOL_PRIVATE_")
                .unwrap()
        },
    )
    .await;
    assert_eq!(
        dbt, native,
        "the DBT guest's environment differs from the native one"
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
async fn guest_sees_only_its_own_environment_and_the_runtime_keeps_its_variables() {
    let fixture = compile_fixture();
    let (native, dbt) = native_and_dbt(&fixture).await;
    assert_eq!(
        dbt, native,
        "the DBT guest's environment differs from the native one"
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built DynamoRIO and the reverie-dbt native client; run with --ignored"]
async fn a_program_path_longer_than_dynamorios_keeps_the_native_environment() {
    let fixture = compile_fixture();
    // About 450 bytes: longer than DynamoRIO's library path (the kernel's exec
    // filename) and shorter than DynamoRIO's 512-byte MAXIMUM_PATH, which
    // drrun enforces. If the path still fit the kernel's storage, DBT would
    // print "execfn-on-stack 1" and the comparison below would fail.
    let mut directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let mut level = 0;
    while directory.as_os_str().len() < 430 {
        directory.push(format!("{level}{}", "d".repeat(39)));
        level += 1;
    }
    std::fs::create_dir_all(&directory).expect("create the long program directory");
    let long = directory.join("guest_environment");
    assert!(long.as_os_str().len() < 512, "{}", long.display());
    std::fs::copy(&fixture, &long).expect("copy the fixture to the long path");
    let (native, dbt) = native_and_dbt(&long).await;

    let expected = native.replace("execfn-on-stack 1", "execfn-on-stack 0");
    assert_ne!(
        expected, native,
        "the native run printed no stack placement"
    );
    assert_eq!(
        dbt, expected,
        "the DBT guest's environment differs from the native one beyond the \
         private-mapping placement of a long AT_EXECFN"
    );
}

// Executable selection is tested independently of the environment tests above.
// The identity mode prints only controlled argv/AT_EXECFN bytes, never environ.
mod executable_frontend {
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Child;
    use std::process::Command;
    use std::process::Stdio;
    use std::time::Duration;
    use std::time::Instant;

    use reverie_dbt::Counter2Global;
    use reverie_dbt::DbtRunner;
    use serde::Deserialize;
    use serde::Serialize;

    const WORKER: &str = "REVERIE_DBT_EXECUTABLE_TEST_SPEC";
    const SELECTOR: &str = "executable_frontend::supervised_launch_worker";

    #[derive(Serialize, Deserialize)]
    struct Spec {
        name: String,
        mode: String,
        program: Vec<u8>,
        args: Vec<Vec<u8>>,
        cwd: PathBuf,
        path: Option<Vec<u8>>,
        arg0: Option<Vec<u8>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Observation {
        errno: Option<i32>,
        error: Option<String>,
        error_kind: Option<String>,
        status: Option<i32>,
        signal: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        tool_diagnostics: Vec<u8>,
        processes: Option<u64>,
        reaped: bool,
    }

    fn bytes(path: impl AsRef<OsStr>) -> Vec<u8> {
        path.as_ref().as_bytes().to_vec()
    }

    fn spec(name: &str, program: impl AsRef<OsStr>, cwd: &Path, path: Option<&OsStr>) -> Spec {
        Spec {
            name: name.into(),
            mode: "native".into(),
            program: bytes(program),
            args: vec![
                b"--launch-identity".to_vec(),
                vec![],
                b"space arg".to_vec(),
                vec![255, 254, 97],
            ],
            cwd: cwd.into(),
            path: path.map(bytes),
            arg0: None,
        }
    }

    struct OwnedChild(Option<Child>);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                // This is exactly the group created for this test worker.
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn run(spec: &Spec) -> Observation {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("spec.json");
        std::fs::write(&input, serde_json::to_vec(spec).unwrap()).unwrap();
        let stdout = directory.path().join("worker.stdout");
        let stderr = directory.path().join("worker.stderr");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                SELECTOR,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(WORKER, &input)
            .env_remove("HERMIT_DBT_RPC_SOCKET")
            .env_remove("REVERIE_DBT_TOOL")
            .stdout(File::create_new(&stdout).unwrap())
            .stderr(File::create_new(&stderr).unwrap())
            .process_group(0);
        let mut child = OwnedChild(Some(command.spawn().unwrap()));
        let group = child.0.as_ref().unwrap().id() as i32;
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "{} / {} exceeded the original 10-second child bound",
                spec.name,
                spec.mode
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "{} / {}: {status}; stdout={:?}; stderr={:?}",
            spec.name,
            spec.mode,
            std::fs::read(&stdout).unwrap(),
            std::fs::read(&stderr).unwrap()
        );
        // The worker waits its native root and adopted helper descendants before
        // writing the record. No remaining process may retain its owned group.
        assert_eq!(unsafe { libc::kill(-group, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        child.0.take().unwrap().wait().unwrap();
        let observation: Observation =
            serde_json::from_slice(&std::fs::read(directory.path().join("result.json")).unwrap())
                .unwrap();
        assert!(observation.reaped);
        println!(
            "EXECUTABLE_CASE:{}",
            serde_json::json!({
                "case": spec.name, "mode": spec.mode, "requested_launch": spec,
                "elapsed_seconds": start.elapsed().as_secs_f64(),
                "bound_seconds": 10, "group_empty": true, "observation": observation,
            })
        );
        observation
    }

    #[test]
    #[ignore = "private worker; invoked by each bounded executable-selection case"]
    fn supervised_launch_worker() {
        let input = PathBuf::from(std::env::var_os(WORKER).expect("owned test specification"));
        let spec: Spec = serde_json::from_slice(&std::fs::read(&input).unwrap()).unwrap();
        // Adopt helpers so completion includes actual retirement, not just an
        // empty parent-side pipe or a detached helper.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let mut command = Command::new(OsString::from_vec(spec.program));
        command
            .args(spec.args.into_iter().map(OsString::from_vec))
            .current_dir(&spec.cwd)
            .env_clear();
        if let Some(path) = spec.path {
            command.env("PATH", OsString::from_vec(path));
        }
        if let Some(arg0) = spec.arg0 {
            command.arg0(OsString::from_vec(arg0));
        }
        let diagnostic_path = input.with_file_name("tool-diagnostics");
        let diagnostics = File::create_new(&diagnostic_path).unwrap();
        let mut processes = None;
        let result = if spec.mode == "dbt" || spec.mode == "dbt-relative-frontend" {
            command.env("HERMIT_DBT_COUNTER2", "1");
            let runner = if spec.mode == "dbt-relative-frontend" {
                // Use the real SDK layout: a lone frontend symlink is not a
                // relocated SDK. This isolated worker has no async runtime yet.
                std::env::set_current_dir(reverie_dbt::bundled_drrun_path().parent().unwrap())
                    .unwrap();
                DbtRunner::new(
                    "drrun",
                    PathBuf::from(std::env::var_os("REVERIE_DBT_CLIENT").unwrap()),
                )
            } else {
                DbtRunner::from_env()
            }
            .unwrap()
            .private_environment_key("HERMIT_DBT_COUNTER2")
            .unwrap()
            .diagnostic_file(&diagnostics)
            .unwrap();
            let result = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(
                    runner.output_with_environment_and_global::<Counter2Global>(
                        &command,
                        &command
                            .get_envs()
                            .filter_map(|(key, value)| {
                                value.map(|value| (key.to_owned(), value.to_owned()))
                            })
                            .collect(),
                        (),
                    ),
                );
            result.map(|(output, global)| {
                let (syscalls, count, _) = global.snapshot();
                assert_eq!(
                    count, 1,
                    "actual Counter2 process report; raw output: {output:?}"
                );
                assert!(syscalls > 0, "actual instrumented process");
                processes = Some(count);
                output
            })
        } else {
            assert!(spec.mode == "native" || spec.mode == "frontend");
            command.output()
        };
        // Wait only children owned by this isolated worker. The outer 10-second
        // supervisor bounds a stuck helper and kills the entire owned group.
        loop {
            let waited = unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) };
            if waited == -1 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
                break;
            }
        }
        let mut observed = Observation {
            errno: None,
            error: None,
            error_kind: None,
            status: None,
            signal: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            tool_diagnostics: std::fs::read(diagnostic_path).unwrap(),
            processes,
            reaped: true,
        };
        match result {
            Ok(output) => {
                observed.status = output.status.code();
                observed.signal = output.status.signal();
                observed.stdout = output.stdout;
                observed.stderr = output.stderr;
            }
            Err(error) => {
                observed.errno = error.raw_os_error();
                observed.error_kind = Some(format!("{:?}", error.kind()));
                observed.error = Some(error.to_string());
            }
        }
        serde_json::to_writer(
            File::create_new(input.with_file_name("result.json")).unwrap(),
            &observed,
        )
        .unwrap();
    }

    fn pair(
        mut case: Spec,
        expected_status: Option<i32>,
        expected_errno: Option<i32>,
    ) -> Observation {
        let native = run(&case);
        case.mode = "dbt".into();
        let dbt = run(&case);
        assert_eq!(
            native.status, expected_status,
            "{} native: {native:?}",
            case.name
        );
        assert_eq!(
            native.errno, expected_errno,
            "{} native: {native:?}",
            case.name
        );
        assert_eq!(dbt.errno, native.errno, "{}: {dbt:?}", case.name);
        assert_eq!(dbt.status, native.status, "{}: {dbt:?}", case.name);
        assert_eq!(dbt.signal, native.signal);
        assert_eq!(dbt.stdout, native.stdout, "{} stdout", case.name);
        assert_eq!(dbt.stderr, native.stderr, "{} stderr", case.name);
        if expected_errno.is_some() {
            assert!(dbt.stdout.is_empty());
            assert!(
                dbt.tool_diagnostics.is_empty(),
                "refused before client entry"
            );
            assert_eq!(dbt.processes, None);
        } else {
            assert_eq!(dbt.processes, Some(1));
            // Coordinated Counter2 sends its typed process report through RPC.
            // Only its uncoordinated path emits a textual summary here; the
            // separate CLI prints its own global summary after this call.
            assert!(
                dbt.tool_diagnostics.is_empty(),
                "coordinated Counter2 must not emit diagnostic text: {:?}",
                dbt.tool_diagnostics
            );
        }
        dbt
    }

    fn fixture(directory: &Path, tag: i32) -> PathBuf {
        let binary = directory.join(format!("image-{tag}"));
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/guest_environment.c");
        let output = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()))
            .args(["-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Werror"])
            .arg(format!("-DLAUNCH_IMAGE_TAG={tag}"))
            .arg(source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(output.status.success(), "C fixture: {output:?}");
        binary
    }

    fn copy(source: &Path, destination: &Path, mode: u32) {
        std::fs::copy(source, destination).unwrap();
        std::fs::set_permissions(destination, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn script(path: &Path, interpreter: &Path, mode: u32) {
        let mut text = b"#!".to_vec();
        text.extend_from_slice(interpreter.as_os_str().as_bytes());
        text.extend_from_slice(b"\n");
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn identity(observed: &Observation, tag: i32, argv0: &OsStr, execfn: &OsStr) {
        let output = String::from_utf8(observed.stdout.clone()).unwrap();
        let line = |kind: &str, value: &OsStr| {
            let hex: String = value
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            format!("launch {kind} 0 {} {hex}", value.len())
        };
        assert!(output.lines().any(|s| s == format!("launch image {tag}")));
        assert!(output.lines().any(|s| s == line("argv", argv0)), "{output}");
        assert!(
            output.lines().any(|s| s == line("execfn", execfn)),
            "{output}"
        );
        assert_eq!(observed.status, Some(tag));
        assert!(
            observed.stderr.is_empty(),
            "identity fixture writes no stderr"
        );
    }

    #[test]
    #[ignore = "requires the current attested SDK and actual prototype client"]
    fn explicit_executable_path_matches_native_elf_identity() {
        let root = tempfile::tempdir().unwrap();
        let image17 = fixture(root.path(), 17);
        let image23 = fixture(root.path(), 23);
        let cwd = root.path().join("cwd");
        let bin = cwd.join("path-bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir(cwd.join("denied")).unwrap();
        copy(&image17, &cwd.join("probe"), 0o700);
        copy(&image23, &bin.join("probe"), 0o700);
        copy(&image23, &cwd.join("denied/probe"), 0o600);
        std::os::unix::fs::symlink("path-bin/probe", cwd.join("guest-link")).unwrap();
        std::os::unix::fs::symlink("probe", bin.join("probe-link")).unwrap();
        let rows = [
            (
                "absolute",
                bin.join("probe"),
                bin.clone().into_os_string(),
                bin.join("probe"),
                23,
            ),
            (
                "relative",
                PathBuf::from("./path-bin/probe"),
                "unused".into(),
                PathBuf::from("./path-bin/probe"),
                23,
            ),
            (
                "PATH-shadow",
                "probe".into(),
                bin.clone().into_os_string(),
                bin.join("probe"),
                23,
            ),
            (
                "relative-PATH",
                "probe".into(),
                "path-bin".into(),
                "path-bin/probe".into(),
                23,
            ),
            (
                "empty-component",
                "probe".into(),
                ":path-bin".into(),
                "probe".into(),
                17,
            ),
            (
                "trailing-slash",
                "probe".into(),
                "path-bin/".into(),
                "path-bin//probe".into(),
                23,
            ),
            (
                "explicit-symlink",
                "./guest-link".into(),
                "unused".into(),
                "./guest-link".into(),
                23,
            ),
            (
                "PATH-symlink",
                "probe-link".into(),
                "path-bin".into(),
                "path-bin/probe-link".into(),
                23,
            ),
            (
                "denied-first",
                "probe".into(),
                "denied:path-bin".into(),
                "path-bin/probe".into(),
                23,
            ),
        ];
        for (name, program, path, execfn, tag) in rows {
            let observed = pair(spec(name, &program, &cwd, Some(&path)), Some(tag), None);
            identity(&observed, tag, program.as_os_str(), execfn.as_os_str());
        }
        for name in ["-probe", "-v", "-verbose"] {
            copy(&image23, &cwd.join(name), 0o700);
            let observed = pair(spec(name, name, &cwd, Some(OsStr::new(""))), Some(23), None);
            identity(&observed, 23, OsStr::new(name), OsStr::new(name));
        }
        let mut unset = spec("unset-PATH", "true", &cwd, None);
        unset.args.clear();
        pair(unset, Some(0), None);
    }

    #[test]
    #[ignore = "requires the current attested SDK and actual prototype client"]
    fn execute_access_matches_native_permission_refusals() {
        let root = tempfile::tempdir().unwrap();
        let image = fixture(root.path(), 23);
        for (name, is_script) in [("elf", false), ("script", true)] {
            let target = root.path().join(name);
            if is_script {
                script(&target, Path::new("/bin/echo"), 0o600);
            } else {
                copy(&image, &target, 0o600);
            }
            pair(
                spec(name, &target, root.path(), None),
                None,
                Some(libc::EACCES),
            );
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
            pair(
                spec(&format!("{name}-executable"), &target, root.path(), None),
                Some(if is_script { 0 } else { 23 }),
                None,
            );
        }
        pair(
            spec("directory", root.path(), root.path(), None),
            None,
            Some(libc::EACCES),
        );
        pair(
            spec("missing", root.path().join("absent"), root.path(), None),
            None,
            Some(libc::ENOENT),
        );
        let first = root.path().join("first");
        let later = root.path().join("later");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&later).unwrap();
        copy(&image, &later.join("probe"), 0o700);
        let candidate = first.join("probe");
        let interpreter = root.path().join("denied-interpreter");
        copy(Path::new("/bin/echo"), &interpreter, 0o600);
        for (name, final_errno) in [
            ("directory", libc::EACCES),
            ("denied", libc::EACCES),
            ("missing-interpreter", libc::ENOENT),
            ("denied-interpreter", libc::EACCES),
        ] {
            match name {
                "directory" => std::fs::create_dir(&candidate).unwrap(),
                "denied" => copy(&image, &candidate, 0o600),
                "missing-interpreter" => script(&candidate, &root.path().join("absent"), 0o700),
                _ => script(&candidate, &interpreter, 0o700),
            }
            pair(
                spec(
                    &format!("{name}-then-executable"),
                    "probe",
                    root.path(),
                    Some(OsStr::new("first:later")),
                ),
                Some(23),
                None,
            );
            pair(
                spec(
                    &format!("{name}-exhausted"),
                    "probe",
                    root.path(),
                    Some(OsStr::new("first:missing")),
                ),
                None,
                Some(final_errno),
            );
            if name == "directory" {
                std::fs::remove_dir(&candidate).unwrap();
            } else {
                std::fs::remove_file(&candidate).unwrap();
            }
        }
    }

    #[test]
    #[ignore = "requires the current attested SDK and actual prototype client"]
    fn invalid_cwd_precedes_executable_access_errors() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("denied-script");
        script(&target, Path::new("/bin/echo"), 0o600);
        let non_directory = root.path().join("not-a-directory");
        std::fs::write(&non_directory, b"not a directory").unwrap();
        // Collect all actual outcomes before checking parity, so one mismatch
        // does not hide the other cwd cases from the retained observations.
        let observations: Vec<_> = [
            ("missing-cwd", root.path().join("missing"), libc::ENOENT),
            ("non-directory-cwd", non_directory, libc::ENOTDIR),
            ("valid-cwd", root.path().to_path_buf(), libc::EACCES),
        ]
        .into_iter()
        .map(|(name, cwd, errno)| {
            let mut case = spec(name, &target, &cwd, None);
            let native = run(&case);
            case.mode = "dbt".into();
            (name, errno, native, run(&case))
        })
        .collect();
        for (name, errno, native, dbt) in observations {
            assert_eq!(native.errno, Some(errno), "{name}: {native:?}");
            assert_eq!(dbt.errno, native.errno, "{name}: {dbt:?}");
            for observed in [native, dbt] {
                assert_eq!(observed.status, None);
                assert_eq!(observed.signal, None);
                assert!(observed.stdout.is_empty());
                assert!(observed.stderr.is_empty());
                assert!(observed.tool_diagnostics.is_empty());
                assert_eq!(observed.processes, None);
                assert!(observed.reaped);
            }
        }
    }

    #[test]
    #[ignore = "requires non-root without DAC read override, current SDK and actual prototype client"]
    fn unreadable_executable_is_a_terminal_named_refusal() {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "execute-only regression requires non-root execution; root is not coverage"
        );
        let root = tempfile::tempdir().unwrap();
        let image17 = fixture(root.path(), 17);
        let image23 = fixture(root.path(), 23);
        let first = root.path().join("first");
        let later = root.path().join("later");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&later).unwrap();
        let candidate = first.join("probe");
        copy(&image17, &candidate, 0o111);
        copy(&image23, &later.join("probe"), 0o700);
        assert_eq!(
            File::open(&candidate).unwrap_err().raw_os_error(),
            Some(libc::EACCES),
            "execute-only regression requires actual read denial, not DAC override"
        );
        println!(
            "EXECUTE_ONLY_DOMAIN:euid={};read_errno={}",
            unsafe { libc::geteuid() },
            libc::EACCES
        );
        let observations: Vec<_> = [
            spec(
                "execute-only-PATH",
                "probe",
                root.path(),
                Some(OsStr::new("first:later")),
            ),
            spec("execute-only-explicit", &candidate, root.path(), None),
        ]
        .into_iter()
        .map(|mut case| {
            let native = run(&case);
            case.mode = "dbt".into();
            let dbt = run(&case);
            (case, native, dbt)
        })
        .collect();
        for (case, native, dbt) in observations {
            assert_eq!(native.status, Some(17), "{}: {native:?}", case.name);
            assert_eq!(native.errno, None);
            let selected = if case.path.is_some() {
                OsStr::new("first/probe")
            } else {
                candidate.as_os_str()
            };
            identity(&native, 17, OsStr::from_bytes(&case.program), selected);
            assert_eq!(
                dbt.error_kind.as_deref(),
                Some("Unsupported"),
                "{}: {dbt:?}",
                case.name
            );
            let error = dbt.error.as_deref().unwrap();
            assert!(
                error.contains("DBT requires a readable executable image"),
                "{error}"
            );
            assert!(
                error.contains("Permission denied"),
                "truthful read failure: {error}"
            );
            assert_eq!(dbt.errno, None, "read denial is not execute denial");
            assert_eq!(dbt.status, None, "must not launch the later image");
            assert_eq!(dbt.signal, None);
            assert!(dbt.stdout.is_empty());
            assert!(dbt.stderr.is_empty());
            assert!(
                dbt.tool_diagnostics.is_empty(),
                "refused before client entry"
            );
            assert_eq!(dbt.processes, None, "no Tool process report");
            assert!(dbt.reaped);
        }
    }

    #[test]
    #[ignore = "requires the current attested SDK and actual prototype client"]
    fn simple_shebang_arguments_match_native_reference() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let target = bin.join("script");
        // Linux preserves a single optional argument. Multiword tails and script
        // AT_EXECFN are separate existing limitations, not claimed here.
        std::fs::write(&target, b"#!/bin/echo optional-token\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink("script", bin.join("link")).unwrap();
        for program in [
            target.into_os_string(),
            "./bin/script".into(),
            "script".into(),
            "link".into(),
        ] {
            pair(
                spec(
                    "simple-shebang",
                    &program,
                    root.path(),
                    Some(OsStr::new("bin")),
                ),
                Some(0),
                None,
            );
        }
    }
    fn frontend(name: &str, binary: &Path, cwd: &Path, arguments: Vec<OsString>) -> Spec {
        let mut case = spec(name, binary, cwd, Some(OsStr::new("")));
        case.mode = "frontend".into();
        case.args = arguments.iter().map(bytes).collect();
        case
    }

    fn selected_frontend(name: &str, image: &Path, cwd: &Path, arg0: &OsStr) -> Spec {
        frontend(
            name,
            reverie_dbt::bundled_drrun_path(),
            cwd,
            vec![
                "-quiet".into(),
                "-app_path".into(),
                image.as_os_str().into(),
                "--".into(),
                arg0.into(),
                "--launch-identity".into(),
            ],
        )
    }

    fn refused(case: &Spec, diagnostic: &str) {
        let observed = run(case);
        assert!(observed.error.is_none(), "{observed:?}");
        assert_ne!(observed.status, Some(0), "{observed:?}");
        assert!(
            observed.stdout.is_empty(),
            "application must not enter: {observed:?}"
        );
        let stderr = String::from_utf8(observed.stderr).unwrap();
        assert!(stderr.contains(diagnostic), "{diagnostic}: {stderr}");
        assert!(!stderr.contains("launch image"), "{stderr}");
    }

    #[test]
    #[ignore = "requires the current attested SDK"]
    fn explicit_executable_path_preserves_frontend_argv_zero() {
        let root = tempfile::tempdir().unwrap();
        let image = fixture(root.path(), 23);
        let mut native = spec(
            "frontend-arg0-native",
            &image,
            root.path(),
            Some(OsStr::new("")),
        );
        native.args = vec![b"--launch-identity".to_vec()];
        native.arg0 = Some(b"chosen-argv0".to_vec());
        let reference = run(&native);
        let observed = run(&selected_frontend(
            "frontend-arg0",
            &image,
            root.path(),
            OsStr::new("chosen-argv0"),
        ));
        assert_eq!(observed.stdout, reference.stdout);
        assert_eq!(observed.stderr, reference.stderr);
        identity(&observed, 23, OsStr::new("chosen-argv0"), image.as_os_str());

        copy(&image, &root.path().join("--"), 0o700);
        let mut native = spec(
            "literal-delimiter-native",
            "--",
            root.path(),
            Some(OsStr::new("")),
        );
        native.args = vec![b"--launch-identity".to_vec()];
        native.arg0 = Some(b"chosen-argv0".to_vec());
        let reference = run(&native);
        let mut literal = selected_frontend(
            "literal-delimiter",
            Path::new("--"),
            root.path(),
            OsStr::new("chosen-argv0"),
        );
        let quiet = run(&literal);
        assert_eq!(quiet.stdout, reference.stdout);
        assert_eq!(quiet.stderr, reference.stderr);
        // The literal value -- is consumed by BOTH parser passes; the following
        // genuine -v must still enable information records.
        literal.name = "literal-delimiter-followed-by-verbosity".into();
        literal.args = vec![
            b"-app_path".to_vec(),
            b"--".to_vec(),
            b"-v".to_vec(),
            b"--".to_vec(),
            b"chosen-argv0".to_vec(),
            b"--launch-identity".to_vec(),
        ];
        let verbose = run(&literal);
        assert_eq!(verbose.stdout, reference.stdout);
        assert_eq!(verbose.status, Some(23));
        let stderr = String::from_utf8(verbose.stderr).unwrap();
        assert!(stderr.contains("INFO:"), "{stderr}");
        assert!(stderr.contains("app cmdline:"), "{stderr}");
    }

    #[test]
    #[ignore = "requires the current attested SDK"]
    fn explicit_executable_path_refuses_invalid_frontend_arguments() {
        let root = tempfile::tempdir().unwrap();
        let image = fixture(root.path(), 23);
        let drrun = reverie_dbt::bundled_drrun_path();
        for help in ["-h", "--help"] {
            let observed = run(&frontend(help, drrun, root.path(), vec![help.into()]));
            assert_eq!(observed.status, Some(0), "{observed:?}");
            let all = [observed.stdout, observed.stderr].concat();
            let help = String::from_utf8(all).unwrap();
            for text in [
                "-app_path <path>",
                "no PATH search",
                "argv[0]",
                "No execute-access check",
                "fewer than 512",
                "-attach",
            ] {
                assert!(help.contains(text), "missing {text}: {help}");
            }
        }
        let cases: Vec<(&str, Vec<OsString>, &str)> = vec![
            (
                "missing",
                vec!["-app_path".into()],
                "requires a nonempty path argument",
            ),
            (
                "empty",
                vec!["-app_path".into(), "".into(), "--".into(), "guest".into()],
                "requires a nonempty path argument",
            ),
            (
                "duplicate",
                vec![
                    "-app_path".into(),
                    image.clone().into(),
                    "-app_path".into(),
                    image.clone().into(),
                    "--".into(),
                    "guest".into(),
                ],
                "specified more than once",
            ),
            (
                "no-application",
                vec!["-app_path".into(), image.clone().into()],
                "no app specified",
            ),
            (
                "misplaced",
                vec![
                    "-disable_rseq".into(),
                    "-app_path".into(),
                    image.clone().into(),
                    "--".into(),
                    "guest".into(),
                ],
                "must precede DR runtime options",
            ),
            (
                "nonexistent",
                vec![
                    "-app_path".into(),
                    root.path().join("absent").into(),
                    "--".into(),
                    "guest".into(),
                ],
                "regular readable ELF image",
            ),
        ];
        for (name, arguments, diagnostic) in cases {
            refused(&frontend(name, drrun, root.path(), arguments), diagnostic);
        }

        let plain = root.path().join("plain");
        std::fs::write(&plain, b"not an ELF image\n").unwrap();
        refused(
            &selected_frontend("non-ELF", &plain, root.path(), OsStr::new("guest")),
            "readable ELF image",
        );
        let fifo = root.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        refused(
            &selected_frontend(
                "FIFO-before-header-open",
                &fifo,
                root.path(),
                OsStr::new("guest"),
            ),
            "regular readable ELF image",
        );

        let marker = root.path().join("native-tool-entered");
        let tool = root.path().join("native-tool");
        std::fs::write(
            &tool,
            format!("#!/bin/sh\nprintf entered > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(
            root.path().join("owned.drrun64"),
            format!("FRONTEND_ABS={}\n", tool.display()),
        )
        .unwrap();
        refused(
            &frontend(
                "native-tool-conflict",
                drrun,
                root.path(),
                vec![
                    "-app_path".into(),
                    image.clone().into(),
                    "-tool_dir".into(),
                    root.path().into(),
                    "-t".into(),
                    "owned".into(),
                    "--".into(),
                    "guest".into(),
                ],
            ),
            "remove it when using -attach or a tool's native frontend",
        );
        assert!(!marker.exists());

        let sleeper = Command::new("/bin/sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let sleeper = OwnedChild(Some(sleeper));
        refused(
            &frontend(
                "attach-conflict",
                drrun,
                root.path(),
                vec![
                    "-app_path".into(),
                    image.clone().into(),
                    "-attach".into(),
                    sleeper.0.as_ref().unwrap().id().to_string().into(),
                ],
            ),
            "remove it when using -attach or a tool's native frontend",
        );
        drop(sleeper);

        // Construct exact literal path lengths with legal individual components.
        let long = root.path().join("a".repeat(180)).join("b".repeat(180));
        std::fs::create_dir_all(&long).unwrap();
        let remaining = 511 - long.as_os_str().len() - 1;
        assert!((1..=255).contains(&remaining));
        let path511 = long.join("c".repeat(remaining));
        copy(&image, &path511, 0o700);
        let observed = run(&selected_frontend(
            "511-byte-path",
            &path511,
            root.path(),
            OsStr::new("guest"),
        ));
        identity(&observed, 23, OsStr::new("guest"), path511.as_os_str());
        let path512 = long.join("c".repeat(remaining + 1));
        copy(&image, &path512, 0o700);
        refused(
            &selected_frontend("512-byte-path", &path512, root.path(), OsStr::new("guest")),
            "use fewer than 512 bytes without truncating",
        );
    }

    #[test]
    #[ignore = "requires current and retained old SDKs, bound by the gate"]
    fn absent_executable_path_option_keeps_frontend_selection() {
        let old = PathBuf::from(
            std::env::var_os("REVERIE_DBT_TEST_OLD_DRRUN").expect("retained original SDK frontend"),
        );
        let current = reverie_dbt::bundled_drrun_path();
        assert_ne!(
            std::fs::read(&old).unwrap(),
            std::fs::read(current).unwrap()
        );
        let root = tempfile::tempdir().unwrap();
        let image17 = fixture(root.path(), 17);
        let image23 = fixture(root.path(), 23);
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        copy(&image17, &root.path().join("probe"), 0o700);
        copy(&image23, &bin.join("probe"), 0o700);
        for (name, program, tag) in [
            ("direct", bin.join("probe"), 23),
            ("cwd-shadow", "probe".into(), 17),
        ] {
            let args = vec![
                "-quiet".into(),
                "--".into(),
                program.into_os_string(),
                "--launch-identity".into(),
            ];
            let mut before = frontend(name, &old, root.path(), args.clone());
            before.path = Some(bytes(&bin));
            let old_result = run(&before);
            let mut after = frontend(name, current, root.path(), args);
            after.path = Some(bytes(&bin));
            let current_result = run(&after);
            assert_eq!(old_result.status, Some(tag), "{old_result:?}");
            assert_eq!(current_result.status, old_result.status);
            assert_eq!(current_result.stdout, old_result.stdout);
            assert_eq!(current_result.stderr, old_result.stderr);
        }
    }

    #[test]
    #[ignore = "requires current and retained old SDKs, bound by the gate"]
    fn public_constructor_binds_selected_frontend() {
        let current = reverie_dbt::bundled_drrun_path();
        let old = PathBuf::from(
            std::env::var_os("REVERIE_DBT_TEST_OLD_DRRUN").expect("retained original SDK frontend"),
        );
        let client = PathBuf::from(std::env::var_os("REVERIE_DBT_CLIENT").expect("actual client"));
        assert!(DbtRunner::new(current, &client).is_ok());
        let error = DbtRunner::new(&old, &client).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(
            error
                .to_string()
                .contains("incompatible DynamoRIO frontend")
        );
        assert!(error.to_string().contains("rebuild the consuming crate"));
        // Constructor equality permits relocation. Executing a standalone copy
        // also requires its SDK libraries; no relocated-SDK run is claimed here.
        let root = tempfile::tempdir().unwrap();
        let relocated = root.path().join("drrun-copy");
        copy(current, &relocated, 0o700);
        assert!(DbtRunner::new(&relocated, &client).is_ok());
        let wrapper = root.path().join("wrapper");
        let marker = root.path().join("wrapper-entered");
        std::fs::write(
            &wrapper,
            format!("#!/bin/sh\nprintf entered > '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            DbtRunner::new(&wrapper, &client).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert!(!marker.exists());
        // The constructor's relative frontend and the guest's cwd contain
        // different same-spelled frontends. Only the attested one may run.
        std::fs::copy(&wrapper, root.path().join("drrun")).unwrap();
        let image = fixture(root.path(), 23);
        let mut relative = spec(
            "constructor-relative-frontend-different-cwd",
            &image,
            root.path(),
            None,
        );
        relative.mode = "dbt-relative-frontend".into();
        let observed = run(&relative);
        identity(&observed, 23, image.as_os_str(), image.as_os_str());
        assert_eq!(observed.processes, Some(1));
        assert!(
            !marker.exists(),
            "guest cwd substituted an unchecked frontend"
        );
        println!(
            "CONSTRUCTOR_IDENTITY:{}",
            serde_json::json!({
                "current": current, "retained_old": old, "current_accepted": true,
                "old_refused": true, "relocated_identical_accepted": true,
                "wrapper_refused_before_marker": true, "relocated_execution": false,
            })
        );
    }
}
