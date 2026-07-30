use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use reverie::ExitStatus;
use reverie::process::Command;
use reverie::process::Stdio;
use reverie_e9patch::E9patchBackend;
use reverie_e9patch::TOOL_PRELOAD_ENV;
use reverie_examples::e9patch_smoke::AotCounterTool;
use reverie_examples::run_e9patch_counter1_with_preload;
use reverie_examples::run_e9patch_noop_with_preload;
use reverie_examples::run_e9patch_write_strace_with_preload;

fn compile_guest() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/e9patch_direct_tool.c");
    let output = directory.path().join("e9patch-direct-tool");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let result = ProcessCommand::new(compiler)
        .args([
            "-std=gnu11",
            "-O0",
            "-fno-pie",
            "-no-pie",
            "-fno-stack-protector",
        ])
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

fn example_preload() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let parent = executable.parent().unwrap();
    [
        parent.join("libreverie_examples.so"),
        parent.join("../libreverie_examples.so"),
        parent.join("../../libreverie_examples.so"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .expect("cargo did not build libreverie_examples.so")
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn sealed_bootstrap_selects_matching_tool_without_environment_mutation() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command
        .env("REVERIE_E9PATCH_EXPECT_BOOTSTRAP_ENV", "1")
        .env("REVERIE_E9PATCH_COORDINATOR", "preexisting-coordinator")
        .env("REVERIE_E9PATCH_EXAMPLE_TOOL", "preexisting-selector")
        .env("REVERIE_E9PATCH_BOOTSTRAP_SENTINEL", "two  spaces\tand-tab");
    let (output, global) =
        E9patchBackend::run_direct_with_output_and_preload_data::<AotCounterTool>(
            command,
            (),
            example_preload(),
            b"e9patch-smoke",
        )
        .await
        .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(global.delivered(), 1);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn inherited_stdio_uses_sealed_bootstrap_and_returns_empty_buffers() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (output, global) = E9patchBackend::run_direct_with_inherited_stdio_and_preload_data::<
        AotCounterTool,
    >(command, (), example_preload(), b"e9patch-smoke")
    .await
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(global.delivered(), 1);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn status_only_launch_returns_exit_status_and_global_state() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command
        .env("REVERIE_E9PATCH_EXAMPLE_TOOL", "e9patch-smoke")
        .env("REVERIE_E9PATCH_WRITE_BURST", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (status, global) =
        E9patchBackend::run_direct_with_preload::<AotCounterTool>(command, (), example_preload())
            .await
            .unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(global.delivered(), 1);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn environment_selected_preload_runs_status_only_tool() {
    const CHILD_ENV: &str = "REVERIE_E9PATCH_TOOL_PRELOAD_TEST_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let status = ProcessCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "environment_selected_preload_runs_status_only_tool",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .env(TOOL_PRELOAD_ENV, example_preload())
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated preload-env test failed: {status}"
        );
        return;
    }

    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command.env("REVERIE_E9PATCH_EXAMPLE_TOOL", "e9patch-smoke");
    let (status, global) = E9patchBackend::run_direct::<AotCounterTool>(command, ())
        .await
        .unwrap();
    assert_eq!(status, ExitStatus::Exited(0));
    assert_eq!(global.delivered(), 1);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn production_noop_preserves_native_rewritten_syscall() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command.env("REVERIE_E9PATCH_EXPECT_NATIVE_GETPID", "1");
    let (output, ()) = run_e9patch_noop_with_preload(command, example_preload())
        .await
        .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn production_counter1_reports_rewritten_syscall_total() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command.env("REVERIE_E9PATCH_EXPECT_RAW_GETPID", "1");
    let (output, total) = run_e9patch_counter1_with_preload(command, example_preload())
        .await
        .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    assert_eq!(total, 2);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn production_strace_observes_filtered_rewritten_write() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command
        .env("REVERIE_E9PATCH_WRITE_MARKER", "1")
        .env("REVERIE_E9PATCH_EXPECT_NATIVE_GETPID", "1");
    let output = run_e9patch_write_strace_with_preload(command, example_preload())
        .await
        .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(output.stdout, b"e9patch-strace\n", "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("write(1,"), "{stderr}");
    assert!(stderr.contains(" = 15"), "{stderr}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn subscribed_residual_write_still_fails_closed_after_direct_start() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command.env("REVERIE_E9PATCH_EXPECT_RESIDUAL_WRITE_FAIL", "1");
    let output = run_e9patch_write_strace_with_preload(command, example_preload())
        .await
        .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("write("), "{stderr}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn subscribed_application_residual_fails_closed_before_direct_start() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command.env("REVERIE_E9PATCH_EXPECT_PRESTART_RESIDUAL_FAIL", "1");
    let output = run_e9patch_write_strace_with_preload(command, example_preload())
        .await
        .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains("write("), "{stderr}");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn legacy_environment_bootstrap_remains_compatible() {
    let (_directory, guest) = compile_guest();
    let mut command = Command::new(guest);
    command.env("REVERIE_E9PATCH_EXAMPLE_TOOL", "e9patch-smoke");
    let (output, global) = E9patchBackend::run_direct_with_output_and_preload::<AotCounterTool>(
        command,
        (),
        example_preload(),
    )
    .await
    .unwrap();
    assert_eq!(output.status, ExitStatus::Exited(0), "{output:?}");
    assert_eq!(global.delivered(), 1);
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires a built e9tool/e9patch pair"]
async fn sealed_bootstrap_rejects_unknown_tool_selector() {
    let (_directory, guest) = compile_guest();
    let result = E9patchBackend::run_direct_with_output_and_preload_data::<AotCounterTool>(
        Command::new(guest),
        (),
        example_preload(),
        b"not-a-tool",
    )
    .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("unknown selector must fail before Tool connection"),
    };
    assert!(
        error
            .to_string()
            .contains("exited before its Tool preload connected"),
        "{error:#}"
    );
}
