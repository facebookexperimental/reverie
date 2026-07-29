use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

use reverie::ExitStatus;
use reverie::process::Command;
use reverie_e9patch::E9patchBackend;
use reverie_examples::e9patch_smoke::AotCounterTool;

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
