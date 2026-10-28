/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

//! Observe the parsed engine option, rather than infer it from random addresses.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

const MARKER: &[u8] = b"placement-marker\n";
const SDK_DEFAULT: u64 = 0x10000000;
const MARKER_SCRIPT: &str = "printf 'placement-marker\\n'";

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("missing {name}")))
}

fn guest(config: &Path) -> Command {
    scripted_guest(config, MARKER_SCRIPT)
}

fn scripted_guest(config: &Path, script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("DYNAMORIO_CONFIGDIR", config);
    command
}

fn test_root(name: &str) -> PathBuf {
    let parent = required_path("REVERIE_DBT_PLACEMENT_ARTIFACT_DIR");
    fs::create_dir_all(&parent).expect("retained option-probe parent");
    let root = parent.join(name);
    fs::create_dir(&root).expect("fresh retained option-probe directory");
    fs::create_dir(root.join("config")).unwrap();
    root
}

fn diagnostic(path: &Path) -> File {
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
        .expect("create exclusive diagnostic file")
}

fn retain_and_check(root: &Path, label: &str, output: &Output, expected_stdout: &[u8]) {
    fs::write(root.join(format!("{label}.stdout")), &output.stdout).unwrap();
    fs::write(root.join(format!("{label}.stderr")), &output.stderr).unwrap();
    fs::write(
        root.join(format!("{label}.status")),
        format!("{}\n", output.status),
    )
    .unwrap();
    assert!(output.status.success(), "{label} failed: {output:?}");
    assert_eq!(output.stdout, expected_stdout, "{label} guest marker");
    assert!(output.stderr.is_empty(), "{label} guest stderr: {output:?}");
}

fn initialized_value(path: &Path) -> u64 {
    observed_values(path, &["init"])[0]
}

fn observed_values(path: &Path, phases: &[&str]) -> Vec<u64> {
    let text = fs::read_to_string(path).expect("read actual engine option report");
    let rows = text.lines().collect::<Vec<_>>();
    assert_eq!(rows.len(), phases.len(), "exact engine event count: {text}");
    rows.iter()
        .zip(phases)
        .map(|(row, phase)| {
            row.strip_prefix(&format!("PRIVATE_PLACEMENT phase={phase} value="))
                .expect("successful actual SDK query at expected event")
                .parse()
                .expect("integer SDK option")
        })
        .collect()
}

#[test]
#[ignore = "requires the built option-query client and verified existing DynamoRIO SDK"]
fn sdk_default_private_placement_matches_real_engine_default() {
    let root = test_root("sdk-default");
    let config = root.join("config");
    let client = required_path("REVERIE_DBT_PLACEMENT_CLIENT");
    let drrun = reverie_dbt::bundled_drrun_path();
    assert!(
        client.is_file() && drrun.is_file(),
        "real runtime artifacts"
    );

    let direct_path = root.join("direct.diagnostic");
    let direct_diagnostic = diagnostic(&direct_path);
    let descriptor = direct_diagnostic.as_raw_fd();
    let input = guest(&config);
    let mut direct = Command::new(drrun);
    direct
        .args(["-quiet", "-disable_rseq", "-stack_size", "2M", "-c"])
        .arg(&client)
        .args(["-diagnostic_fd", "198", "--"])
        .arg(input.get_program())
        .args(input.get_args())
        .env_clear()
        .envs(input.get_envs().map(|(key, value)| (key, value.unwrap())));
    // Match the public runner's existing diagnostic descriptor and personality.
    // Only async-signal-safe libc operations execute between fork and exec.
    unsafe {
        direct.pre_exec(move || {
            if libc::dup2(descriptor, 198) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let current = libc::personality(0xffff_ffff);
            if current < 0
                || libc::personality(current as libc::c_ulong | libc::ADDR_NO_RANDOMIZE as u64) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let direct_output = direct.output().expect("launch real direct engine");
    retain_and_check(&root, "direct", &direct_output, MARKER);
    let direct_value = initialized_value(&direct_path);
    assert_eq!(direct_value, SDK_DEFAULT, "source-bound SDK option default");

    let runner_path = root.join("runner.diagnostic");
    let runner_diagnostic = diagnostic(&runner_path);
    let runner = reverie_dbt::DbtRunner::new(drrun, &client)
        .unwrap()
        .diagnostic_file(&runner_diagnostic)
        .unwrap();
    let runner_output = runner
        .output_with_environment(
            &input,
            &input
                .get_envs()
                .map(|(key, value)| (key.to_os_string(), value.unwrap().to_os_string()))
                .collect(),
        )
        .expect("launch public runner");
    retain_and_check(&root, "runner", &runner_output, MARKER);
    let runner_value = initialized_value(&runner_path);
    assert_eq!(
        runner_value, direct_value,
        "runner default must match SDK vm_max_offset"
    );
}

fn observe_runner(
    name: &str,
    configure: impl FnOnce(reverie_dbt::DbtRunner) -> reverie_dbt::DbtRunner,
    script: &str,
    expected_stdout: &[u8],
    phases: &[&str],
) -> Vec<u64> {
    let root = test_root(name);
    let path = root.join("runner.diagnostic");
    let file = diagnostic(&path);
    let runner = reverie_dbt::DbtRunner::new(
        reverie_dbt::bundled_drrun_path(),
        required_path("REVERIE_DBT_PLACEMENT_CLIENT"),
    )
    .unwrap()
    .diagnostic_file(&file)
    .unwrap();
    let input = scripted_guest(&root.join("config"), script);
    let output = configure(runner)
        .output_with_environment(
            &input,
            &input
                .get_envs()
                .map(|(key, value)| (key.to_os_string(), value.unwrap().to_os_string()))
                .collect(),
        )
        .expect("launch public runner");
    retain_and_check(&root, "runner", &output, expected_stdout);
    observed_values(&path, phases)
}

#[test]
#[ignore = "requires the built option-query client and verified existing DynamoRIO SDK"]
fn explicit_zero_private_placement_reaches_the_engine() {
    let values = observe_runner(
        "explicit-zero",
        |runner| runner.private_placement(reverie_dbt::DbtPrivatePlacement::NoRandomOffset),
        MARKER_SCRIPT,
        MARKER,
        &["init"],
    );
    assert_eq!(values, [0], "explicit zero must reach SDK vm_max_offset");
}

#[test]
#[ignore = "requires the built option-query client and verified existing DynamoRIO SDK"]
fn cloned_zero_private_placement_reaches_the_engine() {
    let values = observe_runner(
        "cloned-zero",
        |runner| {
            runner
                .private_placement(reverie_dbt::DbtPrivatePlacement::NoRandomOffset)
                .clone()
        },
        MARKER_SCRIPT,
        MARKER,
        &["init"],
    );
    assert_eq!(values, [0], "cloned zero must reach SDK vm_max_offset");
}

#[test]
#[ignore = "requires the built option-query client and verified existing DynamoRIO SDK"]
fn resetting_private_placement_restores_the_engine_default() {
    let values = observe_runner(
        "reset-default",
        |runner| {
            runner
                .private_placement(reverie_dbt::DbtPrivatePlacement::NoRandomOffset)
                .private_placement(reverie_dbt::DbtPrivatePlacement::SdkDefault)
        },
        MARKER_SCRIPT,
        MARKER,
        &["init"],
    );
    assert_eq!(
        values,
        [SDK_DEFAULT],
        "reset must restore SDK vm_max_offset default"
    );
}

#[test]
#[ignore = "requires the built option-query client and verified existing DynamoRIO SDK"]
fn private_placement_survives_followed_exec() {
    for (name, policy, expected) in [
        (
            "exec-default",
            reverie_dbt::DbtPrivatePlacement::SdkDefault,
            SDK_DEFAULT,
        ),
        (
            "exec-zero",
            reverie_dbt::DbtPrivatePlacement::NoRandomOffset,
            0,
        ),
    ] {
        let values = observe_runner(
            name,
            |runner| runner.private_placement(policy),
            "printf 'placement-before\\n'; exec /bin/true",
            b"placement-before\n",
            &["init", "init"],
        );
        assert_eq!(values, [expected, expected], "followed exec retains policy");
    }
}

#[test]
#[ignore = "requires the built option-query client and verified existing DynamoRIO SDK"]
fn private_placement_survives_fork() {
    for (name, policy, expected) in [
        (
            "fork-default",
            reverie_dbt::DbtPrivatePlacement::SdkDefault,
            SDK_DEFAULT,
        ),
        (
            "fork-zero",
            reverie_dbt::DbtPrivatePlacement::NoRandomOffset,
            0,
        ),
    ] {
        let values = observe_runner(
            name,
            |runner| runner.private_placement(policy),
            "(printf 'placement-child\\n') & wait; printf 'placement-parent\\n'",
            b"placement-child\nplacement-parent\n",
            &["init", "fork"],
        );
        assert_eq!(values, [expected, expected], "fork retains policy");
    }
}
