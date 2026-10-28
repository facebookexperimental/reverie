/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * Licensed under the BSD-style LICENSE in the root directory.
 */

//! libc import errors in a real private-loaded client, distinct from raw DR helpers.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::process::ExitStatus;

fn checked(command: &mut Command) -> String {
    let output = command.output().expect("run fixture build/readelf");
    assert!(output.status.success(), "{command:?}: {output:?}");
    String::from_utf8(output.stdout).expect("fixture tool output")
}

fn bounded(directory: &Path, name: &str, arguments: &[&Path]) -> (ExitStatus, Vec<u8>, Vec<u8>) {
    let config = directory.join(format!("{name}-config"));
    fs::create_dir(&config).unwrap();
    let stdout = directory.join(format!("{name}.stdout"));
    let stderr = directory.join(format!("{name}.stderr"));
    let mut command = Command::new("timeout");
    command
        .args(["--signal=TERM", "--kill-after=2s", "10s"])
        .args(arguments)
        .current_dir(directory)
        .env_remove("LD_LIBRARY_PATH")
        .env("DYNAMORIO_CONFIGDIR", config)
        .stdout(File::create(&stdout).unwrap())
        .stderr(File::create(&stderr).unwrap());
    unsafe {
        command.pre_exec(|| {
            for (resource, limit) in [(libc::RLIMIT_CORE, 0), (libc::RLIMIT_FSIZE, 1 << 20)] {
                let bound = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(resource, &bound) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let status = command
        .status()
        .expect("bounded native/private-loader probe");
    let out = fs::read(stdout).unwrap();
    let err = fs::read(stderr).unwrap();
    assert!(
        out.len() < 1 << 20 && err.len() < 1 << 20,
        "capture overflow"
    );
    assert!(
        !matches!(status.code(), Some(124 | 137 | 143 | 153)),
        "{name}: timeout or forced termination: {status}: {err:?}"
    );
    (status, out, err)
}

type Row<'a> = BTreeMap<&'a str, &'a str>;

fn rows<'a>(report: &'a str, kind: &str) -> Vec<Row<'a>> {
    report
        .lines()
        .filter_map(|line| {
            let (prefix, values) = line.split_once(' ')?;
            (prefix == kind).then(|| {
                values
                    .split_whitespace()
                    .map(|value| value.split_once('=').expect("key=value field"))
                    .collect()
            })
        })
        .collect()
}

fn number(row: &Row<'_>, key: &str) -> i64 {
    row[key].parse().expect("integer field")
}

fn check_operations(report: &str) {
    let operations = rows(report, "OP");
    assert_eq!(operations.len(), 44, "{report}");
    let mut identities = std::collections::BTreeSet::new();
    for row in operations {
        let identity = (
            number(&row, "slot"),
            number(&row, "phase"),
            number(&row, "op"),
        );
        assert!((0..2).contains(&identity.0) && (0..2).contains(&identity.1));
        assert!(
            (0..11).contains(&identity.2) && identities.insert(identity),
            "{report}"
        );
        assert_eq!(number(&row, "result"), number(&row, "expected"), "{report}");
        assert_eq!(
            number(&row, "errno"),
            number(&row, "expected_errno"),
            "{report}"
        );
        assert_eq!(number(&row, "payload"), 1, "{report}");
    }
}

fn check_summary(report: &str) {
    let summary = rows(report, "SUMMARY");
    assert_eq!(summary.len(), 1, "{report}");
    for (key, expected) in [
        ("calls", 4),
        ("threads", 2),
        ("failures", 0),
        ("setup_errors", 0),
    ] {
        assert_eq!(number(&summary[0], key), expected, "{report}");
    }
}

#[test]
fn private_import_read_write_preserve_libc_errno() {
    run_probe(false);
}

#[test]
fn private_errno_auxiliary_release_keeps_libc_abi() {
    run_probe(true);
}

fn run_probe(release_provider: bool) {
    let temp = build_fixture();
    let client = temp.path().join("libprivate_loader_errno_client.so");
    let guest = temp.path().join("private_loader_errno_guest");
    let dynamic = checked(
        Command::new("readelf")
            .args(["-W", "-d", "-s", "-r"])
            .arg(&client),
    );
    assert!(
        dynamic.contains("(NEEDED)") && dynamic.contains("[libc.so.6]"),
        "{dynamic}"
    );
    for symbol in ["read", "write", "writev", "__errno_location"] {
        assert!(
            dynamic.lines().any(|line| line.contains(" UND ")
                && line
                    .split_whitespace()
                    .any(|word| word.split('@').next() == Some(symbol))),
            "missing ordinary import {symbol}: {dynamic}"
        );
        assert!(
            dynamic.lines().any(|line| line.contains("R_X86_64_")
                && line
                    .split_whitespace()
                    .any(|word| word.split('@').next() == Some(symbol))),
            "missing dynamic relocation {symbol}: {dynamic}"
        );
    }
    let native_report = temp.path().join("native.report");
    let native = bounded(
        temp.path(),
        "native",
        &[&guest, Path::new("--native"), &native_report],
    );
    let guest_report = temp.path().join("guest.report");
    let private_report = temp.path().join("private.report");
    let mut arguments = vec![
        reverie_dbt::bundled_drrun_path(),
        Path::new("-quiet"),
        Path::new("-c"),
        &client,
        &private_report,
    ];
    if release_provider {
        arguments.push(Path::new("--release-provider"));
    }
    arguments.extend([Path::new("--"), &guest, &guest_report]);
    let private = bounded(temp.path(), "private", &arguments);
    // Both commands have completed/reaped before reading and asserting the ABI results.
    let native_text = fs::read_to_string(native_report).unwrap();
    let guest_text = fs::read_to_string(guest_report).unwrap();
    let private_text = fs::read_to_string(private_report).unwrap();
    for (name, (status, stdout, stderr)) in [("native", native), ("private", private)] {
        assert!(
            status.success(),
            "{name}: {status}: {stderr:?}\n{private_text}"
        );
        assert_eq!(stdout, b"private-errno-guest-complete\n");
        assert!(stderr.is_empty(), "{name}: {stderr:?}");
    }
    check_summary(&native_text);
    check_operations(&native_text);
    check_summary(&guest_text);
    let guests = rows(&guest_text, "GUEST");
    let threads = rows(&private_text, "THREAD");
    assert_eq!(guests.len(), 4, "{guest_text}");
    assert_eq!(threads.len(), 4, "{private_text}");
    let mut private_locations = BTreeMap::new();
    let mut guest_locations = BTreeMap::new();
    let mut pairs = std::collections::BTreeSet::new();
    for thread in threads {
        let pair = (number(&thread, "slot"), number(&thread, "phase"));
        assert!(pairs.insert(pair) && (0..2).contains(&pair.0) && (0..2).contains(&pair.1));
        assert_eq!(number(&thread, "prior_ok"), 1, "{private_text}");
        assert_eq!(number(&thread, "setup"), 0, "{private_text}");
        let matched: Vec<_> = guests
            .iter()
            .filter(|row| number(row, "slot") == pair.0 && number(row, "phase") == pair.1)
            .collect();
        assert_eq!(matched.len(), 1, "{guest_text}");
        let guest = matched[0];
        assert_eq!(thread["tid"], guest["tid"]);
        assert_eq!(thread["app"], guest["ptr"]);
        assert_ne!(thread["ptr"], guest["ptr"]);
        assert_ne!(
            thread["accessor"], guest["accessor"],
            "private and app libc accessor must differ"
        );
        assert_eq!(
            number(guest, "before"),
            number(guest, "after"),
            "{guest_text}"
        );
        if let Some(previous) = private_locations.insert(pair.0, thread["ptr"]) {
            assert_eq!(previous, thread["ptr"]);
        }
        if let Some(previous) = guest_locations.insert(pair.0, guest["ptr"]) {
            assert_eq!(previous, guest["ptr"]);
        }
    }
    assert_ne!(private_locations[&0], private_locations[&1]);
    assert_ne!(guest_locations[&0], guest_locations[&1]);
    check_summary(&private_text);
    check_operations(&private_text);
    let lifetime = rows(&private_text, "AUX_RELEASE");
    assert_eq!(lifetime.len(), if release_provider { 2 } else { 0 });
    for (cycle, row) in lifetime.iter().enumerate() {
        assert_eq!(number(row, "cycle"), cycle as i64);
        for key in ["released", "mapped", "same_errno"] {
            assert_eq!(number(row, key), 1, "{private_text}");
        }
    }
}

fn build_fixture() -> tempfile::TempDir {
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy();
        assert!(
            (!name.starts_with("LD_") || name == "LD_LIBRARY_PATH")
                && !name.starts_with("DYNAMORIO_"),
            "inherited loader override: {name}"
        );
    }
    let temp = tempfile::tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/private_loader_errno");
    checked(
        Command::new("cmake")
            .args(["-S"])
            .arg(&source)
            .arg("-B")
            .arg(temp.path())
            .arg("-DCMAKE_BUILD_TYPE=Release")
            .arg("-DDynamoRIO_USE_LIBC=ON")
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
    );
    checked(
        Command::new("cmake")
            .arg("--build")
            .arg(temp.path())
            .args(["--parallel", "2"]),
    );
    temp
}

fn assert_refusal(status: ExitStatus, stdout: &[u8], stderr: &[u8], reason: &str) {
    // Require a normal nonzero exit and the exact class, never a signal/timeout.
    assert!(
        status.code().is_some_and(|code| code != 0 && code != 94),
        "{status}: {stderr:?}"
    );
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(
        String::from_utf8_lossy(stderr).contains(&format!(
            "private libc read/write errno unsupported: {reason}"
        )),
        "{stderr:?}"
    );
}

#[test]
fn private_errno_rejects_non_callable_providers() {
    let temp = build_fixture();
    let guest = temp.path().join("private_loader_errno_guest");
    for style in ["gnu", "sysv"] {
        for (kind, symbol_type, executable, reason) in [
            (
                "object",
                "OBJECT",
                false,
                "errno accessor is not a defined direct function",
            ),
            (
                "notype",
                "NOTYPE",
                true,
                "errno accessor is not a defined direct function",
            ),
            (
                "nonexec",
                "FUNC",
                false,
                "errno accessor is outside its executable segment",
            ),
        ] {
            let name = format!("{kind}-{style}");
            let client = temp.path().join(format!("libc.so.errno-{name}"));
            let dynamic = checked(
                Command::new("readelf")
                    .args(["-W", "-d", "-s", "-l"])
                    .arg(&client),
            );
            assert!(dynamic.contains("[libc.so.6]"), "{dynamic}");
            assert!(
                dynamic.lines().any(|line| line.contains("(SONAME)")
                    && line.contains(&format!("[libc.so.errno-{name}]"))),
                "{dynamic}"
            );
            assert_eq!(dynamic.contains("(GNU_HASH)"), style == "gnu", "{dynamic}");
            assert_eq!(dynamic.contains("(HASH)"), style == "sysv", "{dynamic}");
            let symbols: Vec<_> = dynamic
                .lines()
                .map(|line| line.split_whitespace().collect::<Vec<_>>())
                .filter(|words| {
                    words.len() >= 8
                        && words[6] != "UND"
                        && words[7].split('@').next() == Some("__errno_location")
                })
                .collect();
            assert!(!symbols.is_empty(), "{dynamic}");
            for symbol in symbols {
                assert_eq!(symbol[3], symbol_type, "{dynamic}");
                let address = u64::from_str_radix(symbol[1], 16).unwrap();
                let in_executable = dynamic.lines().any(|line| {
                    let words: Vec<_> = line.split_whitespace().collect();
                    if words.len() < 8 || words[0] != "LOAD" {
                        return false;
                    }
                    let start = u64::from_str_radix(words[2].trim_start_matches("0x"), 16).unwrap();
                    let size = u64::from_str_radix(words[5].trim_start_matches("0x"), 16).unwrap();
                    start <= address && address < start + size && words[6..].contains(&"E")
                });
                assert_eq!(in_executable, executable, "{dynamic}");
            }
            let report = temp.path().join(format!("{name}.report"));
            let guest_report = temp.path().join(format!("{name}.guest"));
            let (status, stdout, stderr) = bounded(
                temp.path(),
                &name,
                &[
                    reverie_dbt::bundled_drrun_path(),
                    Path::new("-quiet"),
                    Path::new("-c"),
                    &client,
                    &report,
                    Path::new("--"),
                    &guest,
                    &guest_report,
                ],
            );
            assert_refusal(status, &stdout, &stderr, reason);
            assert!(!report.exists() && !guest_report.exists());
        }
    }
    let wrong = temp
        .path()
        .join("libprivate_loader_errno_wrong_provider.so");
    let report = temp.path().join("wrong.report");
    let guest_report = temp.path().join("wrong.guest");
    let (status, stdout, stderr) = bounded(
        temp.path(),
        "wrong-provider",
        &[
            reverie_dbt::bundled_drrun_path(),
            Path::new("-quiet"),
            Path::new("-c"),
            &wrong,
            &report,
            Path::new("--"),
            &guest,
            &guest_report,
        ],
    );
    assert_refusal(
        status,
        &stdout,
        &stderr,
        "errno provider is not the owned private libc",
    );
    assert!(!report.exists() && !guest_report.exists());
}

#[test]
fn private_errno_absent_provider_preserves_success_and_refuses_errors() {
    let temp = build_fixture();
    let client = temp.path().join("libprivate_loader_errno_no_libc.so");
    let guest = temp.path().join("private_loader_errno_guest");
    let dynamic = checked(
        Command::new("readelf")
            .args(["-W", "-d", "-s", "-r"])
            .arg(&client),
    );
    assert!(
        !dynamic.contains("[libc.so") && !dynamic.contains("__errno_location"),
        "{dynamic}"
    );
    for symbol in ["read", "write"] {
        assert!(
            dynamic.lines().any(|line| line.contains(" UND ")
                && line
                    .split_whitespace()
                    .any(|word| word.split('@').next() == Some(symbol))),
            "{dynamic}"
        );
        assert!(
            dynamic.lines().any(|line| line.contains("R_X86_64_")
                && line
                    .split_whitespace()
                    .any(|word| word.split('@').next() == Some(symbol))),
            "{dynamic}"
        );
    }
    for mode in ["success", "error-read", "error-write"] {
        let report = temp.path().join(format!("{mode}.report"));
        let guest_report = temp.path().join(format!("{mode}.guest"));
        let (status, stdout, stderr) = bounded(
            temp.path(),
            mode,
            &[
                reverie_dbt::bundled_drrun_path(),
                Path::new("-quiet"),
                Path::new("-c"),
                &client,
                &report,
                Path::new(mode),
                Path::new("--"),
                &guest,
                &guest_report,
            ],
        );
        assert_eq!(
            fs::read(&report).unwrap(),
            b"NO_LIBC success=1 operations=4 payload=1\n"
        );
        if mode == "success" {
            assert!(status.success(), "{status}: {stderr:?}");
            assert_eq!(stdout, b"private-errno-guest-complete\n");
            assert!(stderr.is_empty(), "{stderr:?}");
            check_summary(&fs::read_to_string(&guest_report).unwrap());
        } else {
            assert_refusal(
                status,
                &stdout,
                &stderr,
                "error without an initialized private errno provider",
            );
            assert!(!guest_report.exists());
        }
    }
}

#[test]
fn private_errno_rejects_wrong_private_tls() {
    let temp = build_fixture();
    let client = temp.path().join("libprivate_loader_errno_client.so");
    let guest = temp.path().join("private_loader_errno_guest");
    let report = temp.path().join("tls.report");
    let guest_report = temp.path().join("tls.guest");
    let (status, stdout, stderr) = bounded(
        temp.path(),
        "wrong-private-tls",
        &[
            reverie_dbt::bundled_drrun_path(),
            Path::new("-quiet"),
            Path::new("-c"),
            &client,
            &report,
            Path::new("--wrong-private-tls"),
            Path::new("--"),
            &guest,
            &guest_report,
        ],
    );
    let text = fs::read_to_string(&report).unwrap();
    let tls = rows(&text, "TLS");
    assert_eq!(tls.len(), 1, "{text}");
    assert_eq!(number(&tls[0], "prepared"), 1);
    let base = |name| u64::from_str_radix(tls[0][name], 16).unwrap();
    assert_ne!(base("saved"), 0);
    assert_ne!(base("saved"), base("app"));
    assert_ne!(base("wrong"), base("saved"));
    assert_ne!(base("wrong"), base("app"));
    assert_refusal(
        status,
        &stdout,
        &stderr,
        "error outside this thread's private TLS",
    );
    assert!(!guest_report.exists());
}
