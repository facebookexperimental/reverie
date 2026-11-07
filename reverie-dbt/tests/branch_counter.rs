/* Copyright (c) Meta Platforms, Inc. and affiliates.
 * Licensed under the BSD-style license in the root LICENSE file.
 */

//! Native mechanism controls and explicitly selected standalone Tool controls.

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn run(command: &mut Command, directory: &Path, name: &str) -> Output {
    eprintln!("{name}: {command:?}");
    let output = Command::new("timeout")
        .args(["--signal=TERM", "--kill-after=2s", "20s"])
        .arg(command.get_program())
        .args(command.get_args())
        .output()
        .unwrap_or_else(|error| panic!("{command:?}: {error}"));
    std::fs::write(directory.join(format!("{name}.stdout")), &output.stdout).unwrap();
    std::fs::write(directory.join(format!("{name}.stderr")), &output.stderr).unwrap();
    std::fs::write(
        directory.join(format!("{name}.status")),
        format!("{:?}\n", output.status),
    )
    .unwrap();
    output
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{:?}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sentinel(output: &Output) {
    success(output);
    assert_eq!(output.stdout.len(), 168, "complete original sentinel");
    let words: Vec<_> = output
        .stdout
        .as_chunks::<8>()
        .0
        .iter()
        .map(|word| u64::from_le_bytes(*word))
        .collect();
    assert_eq!(&words[..4], &[0; 4]);
    for i in 0..14 {
        assert_eq!(words[4 + i], 0x1122_3344_5566_7700 + i as u64);
    }
    assert_eq!(words[18], 0xad7, "complete flags");
    assert_eq!(words[19], words[20], "within-run stack preservation");
    // Absolute stacks across runs remain raw evidence, not normalized parity.
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|word| word.strip_prefix(name))
        .unwrap_or_else(|| panic!("missing {name}: {line}"))
}

fn completed(output: &Output) -> &str {
    let stderr = std::str::from_utf8(&output.stderr).expect("client diagnostic UTF-8");
    let mut lines = stderr
        .lines()
        .filter(|line| line.starts_with("CACHE_CONTROL mode="));
    let line = lines.next().expect("actual client completion");
    assert!(lines.next().is_none(), "one completion");
    line
}

fn accepts_counter_control(output: &Output) -> bool {
    let line = completed(output);
    field(line, "failures=") == "0"
        && field(line, "invalidations=") == "1"
        && field(line, "completions=") == "1"
        && field(line, "final_seen=") == "1"
        && field(line, "final=") == "2"
        && field(line, "actual=").parse::<usize>().unwrap() > 0
}

fn setter_decision(directory: &Path) {
    // Exercise the actual Linux/x86-64 release decision with mock setters.
    // This is not evidence of a live queued or direct kernel installation.
    let source = include_str!("../vendor/dynamorio/core/synch.c");
    let start = source
        .find("        app_pc app_continuation = (app_pc)mc->pc;")
        .unwrap();
    let end_marker = "                                                 app_continuation);";
    let end = start + source[start..].find(end_marker).unwrap() + end_marker.len();
    let decision = &source[start..end];
    let guard = "        if (res)\n            instrument_cache_context_invalidated";
    assert_eq!(decision.matches(guard).count(), 1);
    std::fs::write(directory.join("decision.inc"), decision).unwrap();
    std::fs::write(
        directory.join("decision-without-success-guard.inc"),
        decision.replace(guard, "            instrument_cache_context_invalidated"),
    )
    .unwrap();
    std::fs::write(
        directory.join("component.c"),
        include_str!("fixtures/branch_counter/cache_context_setter.c"),
    )
    .unwrap();
    for (name, define) in [
        ("setter-positive", "decision.inc"),
        ("setter-mutant", "decision-without-success-guard.inc"),
    ] {
        success(&run(
            Command::new("cc")
                .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
                .arg(format!("-DSETTER_DECISION_INCLUDE=\"{define}\""))
                .arg(directory.join("component.c"))
                .arg("-o")
                .arg(directory.join(name)),
            directory,
            &format!("{name}-compile"),
        ));
    }
    let positive = run(
        &mut Command::new(directory.join("setter-positive")),
        directory,
        "setter-positive-run",
    );
    success(&positive);
    assert_eq!(positive.stdout, b"PASS direct-success\nPASS queued-success\nPASS failure\nPASS component-notification-decision\n");
    assert!(positive.stderr.is_empty());
    let mutant = run(
        &mut Command::new(directory.join("setter-mutant")),
        directory,
        "setter-mutant-run",
    );
    assert_eq!(mutant.status.code(), Some(1));
    assert_eq!(mutant.stdout, b"PASS direct-success\nPASS queued-success\n");
    assert_eq!(mutant.stderr, b"FAIL failure: unexpected notification\n");
}

#[test]
fn cache_relocation_retires_only_abandoned_counter_phases() {
    // Optional retention is test-only; neither the runtime nor guest reads it.
    let retained = std::env::var_os("REVERIE_DBT_TEST_ARTIFACT_DIR");
    let directory = retained
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| tempfile::tempdir().expect("fixture directory").keep());
    std::fs::create_dir_all(&directory).unwrap();
    assert!(
        !directory.join("native.stdout").exists(),
        "fresh receipt directory"
    );
    eprintln!("cache invalidation artifacts: {}", directory.display());
    setter_decision(&directory);
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/branch_counter");
    let cmake = std::env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
    success(&run(
        Command::new(&cmake)
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(&directory)
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
        &directory,
        "configure",
    ));
    success(&run(
        Command::new(&cmake)
            .arg("--build")
            .arg(&directory)
            .args(["--parallel", "2"]),
        &directory,
        "build",
    ));
    let guest = directory.join("cache_invalidation_guest");
    let symbols = run(
        Command::new("nm").arg("-n").arg(&guest),
        &directory,
        "symbols",
    );
    success(&symbols);
    let symbols = String::from_utf8(symbols.stdout).unwrap();
    let symbol = |name: &str| {
        symbols
            .lines()
            .find_map(|line| {
                let parts: Vec<_> = line.split_whitespace().collect();
                (parts.len() == 3 && parts[2] == name).then(|| format!("0x{}", parts[0]))
            })
            .unwrap_or_else(|| panic!("missing {name}"))
    };
    let branch = symbol("clock_control_branch");
    let helper = symbol("helper_getpid");
    let elf = run(
        Command::new("readelf").args(["-h", "-l"]).arg(&guest),
        &directory,
        "elf",
    );
    success(&elf);
    let elf = String::from_utf8(elf.stdout).unwrap();
    assert!(elf.contains("ELF64") && elf.contains("EXEC") && !elf.contains("INTERP"));
    let disassembly = run(
        Command::new("objdump").arg("-d").arg(&guest),
        &directory,
        "disassembly",
    );
    success(&disassembly);
    let disassembly = String::from_utf8(disassembly.stdout).unwrap();
    let conditional: Vec<_> = disassembly
        .lines()
        .filter(|line| {
            let mnemonic = line
                .split('\t')
                .nth(2)
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            mnemonic.starts_with("loop")
                || (mnemonic.starts_with('j') && mnemonic != "jmp" && mnemonic != "jmpq")
        })
        .collect();
    assert_eq!(
        conditional.len(),
        1,
        "only the retained LOOP: {conditional:?}"
    );
    assert!(conditional[0].contains("e2 fe") && conditional[0].contains("<clock_control_branch>"));
    let native = run(&mut Command::new(&guest), &directory, "native");
    sentinel(&native);
    assert!(native.stderr.is_empty());
    let client = directory.join("libcache_invalidation_client.so");
    for (name, phase, notification) in [
        ("pre", "pre", "normal"),
        ("post", "post", "normal"),
        ("omit", "post", "omit"),
    ] {
        let output = run(
            Command::new(reverie_dbt::bundled_drrun_path())
                .arg("-c")
                .arg(&client)
                .arg(phase)
                .arg(&branch)
                .arg(&helper)
                .arg(notification)
                .arg("--")
                .arg(&guest),
            &directory,
            name,
        );
        sentinel(&output);
        eprintln!("{name}: {}", String::from_utf8_lossy(&output.stderr));
        if notification == "normal" {
            assert!(
                accepts_counter_control(&output),
                "exact count/context/ownership/retirement oracle"
            );
        } else {
            // Same positive oracle must reject the missing lifetime callback;
            // final count2 alone can hide stale emitted-cache phase authority.
            assert!(!accepts_counter_control(&output));
            let line = completed(&output);
            assert_eq!(field(line, "invalidations="), "0");
            assert_eq!(field(line, "completions="), "1");
            assert_eq!(field(line, "final="), "2");
            assert_eq!(field(line, "completion_active="), "1");
            assert_eq!(field(line, "completion_pending="), "1");
            assert_eq!(field(line, "completion_count="), "1");
            assert_ne!(field(line, "failures="), "0");
        }
    }
    if retained.is_none() {
        std::fs::remove_dir_all(directory).unwrap();
    }
}

#[test]
fn returning_guard_preserves_errors_and_original_child_entry() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = std::env::var_os("REVERIE_DBT_TEST_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_owned())
        .join("returning-guard");
    std::fs::create_dir_all(&directory).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/branch_counter");
    let cmake = std::env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
    success(&run(
        Command::new(&cmake)
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(&directory)
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
        &directory,
        "configure",
    ));
    success(&run(
        Command::new(&cmake).arg("--build").arg(&directory).args([
            "--parallel",
            "2",
            "--target",
            "returning_guard_client",
            "cache_invalidation_guest",
        ]),
        &directory,
        "build",
    ));
    let home = reverie_dbt::bundled_dynamorio_cmake_dir()
        .parent()
        .unwrap()
        .to_owned();
    let config = directory.join("dr-config");
    std::fs::create_dir(&config).unwrap();
    let output = run(
        Command::new("env")
            .args(["-i", "PATH=/usr/bin:/bin", "LC_ALL=C"])
            .arg(format!("DYNAMORIO_CONFIGDIR={}", config.display()))
            .arg(home.join("bin64/drrun"))
            .args([
                "-quiet",
                "-disable_rseq",
                "-vm_max_offset",
                "0x0",
                "-stack_size",
                "2M",
                "-c",
            ])
            .arg(directory.join("libreturning_guard_client.so"))
            .arg("--")
            .arg(directory.join("cache_invalidation_guest")),
        &directory,
        "guard",
    );
    sentinel(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr
            .matches("RETURNING_GUARD checks=15 completed=1")
            .count(),
        1,
        "{stderr}"
    );
    assert_eq!(
        stderr.matches("RETURNING_GUARD error ").count(),
        3,
        "{stderr}"
    );
    assert!(!stderr.contains("failed="), "{stderr}");
}

#[test]
#[ignore = "requires built standalone runtime/native client; run explicitly"]
fn enabled_returning_child_refusal_is_a_backend_failure() {
    use std::collections::BTreeMap;
    use std::ffi::OsString;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;

    let temporary = tempfile::tempdir().unwrap();
    let directory = std::env::var_os("REVERIE_DBT_TEST_ARTIFACT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().to_owned())
        .join("returning-refusal");
    std::fs::create_dir_all(&directory).unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/branch_counter");
    success(&run(
        Command::new("cmake")
            .arg("-S")
            .arg(source)
            .arg("-B")
            .arg(&directory)
            .arg(format!(
                "-DDynamoRIO_DIR={}",
                reverie_dbt::bundled_dynamorio_cmake_dir().display()
            )),
        &directory,
        "configure",
    ));
    success(&run(
        Command::new("cmake").arg("--build").arg(&directory).args([
            "--parallel",
            "2",
            "--target",
            "cache_invalidation_guest",
        ]),
        &directory,
        "build",
    ));
    let client = std::env::var_os("REVERIE_DBT_CLIENT").expect("built native client");
    let diagnostics = std::fs::File::create(directory.join("recorder.diagnostics")).unwrap();
    let mut evidence = tempfile::tempfile().unwrap();
    let sink = reverie_dbt::DbtStatsSink::new().unwrap();
    let runner = sink.configure(
        reverie_dbt::DbtRunner::new(reverie_dbt::bundled_drrun_path(), client)
            .unwrap()
            .diagnostic_file(&diagnostics)
            .unwrap()
            .client_argument("-branch-facts")
            .client_argument("-test-wait-for-background")
            .evidence_file(&evidence)
            .unwrap(),
    );
    let config = directory.join("dr-config");
    std::fs::create_dir(&config).unwrap();
    let environment: BTreeMap<OsString, OsString> = [
        ("LC_ALL", "C"),
        ("TZ", "UTC"),
        ("REVERIE_DBT_TOOL", "recorder"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .chain([("DYNAMORIO_CONFIGDIR".into(), config.into_os_string())])
    .collect();
    let result = runner.output_with_environment(
        &Command::new(directory.join("cache_invalidation_guest")),
        &environment,
    );
    std::fs::write(directory.join("recorder.result"), format!("{result:?}\n")).unwrap();
    let error = result.expect_err("returning-child mechanism refusal is not a guest result");
    assert!(
        error
            .to_string()
            .contains("DBT backend or Tool reported an internal failure"),
        "{error}"
    );
    let output = reverie_dbt::failed_run_output(&error).expect("retained failure streams");
    std::fs::write(directory.join("recorder.stdout"), &output.stdout).unwrap();
    std::fs::write(directory.join("recorder.stderr"), &output.stderr).unwrap();
    assert!(
        output.stdout.is_empty() && output.stderr.is_empty(),
        "{output:?}"
    );
    let diagnostics = std::fs::read_to_string(directory.join("recorder.diagnostics")).unwrap();
    let refusal = "reverie-dbt: branch facts unavailable: returning shared-VM child entry is unsupported (syscall 56)\n";
    assert_eq!(diagnostics.matches(refusal).count(), 1, "{diagnostics}");
    evidence.seek(SeekFrom::Start(0)).unwrap();
    let mut accepted = Vec::new();
    evidence.read_to_end(&mut accepted).unwrap();
    std::fs::write(directory.join("accepted-evidence.bin"), &accepted).unwrap();
    assert!(
        accepted.is_empty(),
        "a backend refusal cannot publish accepted guest evidence"
    );
    let capture = sink.capture();
    std::fs::write(directory.join("recorder.stats"), capture.records().unwrap()).unwrap();
    let snapshot = capture.snapshot().unwrap();
    std::fs::write(
        directory.join("recorder.stats.txt"),
        format!("{snapshot}\n"),
    )
    .unwrap();
    assert_eq!(snapshot.process_images(), 1, "{snapshot}");
    assert_eq!(snapshot.backend_failures(), 1, "{snapshot}");
}
