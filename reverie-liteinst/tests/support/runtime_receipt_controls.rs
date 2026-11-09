//! Receipt-only controls through the production consumer in fresh processes.

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use runtime::artifact;
use runtime::contract;

use super::liteinst_runtime as runtime;

const TEST: &str = "runtime_receipt_controls::production_consumer_requires_compiled_sources";
const PHASE: &str = "REVERIE_RUNTIME_RECEIPT_CONTROL_PHASE";
const RESULT: &str = "REVERIE_RUNTIME_RECEIPT_CONTROL_RESULT";
const MISMATCH: &str = "runtime independently resolved compiled source identities differ";

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn child(phase: OsString, report: PathBuf) -> Result<(), String> {
    let phase = phase.to_str().ok_or("child phase is not UTF-8")?;
    require(
        matches!(phase, "valid" | "missing" | "changed"),
        "unknown receipt control child phase",
    )?;
    require(
        report.is_absolute() && !report.exists(),
        "child result must be a new absolute path",
    )?;
    let result = runtime::required_runtime().and_then(|runtime| {
        require(
            runtime.receipt.compiled_sources.is_some(),
            "consumer accepted absent compiled source context",
        )
    });
    let record = serde_json::json!({
        "phase": phase,
        "result": if result.is_ok() { "qualified" } else { "refused" },
        "error": result.as_ref().err(),
    });
    artifact::write_new(
        &report,
        &serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )?;
    // A production refusal remains the child's native failed-test exit.
    result
}

fn required_file(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(env::var_os(name).ok_or_else(|| format!("{name} is required"))?);
    require(path.is_absolute(), "producer input must be absolute")?;
    require(
        artifact::real_file(&path)? == path,
        "producer input must be canonical",
    )?;
    Ok(path)
}

#[test]
fn production_consumer_requires_compiled_sources() -> Result<(), String> {
    match (env::var_os(PHASE), env::var_os(RESULT)) {
        (Some(phase), Some(report)) => return child(phase, PathBuf::from(report)),
        (None, None) => {}
        _ => return Err("partial receipt control child configuration".into()),
    }
    let evidence = runtime::evidence_directory("receipt-source-controls")?;
    println!("receipt source controls evidence {}", evidence.display());
    let source_before = runtime::current_source(&evidence, "controls-before")?;
    let original = required_file("REVERIE_LITEINST_TEST_RUNTIME_MANIFEST")?;
    let elf = required_file("REVERIE_LITEINST_PRELOAD")?;
    let original_identity = artifact::FileIdentity::read(&original)?;
    let elf_identity = artifact::FileIdentity::read(&elf)?;
    let original_bytes = fs::read(&original).map_err(|e| e.to_string())?;
    let genuine: serde_json::Value =
        serde_json::from_slice(&original_bytes).map_err(|e| e.to_string())?;
    require(
        genuine["compiled_sources"].is_object(),
        "genuine receipt needs compiled source identities",
    )?;
    let executable = artifact::real_file(&env::current_exe().map_err(|e| e.to_string())?)?;
    let root = runtime::repository_root()?;
    let mut records = Vec::new();
    let mut launch_attempts = 0;
    let mut captured_children = 0;
    let mut completed_phases = 0;
    let mut matched_refusals = 0;
    let outcome: Result<(), String> = (|| {
        for phase in ["valid", "missing", "changed"] {
            let directory = evidence.join(phase);
            fs::create_dir(&directory).map_err(|e| e.to_string())?;
            let temporary = directory.join("tmp");
            fs::create_dir(&temporary).map_err(|e| e.to_string())?;
            let mut selected = genuine.clone();
            let receipt = if phase == "valid" {
                original.clone()
            } else {
                if phase == "missing" {
                    selected["compiled_sources"] = serde_json::Value::Null;
                } else {
                    let pin = genuine["compiled_sources"]["reverie_pin"]
                        .as_str()
                        .ok_or("genuine compiled source pin is absent")?;
                    require(
                        pin.len() == 40 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()),
                        "genuine compiled source pin must be full hexadecimal",
                    )?;
                    let mut changed = pin.as_bytes().to_vec();
                    changed[0] = if changed[0] == b'0' { b'1' } else { b'0' };
                    selected["compiled_sources"]["reverie_pin"] = String::from_utf8(changed)
                        .map_err(|e| e.to_string())?
                        .into();
                }
                // Revert exactly the selected field to prove every other receipt field held.
                let mut restored = selected.clone();
                if phase == "missing" {
                    restored["compiled_sources"] = genuine["compiled_sources"].clone();
                } else {
                    restored["compiled_sources"]["reverie_pin"] =
                        genuine["compiled_sources"]["reverie_pin"].clone();
                }
                require(
                    restored == genuine && selected != genuine,
                    "control changed an unintended receipt field",
                )?;
                let path = directory.join("runtime.json");
                artifact::write_new(
                    &path,
                    &serde_json::to_vec_pretty(&selected).map_err(|e| e.to_string())?,
                )?;
                path
            };
            let report_path = directory.join("child-result.json");
            let mut held =
                runtime::held_environment(b"host-only runtime receipt source controls".to_vec());
            let mut environment: BTreeMap<OsString, OsString> =
                held.environment.into_iter().collect();
            for (name, value) in [
                (PHASE, OsString::from(phase)),
                (RESULT, report_path.as_os_str().to_owned()),
                (
                    "REVERIE_LITEINST_TEST_RUNTIME_MANIFEST",
                    receipt.as_os_str().to_owned(),
                ),
                ("REVERIE_LITEINST_PRELOAD", elf.as_os_str().to_owned()),
                ("TMPDIR", temporary.as_os_str().to_owned()),
            ] {
                environment.insert(OsString::from(name), value);
            }
            held.environment = environment.into_iter().collect();
            let mut command = Command::new(&executable);
            command
                .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
                .current_dir(&root);
            let receipt_identity = artifact::FileIdentity::read(&receipt)?;
            launch_attempts += 1;
            let run = match contract::run_without_input(command, &held) {
                Ok(run) => run,
                Err(error) => {
                    captured_children += error.captures.len();
                    records.push(serde_json::json!({
                        "phase": phase, "launch_attempt": launch_attempts,
                        "capture_error": error.message, "receipt": receipt_identity,
                        "captured_children": error.captures.iter().map(|capture| serde_json::json!({
                            "code": capture.status.and_then(|status| status.code()),
                            "signal": capture.status.and_then(|status| status.signal()),
                            "end": format!("{:?}", capture.end),
                            "output_truncated": capture.output_truncated,
                        })).collect::<Vec<_>>(),
                    }));
                    runtime::retain_failure(&directory, "child", &error)?;
                    return Err(format!("receipt control capture failed: {error}"));
                }
            };
            captured_children += 1;
            records.push(serde_json::json!({
                "phase": phase, "code": run.status.and_then(|status| status.code()),
                "signal": run.status.and_then(|status| status.signal()),
                "receipt": receipt_identity,
                "result_path": report_path, "launch_attempt": launch_attempts,
            }));
            runtime::retain_capture(&directory, "child", &run)?;
            receipt_identity.verify()?;
            require(
                run.end == contract::CaptureEnd::Complete && !run.output_truncated,
                "receipt control capture is incomplete",
            )?;
            let expected_code = if phase == "valid" { 0 } else { 101 };
            require(
                run.status.is_some_and(|status| {
                    status.code() == Some(expected_code) && status.signal().is_none()
                }),
                "receipt control child returned an unexpected native status",
            )?;
            let report: serde_json::Value =
                serde_json::from_slice(&fs::read(&report_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            require(
                report["phase"] == phase,
                "receipt control child phase differs",
            )?;
            if phase == "valid" {
                require(
                    report["result"] == "qualified" && report["error"].is_null(),
                    "genuine receipt was not admitted by the production consumer",
                )?;
            } else {
                require(
                    report["result"] == "refused",
                    "mutated receipt was admitted",
                )?;
                let error = report["error"]
                    .as_str()
                    .ok_or("refusal child did not record its error")?;
                let prefix = format!("{MISMATCH}; preflight evidence ");
                let failure_directory = Path::new(
                    error
                        .strip_prefix(&prefix)
                        .ok_or_else(|| format!("unexpected receipt refusal reason: {error}"))?,
                );
                let failure =
                    artifact::real_file(&failure_directory.join("preflight.failure.txt"))?;
                require(
                    failure.starts_with(&temporary),
                    "refusal evidence is outside its child temporary directory",
                )?;
                require(
                    fs::read(failure).map_err(|e| e.to_string())? == MISMATCH.as_bytes(),
                    "refusal is not the exact compiled source mismatch",
                )?;
                matched_refusals += 1;
            }
            completed_phases += 1;
        }
        Ok(())
    })();
    // Close inputs after expected and unexpected ordinary child outcomes alike.
    let source_after = runtime::current_source(&evidence, "controls-after")?;
    original_identity.verify()?;
    elf_identity.verify()?;
    require(
        source_before == source_after,
        "source changed during receipt controls",
    )?;
    artifact::write_new(
        &evidence.join("controls.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "test_identity": TEST, "unique_new_test_identities": 1, "parent_invocations": 1,
            "child_launch_attempts": launch_attempts, "captured_child_invocations": captured_children,
            "completed_control_phases": completed_phases, "matched_refusal_controls": matched_refusals,
            "children": records,
            "controls_complete": outcome.is_ok(), "error": outcome.as_ref().err(),
            "source_before": source_before, "source_after": source_after,
            "original_receipt": original_identity, "elf": elf_identity,
            "guest_executions": 0, "runtime_matrix_credit": 0,
        }))
        .map_err(|e| e.to_string())?,
    )?;
    println!(
        "receipt controls: one identity, one parent, {launch_attempts} child launch attempts, {captured_children} captured child invocations, {completed_phases} completed phases; zero guest executions"
    );
    outcome
}
