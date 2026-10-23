//! Separate M2 controls in the qualified real standalone preload.
//! The new C guest is prepared separately using the existing fixed recipe.
//! No consumer compilation, missing-input skip or M1 comparator change occurs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod liteinst_runtime;
#[path = "support/stack_observation.rs"]
mod stack_observation;

use liteinst_runtime::artifact;
use liteinst_runtime::contract;
use stack_observation::Continuation;

const STACK_GUEST_BYTES: &[u8] = include_bytes!("fixtures/m2_stack_guest.c");
const STACK_GUEST_ENV: &str = "REVERIE_LITEINST_STACK_GUEST";
const STACK_GUEST_MANIFEST_ENV: &str = "REVERIE_LITEINST_STACK_GUEST_MANIFEST";

fn selected_file(name: &str) -> Result<PathBuf, String> {
    let selected = PathBuf::from(std::env::var_os(name).ok_or_else(|| {
        format!("{name} is required; prepare the separate M2 C guest and its source-bound GuestReceipt before this consumer")
    })?);
    if !selected.is_absolute() {
        return Err(format!(
            "{name} must select an absolute producer-owned file"
        ));
    }
    let canonical = artifact::real_file(&selected)?;
    if selected != canonical {
        return Err(format!(
            "{name} must select its literal canonical regular file"
        ));
    }
    Ok(canonical)
}

fn capture(
    evidence: &Path,
    command: Command,
    held: &contract::HeldInputs,
) -> Result<contract::CapturedRun, String> {
    match contract::run_without_input(command, held) {
        Ok(run) => {
            liteinst_runtime::retain_capture(evidence, "actual-leaf", &run)?;
            Ok(run)
        }
        Err(failure) => {
            liteinst_runtime::retain_failure(evidence, "actual-leaf", &failure)?;
            Err(format!("{failure}; raw M2 evidence {}", evidence.display()))
        }
    }
}

fn trial(label: &str, inert: bool, alt_stack: bool) -> Result<(), String> {
    let runtime = liteinst_runtime::required_runtime()?;
    let evidence = liteinst_runtime::evidence_directory(&format!("m2-stack-{label}"))?;
    eprintln!("M2 {label} raw evidence: {}", evidence.display());
    let guest = selected_file(STACK_GUEST_ENV)?;
    let guest_manifest = selected_file(STACK_GUEST_MANIFEST_ENV)?;
    let source = runtime
        .source
        .root
        .join("reverie-liteinst/tests/fixtures/m2_stack_guest.c");
    let guest_receipt = artifact::verify_guest_receipt(
        &guest_manifest,
        &guest,
        &source,
        &artifact::sha256(STACK_GUEST_BYTES),
    )?;
    let launcher = artifact::real_file(Path::new(env!("CARGO_BIN_EXE_reverie-liteinst-strace")))?;
    let launcher_identity = artifact::FileIdentity::read(&launcher)?;
    let setarch = artifact::real_file(Path::new("/usr/bin/setarch"))?;
    let setarch_identity = artifact::FileIdentity::read(&setarch)?;
    let mode = if inert { "inert" } else { "observe" };
    let policy = serde_json::to_vec(&serde_json::json!({
        "schema": 1,
        "observation": "M2 real standalone leaf; continuation NotPrepared/NotReached",
        "source_head": runtime.source.head,
        "source_tree": runtime.source.tree,
        "runtime": runtime.receipt.artifact,
        "guest": guest_receipt.binary,
        "guest_source": guest_receipt.source,
        "launcher": launcher_identity,
        "setarch": setarch_identity,
        "mode": mode,
        "alt_stack": alt_stack,
        "site_patching": true,
        "personality": "ADDR_NO_RANDOMIZE via setarch -R",
        "stdin": "closed; fixture reads no input",
        "full_entry_isolation_claimed": false,
        "guest_write_protection_claimed": false,
    }))
    .map_err(|error| error.to_string())?;
    let mut held = liteinst_runtime::held_environment(policy);
    let mut environment: BTreeMap<OsString, OsString> = held.environment.into_iter().collect();
    for name in [
        "REVERIE_INGUEST_TOOL",
        "REVERIE_LITEINST_TOOL",
        reverie_liteinst::COMPAT_EVENT_FD_ENV,
        reverie_liteinst::COMPAT_EVENT_COOKIE_ENV,
        reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV,
    ] {
        environment.remove(&OsString::from(name));
    }
    environment.insert(
        reverie_liteinst::SITE_PATCHING_ENV.into(),
        OsString::from("1"),
    );
    environment.insert(
        reverie_liteinst::ALT_STACK_ENV.into(),
        OsString::from(if alt_stack { "1" } else { "0" }),
    );
    environment.insert(
        "REVERIE_LITEINST_PRELOAD".into(),
        runtime.path.as_os_str().to_owned(),
    );
    let mut command = Command::new(&setarch);
    command.args(["x86_64", "-R"]);
    if inert {
        // Load the genuine constructor-bearing leaf, with no active selector.
        environment.insert("LD_PRELOAD".into(), runtime.path.as_os_str().to_owned());
    } else {
        // The public strace launcher itself selects exactly the qualified leaf.
        command.arg(&launcher);
    }
    command
        .arg(&guest)
        .arg(mode)
        .arg(&runtime.path)
        .current_dir(&runtime.source.root);
    held.environment = environment.into_iter().collect();

    let result = (|| -> Result<(), String> {
        let run = capture(&evidence, command, &held)?;
        if run.input.is_some()
            || !run.status.is_some_and(|status| status.success())
            || run.end != contract::CaptureEnd::Complete
            || run.output_truncated
        {
            return Err(format!(
                "actual M2 leaf did not complete with successful exit/closed stdin; {}",
                evidence.display()
            ));
        }
        let observation = stack_observation::parse(&run.stdout)?;
        let coherent = stack_observation::verify_observation(
            &observation,
            &runtime.path,
            mode,
            alt_stack,
            Continuation::Absent,
        );
        artifact::write_new(
            &evidence.join("observation-result.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "schema": 1,
                "valid_actual_observation": coherent.is_ok(),
                "error": coherent.as_ref().err(),
                "raw_stdout_sha256": artifact::sha256(&run.stdout),
                "continuation_state": "NotPrepared/NotReached",
                "callback_placement_credit": false,
                "full_entry_isolation_claimed": false,
            }))
            .map_err(|error| error.to_string())?,
        )?;
        coherent?;
        if !inert && alt_stack {
            let placement = stack_observation::verify_fixed_stack_placement(
                &observation,
                true,
                Continuation::Absent,
            );
            artifact::write_new(
                &evidence.join("placement-result.json"),
                &serde_json::to_vec_pretty(&serde_json::json!({
                    "schema": 1,
                    "fixed_altstack_placement_and_guard_reads_passed": placement.is_ok(),
                    "error": placement.as_ref().err(),
                    "callback_placement_credit": false,
                    "full_entry_isolation_claimed": false,
                    "guest_write_protection_claimed": false,
                }))
                .map_err(|error| error.to_string())?,
            )?;
            placement?;
        }
        Ok(())
    })();
    // Close source/artifact guards even when the measured baseline fails.
    let after = (|| -> Result<(), String> {
        runtime.receipt.artifact.verify()?;
        guest_receipt.source.verify()?;
        guest_receipt.binary.verify()?;
        launcher_identity.verify()?;
        setarch_identity.verify()?;
        liteinst_runtime::verify_unchanged(&evidence)
    })();
    match (result, after) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(format!("{error}; raw evidence {}", evidence.display())),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(after)) => Err(format!(
            "{error}; final source/artifact guard also failed: {after}; {}",
            evidence.display()
        )),
    }
}

#[test]
fn standalone_leaf_registers_a_fixed_guarded_altstack() -> Result<(), String> {
    trial("standalone-enabled", false, true)
}

#[test]
fn standalone_alt_stack_disabled_receives_no_owned_stack_credit() -> Result<(), String> {
    trial("standalone-disabled", false, false)
}

#[test]
fn inert_true_leaf_leaves_the_fixed_range_and_altstack_unmodified() -> Result<(), String> {
    trial("inert", true, false)
}
