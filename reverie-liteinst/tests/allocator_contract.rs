//! Required M1 controls using the actual standalone launcher and producer-owned
//! runtime/C guest. No consumer Cargo/cc, inert fixture DSO or missing-input skip.

use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::Command;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod liteinst_runtime;

use liteinst_runtime::artifact;
use liteinst_runtime::contract;

fn capture(
    evidence: &Path,
    name: &str,
    command: Command,
    input: [u8; 2],
    held: &contract::HeldInputs,
) -> Result<contract::CapturedRun, String> {
    match contract::run_bounded(command, input, held) {
        Ok(run) => {
            liteinst_runtime::retain_capture(evidence, name, &run)?;
            Ok(run)
        }
        Err(failure) => {
            liteinst_runtime::retain_failure(evidence, name, &failure)?;
            Err(format!("{failure}; raw evidence {}", evidence.display()))
        }
    }
}

fn capture_without_input(
    evidence: &Path,
    name: &str,
    command: Command,
    held: &contract::HeldInputs,
) -> Result<contract::CapturedRun, String> {
    match contract::run_without_input(command, held) {
        Ok(run) => {
            liteinst_runtime::retain_capture(evidence, name, &run)?;
            Ok(run)
        }
        Err(failure) => {
            liteinst_runtime::retain_failure(evidence, name, &failure)?;
            Err(format!("{failure}; raw evidence {}", evidence.display()))
        }
    }
}

fn demand(condition: bool, message: &str, evidence: &Path) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("{message}; raw evidence {}", evidence.display()))
    }
}

fn context(label: &str) -> Result<(std::path::PathBuf, contract::HeldInputs), String> {
    // Even host/guard controls require the qualified actual runtime prerequisite.
    // Their binaries themselves remain ordinary, non-preloaded caller roots.
    let runtime = liteinst_runtime::required_runtime()?;
    runtime.receipt.artifact.verify()?;
    let evidence = liteinst_runtime::evidence_directory(label)?;
    let policy = serde_json::to_vec(&serde_json::json!({
        "runtime_path": runtime.path,
        "runtime_sha256": runtime.receipt.artifact.sha256,
        "source_head": runtime.source.head,
        "source_tree": runtime.source.tree,
        "source_lock_sha256": runtime.source.lock.sha256,
        "core_limit": 0,
    }))
    .map_err(|error| error.to_string())?;
    let held = liteinst_runtime::held_environment(policy);
    eprintln!("M1 {label} raw evidence: {}", evidence.display());
    Ok((evidence, held))
}

#[test]
fn standalone_private_allocator_matrix() -> Result<(), String> {
    let (evidence, mut held) = context("standalone-matrix")?;
    let runtime = liteinst_runtime::required_runtime()?;
    let guest = liteinst_runtime::required_allocator_guest()?;
    guest.receipt.binary.verify()?;
    let launcher = artifact::real_file(Path::new(env!("CARGO_BIN_EXE_reverie-liteinst-strace")))?;
    let launcher_sha256 = artifact::file_sha256(&launcher)?;
    let setarch = artifact::real_file(Path::new("/usr/bin/setarch"))?;
    held.policy = serde_json::to_vec(&serde_json::json!({
        "base_policy_sha256": artifact::sha256(&held.policy),
        "program": setarch,
        "architecture": "x86_64",
        "personality": "ADDR_NO_RANDOMIZE via setarch -R",
        "launcher": launcher,
        "launcher_sha256": launcher_sha256,
        "guest_path": guest.path,
        "guest_sha256": guest.receipt.binary.sha256,
        "runtime_path": runtime.path,
        "runtime_sha256": runtime.receipt.artifact.sha256,
        "argv_env_selection": "unchanged; fixed two-byte stdin only",
    }))
    .map_err(|error| error.to_string())?;
    let mut pairs = Vec::with_capacity(contract::FIXED_CASES.len());
    for case in contract::FIXED_CASES {
        let mut runs = Vec::with_capacity(2);
        for mode in [contract::Mode::Quiet, contract::Mode::Work] {
            let key = contract::TrialKey { mode, case };
            let mut command = Command::new(&setarch);
            command
                .args(["x86_64", "-R"])
                .arg(&launcher)
                .arg(&guest.path)
                .current_dir(&runtime.source.root);
            // Only stdin changes across the fourteen launches. The real strace
            // launcher installs the exact selected runtime and propagates exit.
            let name = format!("{}{}", mode.byte() as char, case.selector() as char);
            runs.push(capture(&evidence, &name, command, key.input(), &held)?);
        }
        let pair =
            contract::compare_pair(&runs[0], &runs[1], case, &runtime.path).map_err(|failure| {
                let label = format!("pair-{}", case.selector() as char);
                match liteinst_runtime::retain_failure(&evidence, &label, &failure) {
                    Ok(()) => format!("{failure}; raw evidence {}", evidence.display()),
                    Err(error) => format!(
                        "{failure}; retaining pair evidence failed: {error}; {}",
                        evidence.display()
                    ),
                }
            })?;
        pairs.push(pair);
    }
    let counts =
        contract::validate_matrix(&pairs).map_err(
            |failure| match liteinst_runtime::retain_failure(&evidence, "matrix", &failure) {
                Ok(()) => format!("{failure}; raw evidence {}", evidence.display()),
                Err(error) => format!(
                    "{failure}; retaining matrix evidence failed: {error}; {}",
                    evidence.display()
                ),
            },
        )?;
    demand(
        artifact::file_sha256(&launcher)? == launcher_sha256,
        "actual launcher changed during matrix",
        &evidence,
    )?;
    liteinst_runtime::verify_unchanged(&evidence)?;
    artifact::write_new(
        &evidence.join("matrix.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "quiet_controls": counts.quiet_controls,
            "completed_work_runs": counts.completed_work_runs,
            "completed_work_case_rows": counts.completed_work_case_rows,
            "observed_work_operations": counts.observed_work_operations,
            "literal_address_pairs": counts.literal_address_pairs,
            "rust_allocator_contract_passed": true,
            "full_memory_isolation_claimed": false,
        }))
        .map_err(|error| error.to_string())?,
    )
}

#[test]
fn host_caller_keeps_its_96_mib_allocator() -> Result<(), String> {
    let (evidence, held) = context("host96mib")?;
    let binary = artifact::real_file(Path::new(env!(
        "CARGO_BIN_EXE_reverie-liteinst-allocator-host-control"
    )))?;
    let run = capture_without_input(&evidence, "host", Command::new(binary), &held)?;
    demand(
        run.status.is_some_and(|status| status.success()),
        "96 MiB caller control did not exit successfully",
        &evidence,
    )?;
    let prefix = b"M1_HOST_CONTROL bytes=100663296 allocations=";
    let suffix = b" private=0 bytes_ok=1\n";
    let count = run
        .stdout
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .ok_or_else(|| {
            format!(
                "96 MiB caller control protocol changed; {}",
                evidence.display()
            )
        })?;
    let allocations = std::str::from_utf8(count)
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    demand(
        !count.is_empty()
            && count.iter().all(u8::is_ascii_digit)
            && allocations.is_some_and(|value| value > 0),
        "caller allocator had no actual allocation/bytes/private-membership success",
        &evidence,
    )?;
    liteinst_runtime::verify_unchanged(&evidence)
}

#[test]
fn system_roots_are_refused_before_all_three_installation_entries() -> Result<(), String> {
    let (evidence, held) = context("installation-refusal")?;
    let binary = artifact::real_file(Path::new(env!(
        "CARGO_BIN_EXE_reverie-liteinst-allocator-install-control"
    )))?;
    for mode in ["install", "quiescent", "bootstrap"] {
        let mut command = Command::new(&binary);
        command.arg(mode);
        let run = capture_without_input(&evidence, mode, command, &held)?;
        demand(
            run.status.is_some_and(|status| status.success()),
            "System-only installation control did not succeed as a named refusal",
            &evidence,
        )?;
        let expected = format!(
            "M1_INSTALL_CONTROL mode={mode} refused=EOPNOTSUPP tool_calls=0 filter_unchanged=1\n"
        );
        demand(
            run.stdout == expected.as_bytes(),
            "installation control omitted actual refusal/callback/filter observations",
            &evidence,
        )?;
    }
    liteinst_runtime::verify_unchanged(&evidence)
}

#[test]
fn private_pointer_guard_has_exact_failure_and_fallback_outcomes() -> Result<(), String> {
    let (evidence, held) = context("private-guard")?;
    let binary = artifact::real_file(Path::new(env!(
        "CARGO_BIN_EXE_reverie-liteinst-allocator-private-control"
    )))?;
    for mode in ["valid", "null", "foreign", "max", "blocked-exit"] {
        let mut command = Command::new(&binary);
        command.arg(mode);
        let run = capture_without_input(&evidence, mode, command, &held)?;
        match mode {
            "valid" => demand(
                run.status.is_some_and(|status| status.success())
                    && run.stdout == b"M1_PRIVATE_GUARD valid=1 bytes_ok=1\n",
                "valid private pointer/layout/content control failed",
                &evidence,
            )?,
            "blocked-exit" => demand(
                run.status
                    .is_some_and(|status| status.signal() == Some(libc::SIGILL))
                    && run.stdout.is_empty(),
                "blocked exit_group must terminate through UD2/SIGILL",
                &evidence,
            )?,
            _ => demand(
                run.status.is_some_and(|status| status.code() == Some(127))
                    && run.stdout.is_empty(),
                "arbitrary-address guard must fail closed with exact status127",
                &evidence,
            )?,
        }
    }
    liteinst_runtime::verify_unchanged(&evidence)
}

#[test]
fn bounded_controls_have_closed_stdin_and_fixture_input_stays_exact() -> Result<(), String> {
    let evidence = liteinst_runtime::evidence_directory("runner-input")?;
    let held = liteinst_runtime::held_environment(b"bounded runner stdin control".to_vec());
    // cat reports every delivered byte and exits at EOF. A control command
    // must observe no fabricated Q/W selector, including when it exits quickly.
    let control = capture_without_input(&evidence, "control", Command::new("/bin/cat"), &held)?;
    demand(
        control.status.is_some_and(|status| status.success())
            && control.input.is_none()
            && control.stdout.is_empty()
            && control.stderr.is_empty(),
        "non-fixture command did not receive an empty, closed stdin",
        &evidence,
    )?;
    let fixture = capture(
        &evidence,
        "fixture",
        Command::new("/bin/cat"),
        *b"QS",
        &held,
    )?;
    demand(
        fixture.status.is_some_and(|status| status.success())
            && fixture.input == Some(*b"QS")
            && fixture.stdout == b"QS"
            && fixture.stderr.is_empty(),
        "fixture command must still receive exactly its two input bytes",
        &evidence,
    )
}
