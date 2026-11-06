//! Raw owner-protection behavior, separate from whole-ELF qualification.

use std::process::Command;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
pub mod liteinst_runtime;
use liteinst_runtime as runtime;
#[path = "support/fulltool_capture.rs"]
mod fulltool_capture;
#[path = "support/raw_mseal_fixture.rs"]
mod raw_mseal_fixture;

const BOUNDARY_C_SOURCE: &[u8] = include_bytes!("fixtures/mapping_boundaries_guest.c");
const ASM_SOURCE: &[u8] = include_bytes!("fixtures/mapping_integrity_guest.S");

fn require(value: bool, message: impl Into<String>) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.into()) }
}

#[test]
fn plain_fulltool_raw_mseal_protects_owner_before_unknown_syscall_refusal() -> Result<(), String> {
    let evidence = runtime::evidence_directory("source-built-raw-mseal")?;
    eprintln!(
        "Source-built FullTool raw-mseal evidence {}",
        evidence.display()
    );
    let leaf = raw_mseal_fixture::build(&evidence)?;
    let before = leaf.source.clone();
    let receipt = runtime::artifact::FileIdentity::read(&leaf.manifest)?;
    let sources = leaf.source.root.join("reverie-liteinst/tests/fixtures");
    let c_source =
        runtime::artifact::FileIdentity::read(&sources.join("mapping_boundaries_guest.c"))?;
    let assembly =
        runtime::artifact::FileIdentity::read(&sources.join("mapping_integrity_guest.S"))?;
    require(
        c_source.sha256 == runtime::artifact::sha256(BOUNDARY_C_SOURCE),
        "compiled/current C source differs",
    )?;
    require(
        assembly.sha256 == runtime::artifact::sha256(ASM_SOURCE),
        "compiled/current assembly source differs",
    )?;
    let result = (|| {
        let binary = evidence.join("plain-fulltool-mseal-guest");
        let held = runtime::held_environment(
            b"independent plain FullTool raw-mseal regression compiler".to_vec(),
        );
        let mut compiler = Command::new(std::env::var_os("CC").unwrap_or_else(|| "cc".into()));
        compiler
            .args([
                "-std=gnu11",
                "-O0",
                "-fno-pie",
                "-no-pie",
                "-fno-builtin",
                "-fno-lto",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,-z,now",
                "-DREVERIE_MAPPING_FULLTOOL=1",
            ])
            .arg(&c_source.path)
            .arg(&assembly.path)
            .arg("-ldl")
            .arg("-o")
            .arg(&binary)
            .current_dir(&evidence);
        require(
            std::time::Instant::now() + std::time::Duration::from_secs(120) < leaf.setup_deadline,
            "source-built setup lacks the existing compiler capture window",
        )?;
        let compiled = match runtime::contract::run_without_input(compiler, &held) {
            Ok(run) => {
                runtime::retain_capture(&evidence, "compiler", &run)?;
                run
            }
            Err(error) => {
                runtime::retain_failure(&evidence, "compiler", &error)?;
                return Err(format!("plain FullTool C compiler: {error}"));
            }
        };
        require(
            compiled.status.is_some_and(|status| status.success())
                && compiled.end == runtime::contract::CaptureEnd::Complete
                && !compiled.output_truncated
                && compiled.input.is_none(),
            "plain FullTool C compiler did not complete successfully",
        )?;
        require(
            std::time::Instant::now() < leaf.setup_deadline,
            "source-built setup deadline exhausted",
        )?;
        let guest = runtime::artifact::FileIdentity::read(&binary)?;
        runtime::artifact::write_new(&evidence.join("inputs.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "source_built_runtime": leaf.artifact, "source_built_manifest": receipt, "source": before,
                "c_source": c_source, "assembly": assembly, "guest": guest,
                "route": "installed FullTool, site patching disabled, plain callback",
                "protected_raw_mseal": -libc::EPERM, "outside_unknown_raw_mseal": -libc::ENOSYS,
                "owner_oracles": "complete VMA, sentinel bytes, owner identity and both lease reuse identities",
                "legacy_positive_legs_changed": false,
            })).map_err(|error| error.to_string())?)?;
        let mut environment = held.environment;
        environment.retain(|(key, _)| {
            !key.to_string_lossy().starts_with("REVERIE_LITEINST_")
                && key != "REVERIE_INGUEST_TOOL"
                && key != "LD_PRELOAD"
        });
        let failures = full_tool_trials(
            &leaf.artifact.path,
            &evidence,
            &binary,
            &environment,
            &["mseal"],
            "MAPPING_BOUNDARY ",
            &[&c_source, &assembly, &guest, &leaf.artifact, &receipt],
        )?;
        require(failures.is_empty(), failures.join("; "))
    })();
    let after = (|| {
        c_source.verify()?;
        assembly.verify()?;
        leaf.artifact.verify()?;
        leaf.original.verify()?;
        receipt.verify()?;
        require(
            runtime::current_source(&evidence, "after")? == before,
            "plain FullTool regression source changed",
        )
    })();
    let result = match (result, after) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => {
            Err(format!("{error}; evidence {}", evidence.display()))
        }
        (Err(error), Err(after)) => Err(format!(
            "{error}; final guard: {after}; evidence {}",
            evidence.display()
        )),
    };
    let retired = leaf.retire(&evidence);
    match (result, retired) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; target cleanup: {cleanup}")),
    }
}

fn full_tool_trials(
    preload: &std::path::Path,
    evidence: &std::path::Path,
    binary: &std::path::Path,
    environment: &[(std::ffi::OsString, std::ffi::OsString)],
    operations: &[&str],
    literal_prefix: &str,
    identities: &[&runtime::artifact::FileIdentity],
) -> Result<Vec<String>, String> {
    let mut failures = Vec::new();
    for operation in operations {
        let name = format!("full-tool-{operation}");
        let socket = evidence.join(format!("{name}.sock"));
        let mut command = Command::new(binary);
        command
            .arg(preload)
            .arg(operation)
            .current_dir(evidence)
            .env_clear()
            .envs(environment.iter().map(|(key, value)| (key, value)))
            .env("LD_PRELOAD", preload)
            .env(reverie_liteinst::COORDINATOR_ENV, &socket)
            .env(reverie_liteinst::SITE_PATCHING_ENV, "0");
        let environment = command
            .get_envs()
            .map(|(key, value)| {
                value
                    .map(|value| (key.to_os_string(), value.to_os_string()))
                    .ok_or_else(|| "FullTool child has a removed environment key".to_owned())
            })
            .collect::<Result<_, _>>()?;
        let held = runtime::contract::HeldInputs {
            environment,
            policy: format!(
                "mapping installed FullTool/{operation}; exact source-built Fixed behavior fixture (not M1 qualified); same C ABI/maps/bytes/identity/lease/fork oracles; exact physical fallback and actual callback counts; no sites or hooks"
            )
            .into_bytes(),
        };
        // Keep the original bounded process-group capture, including its
        // 120-second deadline, 16-MiB cap and raw evidence retention. The
        // actual shared RPC server runs concurrently with that same owner.
        let trial = fulltool_capture::run(command, held, socket);
        match trial {
            Ok(run) => {
                runtime::retain_capture(evidence, &name, &run)?;
                if !run.status.is_some_and(|status| status.success()) {
                    failures.push(format!("{name}: literal child exit {:?}", run.status));
                }
                let text = std::str::from_utf8(&run.stdout)
                    .map_err(|error| format!("{name}: incomplete UTF8 observation: {error}"))?;
                if text
                    .lines()
                    .filter(|line| line.starts_with(literal_prefix))
                    .count()
                    != 1
                {
                    failures.push(format!(
                        "{name}: one complete physical observation required"
                    ));
                }
                let warmup = "MAPPING_FULLTOOL_PROOF label=warmup number=39 total=2 syscall=2 callbacks=2 sites=0 hooks=0";
                if text.lines().filter(|line| *line == warmup).count() != 1 {
                    failures.push(format!(
                        "{name}: exact genuine callback/trap warmup missing"
                    ));
                }
                let expected_proofs = if *operation == "fork" { 4 } else { 2 };
                if text
                    .lines()
                    .filter(|line| line.starts_with("MAPPING_FULLTOOL_PROOF "))
                    .count()
                    != expected_proofs
                {
                    failures.push(format!("{name}: missing exact measured syscall proof"));
                }
                if run.output_truncated
                    || run.input.is_some()
                    || run.end != runtime::contract::CaptureEnd::Complete
                {
                    failures.push(format!("{name}: incomplete/truncated process capture"));
                }
            }
            Err(failure) => {
                runtime::retain_failure(evidence, &name, &failure)?;
                failures.push(format!("{name}: {failure}"));
            }
        }
        for identity in identities {
            identity.verify()?;
        }
    }
    Ok(failures)
}
