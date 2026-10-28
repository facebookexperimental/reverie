//! Additive real forwarding controls; all original workload sources are separate.

use std::ffi::OsStr;
use std::process::Command;

use reverie_liteinst::PreloadTool;
use reverie_liteinst::configure_command;

// This consumer uses only part of the shared runtime qualification support.
#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod runtime;

const C_SOURCE: &[u8] = include_bytes!("fixtures/mapping_integrity_guest.c");
const ASM_SOURCE: &[u8] = include_bytes!("fixtures/mapping_integrity_guest.S");

fn require(value: bool, message: impl Into<String>) -> Result<(), String> {
    if value { Ok(()) } else { Err(message.into()) }
}

#[test]
fn published_owner_guest_mprotect_and_munmap_preserve_real_spare_pages() -> Result<(), String> {
    let leaf = runtime::required_runtime()?;
    let evidence = runtime::evidence_directory("mapping-integrity-minimal")?;
    eprintln!("Mapping integrity literal evidence {}", evidence.display());
    let source_before = runtime::current_source(&evidence, "before")?;
    require(
        source_before == leaf.source,
        "current source differs from qualified runtime",
    )?;
    require(
        leaf.receipt.qualification.allocator_backing.descriptor.mode
            == runtime::artifact::AllocatorBackingMode::Fixed,
        "standalone mapping fixture requires actual Fixed qualification",
    )?;
    let receipt_identity = runtime::artifact::FileIdentity::read(&leaf.receipt_path)?;
    let sources = leaf.source.root.join("reverie-liteinst/tests/fixtures");
    let c_source =
        runtime::artifact::FileIdentity::read(&sources.join("mapping_integrity_guest.c"))?;
    let asm_source =
        runtime::artifact::FileIdentity::read(&sources.join("mapping_integrity_guest.S"))?;
    require(
        c_source.sha256 == runtime::artifact::sha256(C_SOURCE),
        "compiled/current C source differs",
    )?;
    require(
        asm_source.sha256 == runtime::artifact::sha256(ASM_SOURCE),
        "compiled/current asm source differs",
    )?;
    let result = (|| {
        let binary = evidence.join("mapping-integrity-guest");
        let held = runtime::held_environment(b"separate mapping guest compiler".to_vec());
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
            ])
            .arg(&c_source.path)
            .arg(&asm_source.path)
            .arg("-ldl")
            .arg("-o")
            .arg(&binary)
            .current_dir(&evidence);
        let compiled = match runtime::contract::run_without_input(compiler, &held) {
            Ok(run) => run,
            Err(failure) => {
                runtime::retain_failure(&evidence, "compiler", &failure)?;
                return Err(format!(
                    "mapping guest compiler: {failure}; evidence {}",
                    evidence.display()
                ));
            }
        };
        runtime::retain_capture(&evidence, "compiler", &compiled)?;
        require(
            compiled.status.is_some_and(|status| status.success()),
            "mapping guest compiler failed",
        )?;
        let guest_identity = runtime::artifact::FileIdentity::read(&binary)?;
        runtime::artifact::write_new(
            &evidence.join("inputs.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "runtime": leaf.receipt.artifact, "runtime_receipt": receipt_identity,
                "source": source_before, "c_source": c_source, "asm_source": asm_source,
                "guest": guest_identity, "expected_raw_errno": -libc::EPERM,
                "route_evidence_required": true, "original_oracles_changed": false,
                "full_isolation_claimed": false,
            }))
            .map_err(|error| error.to_string())?,
        )?;
        let mut guest_environment = held.environment;
        guest_environment
            .retain(|(name, _)| !name.to_string_lossy().starts_with("REVERIE_LITEINST_"));
        let mut failures = Vec::new();
        for (tool, label) in [
            (PreloadTool::Strace, "strace"),
            (PreloadTool::Compatibility, "compat"),
        ] {
            for operation in ["mprotect", "munmap"] {
                let name = format!("{label}-{operation}");
                let mut command = Command::new(&binary);
                command
                    .arg(&leaf.path)
                    .arg(operation)
                    .current_dir(&evidence)
                    .env_clear()
                    .envs(guest_environment.iter().map(|(key, value)| (key, value)));
                configure_command(&mut command, tool).map_err(|error| error.to_string())?;
                let environment: Vec<_> = command
                    .get_envs()
                    .map(|(key, value)| {
                        value
                            .map(|value| (key.to_os_string(), value.to_os_string()))
                            .ok_or_else(|| {
                                "configured child has a removed environment key".to_owned()
                            })
                    })
                    .collect::<Result<_, _>>()?;
                require(
                    environment.iter().any(|(key, value)| {
                        key == OsStr::new("LD_PRELOAD") && value == leaf.path.as_os_str()
                    }),
                    "configured child preload differs from the qualified runtime",
                )?;
                require(
                    environment.iter().any(|(key, value)| {
                        key == OsStr::new("REVERIE_LITEINST_TOOL") && value == OsStr::new(label)
                    }),
                    "configured child tool selector differs from its trial",
                )?;
                let child_held = runtime::contract::HeldInputs {
                    environment,
                    policy: format!("mapping integrity {label}/{operation}; exact qualified preload; EPERM/maps/sentinel/same-page lease").into_bytes(),
                };
                match runtime::contract::run_without_input(command, &child_held) {
                    Ok(run) => {
                        runtime::retain_capture(&evidence, &name, &run)?;
                        if !run.status.is_some_and(|status| status.success()) {
                            failures.push(format!("{name}: literal child exit {:?}", run.status));
                        }
                        let text = String::from_utf8_lossy(&run.stdout);
                        if text
                            .lines()
                            .filter(|line| line.starts_with("MAPPING_LITERAL "))
                            .count()
                            != 1
                        {
                            failures.push(format!(
                                "{name}: one complete physical observation is required"
                            ));
                        }
                        if run.output_truncated
                            || run.input.is_some()
                            || run.end != runtime::contract::CaptureEnd::Complete
                        {
                            failures.push(format!("{name}: incomplete/truncated process capture"));
                        }
                    }
                    Err(failure) => {
                        runtime::retain_failure(&evidence, &name, &failure)?;
                        failures.push(format!("{name}: {failure}"));
                    }
                }
                c_source.verify()?;
                asm_source.verify()?;
                guest_identity.verify()?;
                leaf.receipt.artifact.verify()?;
                receipt_identity.verify()?;
            }
        }
        require(
            failures.is_empty(),
            format!(
                "{}; literal evidence {}",
                failures.join("; "),
                evidence.display()
            ),
        )
    })();
    let after = runtime::current_source(&evidence, "after");
    c_source.verify()?;
    asm_source.verify()?;
    leaf.receipt.artifact.verify()?;
    receipt_identity.verify()?;
    match after {
        Ok(source_after) if source_after == source_before => result,
        Ok(_) => Err(format!(
            "source changed during mapping trials; prior result {result:?}"
        )),
        Err(error) => Err(format!(
            "mapping source postcheck: {error}; prior result {result:?}"
        )),
    }
}

const BOUNDARY_C_SOURCE: &[u8] = include_bytes!("fixtures/mapping_boundaries_guest.c");

#[test]
fn native_mapping_boundaries_preserve_guards_break_abi_and_fork_owner() -> Result<(), String> {
    let leaf = runtime::required_runtime()?;
    let evidence = runtime::evidence_directory("mapping-boundaries")?;
    eprintln!("Mapping boundary literal evidence {}", evidence.display());
    let source_before = runtime::current_source(&evidence, "before")?;
    require(
        source_before == leaf.source,
        "current source differs from qualified runtime",
    )?;
    require(
        leaf.receipt.qualification.allocator_backing.descriptor.mode
            == runtime::artifact::AllocatorBackingMode::Fixed,
        "standalone mapping fixture requires actual Fixed qualification",
    )?;
    let receipt_identity = runtime::artifact::FileIdentity::read(&leaf.receipt_path)?;
    let sources = leaf.source.root.join("reverie-liteinst/tests/fixtures");
    let c_source =
        runtime::artifact::FileIdentity::read(&sources.join("mapping_boundaries_guest.c"))?;
    let asm_source =
        runtime::artifact::FileIdentity::read(&sources.join("mapping_integrity_guest.S"))?;
    require(
        c_source.sha256 == runtime::artifact::sha256(BOUNDARY_C_SOURCE),
        "compiled/current C source differs",
    )?;
    require(
        asm_source.sha256 == runtime::artifact::sha256(ASM_SOURCE),
        "compiled/current asm source differs",
    )?;
    let result = (|| {
        let binary = evidence.join("mapping-boundaries-guest");
        let held = runtime::held_environment(b"separate mapping guest compiler".to_vec());
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
            ])
            .arg(&c_source.path)
            .arg(&asm_source.path)
            .arg("-ldl")
            .arg("-o")
            .arg(&binary)
            .current_dir(&evidence);
        let compiled = match runtime::contract::run_without_input(compiler, &held) {
            Ok(run) => run,
            Err(failure) => {
                runtime::retain_failure(&evidence, "compiler", &failure)?;
                return Err(format!(
                    "mapping guest compiler: {failure}; evidence {}",
                    evidence.display()
                ));
            }
        };
        runtime::retain_capture(&evidence, "compiler", &compiled)?;
        require(
            compiled.status.is_some_and(|status| status.success()),
            "mapping guest compiler failed",
        )?;
        let guest_identity = runtime::artifact::FileIdentity::read(&binary)?;
        runtime::artifact::write_new(
            &evidence.join("inputs.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "runtime": leaf.receipt.artifact, "runtime_receipt": receipt_identity,
                "source": source_before, "c_source": c_source, "asm_source": asm_source,
                "guest": guest_identity, "mapping_errno": -libc::EPERM,
                "brk_contract": "genuine unchanged break; libc ENOMEM for refused growth",
                "mseal_live_support": "reported separately; ENOSYS gives no live mutation credit",
                "route_evidence_required": true, "original_oracles_changed": false,
                "full_isolation_claimed": false,
            }))
            .map_err(|error| error.to_string())?,
        )?;
        let mut guest_environment = held.environment;
        guest_environment
            .retain(|(name, _)| !name.to_string_lossy().starts_with("REVERIE_LITEINST_"));
        let mut failures = Vec::new();
        for (tool, label) in [
            (PreloadTool::Strace, "strace"),
            (PreloadTool::Compatibility, "compat"),
        ] {
            for operation in ["guard", "live", "brk", "mseal", "fork"] {
                let name = format!("{label}-{operation}");
                let mut command = Command::new(&binary);
                command
                    .arg(&leaf.path)
                    .arg(operation)
                    .current_dir(&evidence)
                    .env_clear()
                    .envs(guest_environment.iter().map(|(key, value)| (key, value)));
                configure_command(&mut command, tool).map_err(|error| error.to_string())?;
                let environment: Vec<_> = command
                    .get_envs()
                    .map(|(key, value)| {
                        value
                            .map(|value| (key.to_os_string(), value.to_os_string()))
                            .ok_or_else(|| {
                                "configured child has a removed environment key".to_owned()
                            })
                    })
                    .collect::<Result<_, _>>()?;
                require(
                    environment.iter().any(|(key, value)| {
                        key == OsStr::new("LD_PRELOAD") && value == leaf.path.as_os_str()
                    }),
                    "configured child preload differs from the qualified runtime",
                )?;
                require(
                    environment.iter().any(|(key, value)| {
                        key == OsStr::new("REVERIE_LITEINST_TOOL") && value == OsStr::new(label)
                    }),
                    "configured child tool selector differs from its trial",
                )?;
                let child_held = runtime::contract::HeldInputs {
                    environment,
                    policy: format!("mapping boundaries {label}/{operation}; exact qualified preload; literal ABI/maps/sentinel/fork/lease").into_bytes(),
                };
                match runtime::contract::run_without_input(command, &child_held) {
                    Ok(run) => {
                        runtime::retain_capture(&evidence, &name, &run)?;
                        if !run.status.is_some_and(|status| status.success()) {
                            failures.push(format!("{name}: literal child exit {:?}", run.status));
                        }
                        let text = String::from_utf8_lossy(&run.stdout);
                        if text
                            .lines()
                            .filter(|line| line.starts_with("MAPPING_BOUNDARY "))
                            .count()
                            != 1
                        {
                            failures.push(format!(
                                "{name}: one complete physical observation is required"
                            ));
                        }
                        if run.output_truncated
                            || run.input.is_some()
                            || run.end != runtime::contract::CaptureEnd::Complete
                        {
                            failures.push(format!("{name}: incomplete/truncated process capture"));
                        }
                    }
                    Err(failure) => {
                        runtime::retain_failure(&evidence, &name, &failure)?;
                        failures.push(format!("{name}: {failure}"));
                    }
                }
                c_source.verify()?;
                asm_source.verify()?;
                guest_identity.verify()?;
                leaf.receipt.artifact.verify()?;
                receipt_identity.verify()?;
            }
        }
        require(
            failures.is_empty(),
            format!(
                "{}; literal evidence {}",
                failures.join("; "),
                evidence.display()
            ),
        )
    })();
    let after = runtime::current_source(&evidence, "after");
    c_source.verify()?;
    asm_source.verify()?;
    leaf.receipt.artifact.verify()?;
    receipt_identity.verify()?;
    match after {
        Ok(source_after) if source_after == source_before => result,
        Ok(_) => Err(format!(
            "source changed during mapping trials; prior result {result:?}"
        )),
        Err(error) => Err(format!(
            "mapping source postcheck: {error}; prior result {result:?}"
        )),
    }
}
