//! Five separate real-leaf groups. These main-time records verify retained
//! constructor state; the independent hardware observer proves live entry.
//! Missing producer inputs are errors, never skips. M1/M2 oracles are unchanged.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod liteinst_runtime;
use liteinst_runtime::artifact as m1_artifact;
use liteinst_runtime::contract;
#[path = "../../scripts/standalone_constructor_fixture.rs"]
mod standalone_constructor_fixture;

const PROBE_SOURCE: &[u8] = include_bytes!("fixtures/standalone_constructor_guest.c");
const BASE: u64 = 0x6000_0000_0000;
const END: u64 = 0x6001_0000_0000;

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema: u32,
    case: String,
    owner: PathBuf,
    owner_base: u64,
    query_before: i32,
    query_after: i32,
    record: [u64; 16],
    record_before: [u64; 16],
    kernel_constructor_before: [u64; 16],
    kernel_constructor_after: [u64; 16],
    tid: i64,
    kernel_pid: i64,
    getpid: i64,
    kernel_before_result: i32,
    kernel_after_result: i32,
    kernel_before_version: u64,
    kernel_after_version: u64,
    kernel_before_status: i64,
    kernel_after_status: i64,
    kernel_before_tid: i64,
    kernel_before_pid: i64,
    kernel_constructor_before_result: i64,
    kernel_constructor_after_result: i64,
    record_crosscheck: i32,
    original_alt_result: i64,
    original_alt_sp: u64,
    original_alt_flags: i32,
    original_alt_size: u64,
    alt_before_result: i64,
    alt_before_sp: u64,
    alt_before_flags: i32,
    alt_before_size: u64,
    alt_after_result: i64,
    alt_after_sp: u64,
    alt_after_flags: i32,
    alt_after_size: u64,
    mapping_before: i64,
    mapping_after: i64,
    probe_mask: u64,
    interior: i64,
    lower_guard: i64,
    upper_guard: i64,
    bitmap_read: i64,
    bitmap: Vec<u64>,
    bootstrap_held: i32,
    root_calls: i64,
}

#[derive(Clone, Copy, Debug)]
enum Expected {
    Active,
    Inert,
    Refused,
    Generic,
}

fn need(value: bool, message: &str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn selected(name: &str) -> Result<PathBuf, String> {
    let path =
        PathBuf::from(std::env::var_os(name).ok_or_else(|| {
            format!("{name} is required; run the explicit real-leaf producer first")
        })?);
    let canonical = m1_artifact::real_file(&path)?;
    need(
        path.is_absolute() && path == canonical,
        "fixture input must be a literal canonical regular file",
    )?;
    Ok(canonical)
}

fn local_function(elf: &goblin::elf::Elf<'_>, name: &str, base: u64) -> Result<u64, String> {
    use goblin::elf::sym;
    let symbols: Vec<_> = elf
        .syms
        .iter()
        .filter(|symbol| {
            elf.strtab.get_at(symbol.st_name) == Some(name)
                && symbol.is_function()
                && symbol.st_shndx != 0
                && symbol.st_size != 0
        })
        .collect();
    need(
        symbols.len() == 1,
        &format!("actual owner must define one {name}"),
    )?;
    let symbol = &symbols[0];
    need(
        symbol.st_bind() == sym::STB_LOCAL || symbol.st_visibility() == sym::STV_HIDDEN,
        &format!("actual {name} must bind locally/hidden"),
    )?;
    need(
        elf.program_headers.iter().any(|segment| {
            segment.p_type == goblin::elf::program_header::PT_LOAD
                && segment.is_executable()
                && symbol.st_value >= segment.p_vaddr
                && symbol
                    .st_value
                    .checked_add(symbol.st_size)
                    .is_some_and(|end| end <= segment.p_vaddr + segment.p_memsz)
        }),
        "actual body/adoption must be inside an executable owner segment",
    )?;
    base.checked_add(symbol.st_value)
        .ok_or_else(|| "actual owner address overflow".to_owned())
}

fn verify_owned(observation: &Observation, runtime: &Path) -> Result<(), String> {
    // Absence is the baseline placement failure, not a missing-prerequisite skip.
    need(
        observation.query_before == 0 && observation.query_after == 0,
        "actual real-leaf constructor record absent; owned active constructor not reached",
    )?;
    let r = &observation.record;
    need(
        r[0] == 1 && r[1] == 4 && observation.tid > 0 && r[2] == observation.tid as u64,
        "constructor must have returned with the actual owning kernel TID",
    )?;
    need(
        r[14] == BASE
            && r[15] == END
            && r[3] == BASE + 0x100000
            && r[5] == r[3] + 4096
            && r[6] == r[5] + 8 * 1024 * 1024
            && r[4] == r[6] + 4096,
        "actual bootstrap must retain the exact fixed 8MiB guarded extent",
    )?;
    need(
        r[7] != 0
            && !(BASE..END).contains(&r[7])
            && (r[5]..r[6]).contains(&r[10])
            && (r[5]..r[6]).contains(&r[11])
            && r[12] == BASE + 4096
            && (BASE + 4096..BASE + 0x100000).contains(&r[13]),
        "caller/real Rust samples/control record do not match owned bootstrap",
    )?;
    let bytes = fs::read(runtime).map_err(|e| e.to_string())?;
    let elf = goblin::elf::Elf::parse(&bytes).map_err(|e| e.to_string())?;
    need(
        r[8] == local_function(
            &elf,
            "reverie_inguest_constructor_adopt_entry",
            observation.owner_base,
        )? && r[9]
            == local_function(
                &elf,
                "reverie_liteinst_standalone_body",
                observation.owner_base,
            )?,
        "constructor record must bind actual same-owner adoption and hidden leaf body",
    )?;
    need(
        observation.interior == 1
            && observation.lower_guard == -i64::from(libc::EFAULT)
            && observation.upper_guard == -i64::from(libc::EFAULT)
            && observation.bitmap_read == 33 * 8
            && observation.probe_mask == 15
            && observation.bitmap.len() == 33
            && observation.bitmap[..32]
                .iter()
                .all(|word| *word == u64::MAX)
            && observation.bitmap[32] & 3 == 3
            && observation.bootstrap_held == 1,
        "kernel guard probes or guard-inclusive retained bootstrap occupancy failed",
    )?;
    need(
        observation.mapping_before == 0 && observation.mapping_after == 0,
        "active actual fixed reservation not present",
    )?;
    Ok(())
}

fn verify_inert(observation: &Observation) -> Result<(), String> {
    need(
        observation.query_before == -1
            && observation.query_after == -1
            && observation.record == [0; 16],
        "inert leaf must not invent a constructor owner",
    )?;
    need(
        observation.mapping_before == -i64::from(libc::ENOMEM)
            && observation.mapping_after == -i64::from(libc::ENOMEM),
        "inert leaf reserved fixed Tool memory",
    )?;
    need(
        observation.getpid == observation.kernel_pid
            && observation.probe_mask == 0
            && observation.bitmap_read == 0
            && observation.bitmap.iter().all(|word| *word == 0),
        "inert guest operation or absent-bootstrap probe state differs",
    )?;
    need(
        observation.alt_before_sp == observation.original_alt_sp
            && observation.alt_before_flags == observation.original_alt_flags
            && observation.alt_before_size == observation.original_alt_size
            && observation.alt_after_sp == observation.original_alt_sp
            && observation.alt_after_flags == observation.original_alt_flags
            && observation.alt_after_size == observation.original_alt_size,
        "inert leaf changed the actual kernel alternate stack",
    )?;
    Ok(())
}

fn verify_active_runtime(
    observation: &Observation,
    run: &contract::CapturedRun,
) -> Result<(), String> {
    need(
        (BASE..END).contains(&observation.alt_before_sp)
            && observation.alt_before_flags == 0
            && observation.alt_before_size == 65536
            && observation.alt_after_sp == observation.alt_before_sp
            && observation.alt_after_flags == observation.alt_before_flags
            && observation.alt_after_size == observation.alt_before_size,
        "active leaf must have actually registered the existing fixed alternate stack",
    )?;
    let stderr = String::from_utf8_lossy(&run.stderr);
    match observation.case.as_str() {
        "compat" | "replace" => need(
            stderr.contains("reverie-liteinst: tool=compat syscall="),
            "raw compat selector did not install the genuine compatibility runtime",
        )?,
        "strace" | "hide" | "root" | "first-valid" | "generic" => need(
            stderr.contains("[liteinst strace pid "),
            "raw strace selector did not install the genuine Strace runtime",
        )?,
        "passthrough" | "spoof-getpid" => need(
            !stderr.contains("tool=compat") && !stderr.contains("[liteinst strace pid "),
            "built-in selector installed a native tracing mode",
        )?,
        _ => return Err("active case not in the finite selector table".to_owned()),
    }
    need(
        observation.getpid
            == if observation.case == "spoof-getpid" {
                reverie_liteinst::SPOOF_PID
            } else {
                // This fixed probe's emitted syscall site is admitted by the
                // native runtime. Compare its actual guest result with the
                // independently observed physical PID; do not accept refusal.
                observation.kernel_pid
            },
        "actual getpid result differs from selected runtime",
    )
}

fn trial(case: &str, expected: Expected) -> Result<(), String> {
    let runtime = liteinst_runtime::required_runtime()?;
    let evidence = liteinst_runtime::evidence_directory(&format!("standalone-constructor-{case}"))?;
    eprintln!(
        "standalone constructor {case} raw evidence: {}",
        evidence.display()
    );
    let guest = selected("REVERIE_LITEINST_CONSTRUCTOR_GUEST")?;
    let guest_manifest = selected("REVERIE_LITEINST_CONSTRUCTOR_GUEST_MANIFEST")?;
    let root = selected("REVERIE_LITEINST_ROOT_INTERPOSER")?;
    let root_manifest = selected("REVERIE_LITEINST_ROOT_INTERPOSER_MANIFEST")?;
    let guest_receipt = m1_artifact::verify_guest_receipt(
        &guest_manifest,
        &guest,
        &runtime
            .source
            .root
            .join("reverie-liteinst/tests/fixtures/standalone_constructor_guest.c"),
        &m1_artifact::sha256(PROBE_SOURCE),
    )?;
    let root_receipt = standalone_constructor_fixture::verify_root_receipt(
        &root_manifest,
        &root,
        &runtime
            .source
            .root
            .join("reverie-liteinst/tests/fixtures/standalone_root_interposer.c"),
    )?;
    let guest_manifest_identity = m1_artifact::FileIdentity::read(&guest_manifest)?;
    let root_manifest_identity = m1_artifact::FileIdentity::read(&root_manifest)?;
    let policy = serde_json::to_vec(&serde_json::json!({
        "schema":1, "case":case, "expected":format!("{expected:?}"),
        "source_head":runtime.source.head, "source_tree":runtime.source.tree,
        "runtime":runtime.receipt.artifact, "guest":guest_receipt.binary,
        "guest_source":guest_receipt.source, "root_interposer":root_receipt.binary,
        "root_source":root_receipt.source, "constructor_snapshot":"main-time retained record",
        "first_instruction_credit":false, "whole_window_credit":false,
        "site_patching":true, "alt_stack":true, "stdin":"closed"
    }))
    .map_err(|e| e.to_string())?;
    let mut held = liteinst_runtime::held_environment(policy);
    let mut environment: BTreeMap<OsString, OsString> = held.environment.into_iter().collect();
    for name in [
        "REVERIE_INGUEST_TOOL",
        "REVERIE_LITEINST_TOOL",
        "STANDALONE_CONSTRUCTOR_GETENV",
        reverie_liteinst::COMPAT_EVENT_FD_ENV,
        reverie_liteinst::COMPAT_EVENT_COOKIE_ENV,
        reverie_liteinst::STRADDLER_STALENESS_TICKS_ENV,
    ] {
        environment.remove(&OsString::from(name));
    }
    environment.insert(reverie_liteinst::SITE_PATCHING_ENV.into(), "1".into());
    environment.insert(reverie_liteinst::ALT_STACK_ENV.into(), "1".into());
    held.environment = environment.into_iter().collect();
    let mut command = Command::new(&guest);
    command
        .arg("prepare")
        .arg(case)
        .arg(&runtime.path)
        .arg(if case == "root" {
            root.as_os_str()
        } else {
            std::ffi::OsStr::new("-")
        })
        .current_dir(&runtime.source.root);
    let result = (|| -> Result<(), String> {
        let run = match contract::run_without_input(command, &held) {
            Ok(run) => {
                liteinst_runtime::retain_capture(&evidence, "actual-leaf", &run)?;
                run
            }
            Err(failure) => {
                liteinst_runtime::retain_failure(&evidence, "actual-leaf", &failure)?;
                return Err(failure.to_string());
            }
        };
        need(
            run.input.is_none()
                && run.end == contract::CaptureEnd::Complete
                && !run.output_truncated,
            "actual leaf exceeded capture bounds or had unexpected stdin",
        )?;
        if matches!(expected, Expected::Refused) {
            let stderr = String::from_utf8_lossy(&run.stderr);
            return need(run.status.is_some_and(|status| status.code() == Some(127)) && run.stdout.is_empty()
                && stderr.contains("reverie-liteinst initialization failed: unsupported REVERIE_LITEINST_TOOL value"),
                "invalid first raw selector must refuse with original diagnostic/exit127 before main");
        }
        need(
            run.status.is_some_and(|status| status.success()),
            "actual real-leaf probe did not exit0",
        )?;
        let observation: Observation = serde_json::from_slice(&run.stdout)
            .map_err(|e| format!("actual standalone observation: {e}"))?;
        need(
            observation.schema == 1
                && observation.case == case
                && observation.owner == runtime.path
                && observation.owner_base != 0
                && observation.tid > 0
                && observation.kernel_pid > 0
                && observation.kernel_before_tid == observation.tid
                && observation.kernel_before_pid == observation.kernel_pid
                && observation.kernel_before_result == 0
                && observation.kernel_after_result == 0
                && observation.kernel_before_version == 1
                && observation.kernel_after_version == 1
                && observation.kernel_before_status == 0
                && observation.kernel_after_status == 0
                && observation.record_crosscheck == 1
                && observation.kernel_constructor_before_result
                    == i64::from(observation.query_before)
                && observation.kernel_constructor_after_result
                    == i64::from(observation.query_after)
                && observation.record_before == observation.kernel_constructor_before
                && observation.record == observation.kernel_constructor_after
                && observation.bitmap.len() == 33
                && observation.original_alt_result == 0
                && observation.alt_before_result == 0
                && observation.alt_after_result == 0,
            "actual owner/case/kernel query identity differs",
        )?;
        match expected {
            Expected::Active => {
                verify_owned(&observation, &runtime.path)?;
                verify_active_runtime(&observation, &run)?;
                need(
                    observation.root_calls == if case == "root" { 0 } else { -1 },
                    "actual hidden leaf root was replaced by public-symbol interposition",
                )
            }
            Expected::Inert => verify_inert(&observation),
            Expected::Generic => {
                need(
                    observation.query_before == -1
                        && observation.query_after == -1
                        && observation.record == [0; 16]
                        && observation.mapping_before == -i64::from(libc::ENOMEM)
                        && observation.mapping_after == 0
                        && observation.root_calls == -1
                        && observation.probe_mask == 0
                        && observation.bitmap_read == 0
                        && observation.bitmap.iter().all(|word| *word == 0),
                    "generic getter activation must remain separate from native owned constructor",
                )?;
                need(
                    observation.alt_before_sp == observation.original_alt_sp
                        && observation.alt_before_flags == observation.original_alt_flags
                        && observation.alt_before_size == observation.original_alt_size,
                    "generic startup was not inert before explicit public call",
                )?;
                // The direct generic call registers a stack at main time.
                need(
                    (BASE..END).contains(&observation.alt_after_sp)
                        && observation.alt_after_size == 65536
                        && observation.alt_after_flags == 0
                        && observation.getpid == observation.kernel_pid,
                    "public generic initializer no longer acquires its getter-selected runtime",
                )?;
                need(
                    String::from_utf8_lossy(&run.stderr).contains("[liteinst strace pid "),
                    "direct public generic initializer did not run genuine getter-selected Strace",
                )
            }
            Expected::Refused => unreachable!(),
        }
    })();
    let recorded = m1_artifact::write_new(
        &evidence.join("predicate-result.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({"case":case,
            "predicate_passed":result.is_ok(), "error":result.as_ref().err(),
            "first_instruction_credit":false, "whole_window_credit":false
        }))
        .map_err(|e| e.to_string())?,
    );
    let after = (|| -> Result<(), String> {
        runtime.receipt.artifact.verify()?;
        guest_receipt.source.verify()?;
        guest_receipt.binary.verify()?;
        root_receipt.source.verify()?;
        root_receipt.binary.verify()?;
        guest_manifest_identity.verify()?;
        root_manifest_identity.verify()?;
        liteinst_runtime::verify_unchanged(&evidence)
    })();
    let result = match (result, recorded) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) => Err(e),
        (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(record)) => Err(format!("{e}; predicate receipt: {record}")),
    };
    match (result, after) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) => Err(format!("{e}; raw evidence {}", evidence.display())),
        (Ok(()), Err(e)) => Err(e),
        (Err(e), Err(after)) => Err(format!("{e}; final guard: {after}; {}", evidence.display())),
    }
}

fn group(cases: &[(&str, Expected)]) {
    // Retain every selected case, including subsequent independent cases after
    // the expected failing-first absence. Never retry or relabel a failure.
    let errors: Vec<_> = cases
        .iter()
        .filter_map(|(case, expected)| {
            trial(case, *expected)
                .err()
                .map(|error| format!("{case}: {error}"))
        })
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn active_leaf_has_returned_authenticated_bootstrap() {
    group(&[
        ("strace", Expected::Active),
        ("compat", Expected::Active),
        ("passthrough", Expected::Active),
        ("spoof-getpid", Expected::Active),
    ]);
}

#[test]
fn raw_selector_presence_overrides_getenv_provider() {
    group(&[
        ("absent", Expected::Inert),
        ("synthesize", Expected::Inert),
        ("lookalikes", Expected::Inert),
        ("hide", Expected::Active),
        ("replace", Expected::Active),
    ]);
}

#[test]
fn raw_selector_refusals_and_first_duplicate() {
    group(&[
        ("empty", Expected::Refused),
        ("invalid", Expected::Refused),
        ("non-utf8", Expected::Refused),
        ("first-invalid", Expected::Refused),
        ("first-valid", Expected::Active),
    ]);
}

#[test]
fn local_leaf_root_survives_public_symbol_interposition() {
    group(&[("root", Expected::Active)]);
}

#[test]
fn generic_initializer_keeps_getenv_acquisition() {
    group(&[("generic", Expected::Generic)]);
}
