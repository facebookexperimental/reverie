//! Additive link-only declaration controls; reuse the producer's exact rlib.
//! No output binary is executed. Runner's ordinary success policy is unchanged.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use goblin::elf::Elf;
use serde_json::Value;

use crate::m1_artifact::CargoArtifact;
use crate::m1_artifact::FileIdentity;
use crate::m1_artifact::Result;
use crate::m1_artifact::Runner;
use crate::m1_artifact::write_new;

const SYMBOL: &str = "reverie_liteinst_allocator_backing_v1";
const MODULE_SOURCE: &[u8] = include_bytes!("allocator_declaration_fixture.rs");
const CONTROLS: &[(&str, &[u8])] = &[
    (
        "anchor.rs",
        include_bytes!("fixtures/allocator-declarations/anchor.rs"),
    ),
    (
        "executable.rs",
        include_bytes!("fixtures/allocator-declarations/executable.rs"),
    ),
    (
        "cdylib.rs",
        include_bytes!("fixtures/allocator-declarations/cdylib.rs"),
    ),
    (
        "owner_a.rs",
        include_bytes!("fixtures/allocator-declarations/owner_a.rs"),
    ),
    (
        "owner_b.rs",
        include_bytes!("fixtures/allocator-declarations/owner_b.rs"),
    ),
    (
        "duplicate.rs",
        include_bytes!("fixtures/allocator-declarations/duplicate.rs"),
    ),
];

fn check(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.into()) }
}

fn canonical(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(|error| error.to_string())
}

/// This separate selector does not generalize the public cdylib-only selectors.
/// All inputs are the metadata and output of the producer's existing Cargo job.
fn select_rlib(
    root: &Path,
    metadata: &Value,
    messages: &str,
    profile: &Value,
    target: &Path,
) -> Result<(FileIdentity, Value, Vec<String>)> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("metadata packages missing")?;
    let packages: Vec<_> = packages
        .iter()
        .filter(|p| p["name"] == "reverie-liteinst")
        .collect();
    check(
        packages.len() == 1,
        "one actual reverie-liteinst package required",
    )?;
    let package = packages[0];
    let manifest = canonical(&root.join("reverie-liteinst/Cargo.toml"))?;
    check(
        package["source"].is_null(),
        "core must be the actual local workspace package",
    )?;
    check(
        canonical(Path::new(
            package["manifest_path"]
                .as_str()
                .ok_or("manifest missing")?,
        ))? == manifest,
        "core manifest differs",
    )?;
    let source = canonical(&root.join("reverie-liteinst/src/lib.rs"))?;
    let mut selected = Vec::new();
    let mut finished = Vec::new();
    let mut native_paths = Vec::new();
    for line in messages.lines().filter(|line| !line.is_empty()) {
        let event: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
        if event["reason"] == "build-finished" {
            finished.push(event["success"].as_bool());
        }
        if event["reason"] == "build-script-executed" {
            for path in event["linked_paths"]
                .as_array()
                .ok_or("linked_paths missing")?
            {
                let path = path.as_str().ok_or("linked path is not a string")?;
                let (kind, path) = path.split_once('=').unwrap_or(("all", path));
                check(
                    ["all", "native", "dependency"].contains(&kind),
                    "unsupported Cargo linked-path kind",
                )?;
                let path = canonical(&root.join(path))?;
                check(
                    path.is_dir(),
                    "Cargo linked path is not an existing directory",
                )?;
                native_paths.push(format!("{kind}={}", path.display()));
            }
        }
        if event["reason"] != "compiler-artifact"
            || event["package_id"] != package["id"]
            || event["target"]["name"] != "reverie_liteinst"
        {
            continue;
        }
        check(
            canonical(Path::new(
                event["manifest_path"]
                    .as_str()
                    .ok_or("artifact manifest missing")?,
            ))? == manifest,
            "artifact manifest differs",
        )?;
        check(
            event["target"]["kind"] == serde_json::json!(["rlib"])
                && event["target"]["crate_types"] == serde_json::json!(["rlib"]),
            "core must be rlib-only",
        )?;
        check(
            canonical(Path::new(
                event["target"]["src_path"]
                    .as_str()
                    .ok_or("artifact source missing")?,
            ))? == source,
            "core library source differs",
        )?;
        check(
            event["features"] == serde_json::json!(["allocator-fixture"])
                && &event["profile"] == profile,
            "core features/profile differ from diagnostic recipe",
        )?;
        let names = event["filenames"]
            .as_array()
            .ok_or("artifact outputs missing")?
            .iter()
            .map(|name| {
                name.as_str()
                    .ok_or_else(|| "artifact output is not a string".to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        let outputs: Vec<_> = names
            .into_iter()
            .filter(|p| Path::new(p).extension().is_some_and(|e| e == "rlib"))
            .collect();
        check(outputs.len() == 1, "core must report one actual rlib")?;
        let rlib = FileIdentity::read(Path::new(outputs[0]))?;
        check(
            rlib.path.starts_with(canonical(target)?),
            "rlib outside the explicit producer target",
        )?;
        selected.push((rlib, event));
    }
    check(
        finished == [Some(true)] && selected.len() == 1,
        "one successful Cargo finish and one core rlib required",
    )?;
    native_paths.sort();
    native_paths.dedup();
    let (rlib, event) = selected.remove(0);
    Ok((rlib, event, native_paths))
}

#[derive(Clone, Copy, Debug)]
enum Expected {
    Success,
    Missing,
    Duplicate,
}

fn named_link_rejection(stderr: &str, expected: Expected) -> bool {
    if !stderr.contains("error: linking with ")
        || stderr
            .lines()
            .any(|line| line.trim_start().starts_with("error[E"))
    {
        return false;
    }
    let lines: Vec<_> = stderr
        .lines()
        .filter(|line| {
            line.contains(SYMBOL)
                && (line.contains("ld:") || line.contains("ld.lld:") || line.contains("rust-lld:"))
        })
        .collect();
    match expected {
        Expected::Missing => lines.iter().any(|line| {
            line.contains("hidden")
                && (line.contains("undefined")
                    || line.contains("isn't defined")
                    || line.contains("not defined"))
        }),
        Expected::Duplicate => lines.iter().any(|line| {
            line.contains("multiple definition")
                || line.contains("duplicate symbol")
                || line.contains("already defined")
        }),
        Expected::Success => false,
    }
}

fn command(
    runner: &mut Runner,
    rustc: &str,
    args: &[String],
    root: &Path,
    expected: Expected,
) -> Result<Value> {
    let before = runner.commands.len();
    let result = runner.run(rustc, args, root);
    let record = runner.commands.get(before);
    let mut admitted = result.is_ok()
        && matches!(expected, Expected::Success)
        && runner.commands.len() == before + 1
        && record.is_some_and(|record| record.status == 0);
    if !matches!(expected, Expected::Success) {
        if let Some(record) = record {
            // Runner emits this exact terminal error only after bounds, stream,
            // process cleanup, log persistence and reap checks have succeeded.
            // A resource/setup error can never be converted to an expected red.
            let stem = record
                .stdout
                .path
                .file_stem()
                .ok_or("command log stem missing")?;
            let terminal_error = format!(
                "{rustc} failed (exit status: 1); logs {}",
                runner.logs.join(stem).display()
            );
            record.stdout.verify()?;
            record.stderr.verify()?;
            let stderr =
                fs::read_to_string(&record.stderr.path).map_err(|error| error.to_string())?;
            admitted = runner.commands.len() == before + 1
                && record.status == 1
                && result.as_ref().err() == Some(&terminal_error)
                && named_link_rejection(&stderr, expected);
        }
    }
    Ok(
        serde_json::json!({"expected":format!("{expected:?}"), "command":record, "runner_error":result.err(), "matched_expected_link_outcome":admitted}),
    )
}

fn positive_elf(path: &Path) -> Result<Value> {
    let identity = FileIdentity::read(path)?;
    let bytes = fs::read(&identity.path).map_err(|error| error.to_string())?;
    let elf = Elf::parse(&bytes).map_err(|error| error.to_string())?;
    check(
        elf.is_64 && elf.little_endian && elf.header.e_machine == goblin::elf::header::EM_X86_64,
        "positive control is not an x86-64 ELF",
    )?;
    check(
        !elf.dynsyms
            .iter()
            .any(|s| s.st_shndx == 0 && elf.dynstrtab.get_at(s.st_name) == Some(SYMBOL)),
        "descriptor left as a dynamic import",
    )?;
    let definitions: Vec<_> = elf
        .syms
        .iter()
        .filter(|s| elf.strtab.get_at(s.st_name) == Some(SYMBOL))
        .collect();
    check(
        definitions.len() == 1,
        "one actual descriptor definition required",
    )?;
    let symbol = definitions[0];
    check(
        symbol.st_shndx != 0
            && symbol.st_size == 16
            && symbol.st_type() == goblin::elf::sym::STT_OBJECT,
        "descriptor type/size/definition differs",
    )?;
    check(
        symbol.st_bind() == goblin::elf::sym::STB_LOCAL
            || (symbol.st_bind() == goblin::elf::sym::STB_GLOBAL
                && symbol.st_visibility() == goblin::elf::sym::STV_HIDDEN),
        "descriptor weak or preemptible",
    )?;
    let mut data = None;
    for load in elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
    {
        if let Some(relative) = symbol.st_value.checked_sub(load.p_vaddr) {
            if relative
                .checked_add(16)
                .is_some_and(|end| end <= load.p_filesz)
            {
                check(
                    load.p_flags & goblin::elf::program_header::PF_W == 0,
                    "descriptor is writable",
                )?;
                let start = usize::try_from(
                    load.p_offset
                        .checked_add(relative)
                        .ok_or("descriptor file offset overflow")?,
                )
                .map_err(|error| error.to_string())?;
                data = bytes.get(start..start.checked_add(16).ok_or("descriptor end overflow")?);
            }
        }
    }
    let data = data.ok_or("descriptor not fully file-backed in a readonly PT_LOAD")?;
    check(
        data[..8] == 1_u64.to_le_bytes() && data[8..] == 1_u64.to_le_bytes(),
        "positive Legacy descriptor words differ",
    )?;
    check(
        elf.syms.iter().any(|s| {
            elf.strtab.get_at(s.st_name) == Some("reverie_liteinst_initialize")
                && s.st_shndx != 0
                && s.st_size > 0
                && s.st_type() == goblin::elf::sym::STT_FUNC
        }),
        "real initializer was eliminated",
    )?;
    identity.verify()?;
    Ok(
        serde_json::json!({"artifact":identity, "descriptor_address":symbol.st_value, "descriptor_binding":symbol.st_bind(), "descriptor_visibility":symbol.st_visibility(), "descriptor_words":[1,1], "real_initializer_retained":true}),
    )
}

/// Integrate immediately after the current Cargo output has been selected.
/// Keep the producer's existing bounds/source guards; this adds no Cargo job.
pub fn run(
    root: &Path,
    bundle: &Path,
    metadata: &Value,
    cargo_messages: &FileIdentity,
    selected_leaf: &CargoArtifact,
    target: &Path,
    producer: &Runner,
) -> Result<PathBuf> {
    cargo_messages.verify()?;
    let messages = fs::read_to_string(&cargo_messages.path).map_err(|error| error.to_string())?;
    check(
        crate::m1_artifact::select_artifact(
            &messages,
            &selected_leaf.package,
            &selected_leaf.features,
            &selected_leaf.profile,
            target,
        )? == *selected_leaf,
        "link-control Cargo output differs from the already selected current leaf",
    )?;
    let (rlib, event, native_paths) =
        select_rlib(root, metadata, &messages, &selected_leaf.profile, target)?;
    let dependency = rlib
        .path
        .parent()
        .ok_or("rlib dependency directory missing")?;
    let sources = root.join("scripts/fixtures/allocator-declarations");
    let mut identities = Vec::new();
    let module = FileIdentity::read(&root.join("scripts/allocator_declaration_fixture.rs"))?;
    check(
        module.sha256 == crate::m1_artifact::sha256(MODULE_SOURCE),
        "link-control compiled/current module differs",
    )?;
    identities.push(module);
    for (name, compiled) in CONTROLS {
        let identity = FileIdentity::read(&sources.join(name))?;
        check(
            identity.sha256 == crate::m1_artifact::sha256(compiled),
            "link-control compiled/current source differs",
        )?;
        identities.push(identity);
    }
    let out = bundle.join("allocator-declarations");
    fs::create_dir(&out).map_err(|error| format!("fresh link-control directory: {error}"))?;
    let remaining = producer.deadline.saturating_duration_since(Instant::now());
    let mut runner = Runner::new(out.join("logs"), remaining, producer.max_stream_bytes)?;
    // Do not grant a fresh full budget: control time consumes the producer's
    // existing exact deadline, with the same stream cap and outer containment.
    runner.deadline = producer.deadline;
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let mut common = vec![
        "--edition=2024".into(),
        "-C".into(),
        "lto=off".into(),
        "--extern".into(),
        format!("reverie_liteinst={}", rlib.path.display()),
        "-L".into(),
        format!("dependency={}", dependency.display()),
    ];
    for path in &native_paths {
        common.extend(["-L".into(), path.clone()]);
    }
    write_new(&out.join("inputs.json"), &serde_json::to_vec_pretty(&serde_json::json!({"cargo_messages":cargo_messages, "selected_leaf":selected_leaf, "cargo_artifact":event, "rlib":rlib, "dependency_directory":dependency, "native_link_paths":native_paths, "control_sources":identities, "rustc":rustc, "common_arguments":common, "same_producer_deadline":true, "max_stream_bytes":producer.max_stream_bytes, "runtime_executions":0})).map_err(|error| error.to_string())?)?;
    let steps = [
        (
            "executable-missing",
            "executable.rs",
            "bin",
            Expected::Missing,
        ),
        (
            "executable-legacy",
            "executable.rs",
            "bin",
            Expected::Success,
        ),
        ("cdylib-missing", "cdylib.rs", "cdylib", Expected::Missing),
        ("cdylib-legacy", "cdylib.rs", "cdylib", Expected::Success),
        (
            "descriptor_owner_a",
            "owner_a.rs",
            "rlib",
            Expected::Success,
        ),
        (
            "descriptor_owner_b",
            "owner_b.rs",
            "rlib",
            Expected::Success,
        ),
        ("duplicate", "duplicate.rs", "bin", Expected::Duplicate),
    ];
    let mut outcomes = Vec::new();
    let mut archives = Vec::<FileIdentity>::new();
    let mut elf_readbacks = Vec::new();
    for (name, source, kind, expected) in steps {
        rlib.verify()?;
        cargo_messages.verify()?;
        for archive in &archives {
            archive.verify()?;
        }
        for identity in &identities {
            identity.verify()?;
        }
        let output = if kind == "rlib" {
            out.join(format!("lib{name}.rlib"))
        } else {
            out.join(name)
        };
        let mut args = common.clone();
        args.extend([
            "--crate-name".into(),
            name.replace('-', "_"),
            format!("--crate-type={kind}"),
            sources.join(source).to_string_lossy().into_owned(),
            "-o".into(),
            output.to_string_lossy().into_owned(),
        ]);
        if name.ends_with("-legacy") {
            args.extend(["--cfg".into(), "feature=\"legacy\"".into()]);
        }
        if kind == "rlib" {
            args.extend(["-C".into(), "codegen-units=1".into()]);
        }
        if name == "duplicate" {
            for owner in ["descriptor_owner_a", "descriptor_owner_b"] {
                args.extend([
                    "--extern".into(),
                    format!("{owner}={}", out.join(format!("lib{owner}.rlib")).display()),
                ]);
            }
            args.extend(["-L".into(), format!("dependency={}", out.display())]);
        }
        let outcome = command(&mut runner, &rustc, &args, root, expected)?;
        write_new(
            &out.join(format!("{name}.json")),
            &serde_json::to_vec_pretty(&outcome).map_err(|error| error.to_string())?,
        )?;
        check(
            outcome["matched_expected_link_outcome"] == true,
            &format!("{name}: unexpected literal outcome; see retained command/log/receipt"),
        )?;
        if name.ends_with("-legacy") {
            let readback = out.join(format!("{name}-elf.json"));
            write_new(
                &readback,
                &serde_json::to_vec_pretty(&positive_elf(&output)?)
                    .map_err(|error| error.to_string())?,
            )?;
            elf_readbacks.push(FileIdentity::read(&readback)?);
        }
        if kind == "rlib" {
            archives.push(FileIdentity::read(&output)?);
        }
        outcomes.push(outcome);
    }
    rlib.verify()?;
    cargo_messages.verify()?;
    for identity in &identities {
        identity.verify()?;
    }
    for artifact in archives.iter().chain(elf_readbacks.iter()) {
        artifact.verify()?;
    }
    check(
        Instant::now() < producer.deadline,
        "declaration controls exhausted the unchanged producer deadline",
    )?;
    let receipt = out.join("results.json");
    write_new(&receipt, &serde_json::to_vec_pretty(&serde_json::json!({"inputs":FileIdentity::read(&out.join("inputs.json"))?, "controls":outcomes, "commands":runner.commands, "owner_archives":archives, "positive_elf_readbacks":elf_readbacks, "expected_link_rejections":3, "expected_links":2, "owner_compilations":2, "runtime_executions":0, "allocator_or_placement_pass_claimed":false})).map_err(|error| error.to_string())?)?;
    Ok(receipt)
}

/// Join the separate raw-status link sidecar to the original runtime receipt.
/// Never add failed control commands to that receipt or edit their exit codes.
pub fn bind_runtime_inputs(
    bundle: &Path,
    runtime_receipt: &Path,
    link_receipt: &Path,
) -> Result<PathBuf> {
    let path = bundle.join("allocator-declarations/runtime-inputs.json");
    write_new(
        &path,
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version":1,
            "runtime_receipt":FileIdentity::read(runtime_receipt)?,
            "link_receipt":FileIdentity::read(link_receipt)?,
            "runtime_commands_policy":"all status zero; unchanged",
            "link_commands_policy":"literal statuses retained in dedicated sidecar",
            "runtime_executions":0,
        }))
        .map_err(|error| error.to_string())?,
    )?;
    Ok(path)
}
