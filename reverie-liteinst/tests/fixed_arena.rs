//! Maintained live placement gate for the unchanged producer-owned C oracle.
//! The runtime receipt proves Fixed admission; successful C execution proves
//! its allocation/content/ownership and 23 literal placement predicates.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

#[allow(dead_code)]
#[path = "support/liteinst_runtime.rs"]
mod liteinst_runtime;

use liteinst_runtime::artifact;
use liteinst_runtime::contract;

const C_SHA256: &str = "25a174f075282ff23bbfaafe94b9a618d993fcb33440a1ae265e594a20dbe403";
const C_SOURCE: &[u8] = include_bytes!("fixtures/fixed_arena_guest.c");
const ADMISSION: &str =
    "source bindings only; Fixed admission requires the complete verified runtime receipt";
const SOURCES: [&str; 10] = [
    "reverie-inguest/src/guest/alloc.rs",
    "reverie-inguest/src/guest/tool_region.rs",
    "reverie-inguest/src/guest/tool_region_arena.rs",
    "reverie-inguest/src/guest/tool_region_constructor.rs",
    "reverie-liteinst/src/allocator_backing.rs",
    "reverie-liteinst/src/patch_alloc.rs",
    "reverie-liteinst/src/allocator_fixture.rs",
    "reverie-liteinst/src/fixed_arena_fixture.rs",
    "reverie-liteinst-artifact/src/lib.rs",
    "scripts/fixed_arena_fixture.rs",
];

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema_version: u32,
    admission: String,
    runtime_receipt: artifact::FileIdentity,
    guest_receipt: artifact::FileIdentity,
    sources: BTreeMap<String, artifact::FileIdentity>,
    executed_tests: u64,
    fixed_placement_pass_claimed: bool,
}

fn demand(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn required(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(std::env::var_os(name).ok_or_else(|| {
        format!("{name} is required; run the maintained producer before this test")
    })?);
    demand(
        path.is_absolute() && artifact::real_file(&path)? == path,
        "fixed probe input must be an exact canonical producer-owned file",
    )?;
    Ok(path)
}

fn fields<'a>(line: &'a str, prefix: &str, keys: &[&str]) -> Result<Vec<&'a str>, String> {
    let tokens: Vec<_> = line
        .strip_prefix(prefix)
        .ok_or("wrong fixed record prefix")?
        .split(' ')
        .collect();
    demand(tokens.len() == keys.len(), "wrong fixed record field count")?;
    tokens
        .into_iter()
        .zip(keys)
        .map(|(token, key)| {
            let (observed, value) = token.split_once('=').ok_or("missing fixed field equals")?;
            demand(
                observed == *key && !value.is_empty(),
                "wrong/empty fixed field",
            )?;
            Ok(value)
        })
        .collect()
}

fn decimal(value: &str) -> Result<u64, String> {
    demand(
        !value.is_empty()
            && value.bytes().all(|b| b.is_ascii_digit())
            && (value.len() == 1 || !value.starts_with('0')),
        "noncanonical fixed decimal",
    )?;
    value.parse().map_err(|_| "fixed decimal overflow".into())
}

fn hex(value: &str) -> Result<u64, String> {
    let value = value
        .strip_prefix("0x")
        .ok_or("missing fixed literal hex prefix")?;
    demand(
        !value.is_empty()
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (value.len() == 1 || !value.starts_with('0')),
        "noncanonical fixed hex",
    )?;
    u64::from_str_radix(value, 16).map_err(|_| "fixed hex overflow".into())
}

fn words<const N: usize>(line: &str, prefix: &str) -> Result<[u64; N], String> {
    let keys: Vec<_> = (0..N).map(|i| format!("w{i}")).collect();
    let keys: Vec<_> = keys.iter().map(String::as_str).collect();
    fields(line, prefix, &keys)?
        .into_iter()
        .map(hex)
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| "wrong fixed word count".into())
}

// Expected rows are the original C workload, including its three deliberate
// allocation failures. No recorded addresses are normalized or guessed.
const OPERATIONS: [(&str, u64, u64, u64, u64, u64, u64); 20] = [
    ("outside-alloc", 0, 0, 0, 64, 16, 0),
    ("outside-zero", 1, 0, 0, 257, 16, 0),
    ("outside-overaligned", 0, 0, 0, 4096, 4096, 0),
    ("outside-grow", 2, 0, 64, 4096, 16, 0),
    ("outside-shrink-in-both-scopes", 2, 3, 4096, 32, 16, 0),
    ("outside-free-in-install", 3, 2, 32, 0, 16, 0),
    ("outside-zero-free", 3, 0, 257, 0, 16, 0),
    ("outside-aligned-free", 3, 0, 4096, 0, 4096, 0),
    ("dispatch-alloc", 0, 1, 0, 96, 16, 0),
    ("dispatch-free", 3, 1, 96, 0, 16, 0),
    ("install-alloc", 0, 2, 0, 73, 4096, 0),
    ("install-zero", 1, 2, 0, 257, 16, 0),
    ("patch-grow-outside", 2, 0, 73, 8192, 4096, 0),
    ("patch-free-in-dispatch", 3, 1, 8192, 0, 4096, 0),
    ("patch-zero-free", 3, 0, 257, 0, 16, 0),
    ("failed-realloc-source", 0, 0, 0, 128, 16, 0),
    ("failed-realloc", 2, 0, 128, 67112960, 16, 2),
    ("failed-realloc-source-free", 3, 0, 128, 0, 16, 0),
    ("install-oversized", 0, 2, 0, 67112960, 16, 2),
    ("install-zero-oversized", 1, 2, 0, 67112960, 16, 2),
];

fn validate_output(stdout: &[u8], runtime: &Path) -> Result<usize, String> {
    let text = std::str::from_utf8(stdout).map_err(|_| "fixed output is not UTF-8")?;
    let (records, maps) = text
        .split_once("fixed raw_maps_begin bytes=")
        .ok_or("missing fixed maps block")?;
    demand(
        !maps.contains("fixed raw_maps_begin bytes="),
        "duplicate fixed maps block",
    )?;
    let (length, maps) = maps.split_once('\n').ok_or("missing maps byte count")?;
    let length = usize::try_from(decimal(length)?).map_err(|_| "maps length overflow")?;
    demand(
        length > 0 && length < 1024 * 1024,
        "maps block exceeds frozen C bound",
    )?;
    let maps_bytes = maps.as_bytes();
    let maps_data = maps_bytes
        .get(..length)
        .ok_or("truncated fixed maps block")?;
    demand(maps_data.ends_with(b"\n") && !maps_data.contains(&0)
        && maps.matches("fixed raw_maps_end\n").count() == 1
        && maps_bytes.get(length..) == Some(b"fixed raw_maps_end\nfixed result operations_complete=1 placement_failures=0 fixed_pass=1\n".as_slice()),
        "maps length/end or literal final Fixed result differs")?;
    for line in std::str::from_utf8(maps_data)
        .map_err(|_| "maps are not UTF-8")?
        .lines()
    {
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        demand(columns.len() >= 5, "incomplete kernel maps record")?;
        let parse_hex = |value: &str| -> Result<u64, String> {
            demand(
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "malformed maps hex",
            )?;
            u64::from_str_radix(value, 16).map_err(|_| "maps hex overflow".into())
        };
        let (start, end) = columns[0].split_once('-').ok_or("missing maps range")?;
        demand(parse_hex(start)? < parse_hex(end)?, "invalid maps range")?;
        demand(columns[1].len() == 4, "wrong maps permissions width")?;
        parse_hex(columns[2])?;
        let (major, minor) = columns[3].split_once(':').ok_or("missing maps device")?;
        parse_hex(major)?;
        parse_hex(minor)?;
        decimal(columns[4])?;
    }
    let mut lines = records.lines();
    let mut next = || {
        lines
            .next()
            .ok_or("missing required fixed record".to_owned())
    };
    let owner = runtime.to_str().ok_or("runtime path is not UTF-8")?;
    let header = fields(
        next()?,
        &format!("fixed fixture abi=1 setup=inert owner={owner} "),
        &[
            "base",
            "operations",
            "operation_failures",
            "reusable_metadata_changed",
        ],
    )?;
    demand(
        hex(header[0])? != 0 && header[1..] == ["20", "0", "1"],
        "incomplete fixed workload header",
    )?;
    let initial = words::<31>(next()?, "fixed snapshot row=0 edge=initial ")?;
    demand(
        initial[..7] == [1, 1, 1, 0, 0, 0, 0] && initial[7..].iter().all(|w| *w == 0),
        "initial genuine None snapshot differs",
    )?;
    let origin = words::<16>(next()?, "fixed origin ")?;
    demand(
        origin[..2] == [1, 4]
            && origin[2] > 0
            && origin[12] == 0x600000001000
            && origin[14..] == [0x600000000000, 0x600100000000],
        "wrong returned explicit generic owner",
    )?;
    for route in contract::ROUTES {
        let row = fields(next()?, "fixed watcher ", &["route", "self"])?;
        demand(
            row[0] == route && decimal(row[1])? > 0,
            "missing/wrong watcher positive control",
        )?;
    }
    let mut stable = None;
    for (i, &(name, op, scope, old_size, size, align, status)) in OPERATIONS.iter().enumerate() {
        let row = fields(
            next()?,
            "fixed operation ",
            &[
                "row",
                "name",
                "op",
                "scope",
                "old",
                "oldsize",
                "size",
                "align",
                "rc",
                "pointer",
                "result_size",
                "status",
                "depths",
                "brk",
                "call0",
                "call1",
                "call2",
                "call3",
                "call4",
                "call5",
            ],
        )?;
        demand(
            decimal(row[0])? == i as u64
                && row[1] == name
                && decimal(row[2])? == op
                && decimal(row[3])? == scope
                && decimal(row[5])? == old_size
                && decimal(row[6])? == size
                && decimal(row[7])? == align
                && decimal(row[8])? == status
                && decimal(row[11])? == status,
            "wrong fixed operation identity/arguments/status",
        )?;
        let old = hex(row[4])?;
        let pointer = hex(row[9])?;
        let result_size = decimal(row[10])?;
        let expected_size = if op == 3 || i == 16 { old_size } else { size };
        demand(
            result_size == expected_size
                && row[12] == format!("{},{},{},{}", scope >> 1, scope & 1, scope >> 1, scope & 1)
                && row[14..].iter().all(|v| *v == "0"),
            "wrong result size/depth or public allocator watcher call",
        )?;
        let (before_brk, after_brk) = row[13].split_once(',').ok_or("wrong brk pair")?;
        demand(
            hex(before_brk)? == hex(after_brk)?,
            "guest brk changed inside operation",
        )?;
        demand(
            if status == 0 {
                pointer != 0 && pointer % align == 0
            } else if i == 16 {
                pointer == old
            } else {
                pointer == 0
            },
            "wrong successful/failed allocation pointer",
        )?;
        let before = words::<31>(next()?, &format!("fixed snapshot row={i} edge=before "))?;
        let after = words::<31>(next()?, &format!("fixed snapshot row={i} edge=after "))?;
        for snapshot in [&before, &after] {
            demand(
                snapshot[..7] == [1, 0, 1, 1, 1, 0, 0]
                    && snapshot[22] == 1
                    && snapshot[30] == 0
                    && snapshot[8].checked_sub(snapshot[7]) == Some(32 * 1024 * 1024)
                    && snapshot[10].checked_sub(snapshot[9]) == Some(32 * 1024 * 1024)
                    && snapshot[12..14] == [8, 8]
                    && snapshot[16..18] == [8, 8]
                    && snapshot[20..22] == [1, 1]
                    && snapshot[24..26] == [8, 8],
                "incomplete ready Fixed snapshot",
            )?;
        }
        let identity = |s: &[u64; 31]| [s[2], s[7], s[8], s[9], s[10], s[11], s[15], s[19], s[23]];
        let observed = identity(&before);
        demand(
            observed == identity(&after) && stable.is_none_or(|first| first == observed),
            "backing/metadata identity changed across fixed snapshots",
        )?;
        stable = Some(observed);
    }
    demand(lines.next().is_none(), "duplicate/spurious fixed records")?;
    // C's frozen placement() independently checks all 23 literal predicates,
    // including exact anonymous RW/guard coverage and every live payload extent.
    Ok(length)
}

#[test]
fn standalone_fixed_arena_workload_and_literal_placement() -> Result<(), String> {
    let evidence = liteinst_runtime::evidence_directory("fixed-arena")?;
    eprintln!("Fixed arena raw evidence: {}", evidence.display());
    let result = (|| {
        let runtime = liteinst_runtime::required_runtime()?;
        demand(
            runtime
                .receipt
                .qualification
                .allocator_backing
                .descriptor
                .mode
                == artifact::AllocatorBackingMode::Fixed,
            "runtime is not typed Fixed qualification",
        )?;
        let guest_path = required("REVERIE_LITEINST_FIXED_GUEST")?;
        let guest_manifest = required("REVERIE_LITEINST_FIXED_GUEST_MANIFEST")?;
        let inputs_path = required("REVERIE_LITEINST_FIXED_INPUTS_MANIFEST")?;
        demand(
            artifact::sha256(C_SOURCE) == C_SHA256,
            "compiled fixed C oracle differs",
        )?;
        let guest = artifact::verify_guest_receipt(
            &guest_manifest,
            &guest_path,
            &runtime
                .source
                .root
                .join("reverie-liteinst/tests/fixtures/fixed_arena_guest.c"),
            C_SHA256,
        )?;
        let inputs: Inputs =
            serde_json::from_slice(&fs::read(&inputs_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("fixed input sidecar: {e}"))?;
        demand(
            inputs.schema_version == 1
                && inputs.admission == ADMISSION
                && inputs.executed_tests == 0
                && !inputs.fixed_placement_pass_claimed,
            "sidecar must bind sources without execution/admission claims",
        )?;
        let expected_sources = SOURCES
            .into_iter()
            .map(|path| {
                Ok((
                    path.to_owned(),
                    artifact::FileIdentity::read(&runtime.source.root.join(path))?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        demand(
            inputs.sources == expected_sources
                && inputs.runtime_receipt == artifact::FileIdentity::read(&runtime.receipt_path)?
                && inputs.guest_receipt == artifact::FileIdentity::read(&guest_manifest)?,
            "sidecar sources or exact runtime/guest receipt joins differ",
        )?;
        let setarch = artifact::FileIdentity::read(Path::new("/usr/bin/setarch"))?;
        let env = artifact::FileIdentity::read(Path::new("/usr/bin/env"))?;
        let mut identities: Vec<_> = inputs.sources.values().cloned().collect();
        identities.extend([
            inputs.runtime_receipt,
            inputs.guest_receipt,
            artifact::FileIdentity::read(&inputs_path)?,
            runtime.receipt.artifact.clone(),
            guest.binary,
            guest.source,
            setarch.clone(),
            env.clone(),
        ]);
        for identity in &identities {
            identity.verify()?;
        }
        demand(
            liteinst_runtime::current_source(&evidence, "probe-before")? == runtime.source,
            "source differs immediately before fixed probe",
        )?;
        artifact::write_new(
            &evidence.join("inputs.json"),
            &serde_json::to_vec_pretty(&identities).map_err(|e| e.to_string())?,
        )?;
        let mut held = liteinst_runtime::held_environment(
            serde_json::to_vec(&serde_json::json!({
                "source_head": runtime.source.head, "source_tree": runtime.source.tree,
                "inputs": identities, "setup": "inert", "stdin": "closed",
                "personality": "setarch x86_64 -R", "full_isolation_claimed": false,
            }))
            .map_err(|e| e.to_string())?,
        );
        // Apply preload only to the guest, through env after setarch has set the
        // personality. No selector or auditor may activate another runtime.
        held.environment = vec![
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("LC_ALL"), OsString::from("C")),
        ];
        let mut command = Command::new(&setarch.path);
        command
            .args(["x86_64", "-R"])
            .arg(&env.path)
            .arg("LD_BIND_NOW=1")
            .arg(format!("LD_PRELOAD={}", runtime.path.display()))
            .arg(&guest_path)
            .arg("inert")
            .arg(&runtime.path)
            .current_dir(&runtime.source.root);
        let captured = match contract::run_without_input(command, &held) {
            Ok(run) => {
                liteinst_runtime::retain_capture(&evidence, "probe", &run)?;
                Ok(run)
            }
            Err(failure) => {
                liteinst_runtime::retain_failure(&evidence, "probe", &failure)?;
                Err(failure.to_string())
            }
        };
        // A failed child still receives the same after-work identity checks.
        for identity in &identities {
            identity.verify()?;
        }
        liteinst_runtime::verify_unchanged(&evidence)?;
        let run = captured?;
        demand(
            run.status.is_some_and(|s| s.code() == Some(0))
                && run.input.is_none()
                && run.end == contract::CaptureEnd::Complete
                && !run.output_truncated,
            "fixed probe did not complete with literal exit0/closed stdin",
        )?;
        let maps_bytes = validate_output(&run.stdout, &runtime.path)?;
        // Refusal controls share this one maintained identity and never launch
        // another guest. Raw capture remains unchanged on disk.
        let text = std::str::from_utf8(&run.stdout).map_err(|_| "fixed output is not UTF-8")?;
        for (from, to) in [
            ("operations=20", "operations=19"),
            ("route=malloc self=", "route=unknown self="),
            ("name=outside-alloc", "name=missing-operation"),
            ("edge=initial w0=0x1", "edge=initial w0=0x0"),
            (
                "fixed raw_maps_begin bytes=",
                "missing raw_maps_begin bytes=",
            ),
            ("fixed_pass=1", "fixed_pass=0"),
        ] {
            demand(
                text.contains(from),
                "refusal control lacks its actual positive operand",
            )?;
            let changed = text.replacen(from, to, 1);
            demand(
                validate_output(changed.as_bytes(), &runtime.path).is_err(),
                "malformed/incomplete fixed evidence unexpectedly accepted",
            )?;
        }
        artifact::write_new(
            &evidence.join("result.json"),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "operation_rows": 20, "snapshots": 41, "watcher_positive_rows": 6,
                "operation_failures": 0, "placement_failures": 0, "fixed_pass": 1,
                "maps_bytes": maps_bytes, "literal_placement_predicates_checked_by_frozen_c": 23,
                "manifest_cells_measured": 0, "full_memory_isolation_claimed": false,
            }))
            .map_err(|e| e.to_string())?,
        )
    })();
    if let Err(error) = &result {
        artifact::write_new(&evidence.join("failure.txt"), error.as_bytes())?;
    }
    result.map_err(|error| format!("{error}; raw evidence {}", evidence.display()))
}
