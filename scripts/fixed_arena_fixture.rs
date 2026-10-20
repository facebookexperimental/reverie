//! Additive source-bound live allocator placement probe.
//! The sidecar binds source identities only. Fixed admission comes from the
//! complete verified runtime receipt; the producer executes no placement tests.
use std::path::Path;
use std::path::PathBuf;

use crate::m1_artifact;
use crate::m1_artifact::FileIdentity;
use crate::m1_artifact::GuestReceipt;
use crate::m1_artifact::Result;
use crate::m1_artifact::Runner;

pub const SOURCE: &[u8] = include_bytes!("../reverie-liteinst/tests/fixtures/fixed_arena_guest.c");
pub const GUEST_ENV: &str = "REVERIE_LITEINST_FIXED_GUEST";
pub const RECEIPT_ENV: &str = "REVERIE_LITEINST_FIXED_GUEST_MANIFEST";

pub fn produce(root: &Path, bundle: &Path, runner: &mut Runner) -> Result<(PathBuf, PathBuf)> {
    let source =
        FileIdentity::read(&root.join("reverie-liteinst/tests/fixtures/fixed_arena_guest.c"))?;
    if source.sha256 != m1_artifact::sha256(SOURCE) {
        return Err("fixed-arena guest compiled/current source differs".into());
    }
    let binary = bundle.join("fixed_arena_guest");
    let receipt_path = bundle.join("fixed-arena-guest.json");
    if binary.exists() || receipt_path.exists() {
        return Err("fixed-arena guest outputs must be fresh".into());
    }
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compiler_version = runner.text(&compiler, &["--version"], root)?;
    runner.run(
        &compiler,
        &[
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-fsyntax-only".into(),
            source.path.to_string_lossy().into_owned(),
        ],
        root,
    )?;
    runner.run(
        &compiler,
        &[
            "-std=c11".into(),
            "-O0".into(),
            "-fno-builtin".into(),
            "-fno-lto".into(),
            "-Wl,--export-dynamic".into(),
            "-Wl,-z,now".into(),
            source.path.to_string_lossy().into_owned(),
            "-o".into(),
            binary.to_string_lossy().into_owned(),
            "-ldl".into(),
        ],
        root,
    )?;
    let receipt = GuestReceipt {
        schema_version: 1,
        source,
        binary: FileIdentity::read(&binary)?,
        compiler_version,
        command: runner
            .commands
            .last()
            .ok_or("fixed-arena compiler record missing")?
            .clone(),
        executed_tests: 0,
    };
    m1_artifact::write_new(
        &receipt_path,
        &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
    )?;
    m1_artifact::verify_guest_receipt(
        &receipt_path,
        &binary,
        &root.join("reverie-liteinst/tests/fixtures/fixed_arena_guest.c"),
        &m1_artifact::sha256(SOURCE),
    )?;
    Ok((binary, receipt_path))
}

/// Bind diagnostic source objects to the actual runtime/guest receipts. This
/// sidecar grants no admission and claims neither executed tests nor placement.
pub fn bind_inputs(
    root: &Path,
    bundle: &Path,
    runtime_receipt: &Path,
    guest_receipt: &Path,
) -> Result<PathBuf> {
    let sources = [
        "reverie-inguest/src/guest/alloc.rs",
        "reverie-inguest/src/guest/tool_region.rs",
        "reverie-inguest/src/guest/tool_region_arena.rs",
        "reverie-inguest/src/guest/tool_region_constructor.rs",
        "reverie-liteinst/src/allocator_backing.rs",
        "reverie-liteinst/src/patch_alloc.rs",
        "reverie-liteinst/src/allocator_fixture.rs",
        "reverie-liteinst/src/fixed_arena_fixture.rs",
        "reverie-liteinst-artifact/src/lib.rs",
        "reverie-liteinst-artifact/src/private_static/selected_initializers.rs",
        "reverie-liteinst-artifact/src/private_static/selected_initializers/native_leaves.rs",
        "reverie-liteinst-artifact/tests/fixtures/musl_memset_member.rs",
        "reverie-liteinst-artifact/tests/fixtures/musl_memset_source.txt",
        "reverie-liteinst-artifact/tests/fixtures/musl_set_thread_area_member.rs",
        "reverie-liteinst-artifact/tests/fixtures/musl_set_thread_area_source.txt",
        "reverie-liteinst-artifact/tests/fixtures/musl_libc_common_map.txt",
        "reverie-liteinst-artifact/tests/fixtures/musl_libc_common_member.rs",
        "reverie-liteinst-artifact/src/private_static/optional-zero-a03.json",
        "reverie-liteinst-artifact/src/private_static/selected_initializers/ordinary_gate.rs",
        "reverie-liteinst-artifact/tests/fixtures/ordinary_preceding_gate_page.rs",
        "reverie-liteinst-artifact/tests/fixtures/selected_init_v12.json",
        "scripts/fixed_arena_fixture.rs",
    ]
    .into_iter()
    .map(|path| Ok((path, FileIdentity::read(&root.join(path))?)))
    .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
    let path = bundle.join("fixed-arena-inputs.json");
    m1_artifact::write_new(
        &path,
        &serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": 1,
            "admission": "source bindings only; Fixed admission requires the complete verified runtime receipt",
            "runtime_receipt": FileIdentity::read(runtime_receipt)?,
            "guest_receipt": FileIdentity::read(guest_receipt)?,
            "sources": sources,
            "executed_tests": 0,
            "fixed_placement_pass_claimed": false,
        }))
        .map_err(|e| e.to_string())?,
    )?;
    Ok(path)
}
