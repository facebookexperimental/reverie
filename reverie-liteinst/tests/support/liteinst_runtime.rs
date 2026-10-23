//! Required producer inputs for genuine standalone LiteInst integration tests.
//!
//! Expected package/profile/source/oracle identities come from this consumer and
//! current Git worktree, never from the receipt being accepted. Verification is
//! cached once per test process; it performs bounded Git reads and no Cargo, cc,
//! dlopen or guest launch. There is no target/deps artifact fallback.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

// Each consumer uses a subset of the shared producer/consumer APIs. Their unit
// tests remain enrolled in every test binary that includes this module.
#[allow(dead_code)]
#[path = "../../../reverie-liteinst-artifact/src/lib.rs"]
pub mod artifact;
#[allow(dead_code)]
#[path = "../../../scripts/m1_contract.rs"]
pub mod contract;

pub const RUST_ORACLE_SHA256: &str =
    "e707144e4e5735c03f9139cc4a2a89d6be2089461d88ed2c949cdd770a7d2cf0";
pub const C_ORACLE_SHA256: &str =
    "e21fd8768d61edc7d14f51b98e2c5f9087fd4ddcfa08a19a2ca646b6df912b2e";
const RUST_ORACLE_BYTES: &[u8] = include_bytes!("../../src/allocator_fixture.rs");
const C_ORACLE_BYTES: &[u8] = include_bytes!("../fixtures/m1_allocator_guest.c");

pub struct QualifiedRuntime {
    pub path: PathBuf,
    pub receipt_path: PathBuf,
    pub receipt: artifact::RuntimeReceipt,
    pub source: artifact::SourceIdentity,
    pub evidence: PathBuf,
}

pub struct QualifiedGuest {
    pub path: PathBuf,
    pub receipt_path: PathBuf,
    pub receipt: artifact::GuestReceipt,
}

static RUNTIME: OnceLock<Result<QualifiedRuntime, String>> = OnceLock::new();
static GUEST: OnceLock<Result<QualifiedGuest, String>> = OnceLock::new();

pub fn required_runtime() -> Result<&'static QualifiedRuntime, String> {
    match RUNTIME.get_or_init(qualify_runtime) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(error.clone()),
    }
}

pub fn required_preload_path() -> Result<PathBuf, String> {
    Ok(required_runtime()?.path.clone())
}

pub fn required_allocator_guest() -> Result<&'static QualifiedGuest, String> {
    match GUEST.get_or_init(qualify_guest) {
        Ok(guest) => Ok(guest),
        Err(error) => Err(error.clone()),
    }
}

fn required_path(name: &str) -> Result<PathBuf, String> {
    let value = std::env::var_os(name).ok_or_else(|| {
        format!("{name} is required; prepare the exact LiteInst runtime/guest with the official producer before running this test")
    })?;
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(format!("{name} must name an absolute producer-owned file"));
    }
    let canonical = artifact::real_file(&path)?;
    if canonical != path {
        return Err(format!("{name} must name its exact canonical regular file"));
    }
    Ok(canonical)
}

pub fn repository_root() -> Result<PathBuf, String> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    fs::canonicalize(
        manifest
            .parent()
            .ok_or("core manifest has no repository parent")?,
    )
    .map_err(|error| format!("canonical repository root: {error}"))
}

/// Capture inheritance once, then install only these literal values on each
/// child. Ambient preloads are excluded so only the actual launcher installs
/// the selected, hashed runtime. No environment values are written to logs.
pub fn held_environment(policy: Vec<u8>) -> contract::HeldInputs {
    let mut environment: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    environment.remove(&OsString::from("LD_PRELOAD"));
    environment.insert(OsString::from("LD_BIND_NOW"), OsString::from("1"));
    contract::HeldInputs {
        environment: environment.into_iter().collect(),
        policy,
    }
}

/// Keep evidence outside the source tree so source cleanliness checks remain
/// meaningful. Both successful and failed child output are retained verbatim.
pub fn evidence_directory(label: &str) -> Result<PathBuf, String> {
    tempfile::Builder::new()
        .prefix(&format!("reverie-m1-{label}-"))
        .tempdir()
        .map(|directory| directory.keep())
        .map_err(|error| format!("create owned evidence directory: {error}"))
}

pub fn retain_capture(
    directory: &Path,
    name: &str,
    run: &contract::CapturedRun,
) -> Result<(), String> {
    artifact::write_new(&directory.join(format!("{name}.stdout")), &run.stdout)?;
    artifact::write_new(&directory.join(format!("{name}.stderr")), &run.stderr)?;
    let record = serde_json::json!({
        "code": run.status.and_then(|status| status.code()),
        "signal": run.status.and_then(|status| status.signal()),
        "input": run.input,
        "elapsed_millis": run.elapsed.as_millis(),
        "end": format!("{:?}", run.end),
        "output_truncated": run.output_truncated,
        "program": run.launch.program,
        "arguments": run.launch.arguments,
        "current_dir": run.launch.current_dir,
        "environment_names": run.launch.held.environment.iter().map(|pair| &pair.0).collect::<Vec<_>>(),
        "held_policy_sha256": artifact::sha256(&run.launch.held.policy),
    });
    artifact::write_new(
        &directory.join(format!("{name}.json")),
        &serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?,
    )
}

pub fn retain_failure(
    directory: &Path,
    name: &str,
    failure: &contract::ContractError,
) -> Result<(), String> {
    artifact::write_new(
        &directory.join(format!("{name}.failure.txt")),
        failure.message.as_bytes(),
    )?;
    for (index, capture) in failure.captures.iter().enumerate() {
        retain_capture(directory, &format!("{name}-capture-{index}"), capture)?;
    }
    Ok(())
}

fn git(root: &Path, args: &[&str], evidence: &Path, label: &str) -> Result<String, String> {
    let mut held = held_environment(b"source-only Git identity read".to_vec());
    held.environment
        .push((OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0")));
    // A caller may already export this setting. Keep one key, with our required
    // read-only value, rather than depending on an ambient lock setting.
    held.environment = held
        .environment
        .into_iter()
        .collect::<BTreeMap<_, _>>()
        .into_iter()
        .collect();
    let mut command = Command::new("git");
    command
        .arg("--no-optional-locks")
        .args(args)
        .current_dir(root);
    let run = match contract::run_without_input(command, &held) {
        Ok(run) => run,
        Err(failure) => {
            retain_failure(evidence, label, &failure)?;
            return Err(format!(
                "Git source identity read: {failure}; raw evidence {}",
                evidence.display()
            ));
        }
    };
    retain_capture(evidence, label, &run)?;
    if !run.status.is_some_and(|status| status.success()) {
        return Err(format!(
            "Git source identity read failed; raw evidence {}",
            evidence.display()
        ));
    }
    String::from_utf8(run.stdout).map_err(|error| format!("Git identity is not UTF-8: {error}"))
}

pub fn current_source(evidence: &Path, prefix: &str) -> Result<artifact::SourceIdentity, String> {
    let root = repository_root()?;
    let observed = git(
        &root,
        &["rev-parse", "--show-toplevel"],
        evidence,
        &format!("{prefix}-root"),
    )?;
    if Path::new(observed.trim_end_matches('\n')) != root {
        return Err("source root differs from the exact current Git worktree".into());
    }
    let head = git(
        &root,
        &["rev-parse", "HEAD"],
        evidence,
        &format!("{prefix}-head"),
    )?
    .trim_end_matches('\n')
    .to_owned();
    let tree = git(
        &root,
        &["rev-parse", "HEAD^{tree}"],
        evidence,
        &format!("{prefix}-tree"),
    )?
    .trim_end_matches('\n')
    .to_owned();
    if head.len() != 40
        || tree.len() != 40
        || !head
            .bytes()
            .chain(tree.bytes())
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("current source must expose exact 40-hex Git HEAD/tree".into());
    }
    let status = git(
        &root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
        evidence,
        &format!("{prefix}-status"),
    )?;
    if !status.is_empty() {
        return Err(format!(
            "current source must be clean; raw status evidence {}",
            evidence.display()
        ));
    }
    if artifact::sha256(RUST_ORACLE_BYTES) != RUST_ORACLE_SHA256
        || artifact::sha256(C_ORACLE_BYTES) != C_ORACLE_SHA256
    {
        return Err("compiled-in oracle bytes differ from the fixed baseline hashes".into());
    }
    let lock = artifact::FileIdentity::read(&root.join("Cargo.lock"))?;
    let oracles = BTreeMap::from([
        (
            "rust_exports".to_owned(),
            artifact::FileIdentity::read(&root.join("reverie-liteinst/src/allocator_fixture.rs"))?,
        ),
        (
            "c_workload".to_owned(),
            artifact::FileIdentity::read(
                &root.join("reverie-liteinst/tests/fixtures/m1_allocator_guest.c"),
            )?,
        ),
    ]);
    if oracles["rust_exports"].sha256 != RUST_ORACLE_SHA256
        || oracles["c_workload"].sha256 != C_ORACLE_SHA256
    {
        return Err("current oracle sources differ from the compiled-in frozen identities".into());
    }
    Ok(artifact::SourceIdentity {
        root,
        head,
        tree,
        status,
        lock,
        oracles,
    })
}

fn qualify_runtime() -> Result<QualifiedRuntime, String> {
    let evidence = evidence_directory("runtime-preflight")?;
    let result: Result<QualifiedRuntime, String> = (|| {
        let path = required_path("REVERIE_LITEINST_PRELOAD")?;
        if path.file_name().and_then(|name| name.to_str()) != Some("libreverie_liteinst.so") {
            return Err("standalone producer must stage canonical libreverie_liteinst.so".into());
        }
        let receipt_path = required_path("REVERIE_LITEINST_TEST_RUNTIME_MANIFEST")?;
        let source = current_source(&evidence, "before")?;
        let leaf = fs::canonicalize(source.root.join("reverie-liteinst-preload"))
            .map_err(|error| format!("actual leaf directory: {error}"))?;
        let leaf_text = leaf
            .to_str()
            .ok_or("Cargo path identity requires a UTF-8 leaf path")?;
        // Cargo's URL path identity is independent of the receipt. These test
        // worktrees use ordinary absolute paths; unfamiliar URL escaping is a
        // named refusal, never an acceptance value copied from a receipt.
        if !leaf_text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte))
        {
            return Err("leaf path needs unsupported Cargo URL escaping".into());
        }
        let package = artifact::PackageIdentity {
            id: format!("path+file://{leaf_text}#0.5.3"),
            name: "reverie-liteinst-preload".into(),
            manifest: artifact::real_file(&leaf.join("Cargo.toml"))?,
            source: None,
            target: "reverie_liteinst_preload".into(),
            kind: vec!["cdylib".into()],
            crate_types: vec!["cdylib".into()],
            target_source: artifact::real_file(&leaf.join("src/lib.rs"))?,
        };
        let features = vec!["allocator-fixture".to_owned()];
        let profile = serde_json::json!({
            "opt_level": "0", "debuginfo": 2, "debug_assertions": true,
            "overflow_checks": true, "test": false,
        });
        let oracle_sha256 = BTreeMap::from([
            ("rust_exports".to_owned(), RUST_ORACLE_SHA256.to_owned()),
            ("c_workload".to_owned(), C_ORACLE_SHA256.to_owned()),
        ]);
        let expectation = artifact::ConsumerExpectation {
            compiled_sources: None,
            package: &package,
            features: &features,
            profile_name: "dev",
            profile: &profile,
            initializer: artifact::STANDALONE_ROOT,
            source_head: &source.head,
            source_tree: &source.tree,
            source_lock_sha256: &source.lock.sha256,
            oracle_sha256: &oracle_sha256,
        };
        let receipt = artifact::verify_runtime_receipt(&receipt_path, &path, &expectation)?;
        if receipt.source_before != source || receipt.source_after != source {
            return Err("receipt source root/lock/oracle paths differ from the exact current source snapshot".into());
        }
        let after = current_source(&evidence, "after")?;
        if after != source {
            return Err("source changed during cached runtime qualification".into());
        }
        Ok(QualifiedRuntime {
            path,
            receipt_path,
            receipt,
            source,
            evidence: evidence.clone(),
        })
    })();
    if let Err(error) = &result {
        artifact::write_new(&evidence.join("preflight.failure.txt"), error.as_bytes())?;
    }
    result.map_err(|error| format!("{error}; preflight evidence {}", evidence.display()))
}

fn qualify_guest() -> Result<QualifiedGuest, String> {
    let runtime = required_runtime()?;
    let path = required_path("REVERIE_LITEINST_ALLOCATOR_GUEST")?;
    let receipt_path = required_path("REVERIE_LITEINST_ALLOCATOR_GUEST_MANIFEST")?;
    let source = &runtime.source.oracles["c_workload"];
    let receipt =
        artifact::verify_guest_receipt(&receipt_path, &path, &source.path, C_ORACLE_SHA256)?;
    Ok(QualifiedGuest {
        path,
        receipt_path,
        receipt,
    })
}

/// Recheck the accepted bytes and current source after actual work. A cached
/// first admission must not conceal a runtime/guest/source mutation later.
pub fn verify_unchanged(evidence: &Path) -> Result<(), String> {
    let runtime = required_runtime()?;
    runtime.receipt.artifact.verify()?;
    if let Some(Ok(guest)) = GUEST.get() {
        guest.receipt.binary.verify()?;
        guest.receipt.source.verify()?;
    }
    if current_source(evidence, "final")? != runtime.source {
        return Err("source HEAD/tree/lock/oracles changed after actual control execution".into());
    }
    Ok(())
}
