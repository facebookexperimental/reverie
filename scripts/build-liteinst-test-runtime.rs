#!/usr/bin/env -S rust-script --force
//! Explicit producer for the actual standalone diagnostic preload leaf.
//! M1 allocation and M2 stack guests have separate source-bound receipts.
//!
//! ```cargo
//! [dependencies]
//! goblin = "=0.10.7"
//! sha2 = "=0.10.9"
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! libc = "0.2"
//! ```
//!
//! Usage: build-liteinst-test-runtime.rs --for-ci /absolute/unique-generation
//! Or: build-liteinst-test-runtime.rs /absolute/producer-config.json
//! Config contains explicit workspace, separate target, unique bundle, profile,
//! exact Cargo profile object, oracle paths/hashes and source HEAD/tree/lock hash.
//! No directory search or warm-file fallback is permitted.

mod allocator_declaration_fixture;
mod fixed_arena_fixture;
mod generic_bootstrap_fixture;
#[path = "../reverie-liteinst-artifact/src/lib.rs"]
pub mod m1_artifact;
mod standalone_constructor_fixture;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use m1_artifact::FileIdentity;
use m1_artifact::GuestReceipt;
use m1_artifact::Result;
use m1_artifact::Runner;
use m1_artifact::RuntimeReceipt;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Config {
    workspace_root: PathBuf,
    target_directory: PathBuf,
    bundle_directory: PathBuf,
    source_head: String,
    source_tree: String,
    source_lock_sha256: String,
    rust_exports: PathBuf,
    c_workload: PathBuf,
    oracle_sha256: BTreeMap<String, String>,
    /// The leaf has exactly allocator-fixture; no default feature exists.
    expected_features: Vec<String>,
    /// The standalone RV producer requires the ordinary dev profile.
    /// H can reuse m1_artifact directly for its independent release producer.
    profile_name: String,
    expected_cargo_profile: Value,
    deadline_seconds: u64,
    max_command_stream_bytes: usize,
}

fn check(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn oracle_hashes() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "rust_exports".to_owned(),
            m1_artifact::FROZEN_RUST_ORACLE.to_owned(),
        ),
        (
            "c_workload".to_owned(),
            m1_artifact::FROZEN_C_ORACLE.to_owned(),
        ),
    ])
}

fn dev_profile() -> Value {
    serde_json::json!({"opt_level":"0", "debuginfo":2, "debug_assertions":true,
                       "overflow_checks":true, "test":false})
}

fn ci_config(generation: PathBuf) -> Result<Config> {
    check(
        generation.is_absolute(),
        "CI generation must be an absolute unique path",
    )?;
    fs::create_dir(&generation).map_err(|e| format!("create unique CI generation: {e}"))?;
    let generation = fs::canonicalize(generation).map_err(|e| e.to_string())?;
    let root = fs::canonicalize(std::env::current_dir().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let rust_exports = root.join("reverie-liteinst/src/allocator_fixture.rs");
    let c_workload = root.join("reverie-liteinst/tests/fixtures/m1_allocator_guest.c");
    let mut runner = Runner::new(
        generation.join("preflight-logs"),
        Duration::from_secs(60),
        1 << 20,
    )?;
    let source = m1_artifact::source_identity(
        &root,
        &root.join("Cargo.lock"),
        &BTreeMap::from([
            ("rust_exports".to_owned(), rust_exports.clone()),
            ("c_workload".to_owned(), c_workload.clone()),
        ]),
        &mut runner,
    )?;
    let config = Config {
        workspace_root: root,
        target_directory: generation.join("target"),
        bundle_directory: generation.join("bundle"),
        source_head: source.head,
        source_tree: source.tree,
        source_lock_sha256: source.lock.sha256,
        rust_exports,
        c_workload,
        oracle_sha256: oracle_hashes(),
        expected_features: vec!["allocator-fixture".to_owned()],
        profile_name: "dev".to_owned(),
        expected_cargo_profile: dev_profile(),
        deadline_seconds: 540,
        max_command_stream_bytes: 64 << 20,
    };
    m1_artifact::write_new(
        &generation.join("producer-config.json"),
        &serde_json::to_vec_pretty(&config).map_err(|e| e.to_string())?,
    )?;
    Ok(config)
}

fn produce_stack_guest(
    root: &std::path::Path,
    bundle: &std::path::Path,
    runner: &mut Runner,
) -> Result<(PathBuf, PathBuf)> {
    const SOURCE: &[u8] = include_bytes!("../reverie-liteinst/tests/fixtures/m2_stack_guest.c");
    let source =
        FileIdentity::read(&root.join("reverie-liteinst/tests/fixtures/m2_stack_guest.c"))?;
    check(
        source.sha256 == m1_artifact::sha256(SOURCE),
        "M2 compiled/current C source differs",
    )?;
    let binary_path = bundle.join("m2_stack_guest");
    check(!binary_path.exists(), "M2 C guest output already exists")?;
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let compiler_version = runner.text(&compiler, &["--version"], root)?;
    // Keep the existing source-bound guest recipe unchanged. This additional
    // syntax check makes warnings fatal for the new fixture alone.
    runner.run(
        &compiler,
        &[
            "-std=c11".to_owned(),
            "-Wall".to_owned(),
            "-Wextra".to_owned(),
            "-Werror".to_owned(),
            "-fsyntax-only".to_owned(),
            source.path.to_string_lossy().into_owned(),
        ],
        root,
    )?;
    runner.run(
        &compiler,
        &[
            "-std=c11".to_owned(),
            "-O0".to_owned(),
            "-fno-builtin".to_owned(),
            "-fno-lto".to_owned(),
            "-Wl,--export-dynamic".to_owned(),
            "-Wl,-z,now".to_owned(),
            source.path.to_string_lossy().into_owned(),
            "-o".to_owned(),
            binary_path.to_string_lossy().into_owned(),
            "-ldl".to_owned(),
        ],
        root,
    )?;
    let guest = GuestReceipt {
        schema_version: 1,
        source,
        binary: FileIdentity::read(&binary_path)?,
        compiler_version,
        command: runner
            .commands
            .last()
            .ok_or("M2 C compiler command missing")?
            .clone(),
        executed_tests: 0,
    };
    let receipt_path = bundle.join("stack-guest.json");
    m1_artifact::write_new(
        &receipt_path,
        &serde_json::to_vec_pretty(&guest).map_err(|e| e.to_string())?,
    )?;
    m1_artifact::verify_guest_receipt(
        &receipt_path,
        &binary_path,
        &guest.source.path,
        &m1_artifact::sha256(SOURCE),
    )?;
    Ok((binary_path, receipt_path))
}

struct StandaloneInputs {
    guest: PathBuf,
    guest_receipt: PathBuf,
    root: PathBuf,
    root_receipt: PathBuf,
}

fn produce_standalone_inputs(
    workspace: &std::path::Path,
    bundle: &std::path::Path,
    runner: &mut Runner,
) -> Result<StandaloneInputs> {
    const PROBE: &[u8] =
        include_bytes!("../reverie-liteinst/tests/fixtures/standalone_constructor_guest.c");
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let compiler_version = runner.text(&compiler, &["--version"], workspace)?;
    let guest_path = bundle.join("standalone_constructor_guest");
    let root_path = bundle.join("libstandalone_root_interposer.so");
    let guest_receipt_path = bundle.join("standalone-constructor-guest.json");
    let root_receipt_path = bundle.join("standalone-root-interposer.json");
    for (relative, bytes, output, receipt_path, shared) in [
        (
            "reverie-liteinst/tests/fixtures/standalone_constructor_guest.c",
            PROBE,
            &guest_path,
            &guest_receipt_path,
            false,
        ),
        (
            "reverie-liteinst/tests/fixtures/standalone_root_interposer.c",
            standalone_constructor_fixture::ROOT_SOURCE,
            &root_path,
            &root_receipt_path,
            true,
        ),
    ] {
        let source = FileIdentity::read(&workspace.join(relative))?;
        check(
            source.sha256 == m1_artifact::sha256(bytes),
            "standalone fixture compiled/current source differs",
        )?;
        check(!output.exists(), "standalone fixture output already exists")?;
        runner.run(
            &compiler,
            &[
                "-std=c11".to_owned(),
                "-Wall".to_owned(),
                "-Wextra".to_owned(),
                "-Werror".to_owned(),
                "-fsyntax-only".to_owned(),
                source.path.to_string_lossy().into_owned(),
            ],
            workspace,
        )?;
        let arguments = if shared {
            standalone_constructor_fixture::root_arguments(&source.path, output)
        } else {
            vec![
                "-std=c11".to_owned(),
                "-O0".to_owned(),
                "-fno-builtin".to_owned(),
                "-fno-lto".to_owned(),
                "-Wl,--export-dynamic".to_owned(),
                "-Wl,-z,now".to_owned(),
                source.path.to_string_lossy().into_owned(),
                "-o".to_owned(),
                output.to_string_lossy().into_owned(),
                "-ldl".to_owned(),
            ]
        };
        runner.run(&compiler, &arguments, workspace)?;
        let receipt = GuestReceipt {
            schema_version: 1,
            source,
            binary: FileIdentity::read(output)?,
            compiler_version: compiler_version.clone(),
            command: runner
                .commands
                .last()
                .ok_or("standalone compiler command missing")?
                .clone(),
            executed_tests: 0,
        };
        m1_artifact::write_new(
            receipt_path,
            &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
        )?;
        if shared {
            standalone_constructor_fixture::verify_root_receipt(
                receipt_path,
                output,
                &receipt.source.path,
            )?;
        } else {
            m1_artifact::verify_guest_receipt(
                receipt_path,
                output,
                &receipt.source.path,
                &m1_artifact::sha256(PROBE),
            )?;
        }
    }
    Ok(StandaloneInputs {
        guest: guest_path,
        guest_receipt: guest_receipt_path,
        root: root_path,
        root_receipt: root_receipt_path,
    })
}

fn produce(
    config: Config,
) -> Result<(
    PathBuf,
    PathBuf,
    PathBuf,
    PathBuf,
    StandaloneInputs,
    (PathBuf, PathBuf),
)> {
    check(
        config.workspace_root.is_absolute()
            && config.target_directory.is_absolute()
            && config.bundle_directory.is_absolute(),
        "workspace/target/bundle must be explicit absolute paths",
    )?;
    let root =
        fs::canonicalize(&config.workspace_root).map_err(|e| format!("workspace root: {e}"))?;
    // The bundle generation is created once; a failure retains command logs,
    // but no runtime.json success receipt. Rerun with a new generation.
    fs::create_dir(&config.bundle_directory)
        .map_err(|e| format!("create unique bundle generation: {e}"))?;
    let bundle = fs::canonicalize(&config.bundle_directory).map_err(|e| e.to_string())?;
    let mut runner = Runner::new(
        bundle.join("logs"),
        Duration::from_secs(config.deadline_seconds),
        config.max_command_stream_bytes,
    )?;
    check(
        config.expected_features == ["allocator-fixture"]
            && config.profile_name == "dev"
            && config.expected_cargo_profile == dev_profile(),
        "RV diagnostic leaf requires independent singleton fixture features and the ordinary dev profile",
    )?;
    check(
        config.oracle_sha256 == oracle_hashes(),
        "oracle acceptance hashes differ from frozen 4f4315 sources",
    )?;
    let oracles = BTreeMap::from([
        ("rust_exports".to_owned(), config.rust_exports),
        ("c_workload".to_owned(), config.c_workload),
    ]);
    let before =
        m1_artifact::source_identity(&root, &root.join("Cargo.lock"), &oracles, &mut runner)?;
    check(
        before.head == config.source_head
            && before.tree == config.source_tree
            && before.lock.sha256 == config.source_lock_sha256,
        "required source HEAD/tree/lock identities differ",
    )?;
    let observed_oracles: BTreeMap<_, _> = before
        .oracles
        .iter()
        .map(|(label, file)| (label.clone(), file.sha256.clone()))
        .collect();
    check(
        observed_oracles == config.oracle_sha256,
        "required unchanged Rust/C oracle hashes differ",
    )?;
    let metadata_bytes = runner.run(
        "cargo",
        &[
            "metadata".to_owned(),
            "--locked".to_owned(),
            "--offline".to_owned(),
            "--no-deps".to_owned(),
            "--format-version=1".to_owned(),
            "--manifest-path".to_owned(),
            root.join("Cargo.toml").to_string_lossy().into_owned(),
        ],
        &root,
    )?;
    let metadata: Value =
        serde_json::from_slice(&metadata_bytes).map_err(|e| format!("cargo metadata: {e}"))?;
    check(
        PathBuf::from(
            metadata["workspace_root"]
                .as_str()
                .ok_or("metadata workspace_root missing")?,
        ) == root,
        "metadata resolved another workspace",
    )?;
    let package = m1_artifact::select_package(
        &metadata,
        "reverie-liteinst-preload",
        "reverie_liteinst_preload",
        &root.join("reverie-liteinst-preload/Cargo.toml"),
        None,
    )?;
    // Require a fresh dedicated target root, not a reused standard Cargo tree.
    // This removes races with ordinary workspace all-feature test compilation.
    fs::create_dir(&config.target_directory)
        .map_err(|e| format!("create unique explicit target directory: {e}"))?;
    let target = fs::canonicalize(&config.target_directory).map_err(|e| e.to_string())?;
    let regular_target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("metadata target directory missing")?,
    );
    check(
        target != regular_target && !regular_target.starts_with(&target),
        "diagnostic target must not replace/contain the regular workspace target",
    )?;
    check(
        !target.starts_with(regular_target.join("debug"))
            && !target.starts_with(regular_target.join("release")),
        "diagnostic target must be separated from regular profile output",
    )?;
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let rustc_verbose = runner.text(&rustc, &["--version", "--verbose"], &root)?;
    let cargo_version = runner.text("cargo", &["--version", "--verbose"], &root)?;
    let readelf_version = runner.text("readelf", &["--version"], &root)?;
    let objdump_version = runner.text("objdump", &["--version"], &root)?;
    let arguments = vec![
        "build".to_owned(),
        "--locked".to_owned(),
        "--offline".to_owned(),
        "--manifest-path".to_owned(),
        root.join("Cargo.toml").to_string_lossy().into_owned(),
        "-p".to_owned(),
        "reverie-liteinst-preload".to_owned(),
        "--lib".to_owned(),
        "--features".to_owned(),
        "allocator-fixture".to_owned(),
        "--profile".to_owned(),
        config.profile_name.clone(),
        "--target-dir".to_owned(),
        target.to_string_lossy().into_owned(),
        "--message-format=json-render-diagnostics".to_owned(),
    ];
    let cargo_build_command_index = runner.commands.len();
    let output = runner.run("cargo", &arguments, &root)?;
    let messages =
        std::str::from_utf8(&output).map_err(|e| format!("Cargo artifact messages: {e}"))?;
    let cargo_artifact = m1_artifact::select_artifact(
        messages,
        &package,
        &config.expected_features,
        &config.expected_cargo_profile,
        &target,
    )?;
    let declaration_messages = runner
        .commands
        .get(cargo_build_command_index)
        .ok_or("current Cargo command record missing")?
        .stdout
        .clone();
    let declarations = allocator_declaration_fixture::run(
        &root,
        &bundle,
        &metadata,
        &declaration_messages,
        &cargo_artifact,
        &target,
        &runner,
    )?;
    let current = FileIdentity::read(&cargo_artifact.reported_path)?;
    let stage = bundle.join("libreverie_liteinst.so");
    // create_new prevents an earlier artifact from being substituted as a warm
    // fallback. Compare before/after copy so Cargo-target mutation is refused.
    m1_artifact::write_new(
        &stage,
        &fs::read(&current.path).map_err(|e| format!("read selected artifact: {e}"))?,
    )?;
    current.verify()?;
    let artifact = FileIdentity::read(&stage)?;
    check(
        artifact.sha256 == current.sha256,
        "staged/current artifact hashes differ",
    )?;
    let qualification =
        m1_artifact::qualify_elf(&stage, m1_artifact::STANDALONE_ROOT, &mut runner)?;
    let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
    let compiler_version = runner.text(&compiler, &["--version"], &root)?;
    let guest_path = bundle.join("m1_allocator_guest");
    check(!guest_path.exists(), "C guest output already exists")?;
    let c_source = before
        .oracles
        .get("c_workload")
        .ok_or("missing C source identity")?
        .clone();
    runner.run(
        &compiler,
        &[
            "-std=c11".to_owned(),
            "-O0".to_owned(),
            "-fno-builtin".to_owned(),
            "-fno-lto".to_owned(),
            "-Wl,--export-dynamic".to_owned(),
            "-Wl,-z,now".to_owned(),
            c_source.path.to_string_lossy().into_owned(),
            "-o".to_owned(),
            guest_path.to_string_lossy().into_owned(),
            "-ldl".to_owned(),
        ],
        &root,
    )?;
    let guest = GuestReceipt {
        schema_version: 1,
        source: c_source,
        binary: FileIdentity::read(&guest_path)?,
        compiler_version,
        command: runner
            .commands
            .last()
            .ok_or("C compiler command missing")?
            .clone(),
        executed_tests: 0,
    };
    let (stack_guest_path, stack_guest_receipt_path) =
        produce_stack_guest(&root, &bundle, &mut runner)?;
    let standalone = produce_standalone_inputs(&root, &bundle, &mut runner)?;
    let generic = generic_bootstrap_fixture::produce(&root, &bundle, &mut runner)?;
    let fixed = fixed_arena_fixture::produce(&root, &bundle, &mut runner)?;
    let after =
        m1_artifact::source_identity(&root, &root.join("Cargo.lock"), &oracles, &mut runner)?;
    check(
        before == after,
        "source HEAD/tree/dirty/lock/oracle identities changed during production",
    )?;
    current.verify()?;
    artifact.verify()?;
    let receipt = RuntimeReceipt {
        compiled_sources: None,
        schema_version: m1_artifact::SCHEMA,
        source_before: before,
        source_after: after,
        cargo_artifact,
        profile_name: config.profile_name,
        artifact,
        qualification,
        rustc_verbose,
        cargo_version,
        readelf_version,
        objdump_version,
        build_environment: [
            "RUSTUP_TOOLCHAIN",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
            "CARGO_BUILD_JOBS",
            "CC",
            "CXX",
            "AR",
            "NIX_DONT_SET_RPATH_x86_64_unknown_linux_gnu",
            "PATH",
        ]
        .into_iter()
        .map(|name| (name.to_owned(), std::env::var(name).ok()))
        .collect(),
        target_directory: target,
        commands: runner.commands,
        executed_tests: 0,
        full_m1_pass_claimed: false,
    };
    let receipt_path = bundle.join("runtime.json");
    m1_artifact::write_new(
        &receipt_path,
        &serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?,
    )?;
    let serialized: RuntimeReceipt =
        serde_json::from_slice(&fs::read(&receipt_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    check(
        serialized.artifact == receipt.artifact,
        "receipt readback changed artifact identity",
    )?;
    let guest_receipt_path = bundle.join("guest.json");
    m1_artifact::write_new(
        &guest_receipt_path,
        &serde_json::to_vec_pretty(&guest).map_err(|e| e.to_string())?,
    )?;
    m1_artifact::verify_guest_receipt(
        &guest_receipt_path,
        &guest_path,
        &guest.source.path,
        m1_artifact::FROZEN_C_ORACLE,
    )?;
    let declaration_inputs =
        allocator_declaration_fixture::bind_runtime_inputs(&bundle, &receipt_path, &declarations)?;
    let fixed_inputs = fixed_arena_fixture::bind_inputs(&root, &bundle, &receipt_path, &fixed.1)?;
    let inputs = BTreeMap::from([
        (
            "REVERIE_LITEINST_ALLOCATOR_DECLARATIONS_MANIFEST",
            declaration_inputs.as_path(),
        ),
        ("REVERIE_LITEINST_PRELOAD", receipt.artifact.path.as_path()),
        (
            "REVERIE_LITEINST_TEST_RUNTIME_MANIFEST",
            receipt_path.as_path(),
        ),
        ("REVERIE_LITEINST_ALLOCATOR_GUEST", guest_path.as_path()),
        (
            "REVERIE_LITEINST_ALLOCATOR_GUEST_MANIFEST",
            guest_receipt_path.as_path(),
        ),
        ("REVERIE_LITEINST_STACK_GUEST", stack_guest_path.as_path()),
        (
            "REVERIE_LITEINST_STACK_GUEST_MANIFEST",
            stack_guest_receipt_path.as_path(),
        ),
        (
            "REVERIE_LITEINST_CONSTRUCTOR_GUEST",
            standalone.guest.as_path(),
        ),
        (
            "REVERIE_LITEINST_CONSTRUCTOR_GUEST_MANIFEST",
            standalone.guest_receipt.as_path(),
        ),
        (
            "REVERIE_LITEINST_ROOT_INTERPOSER",
            standalone.root.as_path(),
        ),
        (
            "REVERIE_LITEINST_ROOT_INTERPOSER_MANIFEST",
            standalone.root_receipt.as_path(),
        ),
        (generic_bootstrap_fixture::GUEST_ENV, generic.0.as_path()),
        (generic_bootstrap_fixture::RECEIPT_ENV, generic.1.as_path()),
        (fixed_arena_fixture::GUEST_ENV, fixed.0.as_path()),
        (fixed_arena_fixture::RECEIPT_ENV, fixed.1.as_path()),
        (
            "REVERIE_LITEINST_FIXED_INPUTS_MANIFEST",
            fixed_inputs.as_path(),
        ),
    ]);
    let mut shell = String::new();
    let mut github = String::new();
    for (name, path) in inputs {
        let value = path.to_str().ok_or("fixture path is not UTF-8")?;
        check(
            !value.contains(['\n', '\r']),
            "fixture path contains a line break",
        )?;
        shell.push_str(&format!(
            "export {name}='{}'\n",
            value.replace('\'', "'\"'\"'")
        ));
        github.push_str(&format!("{name}={value}\n"));
    }
    m1_artifact::write_new(&bundle.join("fixture.env"), shell.as_bytes())?;
    m1_artifact::write_new(&bundle.join("github.env"), github.as_bytes())?;
    Ok((
        receipt_path,
        guest_receipt_path,
        stack_guest_path,
        stack_guest_receipt_path,
        standalone,
        generic,
    ))
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!(
            "Usage: build-liteinst-test-runtime.rs --for-ci /absolute/unique-generation\n       build-liteinst-test-runtime.rs /absolute/producer-config.json\nRun from the clean RV checkout root. The producer executes zero tests."
        );
        return Ok(());
    }
    let config = if args.len() == 2 && args[0] == "--for-ci" {
        ci_config(PathBuf::from(&args[1]))?
    } else {
        check(
            args.len() == 1,
            "usage: build-liteinst-test-runtime.rs --for-ci /absolute/unique-generation",
        )?;
        let path = PathBuf::from(&args[0]);
        check(
            path.is_absolute(),
            "producer config must be an absolute path",
        )?;
        serde_json::from_slice(&fs::read(&path).map_err(|e| format!("read config: {e}"))?)
            .map_err(|e| format!("producer config: {e}"))?
    };
    let (
        receipt_path,
        guest_receipt_path,
        stack_guest_path,
        stack_guest_receipt_path,
        standalone,
        generic,
    ) = produce(config)?;
    // JSON output is data, never a shell `export` snippet with quote ambiguity.
    let receipt: RuntimeReceipt =
        serde_json::from_slice(&fs::read(&receipt_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let guest: GuestReceipt =
        serde_json::from_slice(&fs::read(&guest_receipt_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({
            "REVERIE_LITEINST_PRELOAD": receipt.artifact.path,
            "REVERIE_LITEINST_TEST_RUNTIME_MANIFEST": receipt_path,
            "REVERIE_LITEINST_ALLOCATOR_GUEST": guest.binary.path,
            "REVERIE_LITEINST_ALLOCATOR_GUEST_MANIFEST": guest_receipt_path,
            "REVERIE_LITEINST_STACK_GUEST": stack_guest_path,
            "REVERIE_LITEINST_STACK_GUEST_MANIFEST": stack_guest_receipt_path,
            "REVERIE_LITEINST_CONSTRUCTOR_GUEST": standalone.guest,
            "REVERIE_LITEINST_CONSTRUCTOR_GUEST_MANIFEST": standalone.guest_receipt,
            "REVERIE_LITEINST_ROOT_INTERPOSER": standalone.root,
            "REVERIE_LITEINST_ROOT_INTERPOSER_MANIFEST": standalone.root_receipt,
            "REVERIE_LITEINST_GENERIC_GUEST": generic.0,
            "REVERIE_LITEINST_GENERIC_GUEST_MANIFEST": generic.1,
            "REVERIE_LITEINST_FIXED_GUEST": receipt_path.parent().ok_or("runtime bundle absent")?.join("fixed_arena_guest"),
            "REVERIE_LITEINST_FIXED_GUEST_MANIFEST": receipt_path.parent().ok_or("runtime bundle absent")?.join("fixed-arena-guest.json"),
            "REVERIE_LITEINST_FIXED_INPUTS_MANIFEST": receipt_path.parent().ok_or("runtime bundle absent")?.join("fixed-arena-inputs.json"),
            "REVERIE_LITEINST_ALLOCATOR_DECLARATIONS_MANIFEST": receipt_path.parent().ok_or("runtime bundle absent")?.join("allocator-declarations/runtime-inputs.json"),
            "artifact_sha256": receipt.artifact.sha256,
            "guest_sha256": guest.binary.sha256,
            "executed_tests": 0,
            "full_m1_pass_claimed": false,
        })
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("M1 diagnostic runtime producer: {error}");
            ExitCode::FAILURE
        }
    }
}
