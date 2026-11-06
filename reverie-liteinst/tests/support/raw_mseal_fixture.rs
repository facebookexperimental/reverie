//! A source-built behavior fixture, never an M1-qualified runtime.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use super::liteinst_runtime as runtime;
use super::liteinst_runtime::artifact;

pub struct SourceBuiltFixture {
    pub source: artifact::SourceIdentity,
    pub artifact: artifact::FileIdentity,
    pub original: artifact::FileIdentity,
    pub manifest: PathBuf,
    pub setup_deadline: Instant,
    target: Option<tempfile::TempDir>,
}

fn require(value: bool, message: &str) -> Result<(), String> {
    if value {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

/// Own a fresh nested Cargo target so the calling Cargo test never waits on
/// its own output lock. Every command shares this setup's original 540s end.
pub fn build(evidence: &Path) -> Result<SourceBuiltFixture, String> {
    let setup_deadline = Instant::now() + Duration::from_secs(540);
    let mut runner = artifact::Runner::new(
        evidence.join("source-build"),
        setup_deadline.saturating_duration_since(Instant::now()),
        64 * 1024 * 1024,
    )?;
    runner.deadline = setup_deadline;
    let result = (|| {
        let root = runtime::repository_root()?;
        let oracles = BTreeMap::from([
            (
                "rust_exports".to_owned(),
                root.join("reverie-liteinst/src/allocator_fixture.rs"),
            ),
            (
                "c_workload".to_owned(),
                root.join("reverie-liteinst/tests/fixtures/m1_allocator_guest.c"),
            ),
        ]);
        let source_before =
            artifact::source_identity(&root, &root.join("Cargo.lock"), &oracles, &mut runner)?;
        require(
            source_before.oracles["rust_exports"].sha256 == runtime::RUST_ORACLE_SHA256
                && source_before.oracles["c_workload"].sha256 == runtime::C_ORACLE_SHA256,
            "source-built fixture changed the existing frozen oracle sources",
        )?;
        let metadata_index = runner.commands.len();
        let metadata_raw = runner.run(
            "cargo",
            &[
                "metadata".into(),
                "--locked".into(),
                "--offline".into(),
                "--no-deps".into(),
                "--format-version=1".into(),
                "--manifest-path".into(),
                root.join("Cargo.toml").to_string_lossy().into_owned(),
            ],
            &root,
        )?;
        let metadata: serde_json::Value = serde_json::from_slice(&metadata_raw)
            .map_err(|error| format!("source-built Cargo metadata: {error}"))?;
        require(
            metadata["workspace_root"].as_str() == root.to_str(),
            "Cargo metadata selected another workspace",
        )?;
        let package = artifact::select_package(
            &metadata,
            "reverie-liteinst-preload",
            "reverie_liteinst_preload",
            &root.join("reverie-liteinst-preload/Cargo.toml"),
            None,
        )?;
        let package_metadata = metadata["packages"]
            .as_array()
            .ok_or("Cargo packages missing")?
            .iter()
            .find(|row| row["id"].as_str() == Some(package.id.as_str()))
            .ok_or("selected preload metadata missing")?;
        let features = package_metadata["features"]
            .as_object()
            .ok_or("preload feature map missing")?;
        require(
            features.contains_key("allocator-fixture"),
            "preload allocator fixture feature missing",
        )?;
        // Select the caller's actual compiled mode. Declaring the optional
        // feature in Cargo metadata must not turn an OFF behavior test ON.
        let mut expected_features = vec!["allocator-fixture".to_owned()];
        if cfg!(feature = "liteinst") {
            require(
                features.contains_key("liteinst"),
                "preload LiteInst feature missing",
            )?;
            expected_features.push("liteinst".to_owned());
        }
        let target_owner = tempfile::Builder::new()
            .prefix("reverie-raw-mseal-target-")
            .tempdir()
            .map_err(|error| format!("fresh owned nested Cargo target: {error}"))?;
        let target = fs::canonicalize(target_owner.path()).map_err(|error| error.to_string())?;
        let regular = PathBuf::from(
            metadata["target_directory"]
                .as_str()
                .ok_or("Cargo target directory missing")?,
        );
        require(
            target != regular
                && !regular.starts_with(&target)
                && !target.starts_with(regular.join("debug"))
                && !target.starts_with(regular.join("release")),
            "nested target overlaps ordinary Cargo output",
        )?;
        let expected_profile = serde_json::json!({
            "opt_level":"0", "debuginfo":2, "debug_assertions":true,
            "overflow_checks":true, "test":false,
        });
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
        let rustc_version = runner.text(&rustc, &["--version", "--verbose"], &root)?;
        let cargo_version = runner.text("cargo", &["--version", "--verbose"], &root)?;
        let build_index = runner.commands.len();
        let build_raw = runner.run(
            "cargo",
            &[
                "build".into(),
                "--locked".into(),
                "--offline".into(),
                "--manifest-path".into(),
                root.join("Cargo.toml").to_string_lossy().into_owned(),
                "-p".into(),
                "reverie-liteinst-preload".into(),
                "--lib".into(),
                "--no-default-features".into(),
                "--features".into(),
                expected_features.join(","),
                "--profile".into(),
                "dev".into(),
                "--jobs".into(),
                "8".into(),
                "--target-dir".into(),
                target.to_string_lossy().into_owned(),
                "--message-format=json-render-diagnostics".into(),
            ],
            &root,
        )?;
        let cargo_artifact = artifact::select_artifact(
            std::str::from_utf8(&build_raw).map_err(|error| error.to_string())?,
            &package,
            &expected_features,
            &expected_profile,
            &target,
        )?;
        require(
            !cargo_artifact.fresh,
            "fresh nested target returned a cached preload artifact",
        )?;
        let original = artifact::FileIdentity::read(&cargo_artifact.reported_path)?;
        let staged_path = evidence.join("libreverie_liteinst.so");
        artifact::write_new(
            &staged_path,
            &fs::read(&original.path).map_err(|error| error.to_string())?,
        )?;
        original.verify()?;
        let staged = artifact::FileIdentity::read(&staged_path)?;
        require(
            original.sha256 == staged.sha256,
            "source-built DSO copy changed",
        )?;
        let source_after =
            artifact::source_identity(&root, &root.join("Cargo.lock"), &oracles, &mut runner)?;
        require(
            source_before == source_after,
            "source changed during behavior-fixture build",
        )?;
        require(
            Instant::now() < setup_deadline,
            "behavior fixture setup deadline exhausted",
        )?;
        let manifest = evidence.join("source-built-fixture.json");
        artifact::write_new(
            &manifest,
            &serde_json::to_vec_pretty(&serde_json::json!({
                "kind":"SOURCE_BUILT_FIXED_RAW_MSEAL_BEHAVIOR_ONLY_NONQUALIFIED",
                "m1_qualified":false,
                "source_before":source_before, "source_after":source_after,
                "cargo_artifact":cargo_artifact,
                "original_dso":original, "staged_dso":staged,
            "original_dso_lifecycle":"temporary build input; rechecked before owned target retirement; see target-retirement.json",
                "command_evidence":{
                    "metadata":runner.commands[metadata_index],
                    "cargo_build":runner.commands[build_index],
                },
                "rustc_version":rustc_version, "cargo_version":cargo_version,
                "setup_limit_seconds":540,
            }))
            .map_err(|error| error.to_string())?,
        )?;
        Ok(SourceBuiltFixture {
            source: source_after,
            artifact: staged,
            original,
            manifest,
            setup_deadline,
            target: Some(target_owner),
        })
    })();
    // Preserve actual command records on failed setup too; no failed build is
    // relabelled as a runtime or allocator qualification result.
    let retained = artifact::write_new(
        &evidence.join("source-build-commands.json"),
        &serde_json::to_vec_pretty(&runner.commands).map_err(|error| error.to_string())?,
    );
    match (result, retained) {
        (Ok(fixture), Ok(())) => Ok(fixture),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(retain)) => Err(format!("{error}; command retention: {retain}")),
    }
}

impl SourceBuiltFixture {
    /// The source-built stage and all captures remain. Only this fixture's
    /// temporary Cargo target is retired, after guest and source postchecks.
    pub fn retire(mut self, evidence: &Path) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Err(error) = self.original.verify() {
            errors.push(error);
        }
        if let Err(error) = self.artifact.verify() {
            errors.push(error);
        }
        let target = self
            .target
            .take()
            .ok_or("owned Cargo target already retired")?;
        let target_path = target.path().to_owned();
        if let Err(error) = target.close() {
            errors.push(format!("owned Cargo target retirement: {error}"));
        }
        let absent = !target_path
            .try_exists()
            .map_err(|error| error.to_string())?;
        if !absent {
            errors.push("owned Cargo target remains after retirement".into());
        }
        let record = serde_json::json!({
            "kind":"SOURCE_BUILT_BEHAVIOR_TEMPORARY_TARGET_RETIREMENT",
            "original_dso_observed_before_retirement":self.original,
            "retained_staged_dso":self.artifact,
            "target_path":target_path,
            "target_absent":absent,
            "errors":errors,
        });
        let retained = artifact::write_new(
            &evidence.join("target-retirement.json"),
            &serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?,
        );
        if let Err(error) = retained {
            errors.push(format!("retirement record: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}
