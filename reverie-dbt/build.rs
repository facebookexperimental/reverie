/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::process::Command;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use sha2::Digest;
use sha2::Sha256;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#53): validate the pinned dr_invoke_syscall_as_app mmap fix.
const DYNAMORIO_REVISION: &str = "929840ad9190e5086775e8debc0f0b79b4208d59";
const MAX_PARALLEL_JOBS: usize = 16;
// Provenance: three clean builds of this curated source tree on 2026-08-03:
// 13.91s and 14.54s with 16 jobs on a development runner, and 71.49s with 4 jobs on a
// GitHub-hosted runner. Their elapsed-seconds * requested-jobs proxies were
// 222.56, 232.64, and 285.96 job-seconds. The CI ratchet is 2x the slowest
// observation, rounded up; local source installs report without enforcing it.
const CI_MAX_BUILD_JOB_SECONDS: f64 = 572.0;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=vendor/dynamorio");
    println!("cargo:rerun-if-env-changed=CMAKE");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");
    println!("cargo:rerun-if-env-changed=CI");
    println!("cargo:rerun-if-env-changed=REVERIE_DBT_MAX_BUILD_SECONDS");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let source_dir = manifest_dir.join("vendor/dynamorio");
    let revision = fs::read_to_string(source_dir.join("REVISION"))
        .expect("the vendored DynamoRIO source is missing its REVISION marker");
    assert_eq!(
        revision.trim(),
        DYNAMORIO_REVISION,
        "the vendored DynamoRIO source revision marker changed"
    );
    for required in [
        "CMakeLists.txt",
        "core/lib/globals_shared.h",
        "core/unix/memcache.c",
        "tools/drdeploy.c",
        "ext/drmgr/drmgr.c",
        "ext/drreg/drreg.c",
        "ext/drwrap/drwrap.c",
        "ext/drx/drx.c",
    ] {
        assert!(
            source_dir.join(required).is_file(),
            "the vendored DynamoRIO source is incomplete: missing {required}"
        );
    }

    let out_dir = PathBuf::from(required_env("OUT_DIR"));
    let cmake = env::var_os("CMAKE").unwrap_or_else(|| OsString::from("cmake"));
    let generator = env::var_os("CMAKE_GENERATOR");
    let source_key = source_recipe_key(
        &source_dir,
        &manifest_dir.join("build.rs"),
        &cmake,
        generator.as_deref(),
    );
    let cache_root = shared_cache_root(&out_dir);
    let install_dir = cache_root.join(format!("dynamorio-install-{source_key}"));
    let drrun = install_dir.join("bin64/drrun");
    let observed_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time predates the Unix epoch")
        .as_secs();

    if !install_is_complete(&install_dir) {
        assert!(
            !install_dir.exists(),
            "DynamoRIO build cache contains an incomplete install at {}",
            install_dir.display()
        );
        println!(
            "cargo:warning=DynamoRIO build cache MISS key=sha256:{source_key} observed_unix_seconds={observed_at}"
        );
        let staging = StagingDirectory::create(&cache_root, &source_key);
        let build_dir = staging.path().join("build");
        let staged_install = staging.path().join("install");
        build_dynamorio(
            &source_dir,
            &build_dir,
            &staged_install,
            &cmake,
            generator.as_deref(),
        );
        assert!(
            install_is_complete(&staged_install),
            "DynamoRIO source build produced an incomplete install at {}",
            staged_install.display()
        );
        let published = publish_install(&staged_install, &install_dir);
        println!(
            "cargo:warning=DynamoRIO build cache {} key=sha256:{source_key} install={}",
            if published { "PUBLISHED" } else { "RACE-HIT" },
            install_dir.display()
        );
    } else {
        println!(
            "cargo:warning=DynamoRIO build cache HIT key=sha256:{source_key} observed_unix_seconds={observed_at} install={}",
            install_dir.display()
        );
    }

    println!(
        "cargo:rustc-env=REVERIE_DBT_DYNAMORIO_HOME={}",
        install_dir.display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBT_DYNAMORIO_CMAKE={}",
        install_dir.join("cmake").display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBT_DYNAMORIO_DRRUN={}",
        drrun.display()
    );
}

/// Put native artifacts outside Cargo's package-fingerprint directory.
///
/// Cargo gives the same package a different `OUT_DIR` when build-dependency
/// profiles differ (for example, `cargo build` versus `cargo doc`). Both
/// directories are children of the same target/profile `build` directory, so
/// its parent is the narrowest cache scope they can safely share.
fn shared_cache_root(out_dir: &Path) -> PathBuf {
    let package_fingerprint = out_dir.parent().unwrap_or_else(|| {
        panic!(
            "Cargo OUT_DIR has no package directory: {}",
            out_dir.display()
        )
    });
    let cargo_build_dir = package_fingerprint.parent().unwrap_or_else(|| {
        panic!(
            "Cargo OUT_DIR has no build directory: {}",
            out_dir.display()
        )
    });
    assert_eq!(
        cargo_build_dir.file_name(),
        Some(std::ffi::OsStr::new("build")),
        "unexpected Cargo OUT_DIR layout: {}",
        out_dir.display()
    );
    cargo_build_dir
        .parent()
        .expect("Cargo build directory has no profile parent")
        .join("reverie-dbt-native-cache")
}

fn install_is_complete(install_dir: &Path) -> bool {
    install_dir.join("bin64/drrun").is_file()
        && install_dir.join("cmake/DynamoRIOConfig.cmake").is_file()
}

/// Atomically publish a complete install without overwriting another builder.
///
/// Two Cargo invocations can miss simultaneously. They may both do temporary
/// work, but directory rename ensures consumers observe either no cache entry
/// or one complete immutable install. The loser verifies and reuses the winner.
fn publish_install(staged_install: &Path, install_dir: &Path) -> bool {
    assert!(
        install_is_complete(staged_install),
        "refusing to publish incomplete DynamoRIO install {}",
        staged_install.display()
    );
    if install_is_complete(install_dir) {
        return false;
    }
    assert!(
        !install_dir.exists(),
        "refusing to replace incomplete DynamoRIO cache entry {}",
        install_dir.display()
    );

    match fs::rename(staged_install, install_dir) {
        Ok(()) => true,
        Err(error) if install_is_complete(install_dir) => {
            println!(
                "cargo:warning=another builder published the DynamoRIO cache entry first: {error}"
            );
            false
        }
        Err(error) => panic!(
            "failed to atomically publish DynamoRIO install {} -> {}: {error}",
            staged_install.display(),
            install_dir.display()
        ),
    }
}

struct StagingDirectory {
    path: PathBuf,
}

impl StagingDirectory {
    fn create(cache_root: &Path, source_key: &str) -> Self {
        fs::create_dir_all(cache_root).unwrap_or_else(|error| {
            panic!(
                "failed to create DynamoRIO cache root {}: {error}",
                cache_root.display()
            )
        });
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time predates the Unix epoch")
            .as_nanos();
        for attempt in 0..100 {
            let path = cache_root.join(format!(
                ".staging-{source_key}-{}-{nonce}-{attempt}",
                process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!(
                    "failed to create DynamoRIO staging directory {}: {error}",
                    path.display()
                ),
            }
        }
        panic!("failed to allocate a unique DynamoRIO staging directory")
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!(
                    "reverie-dbt: failed to remove staging directory {}: {error}",
                    self.path.display()
                );
            }
        }
    }
}

fn source_recipe_key(
    source_dir: &Path,
    build_script: &Path,
    cmake: &std::ffi::OsStr,
    generator: Option<&std::ffi::OsStr>,
) -> String {
    let mut hasher = Sha256::new();
    hash_tree(&mut hasher, source_dir, source_dir);
    hash_file(&mut hasher, b"build.rs", build_script);
    hash_value(&mut hasher, b"CMAKE", cmake.as_encoded_bytes());
    hash_value(
        &mut hasher,
        b"CMAKE_GENERATOR",
        generator.map_or(b"<unset>", std::ffi::OsStr::as_encoded_bytes),
    );
    format!("{:x}", hasher.finalize())
}

fn hash_value(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update(b"value\0");
    hasher.update(name.len().to_le_bytes());
    hasher.update(name);
    hasher.update(value.len().to_le_bytes());
    hasher.update(value);
}

fn hash_tree(hasher: &mut Sha256, root: &Path, directory: &Path) {
    let mut entries = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| {
                    panic!("failed to inspect {}: {error}", directory.display())
                })
                .path()
        })
        .collect::<Vec<_>>();
    entries.sort();

    for path in entries {
        let relative = path
            .strip_prefix(root)
            .expect("vendored path escaped its root");
        if path.is_dir() {
            hasher.update(b"directory\0");
            hash_name(hasher, relative);
            hash_tree(hasher, root, &path);
        } else {
            hash_file(hasher, relative.as_os_str().as_encoded_bytes(), &path);
        }
    }
}

fn hash_file(hasher: &mut Sha256, name: &[u8], path: &Path) {
    hasher.update(b"file\0");
    hasher.update(name.len().to_le_bytes());
    hasher.update(name);
    let contents =
        fs::read(path).unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    hasher.update(contents.len().to_le_bytes());
    hasher.update(contents);
}

fn hash_name(hasher: &mut Sha256, path: &Path) {
    let name = path.as_os_str().as_encoded_bytes();
    hasher.update(name.len().to_le_bytes());
    hasher.update(name);
}

fn build_dynamorio(
    source_dir: &Path,
    build_dir: &Path,
    install_dir: &Path,
    cmake: &std::ffi::OsStr,
    generator: Option<&std::ffi::OsStr>,
) {
    let started = Instant::now();
    let mut configure = Command::new(cmake);
    configure
        .arg("-S")
        .arg(source_dir)
        .arg("-B")
        .arg(build_dir)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg(format!("-DCMAKE_INSTALL_PREFIX={}", install_dir.display()))
        .args([
            "-DBUILD_TESTS=OFF",
            "-DBUILD_SAMPLES=OFF",
            "-DBUILD_DOCS=OFF",
            "-DBUILD_CLIENTS=OFF",
            "-DBUILD_EXT=ON",
            "-DBUILD_TOOLS=ON",
        ]);
    if let Some(generator) = generator {
        configure.arg("-G").arg(generator);
    }
    run(&mut configure, "configure DynamoRIO");

    let mut build = Command::new(cmake);
    build.arg("--build").arg(build_dir).args([
        "--config",
        "Release",
        "--target",
        "install",
        "--parallel",
    ]);
    let jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, MAX_PARALLEL_JOBS);
    build.arg(jobs.to_string());
    run(&mut build, "build and install DynamoRIO");

    let seconds = started.elapsed().as_secs_f64();
    println!("cargo:warning=DynamoRIO source build completed in {seconds:.2}s (jobs={jobs})");
    if let Ok(limit) = env::var("REVERIE_DBT_MAX_BUILD_SECONDS") {
        let limit = limit
            .parse::<f64>()
            .expect("REVERIE_DBT_MAX_BUILD_SECONDS must be a positive number");
        assert!(
            limit > 0.0,
            "REVERIE_DBT_MAX_BUILD_SECONDS must be positive"
        );
        assert!(
            seconds <= limit,
            "DynamoRIO source build took {seconds:.2}s, exceeding the {limit:.2}s CI ratchet"
        );
    } else if env::var_os("CI").is_some() {
        enforce_ci_build_ratchet(seconds, jobs);
    }
}

fn enforce_ci_build_ratchet(seconds: f64, jobs: usize) {
    let job_seconds = seconds * jobs as f64;
    assert!(
        job_seconds <= CI_MAX_BUILD_JOB_SECONDS,
        "DynamoRIO source build took {seconds:.2}s with {jobs} jobs ({job_seconds:.2} job-seconds), exceeding the {CI_MAX_BUILD_JOB_SECONDS:.2} job-second CI ratchet"
    );
}

fn run(command: &mut Command, description: &str) {
    eprintln!("reverie-dbt: {description}: {command:?}");
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {description}: {error}"));
    assert!(status.success(), "failed to {description}: {status}");
}

fn required_env(name: &str) -> OsString {
    env::var_os(name).unwrap_or_else(|| panic!("Cargo did not set {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_recipe_key_changes_with_source_or_recipe() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::write(source.join("nested/input.c"), "first\n").unwrap();
        let recipe = directory.path().join("build.rs");
        fs::write(&recipe, "recipe one\n").unwrap();
        let initial = source_recipe_key(&source, &recipe, "cmake".as_ref(), None);
        assert_eq!(
            initial,
            source_recipe_key(&source, &recipe, "cmake".as_ref(), None)
        );

        fs::write(source.join("nested/input.c"), "second\n").unwrap();
        let source_changed = source_recipe_key(&source, &recipe, "cmake".as_ref(), None);
        assert_ne!(initial, source_changed);

        fs::write(&recipe, "recipe two\n").unwrap();
        let recipe_changed = source_recipe_key(&source, &recipe, "cmake".as_ref(), None);
        assert_ne!(source_changed, recipe_changed);

        let cmake_changed = source_recipe_key(&source, &recipe, "custom-cmake".as_ref(), None);
        assert_ne!(recipe_changed, cmake_changed);

        let generator_changed = source_recipe_key(
            &source,
            &recipe,
            "custom-cmake".as_ref(),
            Some("Ninja".as_ref()),
        );
        assert_ne!(cmake_changed, generator_changed);
    }

    #[test]
    fn cargo_fingerprints_share_one_profile_cache() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory
            .path()
            .join("target/debug/build/reverie-dbt-first/out");
        let second = directory
            .path()
            .join("target/debug/build/reverie-dbt-second/out");
        assert_eq!(shared_cache_root(&first), shared_cache_root(&second));
        assert_eq!(
            shared_cache_root(&first),
            directory
                .path()
                .join("target/debug/reverie-dbt-native-cache")
        );
    }

    fn complete_fixture(path: &Path, marker: &str) {
        fs::create_dir_all(path.join("bin64")).unwrap();
        fs::create_dir_all(path.join("cmake")).unwrap();
        fs::write(path.join("bin64/drrun"), marker).unwrap();
        fs::write(path.join("cmake/DynamoRIOConfig.cmake"), marker).unwrap();
    }

    #[test]
    fn atomic_publish_never_overwrites_a_complete_winner() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        let published = directory.path().join("published");
        complete_fixture(&first, "first");
        complete_fixture(&second, "second");

        assert!(publish_install(&first, &published));
        assert!(!publish_install(&second, &published));
        assert_eq!(
            fs::read_to_string(published.join("bin64/drrun")).unwrap(),
            "first"
        );
        assert!(
            second.exists(),
            "losing builder still owns its staging tree"
        );
    }

    #[test]
    #[should_panic(expected = "refusing to replace incomplete DynamoRIO cache entry")]
    fn incomplete_cache_entry_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let staged = directory.path().join("staged");
        let incomplete = directory.path().join("incomplete");
        complete_fixture(&staged, "complete");
        fs::create_dir(&incomplete).unwrap();
        publish_install(&staged, &incomplete);
    }

    #[test]
    fn measured_clean_builds_satisfy_the_ci_ratchet() {
        for (seconds, jobs) in [(13.91, 16), (14.54, 16), (71.49, 4)] {
            enforce_ci_build_ratchet(seconds, jobs);
        }
    }

    #[test]
    #[should_panic(expected = "exceeding the 572.00 job-second CI ratchet")]
    fn throughput_regression_fails_the_ci_ratchet() {
        enforce_ci_build_ratchet(144.0, 4);
    }
}
