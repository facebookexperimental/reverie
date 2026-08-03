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
use std::process::Command;
use std::time::Instant;

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#53): validate the pinned dr_invoke_syscall_as_app mmap fix.
const DYNAMORIO_REVISION: &str = "929840ad9190e5086775e8debc0f0b79b4208d59";
const MAX_PARALLEL_JOBS: usize = 16;
// Provenance: three clean builds of this curated source tree on 2026-08-03:
// 13.91s and 14.54s with 16 jobs on devbig014, and 71.49s with 4 jobs on a
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
    println!("cargo:rerun-if-env-changed=REVERIE_DBI_MAX_BUILD_SECONDS");

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
    let build_dir = out_dir.join("dynamorio-build");
    let install_dir = out_dir.join("dynamorio-install");
    let revision_stamp = out_dir.join("dynamorio-revision");
    let drrun = install_dir.join("bin64/drrun");
    let cmake_config = install_dir.join("cmake/DynamoRIOConfig.cmake");

    let installed_revision = fs::read_to_string(&revision_stamp).unwrap_or_default();
    if installed_revision.trim() != DYNAMORIO_REVISION
        || !drrun.is_file()
        || !cmake_config.is_file()
    {
        build_dynamorio(&source_dir, &build_dir, &install_dir);
        fs::write(&revision_stamp, format!("{DYNAMORIO_REVISION}\n"))
            .expect("failed to write the DynamoRIO revision stamp");
    }

    println!(
        "cargo:rustc-env=REVERIE_DBI_DYNAMORIO_HOME={}",
        install_dir.display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBI_DYNAMORIO_CMAKE={}",
        install_dir.join("cmake").display()
    );
    println!(
        "cargo:rustc-env=REVERIE_DBI_DYNAMORIO_DRRUN={}",
        drrun.display()
    );
}

fn build_dynamorio(source_dir: &Path, build_dir: &Path, install_dir: &Path) {
    let started = Instant::now();
    let cmake = env::var_os("CMAKE").unwrap_or_else(|| OsString::from("cmake"));
    let mut configure = Command::new(&cmake);
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
    if let Some(generator) = env::var_os("CMAKE_GENERATOR") {
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
    if let Ok(limit) = env::var("REVERIE_DBI_MAX_BUILD_SECONDS") {
        let limit = limit
            .parse::<f64>()
            .expect("REVERIE_DBI_MAX_BUILD_SECONDS must be a positive number");
        assert!(
            limit > 0.0,
            "REVERIE_DBI_MAX_BUILD_SECONDS must be positive"
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
    eprintln!("reverie-dbi: {description}: {command:?}");
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
