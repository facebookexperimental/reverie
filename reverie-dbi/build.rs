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

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(#53): validate the pinned dr_invoke_syscall_as_app mmap fix.
const DYNAMORIO_REVISION: &str = "929840ad9190e5086775e8debc0f0b79b4208d59";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../third-party/dynamorio/CMakeLists.txt");
    println!("cargo:rerun-if-changed=../third-party/dynamorio/.git");
    println!("cargo:rerun-if-env-changed=CMAKE");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return;
    }

    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR"));
    let source_dir = manifest_dir.join("../third-party/dynamorio");
    require_initialized_submodule(&source_dir);
    verify_revision(&source_dir);

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

fn require_initialized_submodule(source_dir: &Path) {
    if source_dir.join("CMakeLists.txt").is_file() {
        return;
    }
    panic!(
        "DynamoRIO submodule is not initialized at {}. Run: git submodule update --init --recursive",
        source_dir.display()
    );
}

fn verify_revision(source_dir: &Path) {
    let output = Command::new("git")
        .arg("-C")
        .arg(source_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("failed to query the DynamoRIO submodule revision");
    if !output.status.success() {
        panic!(
            "failed to query the DynamoRIO submodule revision: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let actual = String::from_utf8(output.stdout)
        .expect("DynamoRIO revision is not UTF-8")
        .trim()
        .to_string();
    assert_eq!(
        actual, DYNAMORIO_REVISION,
        "DynamoRIO submodule is not at the tested revision"
    );
}

fn build_dynamorio(source_dir: &Path, build_dir: &Path, install_dir: &Path) {
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
            "-DBUILD_CLIENTS=ON",
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
    if let Some(jobs) = env::var_os("NUM_JOBS") {
        build.arg(jobs);
    }
    run(&mut build, "build and install DynamoRIO");
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
