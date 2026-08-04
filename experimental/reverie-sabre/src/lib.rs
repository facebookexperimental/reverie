/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! This library provides an ergonomic interface writing SaBRe plugins with
//! Rust.

mod callbacks;
pub mod ffi;
#[doc(hidden)]
pub mod internal;
mod paths;
mod protected_files;
mod reverie_adapter;
mod rpc;
mod signal;
mod slot_map;
pub mod stats;
mod thread;
mod tool;
mod utils;
pub mod vdso;

pub use nostd_print::*;
pub use paths::*;
pub use reverie_adapter::*;
pub use reverie_sabre_macros::tool;
pub use tool::*;

/// Returns the SaBRe loader built from the source vendored in this package.
pub fn bundled_sabre_path() -> &'static std::path::Path {
    std::path::Path::new(env!("REVERIE_SABRE_LOADER"))
}

/// Returns the pinned, build-required SaBRe source directory.
pub fn bundled_sabre_source_dir() -> &'static std::path::Path {
    std::path::Path::new(env!("REVERIE_SABRE_SOURCE"))
}

// Tracing programs that use jemalloc will hang if we allocate when jemalloc
// calls readlinkat. Using a different allocator works around this problem.
//
// NOTE: Even though we set the global allocator here, anything that depends on
// this library will use this global allocator. Thus, it will apply to all
// tools/plugins automatically.
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(test)]
mod bundled_source_tests {
    #[test]
    fn bundled_loader_and_revision_are_present() {
        assert!(super::bundled_sabre_path().is_file());
        assert_eq!(
            std::fs::read_to_string(super::bundled_sabre_source_dir().join("REVISION"))
                .unwrap()
                .trim(),
            "41113f849f8799932ed8c7883f5a4de616b9e9fa"
        );
    }

    /// Walk every regular file under a vendored source tree.
    fn vendored_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        fn walk(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("failed to walk the vendored source") {
                let entry = entry.expect("failed to read a vendored directory entry");
                let path = entry.path();
                let kind = entry.file_type().expect("failed to stat a vendored path");
                if kind.is_dir() {
                    walk(&path, found);
                } else if kind.is_file() {
                    found.push(path);
                }
            }
        }
        let mut found = Vec::new();
        walk(root, &mut found);
        assert!(
            found.len() > 50,
            "the vendored SaBRe walk found only {} files",
            found.len()
        );
        found
    }

    /// The vendored SaBRe and libelf trees are source, not payload.
    ///
    /// Detection is a NUL-byte scan over the real bytes rather than an
    /// extension list, so a renamed blob is still caught.
    #[test]
    fn the_vendored_source_contains_no_binary_files() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor");
        let mut offenders = Vec::new();
        for path in vendored_files(&root) {
            let bytes = std::fs::read(&path).expect("failed to read a vendored SaBRe file");
            if bytes.contains(&0) {
                let relative = path.strip_prefix(&root).unwrap_or(&path);
                offenders.push(format!("{} ({} bytes)", relative.display(), bytes.len()));
            }
        }
        assert!(
            offenders.is_empty(),
            "the vendored SaBRe source must not contain binary files: {}",
            offenders.join(", ")
        );
    }

    /// No vendored text file may exceed the 2 MiB coordinator-approval ceiling.
    #[test]
    fn the_vendored_source_has_no_oversized_text_files() {
        const LARGE_TEXT_LIMIT: u64 = 2 * 1024 * 1024;
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor");
        let mut offenders = Vec::new();
        for path in vendored_files(&root) {
            let size = path
                .metadata()
                .expect("failed to stat a vendored SaBRe file")
                .len();
            if size > LARGE_TEXT_LIMIT {
                let relative = path.strip_prefix(&root).unwrap_or(&path);
                offenders.push(format!("{} ({size} bytes)", relative.display()));
            }
        }
        assert!(
            offenders.is_empty(),
            "vendored text files over {LARGE_TEXT_LIMIT} bytes need coordinator approval: {}",
            offenders.join(", ")
        );
    }
}
