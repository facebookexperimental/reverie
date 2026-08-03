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
}
