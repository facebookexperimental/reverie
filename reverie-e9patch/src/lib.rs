/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reverie integration for the e9patch static binary rewriter.
//!
//! This crate currently establishes the package boundary and pinned-source
//! identity. It does not yet implement `reverie::Guest` or
//! `reverie::Backend`; see the crate README for the runtime capabilities
//! those contracts require.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

// TODO-HUMAN-REVIEW(PR-95): Review the public e9patch source identity API.
/// Git revision of the e9patch source pinned in `third-party/e9patch`.
pub const E9PATCH_SOURCE_REVISION: &str = "6c2c03c1da74b14daf1788a9f8dccfa354ce04a6";

#[cfg(test)]
mod tests {
    use super::E9PATCH_SOURCE_REVISION;

    #[test]
    fn pinned_revision_is_a_full_git_object_id() {
        assert_eq!(E9PATCH_SOURCE_REVISION.len(), 40);
        assert!(
            E9PATCH_SOURCE_REVISION
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }
}
