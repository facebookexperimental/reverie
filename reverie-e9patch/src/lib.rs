/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Reverie integration for the e9patch static binary rewriter.
//!
//! This crate validates e9patch preprocessing, replaces recovered syscall
//! instructions with event trampolines, and supplies a correctness-first
//! hybrid `reverie::Backend`. Ptrace remains the lifecycle and `Guest`
//! controller while events from rewritten root-ELF sites originate in e9patch.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod backend;
mod rewrite;

pub use backend::E9patchBackend;
pub use rewrite::E9PATCH_BACKEND_ENV;
pub use rewrite::E9TOOL_ENV;
pub use rewrite::E9patchRewriter;
pub use rewrite::PreparedBinary;
pub use rewrite::RewriteReport;

/// Magic RAX value identifying an e9patch replacement-syscall trap.
// TODO-HUMAN-REVIEW(PR-102): Review the public injected-event ABI marker.
pub const E9PATCH_SYSCALL_TRAP_MARKER: u64 = 0x7265_7665_3965_3970;

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
