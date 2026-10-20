/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

#[test]
fn unchanged_five_check_contract_matches_native() {
    const TEST: &str = "msync::unchanged_five_check_contract_matches_native";
    // The bounded exact-test helper demands `ok <TEST>` in libtest's separate
    // completion record. A successful zero-test child cannot qualify this.
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "msync-writeback",
        // Byte-for-byte fixture, including all five assertions and its exit
        // predicate, from the consumer. It checks file visibility through
        // pread, not persistence across a crash:
        // https://github.com/rrnewton/hermit/blob/e02d9f8368a335df8afb0ec3bf6b30f02846cf5c/tests/c/msync_writeback.c
        include_str!("../fixtures/msync_writeback.c"),
    );
    let image = std::fs::read(&program).unwrap();
    let native = std::process::Command::new(&program)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(0), "{native:?}");
    assert!(native.stderr.is_empty(), "{native:?}");
    assert_eq!(native.stdout, b"msync ok=5\n");
    for ownership in [
        None,
        Some(ThreadOwnership::Host),
        Some(ThreadOwnership::Tool),
    ] {
        let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
        backend
            .install_static_elf_with_context(
                &image,
                &[program.to_str().unwrap()],
                &[],
                &directory.0,
            )
            .unwrap();
        let (code, stdout, stderr) = if let Some(ownership) = ownership {
            backend.set_thread_ownership(ownership);
            let (trace, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            assert_eq!(
                trace
                    .syscalls()
                    .iter()
                    .filter(|name| name.as_str() == "msync")
                    .count(),
                3,
                "ownership={ownership:?}"
            );
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(code, 0, "ownership={ownership:?}");
        assert!(stderr.is_empty(), "ownership={ownership:?}: {stderr:?}");
        assert_eq!(stdout, native.stdout, "ownership={ownership:?}");
    }
}
