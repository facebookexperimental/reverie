/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

#[test]
fn shared_coherence_and_mapping_lifetime_match_native() {
    const TEST: &str = "msync_lifecycle::shared_coherence_and_mapping_lifetime_match_native";
    // Keep the existing deadline and require libtest's exact completion record;
    // a successful zero-test child is not evidence that the fixture executed.
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "msync-lifecycle",
        include_str!("../fixtures/msync_lifecycle.c"),
    );
    let image = std::fs::read(&program).unwrap();
    let native = std::process::Command::new(&program)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(0), "{native:?}");
    assert!(native.stderr.is_empty(), "{native:?}");
    assert_eq!(
        native.stdout,
        b"msync lifecycle shared=ok replacement=ok private=ok syncs=14\n"
    );
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
                14,
                "ownership={ownership:?}: code={code} stdout={stdout:?} stderr={stderr:?}"
            );
            (code, stdout, stderr)
        } else {
            backend.run_static_elf_captured().unwrap()
        };
        assert_eq!(
            code, 0,
            "ownership={ownership:?}: stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(stderr.is_empty(), "ownership={ownership:?}: {stderr:?}");
        assert_eq!(stdout, native.stdout, "ownership={ownership:?}");
    }
}
