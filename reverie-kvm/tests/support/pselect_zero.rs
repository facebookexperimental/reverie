/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

fn pselect_zero_cases(test: &str, modes: &[u8]) {
    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "pselect-zero",
        include_str!("../fixtures/pselect_zero.c"),
    );
    let image = std::fs::read(&program).unwrap();
    for &mode in modes {
        let argument = mode.to_string();
        let native = std::process::Command::new(&program)
            .current_dir(&directory.0)
            .arg(&argument)
            .output()
            .unwrap();
        assert!(native.status.success(), "native mode={mode}: {native:?}");
        assert!(native.stderr.is_empty(), "native mode={mode}: {native:?}");
        assert_eq!(native.stdout.len(), 64 + 8192, "complete report and arena");
        assert_eq!(&native.stdout[12..16], &u32::from(mode).to_ne_bytes());
        let (result, error) = match mode {
            0 | 2 | 8 => (0_i64, 0_i32),
            1 | 3 | 4 | 7 | 9 | 10 => (1, 0),
            5 | 15 => (2, 0),
            6 => (3, 0),
            11..=14 => (-1, libc::EFAULT),
            16 => (-1, libc::EBADF),
            17 => (-1, libc::EINVAL),
            _ => panic!("unregistered pselect mode {mode}"),
        };
        assert_eq!(&native.stdout[..8], &result.to_ne_bytes());
        assert_eq!(&native.stdout[8..12], &error.to_ne_bytes());
        assert_eq!(&native.stdout[36..56], &[0; 20], "padding and zero timeout");
        for ownership in [
            None,
            Some(ThreadOwnership::Host),
            Some(ThreadOwnership::Tool),
        ] {
            let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
            backend
                .install_static_elf_with_context(
                    &image,
                    &[program.to_str().unwrap(), &argument],
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
                        .filter(|name| name.as_str() == "pselect6")
                        .count(),
                    1,
                    "one actual pselect6 callback: mode={mode} ownership={ownership:?}"
                );
                (code, stdout, stderr)
            } else {
                backend.run_static_elf_captured().unwrap()
            };
            eprintln!("pselect zero mode={mode} ownership={ownership:?} code={code}");
            assert_eq!(code, 0, "mode={mode} ownership={ownership:?}");
            assert!(
                stderr.is_empty(),
                "mode={mode} ownership={ownership:?}: {stderr:?}"
            );
            assert_eq!(
                stdout, native.stdout,
                "complete report and arena: mode={mode} ownership={ownership:?}"
            );
        }
    }
}

#[test]
fn readiness_matches_native_pipe_socket_and_path_states() {
    pselect_zero_cases(
        "pselect_zero::readiness_matches_native_pipe_socket_and_path_states",
        &[0, 1, 2, 3, 4, 5, 6],
    );
}

#[test]
fn raw_abi_and_readonly_zero_timeout_match_native() {
    pselect_zero_cases(
        "pselect_zero::raw_abi_and_readonly_zero_timeout_match_native",
        &[7, 8, 9, 10, 17],
    );
}

#[test]
fn copyout_faults_order_and_aliasing_match_native() {
    pselect_zero_cases(
        "pselect_zero::copyout_faults_order_and_aliasing_match_native",
        &[11, 12, 13, 14, 15, 16],
    );
}

#[test]
fn captured_outputs_and_dup_aliases_are_refused() {
    if !leader_self_exec_bounded("pselect_zero::captured_outputs_and_dup_aliases_are_refused") {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "pselect-captured-output",
        include_str!("../fixtures/pselect_captured_output.c"),
    );
    let image = std::fs::read(&program).unwrap();
    let mut outcomes = Vec::new();
    // This is an explicit unsupported-boundary test, not native parity: a
    // native process has ordinary host streams, not Reverie's capture vectors.
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
        let (code, stdout, stderr, callbacks) = if let Some(ownership) = ownership {
            backend.set_thread_ownership(ownership);
            let (trace, code, stdout, stderr) = futures::executor::block_on(
                backend.run_static_elf_with_tool::<StraceTool>((), true),
            )
            .unwrap();
            let count = trace
                .syscalls()
                .iter()
                .filter(|name| name.as_str() == "pselect6")
                .count();
            (code, stdout, stderr, Some(count))
        } else {
            let (code, stdout, stderr) = backend.run_static_elf_captured().unwrap();
            (code, stdout, stderr, None)
        };
        eprintln!(
            "captured pselect ownership={ownership:?} code={code} callbacks={callbacks:?} stderr={stderr:?}"
        );
        outcomes.push((ownership, code, stdout, stderr, callbacks));
    }
    // Retain all three old-production outcomes before reporting the first
    // failure, so direct and both Tool ownership routes are actually exercised.
    for (ownership, code, stdout, stderr, callbacks) in outcomes {
        assert_eq!(code, 0, "ownership={ownership:?}");
        assert_eq!(
            stdout, b"captured pselect refused 4\n",
            "ownership={ownership:?}"
        );
        assert!(stderr.is_empty(), "ownership={ownership:?}: {stderr:?}");
        if ownership.is_some() {
            assert_eq!(callbacks, Some(4), "ownership={ownership:?}");
        }
    }
}
