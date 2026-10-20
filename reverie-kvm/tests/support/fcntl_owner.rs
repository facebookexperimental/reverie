/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

use super::*;

fn captured_run(
    directory: &TestDirectory,
    program: &std::path::Path,
    image: &[u8],
    ownership: Option<ThreadOwnership>,
    expected_calls: &[(&str, usize)],
) -> (i32, Vec<u8>, Vec<u8>) {
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(image, &[program.to_str().unwrap()], &[], &directory.0)
        .unwrap();
    let result = if let Some(ownership) = ownership {
        backend.set_thread_ownership(ownership);
        let (trace, code, stdout, stderr) =
            futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
                .unwrap();
        let syscalls = trace.syscalls();
        for &(name, expected) in expected_calls {
            assert_eq!(
                syscalls.iter().filter(|call| call.as_str() == name).count(),
                expected,
                "actual {name} callbacks: ownership={ownership:?}"
            );
        }
        (code, stdout, stderr)
    } else {
        backend.run_static_elf_captured().unwrap()
    };
    eprintln!("fcntl owner ownership={ownership:?} code={}", result.0);
    result
}

fn six_check_contract(test: &str, negative: bool) {
    // This keeps the existing 30-second deadline and requires exactly one
    // successful named execution in libtest's separate completion record.
    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let extra_args: &[&str] = if negative {
        &["-D_GNU_SOURCE", "-DHERMIT_TEST_ORACLE_NEGATIVE"]
    } else {
        &["-D_GNU_SOURCE"]
    };
    let program = compile_c_program_with_args(
        &directory.0,
        "fcntl-owner",
        // Byte-identical consumer fixture, including all six checks and the
        // planted negative compiler control:
        // https://github.com/rrnewton/hermit/blob/7e10ccd069a9ada75edfa7d6050a2968ab137d9d/tests/c/fcntl_owner.c
        include_str!("../fixtures/fcntl_owner.c"),
        extra_args,
    );
    let image = std::fs::read(&program).unwrap();
    let expected_code = i32::from(negative);
    let checks = if negative { 5 } else { 6 };
    let expected_stdout = format!(
        "fowner ok={checks} getsig={} owner_type=1 getown_is_self=1 ex_pid_is_self=1\n",
        libc::SIGUSR1,
    );
    let native = std::process::Command::new(&program)
        .current_dir(&directory.0)
        .output()
        .unwrap();
    assert_eq!(native.status.code(), Some(expected_code), "{native:?}");
    assert!(native.stderr.is_empty(), "{native:?}");
    assert_eq!(native.stdout, expected_stdout.as_bytes());
    for ownership in [
        None,
        Some(ThreadOwnership::Host),
        Some(ThreadOwnership::Tool),
    ] {
        let (code, stdout, stderr) =
            captured_run(&directory, &program, &image, ownership, &[("fcntl", 6)]);
        assert_eq!(code, expected_code, "ownership={ownership:?}");
        assert!(stderr.is_empty(), "ownership={ownership:?}: {stderr:?}");
        assert_eq!(stdout, native.stdout, "ownership={ownership:?}");
    }
}

#[test]
fn unchanged_six_check_contract_matches_native() {
    six_check_contract(
        "fcntl_owner::unchanged_six_check_contract_matches_native",
        false,
    );
}

#[test]
fn unchanged_negative_control_preserves_failure() {
    six_check_contract(
        "fcntl_owner::unchanged_negative_control_preserves_failure",
        true,
    );
}

#[test]
fn fork_aliases_keep_configuration_and_permanent_guards() {
    const TEST: &str = "fcntl_owner::fork_aliases_keep_configuration_and_permanent_guards";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "fcntl-owner-boundary",
        include_str!("../fixtures/fcntl_owner_boundary.c"),
    );
    let image = std::fs::read(&program).unwrap();
    // The limited creator-process configuration domain deliberately refuses
    // these inherited operations. This is a capability-boundary assertion,
    // not native parity or a claim of asynchronous signal delivery.
    for ownership in [
        None,
        Some(ThreadOwnership::Host),
        Some(ThreadOwnership::Tool),
    ] {
        let (code, stdout, stderr) = captured_run(
            &directory,
            &program,
            &image,
            ownership,
            &[("fcntl", 137), ("sendmsg", 12), ("recvmsg", 12)],
        );
        assert_eq!(code, 0, "ownership={ownership:?}: {stderr:?}");
        assert!(stderr.is_empty(), "ownership={ownership:?}: {stderr:?}");
        assert_eq!(
            stdout,
            b"fowner boundary child_six=36 child_async=6 child_export=6 parent_exact=6 cleared_guards=6 pipe_io=1\n",
            "ownership={ownership:?}"
        );
    }
}
