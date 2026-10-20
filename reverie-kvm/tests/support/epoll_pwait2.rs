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
    argument: &str,
    ownership: Option<ThreadOwnership>,
    calls: usize,
) -> Vec<u8> {
    let mut backend = KvmBackend::new(256 * 1024 * 1024).unwrap();
    backend
        .install_static_elf_with_context(
            image,
            &[program.to_str().unwrap(), argument],
            &[],
            &directory.0,
        )
        .unwrap();
    let (code, stdout, stderr) = if let Some(ownership) = ownership {
        backend.set_thread_ownership(ownership);
        let (trace, code, stdout, stderr) =
            futures::executor::block_on(backend.run_static_elf_with_tool::<StraceTool>((), true))
                .unwrap();
        assert_eq!(
            trace
                .syscalls()
                .iter()
                .filter(|name| name.as_str() == "epoll_pwait2")
                .count(),
            calls,
            "actual syscall-441 callbacks: argument={argument} ownership={ownership:?}"
        );
        (code, stdout, stderr)
    } else {
        backend.run_static_elf_captured().unwrap()
    };
    eprintln!("epoll_pwait2 argument={argument} ownership={ownership:?} code={code}");
    assert_eq!(code, 0, "argument={argument} ownership={ownership:?}");
    assert!(
        stderr.is_empty(),
        "argument={argument} ownership={ownership:?}: {stderr:?}"
    );
    stdout
}

fn native_invalid_fd_zero_count_errno() -> i32 {
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut errors = [0; 2];
    for (count, error) in errors.iter_mut().enumerate() {
        // SAFETY: -1 can never identify an epoll. The kernel cannot reach
        // output copyout; timeout is valid input and no mask is requested.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_epoll_pwait2,
                -1_i32,
                usize::MAX,
                count as i32,
                &zero,
                0usize,
                0usize,
            )
        };
        let native_errno = std::io::Error::last_os_error();
        assert_eq!(raw, -1, "native invalid-fd ABI setup must fail");
        *error = native_errno.raw_os_error().unwrap();
    }
    let expected_range = if errors[0] == libc::EINVAL {
        libc::EFAULT
    } else if errors[0] == libc::EBADF {
        libc::EBADF
    } else {
        panic!("unrecognized native epoll_pwait2 ABI: {errors:?}");
    };
    assert_eq!(errors[1], expected_range, "native range/fd ABI setup");
    eprintln!("native epoll_pwait2 ABI setup (two host-only calls): {errors:?}");
    errors[0]
}

fn parity_cases(test: &str, modes: &[u8]) {
    if !leader_self_exec_bounded(test) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "epoll-pwait2",
        include_str!("../fixtures/epoll_pwait2.c"),
    );
    let image = std::fs::read(&program).unwrap();
    let invalid_fd_errno = modes.contains(&14).then(native_invalid_fd_zero_count_errno);
    for &mode in modes {
        let argument = if mode == 14 {
            format!("14:{}", invalid_fd_errno.unwrap())
        } else {
            mode.to_string()
        };
        let native = std::process::Command::new(&program)
            .current_dir(&directory.0)
            .arg(&argument)
            .output()
            .unwrap();
        assert!(native.status.success(), "native mode={mode}: {native:?}");
        assert!(native.stderr.is_empty(), "native mode={mode}: {native:?}");
        assert_eq!(
            native.stdout.len(),
            64 + 8192 + 4096,
            "complete report, output arena and readonly timeout page"
        );
        let (result, error) = match mode {
            0 | 4 | 6 | 8 => (0_i64, 0_i32),
            1 | 2 | 3 | 11 => (1, 0),
            5 | 7 | 9 | 10 => (-1, libc::EFAULT),
            12 | 13 | 15 => (-1, libc::EINVAL),
            14 => (-1, invalid_fd_errno.unwrap()),
            _ => panic!("unregistered epoll_pwait2 mode {mode}"),
        };
        let retry = matches!(mode, 5 | 7 | 9 | 10 | 11);
        let calls = if retry { 3_u32 } else { 1_u32 };
        let retry_result = if retry { 1_i64 } else { 0_i64 };
        assert_eq!(&native.stdout[..8], &result.to_ne_bytes());
        assert_eq!(&native.stdout[8..12], &error.to_ne_bytes());
        assert_eq!(&native.stdout[12..16], &u32::from(mode).to_ne_bytes());
        assert_eq!(&native.stdout[36..40], &calls.to_ne_bytes());
        assert_eq!(
            &native.stdout[40..48],
            &retry_result.to_ne_bytes(),
            "faulted one-shot event remains queued"
        );
        assert_eq!(
            &native.stdout[48..56],
            &0_i64.to_ne_bytes(),
            "successful retry disables the one-shot registration"
        );
        assert_eq!(&native.stdout[64 + 8192..64 + 8192 + 16], &[0; 16]);
        assert_eq!(&native.stdout[64 + 8192 + 16..], &[0xa5; 4096 - 16]);
        // The C fixture independently checks every arena byte against its
        // explicit Linux outcome. Compare all bytes here; no sorting, masked
        // fields, tolerated errors or native/KVM "either" result is accepted.
        for ownership in [
            None,
            Some(ThreadOwnership::Host),
            Some(ThreadOwnership::Tool),
        ] {
            let stdout = captured_run(
                &directory,
                &program,
                &image,
                &argument,
                ownership,
                calls as usize,
            );
            assert_eq!(
                stdout, native.stdout,
                "complete report and arenas: mode={mode} ownership={ownership:?}"
            );
        }
    }
}

#[test]
fn seven_check_contract_matches_native() {
    const TEST: &str = "epoll_pwait2::seven_check_contract_matches_native";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "epoll-pwait2-contract",
        include_str!("../fixtures/epoll_pwait2.c"),
    );
    let image = std::fs::read(&program).unwrap();
    let native = std::process::Command::new(&program)
        .arg("contract")
        .output()
        .unwrap();
    assert!(native.status.success(), "{native:?}");
    assert!(native.stderr.is_empty(), "{native:?}");
    assert_eq!(native.stdout, b"epoll_pwait2 ok=7\n");
    for ownership in [
        None,
        Some(ThreadOwnership::Host),
        Some(ThreadOwnership::Tool),
    ] {
        assert_eq!(
            captured_run(&directory, &program, &image, "contract", ownership, 2),
            native.stdout,
            "ownership={ownership:?}"
        );
    }
}

#[test]
fn empty_and_ready_eventfd_match_native() {
    parity_cases(
        "epoll_pwait2::empty_and_ready_eventfd_match_native",
        &[0, 1],
    );
}

#[test]
fn raw_abi_and_readonly_timeout_match_native() {
    parity_cases(
        "epoll_pwait2::raw_abi_and_readonly_timeout_match_native",
        &[2, 3, 12, 13, 14, 15],
    );
}

#[test]
fn inaccessible_output_depends_on_readiness() {
    parity_cases(
        "epoll_pwait2::inaccessible_output_depends_on_readiness",
        &[4, 5, 6, 7, 8, 9],
    );
}

#[test]
fn scalar_faults_preserve_bytes_and_oneshot_events() {
    parity_cases(
        "epoll_pwait2::scalar_faults_preserve_bytes_and_oneshot_events",
        &[10, 11],
    );
}

#[test]
fn captured_output_and_dup_registrations_are_refused() {
    const TEST: &str = "epoll_pwait2::captured_output_and_dup_registrations_are_refused";
    if !leader_self_exec_bounded(TEST) {
        return;
    }
    let directory = TestDirectory::new();
    let program = compile_c_program(
        &directory.0,
        "epoll-pwait2-captured",
        include_str!("../fixtures/epoll_pwait2.c"),
    );
    let image = std::fs::read(&program).unwrap();
    // This is an explicit unsupported-boundary assertion, not native parity.
    // leader_self_exec_bounded gives this child a pipe at host stdout, and the
    // fixture insists that both captured targets really entered the epoll set.
    for ownership in [
        None,
        Some(ThreadOwnership::Host),
        Some(ThreadOwnership::Tool),
    ] {
        assert_eq!(
            captured_run(&directory, &program, &image, "captured", ownership, 3),
            b"captured epoll_pwait2 refused 2\n",
            "ownership={ownership:?}"
        );
    }
}
