/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Guest checks for LiteInst example-tool integration tests.

fn main() {
    match std::env::args().nth(1).as_deref() {
        None => check_environment(),
        Some("check-fd-198") => check_inherited_descriptor(),
        Some("check-coordinator-environment") => check_coordinator_environment(),
        // TODO-HUMAN-REVIEW(PR-148): Review the allocator-reentry test guest mode.
        Some("exercise-allocator") => exercise_allocator(),
        // TODO-HUMAN-REVIEW(PR-157): Review the chaos short-read test guest mode.
        Some("exercise-chaos-read") => exercise_chaos_read(),
        // TODO-HUMAN-REVIEW(PR-157): Review the chaos interrupted-read test guest mode.
        Some("exercise-chaos-interrupt") => exercise_chaos_interrupt(),
        // TODO-HUMAN-REVIEW(PR-157): Review the chaos skip-suppression test guest mode.
        Some("exercise-chaos-full-read") => exercise_chaos_full_read(),
        // TODO-HUMAN-REVIEW(PR-152): Review the chunky_print ordering test guest mode.
        Some("chunky-alias-order") => exercise_chunky_alias_order(),
        Some(argument) => panic!("unknown argument {argument:?}"),
    }
}

fn check_environment() {
    let data = std::fs::read("/proc/self/environ").unwrap();
    let entries = data.split(|byte| *byte == 0).collect::<Vec<_>>();
    assert_eq!(
        entries.last(),
        Some(&&[][..]),
        "environment lacks final NUL"
    );
    assert!(
        entries[..entries.len() - 1]
            .iter()
            .all(|entry| !entry.is_empty()),
        "environment contains empty entries"
    );
    for control in [
        b"REVERIE_LITEINST_COORDINATOR=".as_slice(),
        b"REVERIE_LITEINST_EXAMPLE_TOOL=".as_slice(),
    ] {
        assert!(!data.windows(control.len()).any(|window| window == control));
    }
    println!("raw-environment-ok");
}

fn check_coordinator_environment() {
    assert_eq!(
        std::env::var("REVERIE_LITEINST_COORDINATOR").unwrap(),
        "guest-value"
    );
    println!("coordinator-environment-preserved");
}

fn check_inherited_descriptor() {
    assert_eq!(
        std::fs::read_link("/proc/self/fd/198").unwrap(),
        std::path::Path::new("/dev/null")
    );
    println!("fd-198-preserved");
}

// TODO-HUMAN-REVIEW(PR-148): Review deterministic guest allocator growth coverage.
fn exercise_allocator() {
    let mut blocks = Vec::with_capacity(256);
    for value in 0_u8..=255 {
        blocks.push(vec![value; 64 * 1024]);
    }
    let checksum = blocks
        .iter()
        .map(|block| usize::from(block[0]) + usize::from(block[block.len() - 1]))
        .sum::<usize>();
    assert_eq!(checksum, 2 * (0_usize..=255).sum::<usize>());

    let mut large = vec![0x5a_u8; 8 * 1024 * 1024];
    let last = large.len() - 1;
    large[last] = 0xa5;
    assert_eq!(large[0], 0x5a);
    assert_eq!(large[last], 0xa5);

    println!("allocator-growth-ok");
}

fn prepare_chaos_pipe() -> [libc::c_int; 2] {
    // Cross the intervention boundary after loader startup without spending
    // most of the integration-test timeout formatting deliberately skipped
    // syscalls.
    for _ in 0..32 {
        let pid = unsafe { libc::syscall(libc::SYS_getpid) };
        assert!(pid > 0);
    }

    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    let input = b"data";
    assert_eq!(
        unsafe { libc::write(pipe[1], input.as_ptr().cast(), input.len()) },
        input.len() as isize
    );
    pipe
}

// TODO-HUMAN-REVIEW(PR-157): Review the anti-noop chaos short-read coverage.
fn exercise_chaos_read() {
    let pipe = prepare_chaos_pipe();
    let mut output = [0_u8; 4];
    assert_eq!(
        unsafe { libc::read(pipe[0], output.as_mut_ptr().cast(), output.len()) },
        1
    );
    assert_eq!(output[0], b'd');
    assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
    assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
    println!("chaos-read-one");
}

// TODO-HUMAN-REVIEW(PR-157): Review the anti-noop chaos error-injection coverage.
fn exercise_chaos_interrupt() {
    let pipe = prepare_chaos_pipe();
    let mut output = [0_u8; 4];
    assert_eq!(
        unsafe { libc::read(pipe[0], output.as_mut_ptr().cast(), output.len()) },
        -1
    );
    assert_eq!(unsafe { *libc::__errno_location() }, libc::EINTR);
    assert_eq!(
        unsafe { libc::read(pipe[0], output.as_mut_ptr().cast(), output.len()) },
        1
    );
    assert_eq!(output[0], b'd');
    assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
    assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
    println!("chaos-interrupt-then-one");
}

// TODO-HUMAN-REVIEW(PR-157): Review the chaos pre-boundary suppression coverage.
fn exercise_chaos_full_read() {
    let pipe = prepare_chaos_pipe();
    let mut output = [0_u8; 4];
    assert_eq!(
        unsafe { libc::read(pipe[0], output.as_mut_ptr().cast(), output.len()) },
        4
    );
    assert_eq!(&output, b"data");
    assert_eq!(unsafe { libc::close(pipe[0]) }, 0);
    assert_eq!(unsafe { libc::close(pipe[1]) }, 0);
    println!("chaos-read-four");
}

// TODO-HUMAN-REVIEW(PR-152): Review deterministic chunky_print ordering coverage.
fn exercise_chunky_alias_order() {
    let alias = unsafe { libc::dup(libc::STDOUT_FILENO) };
    assert!(alias > libc::STDERR_FILENO);
    for index in 0_u8..16 {
        let tens = b'0' + index / 10;
        let ones = b'0' + index % 10;
        let buffered = [b'B', tens, ones, b';'];
        let pass_through = [b'P', tens, ones, b';'];
        let written = unsafe { libc::write(libc::STDOUT_FILENO, buffered.as_ptr().cast(), 4) };
        assert_eq!(written, 4);
        let written = unsafe { libc::write(alias, pass_through.as_ptr().cast(), 4) };
        assert_eq!(written, 4);
    }
    assert_eq!(unsafe { libc::close(alias) }, 0);
}
