/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

const WAIT4_COPYOUT_BASE: u64 = 0x1_0000;

fn wait4_copyout_memory() -> GuestMemory {
    let memory = GuestMemory::new(WAIT4_COPYOUT_BASE, 3 * PAGE_SIZE as usize).unwrap();
    memory
        .map_user_permissions(WAIT4_COPYOUT_BASE, 3 * PAGE_SIZE, true, true)
        .unwrap();
    memory.enable_user_access();
    memory
        .write_raw(WAIT4_COPYOUT_BASE, &vec![0xa5; 3 * PAGE_SIZE as usize])
        .unwrap();
    memory
}

fn assert_wait4_copyout_effects(
    memory: &mut GuestMemory,
    args: [u64; 6],
    result: i64,
    expected: &[u8],
) {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    state.children.insert(7, ExitStatus::Exited(3));
    state.children.insert(8, ExitStatus::Exited(4));
    assert_eq!(wait4(memory, &mut state, &args), result, "{args:?}");
    let receipt = state
        .consumed_child_wait
        .take()
        .expect("consuming wait retained its receipt");
    assert_eq!(receipt.child_pid(), 7);
    state.children.acknowledge(receipt).unwrap();
    assert_eq!(state.children.len(), 1);
    assert_eq!(state.children.get(&8), Some(ExitStatus::Exited(4)));
    let mut actual = vec![0; expected.len()];
    memory.read_raw(WAIT4_COPYOUT_BASE, &mut actual).unwrap();
    assert_eq!(actual, expected, "first wait: {args:?}");
    // The scalar handler's consuming effect is delivered even on EFAULT.
    // Model its acknowledgement before the next exact-child wait.
    assert_eq!(
        wait4(memory, &mut state, &args),
        negative_errno(libc::ECHILD),
        "second wait: {args:?}"
    );
    assert!(state.consumed_child_wait.is_none());
    assert_eq!(state.children.len(), 1);
    assert_eq!(state.children.get(&8), Some(ExitStatus::Exited(4)));
    memory.read_raw(WAIT4_COPYOUT_BASE, &mut actual).unwrap();
    assert_eq!(actual, expected, "ECHILD changed output: {args:?}");
}

#[test]
fn wait4_read_only_outputs_fault_after_reaping_in_output_order() {
    let status = WAIT4_COPYOUT_BASE + 0x100;
    let usage = WAIT4_COPYOUT_BASE + PAGE_SIZE + 0x100;
    for status_fault in [true, false] {
        for options in [0, libc::WUNTRACED as u64] {
            let mut memory = wait4_copyout_memory();
            memory
                .map_user_permissions(
                    WAIT4_COPYOUT_BASE + if status_fault { 0 } else { PAGE_SIZE },
                    PAGE_SIZE,
                    true,
                    false,
                )
                .unwrap();
            let mut expected = vec![0xa5; 3 * PAGE_SIZE as usize];
            if !status_fault {
                expected[0x100..0x104].copy_from_slice(&(3_i32 << 8).to_ne_bytes());
            }
            assert_wait4_copyout_effects(
                &mut memory,
                [7, status, options, usage, 0, 0],
                negative_errno(libc::EFAULT),
                &expected,
            );
        }
    }
}

#[test]
fn wait4_split_status_copyout_is_nonpartial_and_leaves_rusage_untouched() {
    for accessible in [true, false] {
        for prefix in [1, 2, 3] {
            let mut memory = wait4_copyout_memory();
            memory
                .map_user_permissions(WAIT4_COPYOUT_BASE + PAGE_SIZE, PAGE_SIZE, accessible, false)
                .unwrap();
            let status = WAIT4_COPYOUT_BASE + PAGE_SIZE - prefix;
            let usage = WAIT4_COPYOUT_BASE + 2 * PAGE_SIZE + 0x100;
            assert_wait4_copyout_effects(
                &mut memory,
                [7, status, libc::WUNTRACED as u64, usage, 0, 0],
                negative_errno(libc::EFAULT),
                &vec![0xa5; 3 * PAGE_SIZE as usize],
            );
        }
    }
}

#[test]
fn wait4_split_rusage_copyout_keeps_status_and_the_writable_prefix() {
    // These splits distinguish a bulk copy from an all-or-nothing
    // permission probe without depending on native rusage counter values.
    for accessible in [true, false] {
        for prefix in [1, 8, 64] {
            let mut memory = wait4_copyout_memory();
            memory
                .map_user_permissions(
                    WAIT4_COPYOUT_BASE + 2 * PAGE_SIZE,
                    PAGE_SIZE,
                    accessible,
                    false,
                )
                .unwrap();
            let status = WAIT4_COPYOUT_BASE + 0x100;
            let usage = WAIT4_COPYOUT_BASE + 2 * PAGE_SIZE - prefix as u64;
            let mut expected = vec![0xa5; 3 * PAGE_SIZE as usize];
            expected[0x100..0x104].copy_from_slice(&(3_i32 << 8).to_ne_bytes());
            let start = (usage - WAIT4_COPYOUT_BASE) as usize;
            // The backend's pre-existing rusage accounting remains zero.
            expected[start..start + prefix].fill(0);
            assert_wait4_copyout_effects(
                &mut memory,
                [7, status, libc::WUNTRACED as u64, usage, 0, 0],
                negative_errno(libc::EFAULT),
                &expected,
            );
        }
    }
}

#[test]
fn wait4_writable_split_and_null_outputs_preserve_canaries() {
    let status = WAIT4_COPYOUT_BASE + PAGE_SIZE - 2;
    let usage = WAIT4_COPYOUT_BASE + 2 * PAGE_SIZE - 64;
    for write_status in [true, false] {
        for write_usage in [true, false] {
            let mut memory = wait4_copyout_memory();
            let mut expected = vec![0xa5; 3 * PAGE_SIZE as usize];
            if write_status {
                let start = (status - WAIT4_COPYOUT_BASE) as usize;
                expected[start..start + 4].copy_from_slice(&(3_i32 << 8).to_ne_bytes());
            }
            if write_usage {
                let start = (usage - WAIT4_COPYOUT_BASE) as usize;
                expected[start..start + std::mem::size_of::<libc::rusage>()].fill(0);
            }
            assert_wait4_copyout_effects(
                &mut memory,
                [
                    7,
                    if write_status { status } else { 0 },
                    libc::WUNTRACED as u64,
                    if write_usage { usage } else { 0 },
                    0,
                    0,
                ],
                7,
                &expected,
            );
        }
    }
}
