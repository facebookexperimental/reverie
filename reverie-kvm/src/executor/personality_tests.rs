// Run the same controls through the existing syscall and lifecycle APIs on
// both source variants. No control calls the supervisor's personality syscall.
const TEST_FIXED_PERSONALITY: u64 = 0x0004_0000;
const TEST_UNAME26_PERSONALITY: u64 = 0x0006_0000;
const TEST_PERSONALITY_QUERY: u64 = u32::MAX as u64;

fn test_personality_call(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    value: u64,
) -> i64 {
    syscall_result(memory, state, libc::SYS_personality, [value, 0, 0, 0, 0, 0])
}

fn test_personality_uname(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
) -> [u8; 65 * 6] {
    assert_eq!(
        syscall_result(memory, state, libc::SYS_uname, [0x100, 0, 0, 0, 0, 0]),
        0,
    );
    let mut bytes = [0; 65 * 6];
    memory.read(0x100, &mut bytes).unwrap();
    bytes
}

#[test]
fn personality_fixed_profile_round_trip_uses_low_word_and_refuses_unmodeled_flags() {
    const HIGH_WORD: u64 = 0xcafe_babe_0000_0000;
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    for query in [
        TEST_PERSONALITY_QUERY,
        u64::MAX,
        HIGH_WORD | TEST_PERSONALITY_QUERY,
    ] {
        assert_eq!(
            test_personality_call(&mut memory, &mut state, query),
            TEST_FIXED_PERSONALITY as i64,
        );
    }
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_UNAME26_PERSONALITY),
        TEST_FIXED_PERSONALITY as i64,
    );
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_PERSONALITY_QUERY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_UNAME26_PERSONALITY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(
        test_personality_call(&mut memory, &mut state, HIGH_WORD | TEST_FIXED_PERSONALITY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    // Explicit unsupported KVM profiles; these are not Linux-invalid flags.
    for request in [
        0,
        0x0002_0000,
        TEST_FIXED_PERSONALITY | 1,
        TEST_FIXED_PERSONALITY | 0x0040_0000,
        TEST_FIXED_PERSONALITY | 0x0020_0000,
        TEST_FIXED_PERSONALITY | 0x8000_0000,
    ] {
        assert_eq!(
            test_personality_call(&mut memory, &mut state, request),
            negative_errno(libc::ENOSYS),
        );
        assert_eq!(
            test_personality_call(&mut memory, &mut state, TEST_PERSONALITY_QUERY),
            TEST_FIXED_PERSONALITY as i64,
        );
    }
}

#[test]
fn personality_fixed_profile_uname26_changes_release_and_restores_it() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_PERSONALITY_QUERY),
        TEST_FIXED_PERSONALITY as i64,
    );
    let baseline = test_personality_uname(&mut memory, &mut state);
    let mut expected_release = [0; 65];
    expected_release[..5].copy_from_slice(b"6.0.0");
    assert_eq!(baseline[2 * 65..3 * 65], expected_release);
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_UNAME26_PERSONALITY),
        TEST_FIXED_PERSONALITY as i64,
    );
    let mut compatible = baseline;
    compatible[2 * 65..3 * 65].fill(0);
    compatible[2 * 65..2 * 65 + 6].copy_from_slice(b"2.6.60");
    assert_eq!(test_personality_uname(&mut memory, &mut state), compatible);
    for address in [u64::MAX, PAGE_SIZE - (65 * 6 - 1)] {
        assert_eq!(
            syscall_result(
                &mut memory,
                &mut state,
                libc::SYS_uname,
                [address, 0, 0, 0, 0, 0],
            ),
            negative_errno(libc::EFAULT),
        );
        assert_eq!(
            test_personality_call(&mut memory, &mut state, TEST_PERSONALITY_QUERY),
            TEST_UNAME26_PERSONALITY as i64,
        );
    }
    assert_eq!(test_personality_uname(&mut memory, &mut state), compatible);
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_FIXED_PERSONALITY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(test_personality_uname(&mut memory, &mut state), baseline);
}

#[test]
fn personality_fixed_profile_is_task_local_and_survives_fork_thread_exec() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_UNAME26_PERSONALITY),
        TEST_FIXED_PERSONALITY as i64,
    );
    let compatible = test_personality_uname(&mut memory, &mut state);
    let mut forked = state.try_clone_for_fork(2).unwrap();
    assert_eq!(
        test_personality_call(&mut memory, &mut forked, TEST_PERSONALITY_QUERY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_FIXED_PERSONALITY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(test_personality_uname(&mut memory, &mut forked), compatible);
    let mut replacement = test_state(&root.0);
    replacement.inherit_process_state(forked);
    assert_eq!(
        test_personality_call(&mut memory, &mut replacement, TEST_PERSONALITY_QUERY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(test_personality_uname(&mut memory, &mut replacement), compatible);
    assert_eq!(
        test_personality_call(&mut memory, &mut state, TEST_UNAME26_PERSONALITY),
        TEST_FIXED_PERSONALITY as i64,
    );
    let mut leader = ElfExecutor::new(state, false);
    let mut sibling = leader.thread_child(3).unwrap();
    assert_eq!(
        test_personality_call(&mut memory, &mut sibling.state, TEST_FIXED_PERSONALITY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(
        test_personality_call(&mut memory, &mut leader.state, TEST_PERSONALITY_QUERY),
        TEST_UNAME26_PERSONALITY as i64,
    );
    assert_eq!(test_personality_uname(&mut memory, &mut leader.state), compatible);
    let mut worker_fork = sibling.state.try_clone_for_fork(4).unwrap();
    assert_eq!(
        test_personality_call(&mut memory, &mut worker_fork, TEST_PERSONALITY_QUERY),
        TEST_FIXED_PERSONALITY as i64,
    );
    assert_ne!(test_personality_uname(&mut memory, &mut worker_fork), compatible);
    let mut worker_replacement = test_state(&root.0);
    worker_replacement.inherit_process_state(worker_fork);
    assert_eq!(
        test_personality_call(&mut memory, &mut worker_replacement, TEST_PERSONALITY_QUERY),
        TEST_FIXED_PERSONALITY as i64,
    );
}
