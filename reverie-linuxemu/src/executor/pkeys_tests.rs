// Protection keys on a CPU without them (`executor/pkeys.rs`): each errno and
// the order of the checks that give it, as Linux's mm/mprotect.c and
// arch/x86/include/asm/pkeys.h give them when OSPKE is clear.

/// `PKEY_DISABLE_WRITE` (include/uapi/asm-generic/mman-common.h).
const TEST_PKEY_DISABLE_WRITE: u64 = 0x2;

fn pkey_test_call(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    number: libc::c_long,
    args: [u64; 6],
) -> i64 {
    syscall_result(memory, state, number, args)
}

fn pkey_test_alloc(
    memory: &mut GuestMemory,
    state: &mut LoadedStaticElf,
    flags: u64,
    init_val: u64,
) -> i64 {
    pkey_test_call(
        memory,
        state,
        libc::SYS_pkey_alloc,
        [flags, init_val, 0, 0, 0, 0],
    )
}

/// A process with two read-write pages mapped, and the address of the first.
fn pkey_test_mapping(root: &TestDir) -> (GuestMemory, LoadedStaticElf, u64) {
    let mut state = test_state(&root.0);
    let memory_size = BOOT_RESERVED_END + 8 * PAGE_SIZE;
    let mut memory = GuestMemory::new(0, memory_size as usize).unwrap();
    state.mmap_next = BOOT_RESERVED_END + PAGE_SIZE;
    state.mmap_limit = memory_size;
    let mapping = pkey_test_call(
        &mut memory,
        &mut state,
        libc::SYS_mmap,
        [
            0,
            2 * PAGE_SIZE,
            (libc::PROT_READ | libc::PROT_WRITE) as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
            -1_i32 as u64,
            0,
        ],
    ) as u64;
    memory.enable_user_access();
    (memory, state, mapping)
}

/// pkey_alloc refuses a flag or an `init_val` bit outside `PKEY_ACCESS_MASK`,
/// in all 64 bits of either, before it takes a key (EINVAL). The first call
/// that passes those checks takes key 0, whose PKRU setup fails (EINVAL) and
/// which stays taken, so every later call finds every key taken (ENOSPC);
/// the argument checks still come first.
#[test]
fn pkey_alloc_checks_its_arguments_then_takes_key_zero_once() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let einval = negative_errno(libc::EINVAL);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 1, 0), einval);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 0, 4), einval);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 1 << 32, 0), einval);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 0, 1 << 32), einval);
    assert!(!state.pkey_zero_claimed.load(Ordering::SeqCst));
    assert_eq!(
        pkey_test_alloc(&mut memory, &mut state, 0, TEST_PKEY_DISABLE_WRITE),
        einval
    );
    assert!(state.pkey_zero_claimed.load(Ordering::SeqCst));
    let enospc = negative_errno(libc::ENOSPC);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 0, 0), enospc);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 0, 3), enospc);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 1, 0), einval);
    assert_eq!(pkey_test_alloc(&mut memory, &mut state, 0, 8), einval);
}

/// No key is ever allocated, so pkey_free refuses every key (EINVAL), key 0
/// included, before and after an allocation was tried.
#[test]
fn pkey_free_refuses_every_key() {
    let root = TestDir::new();
    let mut state = test_state(&root.0);
    let mut memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    let keys = [0, 1, 15, 16, u32::MAX as u64, u64::MAX];
    for attempt in 0..2 {
        for key in keys {
            assert_eq!(
                pkey_test_call(
                    &mut memory,
                    &mut state,
                    libc::SYS_pkey_free,
                    [key, 0, 0, 0, 0, 0]
                ),
                negative_errno(libc::EINVAL),
                "attempt {attempt}, key {key:#x}"
            );
        }
        pkey_test_alloc(&mut memory, &mut state, 0, 0);
    }
}

/// pkey_mprotect with key -1 is mprotect: it protects the pages, PROT_SEM
/// included, which changes nothing on x86-64. The key is an `int`, so only
/// the register's low 32 bits name it.
#[test]
fn pkey_mprotect_with_key_minus_one_is_mprotect() {
    let root = TestDir::new();
    let (mut memory, mut state, mapping) = pkey_test_mapping(&root);
    let boundary = AddrMut::from_raw((mapping + PAGE_SIZE - 8) as usize).unwrap();
    let protect = |memory: &mut GuestMemory, state: &mut LoadedStaticElf, number, prot, key| {
        pkey_test_call(
            memory,
            state,
            number,
            [mapping + PAGE_SIZE, PAGE_SIZE, prot, key, 0, 0],
        )
    };
    let none = libc::PROT_NONE as u64;
    let read_write = (libc::PROT_READ | libc::PROT_WRITE) as u64 | PROT_SEM;
    for key in [u64::MAX, u32::MAX as u64, 0xdead_beef_ffff_ffff] {
        assert_eq!(
            protect(&mut memory, &mut state, libc::SYS_pkey_mprotect, none, key),
            0,
            "{key:#x}"
        );
        assert_eq!(
            MemoryAccess::write(&mut memory, boundary, &[0x5a; 16]).unwrap(),
            8,
            "{key:#x}"
        );
        assert_eq!(
            protect(
                &mut memory,
                &mut state,
                libc::SYS_pkey_mprotect,
                read_write,
                key
            ),
            0,
            "{key:#x}"
        );
        assert_eq!(
            MemoryAccess::write(&mut memory, boundary, &[0x33; 16]).unwrap(),
            16,
            "{key:#x}"
        );
    }
}

/// mprotect, and pkey_mprotect with key -1, give Linux's answers in
/// do_mprotect_pkey's order: both grows flags, or a start that is not
/// page-aligned (EINVAL); a zero length (0); a range that wraps (ENOMEM);
/// the protection bits, of which PROT_SEM is valid (EINVAL); and only then
/// the mappings: one grows flag where no mapping grows (EINVAL where the
/// range reaches a mapping, ENOMEM where it does not), or a page that is
/// not mapped (ENOMEM). Each expected answer is what Linux 6.19.2 gave on a
/// vCPU without protection keys for the same call on the same layout: an
/// unmapped page, a read-write page, then unmapped pages.
#[test]
fn mprotect_and_key_minus_one_check_in_linux_order() {
    let root = TestDir::new();
    let (mut memory, mut state, mapping) = pkey_test_mapping(&root);
    // The probe's layout: `hole_below`, then the read-write page `mapped`,
    // then the unmapped `hole_above`.
    assert_eq!(
        pkey_test_call(
            &mut memory,
            &mut state,
            libc::SYS_munmap,
            [mapping, PAGE_SIZE, 0, 0, 0, 0]
        ),
        0
    );
    let (hole_below, mapped, hole_above) = (mapping, mapping + PAGE_SIZE, mapping + 2 * PAGE_SIZE);
    let rw = (libc::PROT_READ | libc::PROT_WRITE) as u64;
    let read = libc::PROT_READ as u64;
    let (sem, down, up) = (
        PROT_SEM,
        libc::PROT_GROWSDOWN as u64,
        libc::PROT_GROWSUP as u64,
    );
    let (einval, enomem) = (negative_errno(libc::EINVAL), negative_errno(libc::ENOMEM));
    let wrap = mapped.wrapping_neg();
    let cases = [
        // Both grows flags, before alignment and length.
        ([mapped + 1, 0, rw | down | up], einval),
        // Alignment, before the length.
        ([mapped + 1, 0, 0x10], einval),
        ([mapped + 1, PAGE_SIZE, rw], einval),
        // A zero length, before the range, the protection bits and the
        // mappings.
        ([mapped, 0, 0x10], 0),
        ([hole_above, 0, rw | down], 0),
        // A range that wraps, before the protection bits.
        ([mapped, wrap, 0x10], enomem),
        ([mapped, wrap, rw], enomem),
        ([mapped, u64::MAX, 0x10], enomem),
        // The protection bits, before the mappings; PROT_SEM is valid.
        ([mapped, PAGE_SIZE, 0x10], einval),
        ([hole_above, PAGE_SIZE, 0x10 | down], einval),
        ([mapped, PAGE_SIZE, rw | sem], 0),
        // One grows flag: no mapping grows.
        ([mapped, PAGE_SIZE, rw | down], einval),
        ([mapped, PAGE_SIZE, read | up], einval),
        ([hole_above, PAGE_SIZE, rw | down], enomem),
        ([hole_above, PAGE_SIZE, read | up], enomem),
        ([hole_below, 2 * PAGE_SIZE, rw | down], einval),
        ([hole_below, 2 * PAGE_SIZE, read | up], enomem),
        // A page that is not mapped.
        ([hole_above, PAGE_SIZE, rw], enomem),
        ([mapped, 2 * PAGE_SIZE, rw], enomem),
    ];
    for ([start, length, prot], result) in cases {
        assert_eq!(
            pkey_test_call(
                &mut memory,
                &mut state,
                libc::SYS_mprotect,
                [start, length, prot, 0, 0, 0]
            ),
            result,
            "mprotect({start:#x}, {length:#x}, {prot:#x})"
        );
        for key in [u64::MAX, u32::MAX as u64] {
            assert_eq!(
                pkey_test_call(
                    &mut memory,
                    &mut state,
                    libc::SYS_pkey_mprotect,
                    [start, length, prot, key, 0, 0]
                ),
                result,
                "pkey_mprotect({start:#x}, {length:#x}, {prot:#x}, {key:#x})"
            );
        }
    }
    // Nothing changed the read-write page.
    let start = AddrMut::from_raw(mapped as usize).unwrap();
    assert_eq!(
        MemoryAccess::write(&mut memory, start, &[0x44; 16]).unwrap(),
        16
    );
}

/// pkey_mprotect with any other key fails with EINVAL once the checks
/// before the key's pass, and changes nothing: both grows flags or a start
/// that is not page-aligned (EINVAL) come first, then a zero length (0),
/// then a range that wraps (ENOMEM), then `prot` and the key (EINVAL).
#[test]
fn pkey_mprotect_with_another_key_fails_after_the_checks_before_it() {
    let root = TestDir::new();
    let (mut memory, mut state, mapping) = pkey_test_mapping(&root);
    let read_write = (libc::PROT_READ | libc::PROT_WRITE) as u64;
    let grows = (libc::PROT_GROWSDOWN | libc::PROT_GROWSUP) as u64;
    let einval = negative_errno(libc::EINVAL);
    let enomem = negative_errno(libc::ENOMEM);
    for (args, result) in [
        // Both grows flags: refused even at an aligned start with a zero
        // length, which would otherwise succeed.
        ([mapping, 0, read_write | grows, 5, 0, 0], einval),
        ([mapping + 1, 0, read_write | grows, 5, 0, 0], einval),
        // Alignment, before the length.
        ([mapping + 1, 0, read_write, 5, 0, 0], einval),
        // A zero length, before the range, prot and the key.
        ([mapping, 0, read_write, 5, 0, 0], 0),
        ([mapping, 0, 0x10, 5, 0, 0], 0),
        ([mapping, 0, libc::PROT_GROWSDOWN as u64, 0, 0, 0], 0),
        // A range that wraps, before prot and the key.
        ([mapping, u64::MAX - mapping + 1, 0x10, 5, 0, 0], enomem),
        ([mapping, u64::MAX, read_write, 5, 0, 0], enomem),
        // The length is rounded up to a page before the range is checked:
        // one byte in the last page wraps.
        (
            [0u64.wrapping_sub(PAGE_SIZE), 1, read_write, 5, 0, 0],
            enomem,
        ),
        // prot, or the key, which nothing allocated.
        ([mapping, PAGE_SIZE, 0x10, 5, 0, 0], einval),
        ([mapping, PAGE_SIZE, read_write, 5, 0, 0], einval),
        ([mapping, PAGE_SIZE, read_write, 0, 0, 0], einval),
        (
            [mapping, PAGE_SIZE, libc::PROT_NONE as u64, 15, 0, 0],
            einval,
        ),
        (
            [mapping, PAGE_SIZE, read_write, u32::MAX as u64 - 1, 0, 0],
            einval,
        ),
        ([mapping, PAGE_SIZE, read_write | 0x8, 1, 0, 0], einval),
    ] {
        assert_eq!(
            pkey_test_call(&mut memory, &mut state, libc::SYS_pkey_mprotect, args),
            result,
            "{args:x?}"
        );
    }
    // After an allocation was tried too, and the pages kept their protection.
    pkey_test_alloc(&mut memory, &mut state, 0, 0);
    assert_eq!(
        pkey_test_call(
            &mut memory,
            &mut state,
            libc::SYS_pkey_mprotect,
            [mapping, 2 * PAGE_SIZE, libc::PROT_NONE as u64, 0, 0, 0]
        ),
        einval
    );
    let start = AddrMut::from_raw(mapping as usize).unwrap();
    assert_eq!(
        MemoryAccess::write(&mut memory, start, &[0x77; 16]).unwrap(),
        16
    );
}

/// These answers are a CPU's without protection keys. The KVM backend's
/// vCPU is one only while XCR0, which it sets to `FIXED_XFEATURES`, holds no
/// PKRU state (XFEATURE 9) and CR4.PKE stays clear (asserted in reverie-kvm's
/// vm/initial_fpu_state_tests.rs). Were either to change, Linux would
/// allocate keys 1 to 15, and these answers would be wrong.
#[test]
fn the_vcpu_these_answers_model_has_no_pkru_state() {
    assert_eq!(crate::signal::FIXED_XFEATURES & (1 << 9), 0);
}

/// The taken key belongs to the address space: a thread and a vfork child
/// share it, a forked child takes an independent copy, and exec starts
/// without it, as Linux's `pkey_allocation_map` does.
#[test]
fn the_taken_key_follows_the_address_space() {
    let mut f = FdinfoFixture::new(false);
    let alloc = |executor: &mut ElfExecutor, memory: &GuestMemory| {
        executor.execute(
            &SyscallRequest::new(libc::SYS_pkey_alloc as u64, [0; 6]),
            memory,
        )
    };
    let pid = f.executor.state.pid;
    // A forked child copies the state before the take.
    let mut child = f.executor.state.try_clone_for_fork(pid + 1).unwrap();
    assert_eq!(
        alloc(&mut f.executor, &f.memory),
        negative_errno(libc::EINVAL)
    );
    assert!(!child.pkey_zero_claimed.load(Ordering::SeqCst));
    let mut child_memory = GuestMemory::new(0, PAGE_SIZE as usize).unwrap();
    assert_eq!(
        pkey_test_alloc(&mut child_memory, &mut child, 0, 0),
        negative_errno(libc::EINVAL)
    );
    // A thread shares the parent's, taken already.
    let mut thread = f.executor.thread_child(pid + 10).unwrap();
    assert!(Arc::ptr_eq(
        &f.executor.state.pkey_zero_claimed,
        &thread.state.pkey_zero_claimed
    ));
    assert_eq!(alloc(&mut thread, &f.memory), negative_errno(libc::ENOSPC));
    // A vfork child shares the address space, and with it the key.
    let vfork_child = f.executor.fork_child(pid + 2, false, true).unwrap();
    assert!(Arc::ptr_eq(
        &f.executor.state.pkey_zero_claimed,
        &vfork_child.state.pkey_zero_claimed
    ));
    // A forked child after the take copies it taken.
    let forked = f.executor.fork_child(pid + 3, false, false).unwrap();
    assert!(forked.state.pkey_zero_claimed.load(Ordering::SeqCst));
    assert!(!Arc::ptr_eq(
        &f.executor.state.pkey_zero_claimed,
        &forked.state.pkey_zero_claimed
    ));
    // Exec: the new image inherits process state, but not the key.
    let copy = f.executor.state.try_clone_for_fork(pid + 4).unwrap();
    let root = TestDir::new();
    let mut image = test_state(&root.0);
    image.inherit_process_state(copy);
    assert!(!image.pkey_zero_claimed.load(Ordering::SeqCst));
}
