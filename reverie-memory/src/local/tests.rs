use std::ffi::CString;
use std::io;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use super::Addr;
use super::AddrMut;
use super::Errno;
use super::LocalMemory;
use super::MemoryAccess;

struct Mapping {
    base: *mut u8,
    page: usize,
    owned: [bool; 3],
}

impl Mapping {
    fn new() -> Self {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        assert!(page.is_power_of_two());
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page * 3,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        let mapping = Self {
            base: base.cast(),
            page,
            owned: [true; 3],
        };
        for index in 0..page * 3 {
            unsafe { mapping.base.add(index).write((index % 251 + 1) as u8) };
        }
        mapping
    }

    fn protect_second(&self, protection: i32) {
        assert!(self.owned[1]);
        assert_eq!(
            unsafe { libc::mprotect(self.base.add(self.page).cast(), self.page, protection) },
            0
        );
    }

    fn unmap_second(&mut self) {
        assert!(self.owned[1]);
        assert_eq!(
            unsafe { libc::munmap(self.address(self.page) as *mut _, self.page) },
            0
        );
        self.owned[1] = false;
    }

    fn address(&self, offset: usize) -> usize {
        self.base as usize + offset
    }

    fn snapshot(&self) -> Vec<u8> {
        self.protect_second(libc::PROT_READ | libc::PROT_WRITE);
        unsafe { std::slice::from_raw_parts(self.base, self.page * 3).to_vec() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        for (index, owned) in self.owned.iter().enumerate() {
            if *owned {
                assert_eq!(
                    unsafe { libc::munmap(self.address(index * self.page) as *mut _, self.page) },
                    0
                );
            }
        }
    }
}

// An unmapped hole is no longer reserved. Run these cases in separate processes
// so another parallel test cannot put a mapping into a hole being probed. Each
// parent test waits for its exact discovered test to finish successfully; the
// rest of the suite retains libtest's ordinary parallel execution.
fn in_isolated_process(test_name: &str) -> bool {
    const CHILD_TEST: &str = "REVERIE_MEMORY_UNMAPPED_CHILD_TEST";
    if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
        return true;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(CHILD_TEST, test_name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut timed_out = false;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            timed_out = true;
            child.kill().unwrap();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !timed_out && output.status.success(),
        "{test_name}: timed_out={timed_out}, status={}\nstdout: {stdout}\nstderr: {stderr}",
        output.status
    );
    assert!(stdout.contains(&format!("test {test_name} ... ok")));
    assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    assert!(stderr.is_empty(), "{test_name}: {stderr}");
    false
}

fn iovec(address: usize, length: usize) -> libc::iovec {
    libc::iovec {
        iov_base: address as *mut libc::c_void,
        iov_len: length,
    }
}

fn native(write: bool, local: &[libc::iovec], remote: &[libc::iovec]) -> Result<usize, Errno> {
    let result = unsafe {
        if write {
            libc::process_vm_writev(
                libc::getpid(),
                local.as_ptr(),
                local.len() as _,
                remote.as_ptr(),
                remote.len() as _,
                0,
            )
        } else {
            libc::process_vm_readv(
                libc::getpid(),
                local.as_ptr(),
                local.len() as _,
                remote.as_ptr(),
                remote.len() as _,
                0,
            )
        }
    };
    Errno::result(result).map(|count| count as usize)
}

// IoSlice's documented Unix iovec ABI lets these tests construct remote
// descriptors without constructing Rust slices over invalid guest pointees.
// Only the descriptor arrays are borrowed; neither helper dereferences a
// remote buffer, and the methods under test must not do so either.
unsafe fn read_descriptors(vectors: &[libc::iovec]) -> &[io::IoSlice<'_>] {
    unsafe { std::slice::from_raw_parts(vectors.as_ptr().cast(), vectors.len()) }
}

unsafe fn write_descriptors(vectors: &mut [libc::iovec]) -> &mut [io::IoSliceMut<'_>] {
    unsafe { std::slice::from_raw_parts_mut(vectors.as_mut_ptr().cast(), vectors.len()) }
}

#[test]
fn scalar_transfers_match_native_counts_and_all_destination_bytes() {
    let page = Mapping::new().page;
    for write in [false, true] {
        for protection in [libc::PROT_NONE, libc::PROT_READ] {
            for offset in [0, page - 3, page] {
                for length in [1, 7, 8, 9, 16, page - 1, page, page + 1] {
                    let control = Mapping::new();
                    let candidate = Mapping::new();
                    control.protect_second(protection);
                    candidate.protect_second(protection);
                    let mut expected = vec![0xa7; length];
                    let mut observed = expected.clone();
                    let result = native(
                        write,
                        &[iovec(expected.as_mut_ptr() as usize, length)],
                        &[iovec(control.address(offset), length)],
                    );
                    let mut memory = LocalMemory::new();
                    let actual = if write {
                        memory.write(
                            AddrMut::from_raw(candidate.address(offset)).unwrap(),
                            &observed,
                        )
                    } else {
                        memory.read(
                            Addr::from_raw(candidate.address(offset)).unwrap(),
                            &mut observed,
                        )
                    };
                    assert_eq!(
                        actual, result,
                        "write={write} prot={protection} offset={offset} len={length}"
                    );
                    assert_eq!(observed, expected, "local destination or source changed");
                    assert_eq!(
                        candidate.snapshot(),
                        control.snapshot(),
                        "remote destination or source changed"
                    );
                }
            }
        }
    }
}

#[test]
fn exact_copies_report_fault_after_retaining_the_transferred_prefix() {
    let mapping = Mapping::new();
    let start = mapping.page - 3;
    let before = mapping.snapshot();
    mapping.protect_second(libc::PROT_NONE);
    let mut memory = LocalMemory::new();
    let mut observed = [0xa7; 9];
    assert_eq!(
        memory.read_exact(
            Addr::from_raw(mapping.address(start)).unwrap(),
            &mut observed
        ),
        Err(Errno::EFAULT)
    );
    assert_eq!(&observed[..3], &before[start..start + 3]);
    assert_eq!(&observed[3..], &[0xa7; 6]);
    assert_eq!(
        memory.write_exact(
            AddrMut::from_raw(mapping.address(start)).unwrap(),
            &[0xb8; 9]
        ),
        Err(Errno::EFAULT)
    );
    let mut expected = before;
    expected[start..start + 3].fill(0xb8);
    assert_eq!(mapping.snapshot(), expected);
}

#[test]
fn scalar_faults_and_zero_length_preserve_the_existing_error_contract() {
    if !in_isolated_process(
        "local::transfer_tests::scalar_faults_and_zero_length_preserve_the_existing_error_contract",
    ) {
        return;
    }
    let mut memory = LocalMemory::new();
    for address in [1, usize::MAX - 3, usize::MAX] {
        let mut buffer = [0x35; 8];
        assert_eq!(
            memory.read(Addr::from_raw(address).unwrap(), &mut buffer),
            Err(Errno::EFAULT)
        );
        assert_eq!(buffer, [0x35; 8]);
        assert_eq!(
            memory.write(AddrMut::from_raw(address).unwrap(), &buffer),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            memory.read(Addr::from_raw(address).unwrap(), &mut []),
            Ok(0)
        );
        assert_eq!(
            memory.write(AddrMut::from_raw(address).unwrap(), &[]),
            Ok(0)
        );
    }
    let mut mapping = Mapping::new();
    let address = mapping.address(mapping.page);
    mapping.unmap_second();
    assert_eq!(
        memory.write(AddrMut::from_raw(address).unwrap(), &[1; 16]),
        Err(Errno::EFAULT)
    );
}

#[test]
fn vectored_transfers_match_native_order_partial_counts_and_side_effects() {
    let page = Mapping::new().page;
    let cases = [
        vec![],
        vec![(0, 0), (0, 3), (3, 0), (3, 5), (8, 7), (15, 0)],
        vec![(0, 5), (page, 7), (page * 2, 4)],
        vec![(page - 3, 9)],
        vec![(page, 1), (0, 2)],
        vec![(0, 5), (2, 5)],
        vec![(0, 0), (page, 0)],
    ];
    for write in [false, true] {
        for offsets in &cases {
            let control = Mapping::new();
            let candidate = Mapping::new();
            control.protect_second(libc::PROT_NONE);
            candidate.protect_second(libc::PROT_NONE);
            let mut expected = (0..18).map(|index| 0xa0 + index).collect::<Vec<u8>>();
            let mut observed = expected.clone();
            let local_offsets = [(0, 0), (0, 4), (4, 0), (4, 11), (15, 3), (18, 0)];
            let local = local_offsets
                .map(|(offset, length)| iovec(expected.as_mut_ptr() as usize + offset, length));
            let remote = offsets
                .iter()
                .map(|&(offset, length)| iovec(control.address(offset), length))
                .collect::<Vec<_>>();
            let raw = native(write, &local, &remote);
            let expected_result = match raw {
                Err(Errno::EFAULT) => Ok(0),
                result => result,
            };
            let mut local = local_offsets
                .map(|(offset, length)| iovec(observed.as_mut_ptr() as usize + offset, length));
            let mut remote = offsets
                .iter()
                .map(|&(offset, length)| iovec(candidate.address(offset), length))
                .collect::<Vec<_>>();
            let mut memory = LocalMemory::new();
            let result = unsafe {
                if write {
                    memory.write_vectored(read_descriptors(&local), write_descriptors(&mut remote))
                } else {
                    memory.read_vectored(read_descriptors(&remote), write_descriptors(&mut local))
                }
            };
            assert_eq!(
                result, expected_result,
                "write={write} offsets={offsets:?} native={raw:?}"
            );
            assert_eq!(observed, expected);
            assert_eq!(candidate.snapshot(), control.snapshot());
        }
    }
}

#[test]
fn vectored_limits_and_invalid_addresses_keep_native_errors_distinct() {
    let mut memory = LocalMemory::new();
    for write in [false, true] {
        for mut remote in [
            vec![iovec(1, 1)],
            vec![iovec(usize::MAX - 3, 8)],
            vec![iovec(1, isize::MAX as usize + 1)],
            vec![iovec(1, 0); 1025],
        ] {
            let mut byte = [0x35];
            let mut local = [iovec(byte.as_mut_ptr() as usize, 1)];
            let raw = native(write, &local, &remote);
            let expected = match raw {
                Err(Errno::EFAULT) => Ok(0),
                result => result,
            };
            let result = unsafe {
                if write {
                    memory.write_vectored(read_descriptors(&local), write_descriptors(&mut remote))
                } else {
                    memory.read_vectored(read_descriptors(&remote), write_descriptors(&mut local))
                }
            };
            assert_eq!(
                result,
                expected,
                "write={write} vectors={} first_len={}",
                remote.len(),
                remote[0].iov_len
            );
            assert_eq!(byte, [0x35]);
        }
    }
}

#[test]
fn vectored_copies_stop_at_an_unmapped_middle_vector() {
    if !in_isolated_process(
        "local::transfer_tests::vectored_copies_stop_at_an_unmapped_middle_vector",
    ) {
        return;
    }
    for write in [false, true] {
        let mut control = Mapping::new();
        let mut candidate = Mapping::new();
        control.unmap_second();
        candidate.unmap_second();
        let mut expected = [0xa7; 16];
        let mut observed = expected;
        let remote = |mapping: &Mapping| {
            [
                iovec(mapping.address(mapping.page), 0),
                iovec(mapping.address(0), 3),
                iovec(mapping.address(mapping.page), 7),
                iovec(mapping.address(mapping.page * 2), 6),
            ]
        };
        let result = native(
            write,
            &[iovec(expected.as_mut_ptr() as usize, 16)],
            &remote(&control),
        );
        assert_eq!(result, Ok(3));
        let mut local = [iovec(observed.as_mut_ptr() as usize, 16)];
        let mut remote = remote(&candidate);
        let mut memory = LocalMemory::new();
        let actual = unsafe {
            if write {
                memory.write_vectored(read_descriptors(&local), write_descriptors(&mut remote))
            } else {
                memory.read_vectored(read_descriptors(&remote), write_descriptors(&mut local))
            }
        };
        assert_eq!(actual, result);
        assert_eq!(observed, expected);
        for offset in [0, control.page * 2] {
            assert_eq!(
                unsafe { std::slice::from_raw_parts(candidate.base.add(offset), candidate.page) },
                unsafe { std::slice::from_raw_parts(control.base.add(offset), control.page) }
            );
        }
    }
}

#[test]
fn cstrings_stop_at_nul_and_fault_only_when_more_bytes_are_required() {
    if !in_isolated_process(
        "local::transfer_tests::cstrings_stop_at_nul_and_fault_only_when_more_bytes_are_required",
    ) {
        return;
    }
    let memory = LocalMemory::new();
    let mut mapping = Mapping::new();
    mapping.protect_second(libc::PROT_NONE);
    let start = mapping.page - 17;
    unsafe { mapping.base.add(start).write_bytes(b'x', 17) };
    let address = Addr::from_raw(mapping.address(start)).unwrap();
    assert_eq!(memory.read_cstring(address), Err(Errno::EFAULT));
    assert_eq!(
        memory.read_cstring(Addr::from_raw(1).unwrap()),
        Err(Errno::EFAULT)
    );
    unsafe { mapping.base.add(mapping.page - 1).write(0) };
    let expected = CString::new(vec![b'x'; 16]).unwrap();
    assert_eq!(memory.read_cstring(address).unwrap(), expected);
    for size in [1, 7, 16, 17, 512, mapping.page + 1] {
        assert_eq!(
            memory
                .read_cstring_with_buf(address, &mut vec![0; size])
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        memory
            .read_cstring(Addr::from_raw(mapping.address(mapping.page - 1)).unwrap())
            .unwrap(),
        CString::new("").unwrap()
    );
    assert_eq!(
        memory.read_cstring_with_buf(address, &mut []),
        Err(Errno::EFAULT)
    );
    mapping.unmap_second();
    assert_eq!(memory.read_cstring(address).unwrap(), expected);
    unsafe { mapping.base.add(mapping.page - 1).write(b'x') };
    assert_eq!(memory.read_cstring(address), Err(Errno::EFAULT));
}

#[test]
fn mapping_drop_preserves_a_replacement_in_its_released_hole() {
    if !in_isolated_process(
        "local::transfer_tests::mapping_drop_preserves_a_replacement_in_its_released_hole",
    ) {
        return;
    }
    struct Replacement {
        base: *mut libc::c_void,
        length: usize,
    }
    impl Drop for Replacement {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::munmap(self.base, self.length) }, 0);
        }
    }

    let mut mapping = Mapping::new();
    let address = mapping.address(mapping.page);
    let mut observed = vec![0xa7u8; mapping.page];
    let expected = vec![0x6du8; mapping.page];
    mapping.unmap_second();
    let base = unsafe {
        libc::mmap(
            address as *mut _,
            mapping.page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_ne!(base, libc::MAP_FAILED);
    let replacement = Replacement {
        base,
        length: mapping.page,
    };
    assert_eq!(replacement.base as usize, address);
    unsafe {
        replacement
            .base
            .cast::<u8>()
            .write_bytes(0x6d, replacement.length)
    };
    drop(mapping);

    // A faulty whole-range unmap must produce a failed syscall assertion, not
    // a Rust read through a pointer whose allocation might have been removed.
    assert_eq!(
        native(
            false,
            &[iovec(observed.as_mut_ptr() as usize, observed.len())],
            &[iovec(address, replacement.length)],
        ),
        Ok(replacement.length)
    );
    assert_eq!(observed, expected);
}

#[test]
fn cstring_address_advancement_is_checked_after_examining_the_chunk() {
    struct LastByte(u8);
    impl MemoryAccess for LastByte {
        fn read_vectored(
            &self,
            _: &[io::IoSlice],
            _: &mut [io::IoSliceMut],
        ) -> Result<usize, Errno> {
            unreachable!()
        }
        fn write_vectored(
            &mut self,
            _: &[io::IoSlice],
            _: &mut [io::IoSliceMut],
        ) -> Result<usize, Errno> {
            unreachable!()
        }
        fn read<'a, A: Into<Addr<'a, u8>>>(
            &self,
            address: A,
            buffer: &mut [u8],
        ) -> Result<usize, Errno> {
            assert_eq!(address.into().as_raw(), usize::MAX);
            buffer[0] = self.0;
            Ok(1)
        }
    }
    let address = Addr::from_raw(usize::MAX).unwrap();
    assert_eq!(
        LastByte(b'x').read_cstring_with_buf(address, &mut [0]),
        Err(Errno::EFAULT)
    );
    assert_eq!(
        LastByte(0)
            .read_cstring_with_buf(address, &mut [0])
            .unwrap(),
        CString::new("").unwrap()
    );
}

#[test]
fn user_access_writes_match_native_counts_and_every_destination_byte() {
    let page = Mapping::new().page;
    for protection in [libc::PROT_NONE, libc::PROT_READ] {
        for offset in [0, page - 3, page] {
            for length in [0, 1, 7, 8, 9, page + 8] {
                let control = Mapping::new();
                let candidate = Mapping::new();
                control.protect_second(protection);
                candidate.protect_second(protection);
                let source: Vec<_> = (0..length + 1).map(|i| (19 + i * 37) as u8).collect();
                let source = &source[1..];
                let expected = native(
                    true,
                    &[iovec(source.as_ptr() as usize, source.len())],
                    &[iovec(control.address(offset), source.len())],
                );
                // Kernel-independent oracle for the control: only the bytes
                // before the protected second page can be copied.
                let accessible = if offset < page {
                    (page - offset).min(length)
                } else {
                    0
                };
                assert_eq!(
                    expected,
                    if accessible != 0 || length == 0 {
                        Ok(accessible)
                    } else {
                        Err(Errno::EFAULT)
                    },
                    "control prot={protection} offset={offset} len={length}"
                );
                let observed = LocalMemory::new().write_with_user_access(
                    AddrMut::from_raw(candidate.address(offset)).unwrap(),
                    source,
                );
                assert_eq!(
                    observed, expected,
                    "prot={protection} offset={offset} len={length}"
                );
                // Kernel-independent image: the accessible prefix holds the
                // source, every other byte keeps Mapping::new's fill.
                let image: Vec<u8> = (0..page * 3)
                    .map(|index| {
                        if index >= offset && index - offset < accessible {
                            source[index - offset]
                        } else {
                            (index % 251 + 1) as u8
                        }
                    })
                    .collect();
                assert_eq!(
                    candidate.snapshot(),
                    image,
                    "prot={protection} offset={offset} len={length}"
                );
                assert_eq!(control.snapshot(), image);
            }
        }
    }
}
#[test]
fn user_access_empty_invalid_and_wrapping_addresses_are_bounded() {
    for address in [1, usize::MAX - 3, usize::MAX, 0x0100_0000_0000_0000] {
        let address = AddrMut::from_raw(address).unwrap();
        let mut memory = LocalMemory::new();
        assert_eq!(memory.write_with_user_access(address, &[]), Ok(0));
        for size in [1, 7, 8, 9] {
            assert_eq!(
                memory.write_with_user_access(address, &[0x73; 9][..size]),
                Err(Errno::EFAULT)
            );
        }
    }
}

#[test]
fn exact_copies_round_trip_and_invalid_writes_leave_memory_unchanged() {
    let mut memory = LocalMemory::new();
    let source = *b"sabre";
    let mut copy = [0; 5];
    memory
        .read_exact(Addr::from_ptr(source.as_ptr()).unwrap(), &mut copy)
        .unwrap();
    assert_eq!(copy, source);
    let mut destination = [0; 5];
    memory
        .write_exact(
            AddrMut::from_ptr(destination.as_mut_ptr()).unwrap(),
            b"guest",
        )
        .unwrap();
    assert_eq!(&destination, b"guest");

    // An invalid destination must not reach any mapping, through any write.
    let canary = Mapping::new();
    let before = canary.snapshot();
    for address in [1, usize::MAX - 3, usize::MAX] {
        let address = AddrMut::from_raw(address).unwrap();
        for source in [&b"x"[..], &b"rejected"[..]] {
            assert_eq!(memory.write_exact(address, source), Err(Errno::EFAULT));
            assert_eq!(
                memory.write_with_user_access(address, source),
                Err(Errno::EFAULT)
            );
            assert_eq!(canary.snapshot(), before);
        }
    }
}

/// Installs, on the calling thread only, a seccomp filter under which the
/// kernel fails every `process_vm_writev` with `errno`, so a test can observe
/// a genuine non-fault kernel error through an unmodified `LocalMemory`.
#[cfg(target_arch = "x86_64")]
fn fail_process_vm_writev_with(errno: libc::c_int) {
    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const ARCH_OFFSET: u32 = 4;
    const NR_OFFSET: u32 = 0;
    let statement = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let ret = libc::BPF_RET | libc::BPF_K;
    let mut filter = [
        statement(load, ARCH_OFFSET),
        jump(AUDIT_ARCH_X86_64, 0, 3),
        statement(load, NR_OFFSET),
        jump(libc::SYS_process_vm_writev as u32, 0, 1),
        statement(ret, libc::SECCOMP_RET_ERRNO | errno as u32),
        statement(ret, libc::SECCOMP_RET_ALLOW),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            )
        },
        0
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn user_access_writes_preserve_a_non_fault_errno() {
    // The filter cannot be removed, so it is installed in an isolated child.
    if !in_isolated_process("local::transfer_tests::user_access_writes_preserve_a_non_fault_errno")
    {
        return;
    }
    fail_process_vm_writev_with(libc::ESRCH);
    let mut memory = LocalMemory::new();
    let mut destination = [0xa5u8; 8];
    let address = AddrMut::from_ptr(destination.as_mut_ptr()).unwrap();
    assert_eq!(
        memory.write_with_user_access(address, b"rejected"),
        Err(Errno::ESRCH)
    );
    assert_eq!(destination, [0xa5; 8]);
    assert_eq!(
        memory.write_with_user_access(AddrMut::from_raw(usize::MAX).unwrap(), &[]),
        Ok(0)
    );
}

#[path = "executor_tests.rs"]
mod executor_tests;
