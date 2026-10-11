/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Allocator controls, not a claim about real installed runtime stack placement.
//!
//! Each test re-executes only itself before reserving any address or applying a
//! seccomp filter. The shared libtest process never acquires a region. Raw fork
//! descendants perform only bounded memory/syscall controls and raw exit; they
//! never unwind, allocate through libc, or call the test harness.

#[path = "tool_region_constructor_tests.rs"]
mod constructor;

// Native hardware oracle preparation only. The baseline deliberately fails
// its new denial assertions on key-zero owners; no existing test is weakened.
#[path = "tool_region_keyed_oracle.rs"]
mod keyed_oracle;

#[path = "tool_region_keyed_tests.rs"]
mod keyed_owner;

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;
use std::time::Instant;

use super::*;

const CHILD_ENV: &str = "REVERIE_TOOL_REGION_CONTROL_CHILD";
const OUTPUT_LIMIT: usize = 64 * 1024;
const PROCESS_TIMEOUT: Duration = Duration::from_secs(30);
const FORK_TIMEOUT: Duration = Duration::from_secs(3);

struct Captured {
    bytes: Vec<u8>,
    exceeded: bool,
}

fn capture(mut input: impl Read) -> io::Result<Captured> {
    let mut result = Captured {
        bytes: Vec::new(),
        exceeded: false,
    };
    let mut buffer = [0_u8; 4096];
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => return Ok(result),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        let retained = count.min(OUTPUT_LIMIT - result.bytes.len());
        result.bytes.extend_from_slice(&buffer[..retained]);
        result.exceeded |= retained != count;
        // Keep draining after the limit so the child cannot block on a pipe.
        // Exceeding the limit is a failure, not silently truncated success.
    }
}

fn isolated(name: &str, body: fn()) {
    if std::env::var(CHILD_ENV).as_deref() == Ok(name) {
        body();
        println!("\nTOOL_REGION_CONTROL_OK:{name}");
        return;
    }
    let module = module_path!()
        .split_once("::")
        .expect("tests must be a child module")
        .1;
    let exact = format!("{module}::{name}");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &exact,
            "--include-ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let stdout_reader = std::thread::spawn(move || capture(stdout));
    let stderr_reader = std::thread::spawn(move || capture(stderr));
    let group = -(child.id() as i32);
    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let mut timed_out = false;
    let mut reap_deadline = deadline;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if !timed_out && Instant::now() >= deadline {
            timed_out = true;
            // SAFETY: this dedicated group belongs to the unreaped child and
            // includes its raw-fork descendants. Do not wait without a bound.
            let killed = unsafe { libc::kill(group, libc::SIGKILL) };
            let error = io::Error::last_os_error().raw_os_error();
            assert!(
                killed == 0 || error == Some(libc::ESRCH),
                "failed to kill timed-out process group: {error:?}"
            );
            reap_deadline = Instant::now() + FORK_TIMEOUT;
        }
        assert!(
            !timed_out || Instant::now() < reap_deadline,
            "timed-out leader was not reaped"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    // try_wait has reaped the leader. A normal completed control has no group
    // left. If a raw descendant survived (including after a panic), kill it
    // before touching reader joins and fail this control even after cleanup.
    // SAFETY: descendants of this dedicated test process retain this group.
    let cleanup = unsafe { libc::kill(group, libc::SIGKILL) };
    let cleanup_error = io::Error::last_os_error().raw_os_error();
    let leftovers = cleanup == 0;
    let clean_group = cleanup == -1 && cleanup_error == Some(libc::ESRCH);
    let reader_deadline = Instant::now() + FORK_TIMEOUT;
    while !stdout_reader.is_finished() || !stderr_reader.is_finished() {
        assert!(
            Instant::now() < reader_deadline,
            "stdout/stderr did not close after process-group cleanup"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let stdout = stdout_reader.join().unwrap().unwrap();
    let stderr = stderr_reader.join().unwrap().unwrap();
    let out = String::from_utf8_lossy(&stdout.bytes);
    let err = String::from_utf8_lossy(&stderr.bytes);
    assert!(
        clean_group && !leftovers,
        "{exact}: leftover descendants or cleanup error {cleanup_error:?}; \
         actual leader {status}\n{out}\n{err}"
    );
    assert!(!timed_out, "{exact}: timed out\n{out}\n{err}");
    assert!(
        !stdout.exceeded && !stderr.exceeded,
        "{exact}: exceeded the output limit"
    );
    assert!(status.success(), "{exact}: {status}\n{out}\n{err}");
    let marker = format!("TOOL_REGION_CONTROL_OK:{name}");
    assert_eq!(
        out.lines().filter(|line| *line == marker).count(),
        1,
        "the exact child test must actually execute: {out}"
    );
}

fn raw(number: i64, args: [u64; 6]) -> i64 {
    // SAFETY: each caller supplies live buffers and its own mapping ranges.
    unsafe { raw_syscall6(number, args) }
}

fn map(address: usize, bytes: usize, protection: i32, extra_flags: i32) -> usize {
    let result = raw(
        libc::SYS_mmap,
        [
            address as u64,
            bytes as u64,
            protection as u64,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | extra_flags) as u64,
            u64::MAX,
            0,
        ],
    );
    assert!(result > 0, "raw mmap failed: {result}");
    result as usize
}

fn protection(address: usize, bytes: usize, protection: i32) -> i64 {
    raw(
        libc::SYS_mprotect,
        [address as u64, bytes as u64, protection as u64, 0, 0, 0],
    )
}

fn permissions_at(address: usize) -> String {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (start, end) = fields.next().unwrap().split_once('-').unwrap();
        let start = usize::from_str_radix(start, 16).unwrap();
        let end = usize::from_str_radix(end, 16).unwrap();
        if start <= address && address < end {
            return fields.next().unwrap().to_owned();
        }
    }
    panic!("no mapping contains {address:#x}");
}

fn mapping_overlaps(maps: &mut std::fs::File, start: usize, end: usize) -> bool {
    // The descriptor was opened before cleanup. Avoid a heap allocation here:
    // one could otherwise create a new, unrelated mapping in the freed gap.
    let mut buffer = [0_u8; OUTPUT_LIMIT];
    let mut used = 0;
    loop {
        assert!(used < buffer.len(), "maps exceeded the bounded buffer");
        let count = maps.read(&mut buffer[used..]).unwrap();
        if count == 0 {
            break;
        }
        used += count;
    }
    std::str::from_utf8(&buffer[..used])
        .unwrap()
        .lines()
        .any(|line| {
            let range = line.split_whitespace().next().unwrap();
            let (low, high) = range.split_once('-').unwrap();
            let low = usize::from_str_radix(low, 16).unwrap();
            let high = usize::from_str_radix(high, 16).unwrap();
            low < end && start < high
        })
}

fn resident_query(address: usize) -> i64 {
    let mut resident = 0_u8;
    raw(
        libc::SYS_mincore,
        [
            address as u64,
            PAGE as u64,
            &mut resident as *mut u8 as u64,
            0,
            0,
            0,
        ],
    )
}

fn owns(region: &ToolRegion, start: usize, pages: usize) -> bool {
    let mut guard = region.lock().unwrap();
    let bitmap = guard.bitmap();
    (start..start + pages).all(|page| bitmap[page / 64] & (1_u64 << (page % 64)) != 0)
}

fn raw_exit(code: i32) -> ! {
    raw(libc::SYS_exit_group, [code as u64, 0, 0, 0, 0, 0]);
    // SAFETY: exit_group must not return; fail closed if it does.
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

#[repr(C)]
struct KernelAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: u64,
}

fn prepare_fault_child() {
    let action = KernelAction {
        handler: libc::SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let mask = 0_u64;
    let core_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if raw(
        libc::SYS_rt_sigaction,
        [
            libc::SIGSEGV as u64,
            &action as *const KernelAction as u64,
            0,
            8,
            0,
            0,
        ],
    ) != 0
        || raw(
            libc::SYS_rt_sigprocmask,
            [
                libc::SIG_SETMASK as u64,
                &mask as *const u64 as u64,
                0,
                8,
                0,
                0,
            ],
        ) != 0
        || raw(
            libc::SYS_prctl,
            [libc::PR_SET_DUMPABLE as u64, 0, 0, 0, 0, 0],
        ) != 0
        || raw(
            libc::SYS_setrlimit,
            [
                libc::RLIMIT_CORE as u64,
                &core_limit as *const libc::rlimit as u64,
                0,
                0,
                0,
                0,
            ],
        ) != 0
    {
        raw_exit(90);
    }
}

fn wait_raw(pid: i64) -> i32 {
    let deadline = Instant::now() + FORK_TIMEOUT;
    let mut killed = false;
    let mut kill_deadline = deadline;
    loop {
        let mut status = 0_i32;
        let result = raw(
            libc::SYS_wait4,
            [
                pid as u64,
                &mut status as *mut i32 as u64,
                libc::WNOHANG as u64,
                0,
                0,
                0,
            ],
        );
        if result == pid {
            assert!(!killed, "raw fork child {pid} exceeded its deadline");
            return status;
        }
        assert!(
            result == 0 || result == -i64::from(libc::EINTR),
            "raw wait4({pid}) failed: {result}"
        );
        if !killed && Instant::now() >= deadline {
            assert_eq!(
                raw(
                    libc::SYS_kill,
                    [pid as u64, libc::SIGKILL as u64, 0, 0, 0, 0]
                ),
                0
            );
            killed = true;
            kill_deadline = Instant::now() + FORK_TIMEOUT;
        }
        assert!(
            !killed || Instant::now() < kill_deadline,
            "killed child was not reaped"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn faults(address: usize, write: bool) {
    let pid = raw(libc::SYS_fork, [0; 6]);
    assert!(pid >= 0, "raw fork failed: {pid}");
    if pid == 0 {
        prepare_fault_child();
        // Use assembly rather than an invalid Rust reference/dereference.
        // SAFETY: only this disposable child intentionally accesses the page.
        unsafe {
            if write {
                core::arch::asm!(
                    "mov byte ptr [{address}], 0x5a",
                    address = in(reg) address,
                    options(nostack, preserves_flags),
                );
            } else {
                core::arch::asm!(
                    "mov al, byte ptr [{address}]",
                    address = in(reg) address,
                    out("al") _,
                    options(nostack, readonly, preserves_flags),
                );
            }
        }
        raw_exit(0);
    }
    let status = wait_raw(pid);
    assert!(
        libc::WIFSIGNALED(status),
        "page {address:#x}: status {status:#x}"
    );
    assert_eq!(libc::WTERMSIG(status), libc::SIGSEGV, "page {address:#x}");
}

fn guard(address: usize) {
    faults(address, false);
    faults(address, true);
}

fn zero_interior(lease: &StackLease) {
    // SAFETY: the live lease owns this entire readable/writable interior.
    let bytes =
        unsafe { core::slice::from_raw_parts(lease.base() as *const u8, lease.usable_bytes()) };
    assert!(
        bytes.iter().all(|&byte| byte == 0),
        "reused interior retained data"
    );
}

fn dirty_interior(lease: &StackLease) {
    // SAFETY: the live lease owns this entire writable interior.
    unsafe { core::ptr::write_bytes(lease.base() as *mut u8, 0xa7, lease.usable_bytes()) };
}

fn deny_madvise() {
    let mut instructions = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_madvise as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: instructions.len() as u16,
        filter: instructions.as_mut_ptr(),
    };
    assert_eq!(
        raw(
            libc::SYS_prctl,
            [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0]
        ),
        0
    );
    // No TSYNC: only this isolated test thread gains the error filter. It
    // denies precisely madvise, leaving its other setup/wait/exit calls alone.
    assert_eq!(
        raw(
            libc::SYS_seccomp,
            [
                libc::SECCOMP_SET_MODE_FILTER as u64,
                0,
                &program as *const libc::sock_fprog as u64,
                0,
                0,
                0
            ],
        ),
        0
    );
}

fn altstack() -> libc::stack_t {
    // SAFETY: all-zero stack_t fields are valid output storage for the kernel.
    let mut stack = unsafe { core::mem::zeroed::<libc::stack_t>() };
    assert_eq!(
        raw(
            libc::SYS_sigaltstack,
            [0, &mut stack as *mut libc::stack_t as u64, 0, 0, 0, 0]
        ),
        0
    );
    stack
}

#[test]
fn literal_reservation_control_and_boundary_guards() {
    isolated("literal_reservation_control_and_boundary_guards", || {
        assert_eq!(BASE, 0x6000_0000_0000);
        assert_eq!(BYTES, 4_usize * 1024 * 1024 * 1024);
        assert_eq!(END, 0x6001_0000_0000);
        assert_eq!(PAGE, 4096);
        let region = ToolRegion::reserve().unwrap();
        assert!(core::ptr::eq(region, ToolRegion::reserve().unwrap()));
        assert_eq!(region.control as usize, BASE + PAGE);
        assert_eq!(permissions_at(BASE + PAGE), "rw-p");
        assert_eq!(permissions_at(BASE), "---p");
        assert_eq!(permissions_at(END - PAGE), "---p");
        assert_eq!(region.claim(1).unwrap(), DATA_FIRST);
        assert!(owns(region, DATA_FIRST, 1));
        // Setting allocation bits does not make the data backing writable.
        guard(BASE);
        guard(BASE + DATA_FIRST * PAGE);
        guard(END - PAGE);
    });
}

#[test]
fn collision_preserves_sentinel_contents_and_permissions() {
    isolated(
        "collision_preserves_sentinel_contents_and_permissions",
        || {
            let occupant = map(
                BASE,
                2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED_NOREPLACE,
            );
            assert_eq!(occupant, BASE);
            // SAFETY: these two pages belong to this isolated child.
            unsafe {
                core::ptr::write_volatile(occupant as *mut u8, 0x35);
                core::ptr::write_volatile((occupant + PAGE) as *mut u8, 0xe2);
            }
            assert_eq!(protection(occupant, 2 * PAGE, libc::PROT_READ), 0);
            let before = permissions_at(occupant);
            assert_eq!(before, "r--p");
            assert_eq!(ToolRegion::reserve_inner().unwrap_err(), libc::EEXIST);
            assert_eq!(permissions_at(occupant), before);
            assert_eq!(permissions_at(occupant + PAGE), "r--p");
            // SAFETY: refusal must have retained the two readable pages.
            unsafe {
                assert_eq!(core::ptr::read_volatile(occupant as *const u8), 0x35);
                assert_eq!(
                    core::ptr::read_volatile((occupant + PAGE) as *const u8),
                    0xe2
                );
            }
            faults(occupant, true);
            faults(occupant + PAGE, true);
        },
    );
}

#[test]
fn wrong_returned_mapping_is_released_without_touching_occupant() {
    isolated(
        "wrong_returned_mapping_is_released_without_touching_occupant",
        || {
            let occupant = map(
                BASE,
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED_NOREPLACE,
            );
            assert_eq!(occupant, BASE);
            // SAFETY: this page belongs to this isolated child.
            unsafe { core::ptr::write_volatile(occupant as *mut u8, 0x6b) };
            assert_eq!(protection(occupant, PAGE, libc::PROT_READ), 0);
            let actual = map(0, BYTES, libc::PROT_NONE, 0);
            let actual_end = actual.checked_add(BYTES).unwrap();
            assert!(
                actual_end <= BASE || END <= actual,
                "returned mapping must be separate"
            );
            assert_eq!(resident_query(actual), 0);
            assert_eq!(resident_query(actual_end - PAGE), 0);
            let mut maps = std::fs::File::open("/proc/self/maps").unwrap();
            assert_eq!(validate_reservation(actual), Err(libc::EOPNOTSUPP));
            assert_eq!(resident_query(actual), -i64::from(libc::ENOMEM));
            assert_eq!(resident_query(actual_end - PAGE), -i64::from(libc::ENOMEM));
            assert!(
                !mapping_overlaps(&mut maps, actual, actual_end),
                "cleanup must remove the entire returned mapping"
            );
            assert_eq!(permissions_at(occupant), "r--p");
            // SAFETY: requested occupant must still exist and retain its contents.
            assert_eq!(
                unsafe { core::ptr::read_volatile(occupant as *const u8) },
                0x6b
            );
            faults(occupant, true);
        },
    );
}

#[test]
fn rounding_invalid_sizes_and_real_bitmap_exhaustion() {
    isolated("rounding_invalid_sizes_and_real_bitmap_exhaustion", || {
        let region = ToolRegion::reserve().unwrap();
        let one = region.stack(1).unwrap();
        let two = region.stack(PAGE + 1).unwrap();
        assert_eq!(one.usable_bytes(), PAGE);
        assert_eq!(two.usable_bytes(), 2 * PAGE);
        assert_eq!(one.base() % PAGE, 0);
        assert_eq!(one.top(), one.base() + PAGE);
        assert_eq!(two.top(), two.base() + 2 * PAGE);
        assert_eq!(
            region.stack(0).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            region.stack(usize::MAX).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(
            region.stack(BYTES).unwrap_err().raw_os_error(),
            Some(libc::ENOMEM)
        );
        assert_eq!(
            region.claim(0).unwrap_err().raw_os_error(),
            Some(libc::ENOMEM)
        );
        drop(one);
        drop(two);
        // Exhaust the same complete real bitmap, now partitioned by the two
        // permanent arena/guard bands. No searchable capacity is hidden.
        let bands = [(65535, 73729), (81919, 90113)];
        assert_eq!(bands, [arena::TOOL_BAND, arena::PATCH_BAND]);
        let searchable = DATA_END - DATA_FIRST;
        assert_eq!(searchable, 1048319);
        {
            let mut held = region.lock().unwrap();
            let bitmap = held.bitmap();
            for page in DATA_FIRST..DATA_END {
                let permanent = bands
                    .iter()
                    .any(|&(start, end)| start <= page && page < end);
                assert_eq!(
                    bitmap[page / 64] & (1_u64 << (page % 64)) != 0,
                    permanent,
                    "unexpected initial ownership bit {page}"
                );
            }
        }
        let free = [(256, 65535), (73729, 81919), (90113, 1048575)];
        let lengths = [65279, 8190, 958462];
        let available: usize = lengths.iter().sum();
        let permanent: usize = bands.iter().map(|&(start, end)| end - start).sum();
        assert_eq!(available, 1031931);
        assert_eq!(permanent, 8194 + 8194);
        assert_eq!(available + permanent, searchable);
        assert_eq!(
            region.claim(searchable + 1).unwrap_err().raw_os_error(),
            Some(libc::ENOMEM)
        );
        assert_eq!(
            region.claim(available).unwrap_err().raw_os_error(),
            Some(libc::ENOMEM),
            "total free capacity is not one contiguous extent"
        );
        for (index, ((start, end), length)) in free.into_iter().zip(lengths).enumerate() {
            assert_eq!(end - start, length);
            assert_eq!(region.claim(length).unwrap(), start);
            assert!(owns(region, start, length));
            let mut held = region.lock().unwrap();
            let bitmap = held.bitmap();
            for page in DATA_FIRST..DATA_END {
                let expected = bands.iter().any(|&(low, high)| low <= page && page < high)
                    || free[..=index]
                        .iter()
                        .any(|&(low, high)| low <= page && page < high);
                assert_eq!(
                    bitmap[page / 64] & (1_u64 << (page % 64)) != 0,
                    expected,
                    "unexpected ownership after band {index}: bit {page}"
                );
            }
        }
        assert!(owns(region, DATA_FIRST, searchable));
        assert_eq!(
            region.claim(1).unwrap_err().raw_os_error(),
            Some(libc::ENOMEM)
        );
        assert_eq!(
            region.stack(1).unwrap_err().raw_os_error(),
            Some(libc::ENOMEM)
        );
        // This exercises the full real bitmap, not a synthetic small capacity.
        // No four-GiB mprotect or write occurs: a formerly virgin page faults.
        guard(BASE + (DATA_FIRST + 64) * PAGE);
        for bottom in [arena::TOOL_BOTTOM, arena::PATCH_BOTTOM] {
            assert_eq!(permissions_at(bottom), "rw-p");
            assert_eq!(permissions_at(bottom + arena::ARENA_BYTES - 1), "rw-p");
            for address in [bottom - PAGE, bottom + arena::ARENA_BYTES] {
                assert_eq!(permissions_at(address), "---p");
                guard(address);
            }
        }
    });
}

#[test]
fn distinct_and_published_live_leases_cannot_be_reused() {
    isolated(
        "distinct_and_published_live_leases_cannot_be_reused",
        || {
            let region = ToolRegion::reserve().unwrap();
            let first = region.stack(PAGE).unwrap();
            let second = region.stack(PAGE).unwrap();
            assert!(first.top() + PAGE <= second.base() - PAGE);
            let published_base = first.base();
            let published_start = first.start;
            let published_pages = first.pages;
            let recycled_start = second.start;
            // SAFETY: first is a live writable lease.
            unsafe { core::ptr::write_volatile(published_base as *mut u8, 0x41) };
            // Publication retains the lease exactly as a real registered stack must.
            core::mem::forget(first);
            drop(second);
            let replacement = region.stack(PAGE).unwrap();
            assert_eq!(replacement.start, recycled_start);
            assert_ne!(replacement.base(), published_base);
            zero_interior(&replacement);
            dirty_interior(&replacement);
            assert!(owns(region, published_start, published_pages));
            // SAFETY: the published retained lease must still be writable/readable.
            assert_eq!(
                unsafe { core::ptr::read_volatile(published_base as *const u8) },
                0x41
            );
            drop(replacement);
            let wider = region.stack(3 * PAGE).unwrap();
            assert_ne!(wider.base(), published_base);
            assert!(published_base + 2 * PAGE <= wider.base() - PAGE);
            assert_eq!(
                unsafe { core::ptr::read_volatile(published_base as *const u8) },
                0x41
            );
        },
    );
}

#[test]
fn smaller_reuse_after_drop_has_zero_contents_and_real_guards() {
    isolated(
        "smaller_reuse_after_drop_has_zero_contents_and_real_guards",
        || {
            let region = ToolRegion::reserve().unwrap();
            let large = region.stack(4 * PAGE).unwrap();
            let start = large.start;
            let old_base = large.base();
            dirty_interior(&large);
            drop(large);
            let small = region.stack(PAGE).unwrap();
            assert_eq!(
                small.start, start,
                "must exercise reuse, not a fresh extent"
            );
            zero_interior(&small);
            guard(small.base() - PAGE);
            guard(small.top());
            // This address was in the old writable interior and remains outside
            // the smaller lease; resetting only its new guards is insufficient.
            guard(old_base + 3 * PAGE);
        },
    );
}

#[test]
fn actual_failed_altstack_publication_reuses_only_reset_zero_pages() {
    isolated(
        "actual_failed_altstack_publication_reuses_only_reset_zero_pages",
        || {
            let region = ToolRegion::reserve().unwrap();
            let large = region.stack(4 * PAGE).unwrap();
            let start = large.start;
            dirty_interior(&large);
            let before = altstack();
            let invalid = libc::stack_t {
                ss_sp: large.base() as *mut libc::c_void,
                ss_flags: 0,
                ss_size: 0, // A real kernel ENOMEM, not a mocked publication result.
            };
            assert_eq!(
                raw(
                    libc::SYS_sigaltstack,
                    [&invalid as *const libc::stack_t as u64, 0, 0, 0, 0, 0]
                ),
                -i64::from(libc::ENOMEM)
            );
            let after = altstack();
            assert_eq!(after.ss_sp, before.ss_sp);
            assert_eq!(after.ss_flags, before.ss_flags);
            assert_eq!(after.ss_size, before.ss_size);
            drop(large);
            let small = region.stack(PAGE).unwrap();
            assert_eq!(small.start, start);
            zero_interior(&small);
            guard(small.base() - PAGE);
            guard(small.top());
        },
    );
}

#[test]
fn reset_and_discard_kernel_failures_quarantine_complete_extents() {
    isolated(
        "reset_and_discard_kernel_failures_quarantine_complete_extents",
        || {
            let region = ToolRegion::reserve().unwrap();
            let reset_failure = region.stack(2 * PAGE).unwrap();
            let reset_start = reset_failure.start;
            let reset_pages = reset_failure.pages;
            // Remove one page from this unpublished allocation. Full-range
            // mprotect now genuinely fails with ENOMEM at the hole.
            assert_eq!(
                raw(
                    libc::SYS_munmap,
                    [reset_failure.base() as u64, PAGE as u64, 0, 0, 0, 0]
                ),
                0
            );
            assert_eq!(
                protection(
                    BASE + reset_start * PAGE,
                    reset_pages * PAGE,
                    libc::PROT_NONE
                ),
                -i64::from(libc::ENOMEM)
            );
            drop(reset_failure);
            assert!(owns(region, reset_start, reset_pages));
            let discard_failure = region.stack(2 * PAGE).unwrap();
            let discard_start = discard_failure.start;
            let discard_pages = discard_failure.pages;
            let discard_base = discard_failure.base();
            assert_ne!(discard_start, reset_start);
            dirty_interior(&discard_failure);
            deny_madvise();
            assert_eq!(
                raw(
                    libc::SYS_madvise,
                    [
                        discard_base as u64,
                        PAGE as u64,
                        libc::MADV_DONTNEED as u64,
                        0,
                        0,
                        0
                    ]
                ),
                -i64::from(libc::EPERM),
                "the child-local error filter must really be installed"
            );
            drop(discard_failure);
            assert!(owns(region, discard_start, discard_pages));
            guard(discard_base);
            let next = region.stack(PAGE).unwrap();
            assert_ne!(next.start, reset_start);
            assert_ne!(next.start, discard_start);
            assert!(owns(region, reset_start, reset_pages));
            assert!(owns(region, discard_start, discard_pages));
            core::mem::forget(next);
        },
    );
}

#[test]
fn contention_refuses_allocation_and_quarantines_unpublished_drop() {
    isolated(
        "contention_refuses_allocation_and_quarantines_unpublished_drop",
        || {
            let region = ToolRegion::reserve().unwrap();
            let lease = region.stack(PAGE).unwrap();
            let start = lease.start;
            let pages = lease.pages;
            let base = lease.base();
            let mut held = region.lock().unwrap();
            assert_eq!(
                region.stack(PAGE).unwrap_err().raw_os_error(),
                Some(libc::EAGAIN)
            );
            // Deliberately retain the test lock through rollback to exercise its
            // bounded quarantine branch. No guest callback or fork occurs here.
            drop(lease);
            let bitmap = held.bitmap();
            assert!(
                (start..start + pages).all(|page| bitmap[page / 64] & (1_u64 << (page % 64)) != 0)
            );
            drop(held);
            guard(base);
            let next = region.stack(PAGE).unwrap();
            assert_ne!(next.start, start);
            assert!(owns(region, start, pages));
        },
    );
}

#[test]
fn plain_fork_preserves_private_cow_contents_and_allocator_ownership() {
    isolated(
        "plain_fork_preserves_private_cow_contents_and_allocator_ownership",
        || {
            let region = ToolRegion::reserve().unwrap();
            let lease = region.stack(PAGE).unwrap();
            let address = lease.base() as *mut u8;
            // SAFETY: this live lease owns the byte in both future COW processes.
            unsafe { core::ptr::write_volatile(address, 0x19) };
            let child_claim = lease.start + lease.pages;
            let pid = raw(libc::SYS_fork, [0; 6]);
            assert!(pid >= 0, "raw fork failed: {pid}");
            if pid == 0 {
                // No allocator lock was held across fork. claim's successful path
                // touches only the inherited control bitmap and scalar lock.
                if unsafe { core::ptr::read_volatile(address) } != 0x19 {
                    raw_exit(91);
                }
                unsafe { core::ptr::write_volatile(address, 0xe8) };
                let claimed = match region.claim(1) {
                    Ok(claimed) => claimed,
                    Err(_) => raw_exit(92),
                };
                if claimed != child_claim || unsafe { core::ptr::read_volatile(address) } != 0xe8 {
                    raw_exit(93);
                }
                raw_exit(0);
            }
            let status = wait_raw(pid);
            assert!(libc::WIFEXITED(status), "COW child status: {status:#x}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
            // SAFETY: the parent's unchanged live lease still owns this byte.
            assert_eq!(unsafe { core::ptr::read_volatile(address) }, 0x19);
            assert!(owns(region, lease.start, lease.pages));
            assert_eq!(
                region.claim(1).unwrap(),
                child_claim,
                "child bitmap writes must be COW too"
            );
            assert_eq!(unsafe { core::ptr::read_volatile(address) }, 0x19);
        },
    );
}

fn fixed_refusal(address: usize, realloc: bool) {
    use core::alloc::GlobalAlloc;
    use core::alloc::Layout;

    use super::super::alloc::FixedToolAllocator;

    let pid = raw(libc::SYS_fork, [0; 6]);
    assert!(pid >= 0, "raw fork failed: {pid}");
    if pid == 0 {
        let layout = Layout::from_size_align(8, 8).unwrap();
        // Deliberately invalid GlobalAlloc pointers test the reject-only gate.
        // No header or payload at these addresses may be dereferenced.
        unsafe {
            if realloc {
                FixedToolAllocator.realloc(address as *mut u8, layout, 16);
            } else {
                FixedToolAllocator.dealloc(address as *mut u8, layout);
            }
        }
        raw_exit(90);
    }
    let status = wait_raw(pid);
    assert!(
        libc::WIFEXITED(status),
        "refusal read a header: {status:#x}"
    );
    assert_eq!(libc::WEXITSTATUS(status), 127);
}

#[test]
fn fixed_allocator_readiness_and_foreign_headers_refuse() {
    isolated(
        "fixed_allocator_readiness_and_foreign_headers_refuse",
        || {
            use core::alloc::GlobalAlloc;
            use core::alloc::Layout;

            use super::super::alloc::FixedToolAllocator;
            use super::super::alloc::PrivateToolAllocator;
            use super::super::alloc::fixed_tool_heap_contains;

            let layout = Layout::from_size_align(64, 64).unwrap();
            assert!(fixed_arena_backing().is_none());
            assert!(arena::metadata_addresses().is_none());
            assert!(!fixed_tool_heap_contains(arena::TOOL_BOTTOM as *const u8));
            assert!(unsafe { FixedToolAllocator.alloc(layout) }.is_null());
            assert!(unsafe { FixedToolAllocator.alloc_zeroed(layout) }.is_null());
            // Even a guessed address inside the future arena must refuse before
            // reading the unmapped backpointer while authentic publication is absent.
            fixed_refusal(arena::TOOL_BOTTOM + 32, false);
            fixed_refusal(arena::TOOL_BOTTOM + 32, true);

            let region = ToolRegion::reserve().unwrap();
            let backing = fixed_arena_backing().unwrap();
            assert_eq!(backing.tool_bottom, arena::TOOL_BOTTOM);
            assert_eq!(backing.tool_top, arena::TOOL_BOTTOM + arena::ARENA_BYTES);
            assert_eq!(backing.patch_bottom, arena::PATCH_BOTTOM);
            assert_eq!(backing.patch_top, arena::PATCH_BOTTOM + arena::ARENA_BYTES);
            assert!(owns(region, arena::TOOL_BAND.0, 8194));
            assert!(owns(region, arena::PATCH_BAND.0, 8194));
            assert!(!fixed_tool_heap_contains(backing.tool_top as *const u8));
            fixed_refusal(backing.tool_bottom - PAGE + 32, false);
            fixed_refusal(backing.tool_bottom - PAGE + 32, true);
            let legacy = unsafe { PrivateToolAllocator.alloc(layout) };
            assert!(!legacy.is_null());
            assert!(!fixed_tool_heap_contains(legacy));
            fixed_refusal(legacy as usize, false);
            fixed_refusal(legacy as usize, true);
            unsafe { PrivateToolAllocator.dealloc(legacy, layout) };
        },
    );
}

#[test]
fn fixed_reusable_allocations_preserve_alignment_reuse_and_failed_realloc() {
    isolated(
        "fixed_reusable_allocations_preserve_alignment_reuse_and_failed_realloc",
        || {
            use core::alloc::GlobalAlloc;
            use core::alloc::Layout;

            use super::super::alloc::FixedToolAllocator;
            use super::super::alloc::fixed_tool_heap_contains;
            use super::super::alloc::tool_heap_contains;

            ToolRegion::reserve().unwrap();
            let addresses = arena::metadata_addresses().unwrap();
            for address in [
                addresses.tool_cursor,
                addresses.tool_free_head,
                addresses.tool_lock,
                addresses.patch_cursor,
            ] {
                assert!(
                    (arena::METADATA_ADDRESS..arena::METADATA_ADDRESS + PAGE).contains(&address)
                );
            }
            let backing = fixed_arena_backing().unwrap();
            assert_eq!(addresses.patch_cursor, backing.patch_cursor as usize);
            assert_eq!(
                unsafe { (*backing.patch_cursor).load(Ordering::Acquire) },
                0
            );
            let layout = Layout::from_size_align(257, 4096).unwrap();
            let pointer = unsafe { FixedToolAllocator.alloc_zeroed(layout) };
            assert!(!pointer.is_null());
            assert!(fixed_tool_heap_contains(pointer));
            assert!(!tool_heap_contains(pointer));
            assert_eq!(pointer as usize % layout.align(), 0);
            assert!(pointer as usize + layout.size() <= backing.tool_top);
            for index in 0..layout.size() {
                assert_eq!(unsafe { pointer.add(index).read() }, 0);
                unsafe { pointer.add(index).write(index as u8) };
            }
            let failed =
                unsafe { FixedToolAllocator.realloc(pointer, layout, arena::ARENA_BYTES + 1) };
            assert!(failed.is_null());
            for index in 0..layout.size() {
                assert_eq!(unsafe { pointer.add(index).read() }, index as u8);
            }
            let grown = unsafe { FixedToolAllocator.realloc(pointer, layout, 8192) };
            assert!(!grown.is_null());
            assert_eq!(grown as usize % layout.align(), 0);
            for index in 0..layout.size() {
                assert_eq!(unsafe { grown.add(index).read() }, index as u8);
            }
            unsafe {
                FixedToolAllocator.dealloc(grown, Layout::from_size_align(8192, 4096).unwrap());
            }
            let reused = unsafe { FixedToolAllocator.alloc(layout) };
            assert_eq!(reused, pointer);
            // These are actual cells used by the shared algorithm, read only while
            // this isolated owner is quiescent; neither address is a guessed span.
            assert!(unsafe { (addresses.tool_cursor as *const usize).read() } > layout.size());
            assert_ne!(
                unsafe { (addresses.tool_free_head as *const usize).read() },
                0
            );
            unsafe { FixedToolAllocator.dealloc(reused, layout) };
        },
    );
}

#[test]
fn fixed_payloads_and_scalar_metadata_inherit_without_reset_on_plain_fork() {
    isolated(
        "fixed_payloads_and_scalar_metadata_inherit_without_reset_on_plain_fork",
        || {
            use core::alloc::GlobalAlloc;
            use core::alloc::Layout;

            use super::super::alloc::FixedToolAllocator;

            ToolRegion::reserve().unwrap();
            let backing = fixed_arena_backing().unwrap();
            let layout = Layout::from_size_align(64, 64).unwrap();
            let live = unsafe { FixedToolAllocator.alloc(layout) };
            let free = unsafe { FixedToolAllocator.alloc(layout) };
            assert!(!live.is_null() && !free.is_null());
            unsafe {
                live.write(0x19);
                FixedToolAllocator.dealloc(free, layout);
                (backing.patch_bottom as *mut u8).write(0x27);
            }
            // SAFETY: the isolated control advances this authentic fresh cursor
            // past the deliberately initialized patch payload, never backwards.
            unsafe { (*backing.patch_cursor).store(64, Ordering::Release) };
            // No reusable/bitmap lock is held across this supported quiescent fork.
            let pid = raw(libc::SYS_fork, [0; 6]);
            assert!(pid >= 0, "raw fork failed: {pid}");
            if pid == 0 {
                let Some(child) = fixed_arena_backing() else {
                    raw_exit(91)
                };
                if unsafe { (*child.patch_cursor).load(Ordering::Acquire) } != 64
                    || unsafe { live.read() } != 0x19
                    || unsafe { (child.patch_bottom as *const u8).read() } != 0x27
                {
                    raw_exit(92);
                }
                let reused = unsafe { FixedToolAllocator.alloc(layout) };
                if reused != free {
                    raw_exit(93);
                }
                unsafe {
                    reused.write(0xa6);
                    live.write(0xe8);
                    (child.patch_bottom as *mut u8).write(0xb4);
                }
                // SAFETY: only the isolated child's private COW cursor advances.
                unsafe { (*child.patch_cursor).store(128, Ordering::Release) };
                raw_exit(0);
            }
            let status = wait_raw(pid);
            assert!(libc::WIFEXITED(status), "COW child status: {status:#x}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert_eq!(unsafe { live.read() }, 0x19);
            assert_eq!(unsafe { (backing.patch_bottom as *const u8).read() }, 0x27);
            assert_eq!(
                unsafe { (*backing.patch_cursor).load(Ordering::Acquire) },
                64
            );
            let reused = unsafe { FixedToolAllocator.alloc(layout) };
            assert_eq!(reused, free, "child free-list mutation must be COW");
            unsafe {
                FixedToolAllocator.dealloc(reused, layout);
                FixedToolAllocator.dealloc(live, layout);
            }
        },
    );
}

#[test]
fn ordinary_reserve_retains_collision_errno_after_owned_unmap() {
    isolated(
        "ordinary_reserve_retains_collision_errno_after_owned_unmap",
        || {
            let occupant = map(
                BASE,
                2 * PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED_NOREPLACE,
            );
            assert_eq!(occupant, BASE);
            // SAFETY: these two pages belong only to this isolated child.
            unsafe {
                core::ptr::write_volatile(occupant as *mut u8, 0x35);
                core::ptr::write_volatile((occupant + PAGE) as *mut u8, 0xe2);
            }
            assert_eq!(protection(occupant, 2 * PAGE, libc::PROT_READ), 0);
            assert_eq!(permissions_at(occupant), "r--p");
            assert_eq!(permissions_at(occupant + PAGE), "r--p");

            // This is the public caching path, not reserve_inner or REGION.
            assert_eq!(
                ToolRegion::reserve().unwrap_err().raw_os_error(),
                Some(libc::EEXIST),
            );
            assert_eq!(permissions_at(occupant), "r--p");
            assert_eq!(permissions_at(occupant + PAGE), "r--p");
            // SAFETY: failed reservation must leave our two readable pages.
            unsafe {
                assert_eq!(core::ptr::read_volatile(occupant as *const u8), 0x35);
                assert_eq!(
                    core::ptr::read_volatile((occupant + PAGE) as *const u8),
                    0xe2,
                );
            }

            // Open before freeing the gap, as mapping_overlaps requires.
            let mut maps = std::fs::File::open("/proc/self/maps").unwrap();
            assert_eq!(
                raw(
                    libc::SYS_munmap,
                    [occupant as u64, (2 * PAGE) as u64, 0, 0, 0, 0],
                ),
                0,
            );
            assert_eq!(resident_query(occupant), -i64::from(libc::ENOMEM));
            assert_eq!(resident_query(occupant + PAGE), -i64::from(libc::ENOMEM));
            // The collision is gone. Retry would now reserve and publish a
            // region; preservation requires the original cached EEXIST.
            assert_eq!(
                ToolRegion::reserve().unwrap_err().raw_os_error(),
                Some(libc::EEXIST),
            );
            assert!(!mapping_overlaps(&mut maps, BASE, END));
        },
    );
}

#[test]
fn raw_fork_with_unpublished_initialization_gate_refuses_nonwaiting() {
    isolated(
        "raw_fork_with_unpublished_initialization_gate_refuses_nonwaiting",
        || {
            // Start in a fresh isolated process. Own the same real RAII gate
            // used by ordinary reserve, without publishing a reservation.
            let guard = InitializationGuard::acquire().unwrap();
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0, "raw fork failed: {child}");
            if child == 0 {
                // The child inherits an occupied gate. Do not drop/reset its
                // inherited guard, format/panic, run the harness or allocate.
                // reserve's genuine EAGAIN path constructs a raw OS error.
                let code = match ToolRegion::reserve() {
                    Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => 0,
                    Err(_) => 111,
                    Ok(_) => 112,
                };
                raw_exit(code);
            }
            // Existing bounded WNOHANG wait kills and reaps on its 3s limit.
            // All assertions, unwinding and guard cleanup occur in the parent.
            let status = wait_raw(child);
            assert!(
                libc::WIFEXITED(status),
                "held-gate child status: {status:#x}"
            );
            assert_eq!(libc::WEXITSTATUS(status), 0);
            drop(guard);
            // Parent gate release remains effective; ordinary reserve can
            // still publish once and reuse the exact same public owner.
            let region = ToolRegion::reserve().unwrap();
            assert!(core::ptr::eq(region, ToolRegion::reserve().unwrap()));
        },
    );
}

#[test]
fn published_owner_protects_reservation_without_a_signal_restorer() {
    isolated(
        "published_owner_protects_reservation_without_a_signal_restorer",
        || {
            let guarded = super::super::restorer::mapping_change_refused;
            assert!(REGION.get().is_none());
            assert!(!guarded(libc::SYS_process_madvise, [0; 6]));
            let region = ToolRegion::reserve().unwrap();
            let lease = region.stack(PAGE).unwrap();
            assert!(REGION.get().is_some_and(Result::is_ok));

            // These are real published-owner addresses: the outer guards, a
            // live writable lease, and still-reserved future lease capacity.
            // No restorer has been registered in this isolated process.
            let addresses = [BASE, lease.base(), END - PAGE, BASE + BYTES / 2];
            let numbers = [
                libc::SYS_munmap,
                libc::SYS_mprotect,
                libc::SYS_pkey_mprotect,
                libc::SYS_madvise,
                libc::SYS_remap_file_pages,
                libc::SYS_mseal,
            ];
            let mut missing = Vec::new();
            for number in numbers {
                for address in addresses {
                    if !guarded(number, [address as u64, PAGE as u64, 0, 0, 0, 0]) {
                        missing.push((number, address));
                    }
                    assert!(!guarded(number, [address as u64, 0, 0, 0, 0, 0]));
                }
                for address in [BASE - PAGE, END] {
                    assert!(!guarded(number, [address as u64, PAGE as u64, 0, 0, 0, 0]));
                }
            }
            assert!(
                missing.is_empty(),
                "unprotected owner operations: {missing:?}"
            );
            assert!(guarded(libc::SYS_process_madvise, [0; 6]));
            // Genuine Tool leases remain usable through their own raw gates.
            zero_interior(&lease);
            dirty_interior(&lease);
            drop(lease);
            zero_interior(&region.stack(PAGE).unwrap());
        },
    );
}

#[test]
fn absent_and_failed_owner_do_not_protect_an_unrecognized_mapping() {
    isolated(
        "absent_and_failed_owner_do_not_protect_an_unrecognized_mapping",
        || {
            let guarded = super::super::restorer::mapping_change_refused;
            let args = [BASE as u64, PAGE as u64, 0, 0, 0, 0];
            assert!(REGION.get().is_none());
            assert!(!guarded(libc::SYS_mprotect, args));
            assert!(REGION.get().is_none(), "query must not reserve memory");
            assert_eq!(
                map(
                    BASE,
                    PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_FIXED_NOREPLACE
                ),
                BASE
            );
            assert_eq!(
                ToolRegion::reserve().unwrap_err().raw_os_error(),
                Some(libc::EEXIST)
            );
            assert!(REGION.get().is_some_and(Result::is_err));
            assert!(!guarded(libc::SYS_mprotect, args));
            assert!(!guarded(libc::SYS_process_madvise, [0; 6]));
            assert_eq!(raw(libc::SYS_munmap, args), 0);
        },
    );
}

#[test]
fn published_owner_mapping_guard_is_inherited_by_plain_fork() {
    isolated(
        "published_owner_mapping_guard_is_inherited_by_plain_fork",
        || {
            let _region = ToolRegion::reserve().unwrap();
            let pid = raw(libc::SYS_fork, [0; 6]);
            if pid == 0 {
                let guarded = super::super::restorer::mapping_change_refused(
                    libc::SYS_mprotect,
                    [
                        (END - PAGE) as u64,
                        PAGE as u64,
                        libc::PROT_WRITE as u64,
                        0,
                        0,
                        0,
                    ],
                );
                raw_exit(if guarded { 0 } else { 1 });
            }
            assert!(pid > 0, "fork failed: {pid}");
            let status = wait_raw(pid);
            assert!(libc::WIFEXITED(status), "child did not exit: {status:#x}");
            assert_eq!(libc::WEXITSTATUS(status), 0, "child lost owner protection");
        },
    );
}

#[test]
fn invalid_kernel_break_query_refuses_without_returning_an_errno_as_a_pointer() {
    isolated(
        "invalid_kernel_break_query_refuses_without_returning_an_errno_as_a_pointer",
        || {
            let _region = ToolRegion::reserve().unwrap();
            let pid = raw(libc::SYS_fork, [0; 6]);
            if pid == 0 {
                // Only this disposable child changes seccomp state. Make the
                // actual trusted brk(0) query return EPERM; every other syscall
                // remains available, including the guard's diagnostic/exit.
                let filter = [
                    libc::sock_filter {
                        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                        jt: 0,
                        jf: 0,
                        k: 0,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 1,
                        k: libc::SYS_brk as u32,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_RET | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                    },
                    libc::sock_filter {
                        code: (libc::BPF_RET | libc::BPF_K) as u16,
                        jt: 0,
                        jf: 0,
                        k: libc::SECCOMP_RET_ALLOW,
                    },
                ];
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_ptr() as *mut libc::sock_filter,
                };
                if raw(
                    libc::SYS_prctl,
                    [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0],
                ) != 0
                {
                    raw_exit(111);
                }
                if raw(
                    libc::SYS_seccomp,
                    [
                        libc::SECCOMP_SET_MODE_FILTER as u64,
                        0,
                        (&raw const program) as u64,
                        0,
                        0,
                        0,
                    ],
                ) != 0
                {
                    raw_exit(112);
                }
                let _ = super::super::restorer::mapping_change_result(
                    libc::SYS_brk,
                    [BASE as u64, 0, 0, 0, 0, 0],
                );
                raw_exit(113); // No scalar, including -EPERM, may be returned.
            }
            assert!(pid > 0, "fork failed: {pid}");
            let status = wait_raw(pid);
            assert!(
                libc::WIFEXITED(status),
                "guard child did not exit: {status:#x}"
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                125,
                "invalid break query did not refuse"
            );
        },
    );
}
