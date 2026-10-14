/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Isolated native mechanism controls, not actual Detcore constructor credit.

use core::mem::offset_of;
use core::sync::atomic::AtomicUsize;

use super::super::constructor::*;
use super::*;

static BODY_RSP: AtomicUsize = AtomicUsize::new(0);
static HANDLER_ERRNO: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn body() {
    let rsp: usize;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, preserves_flags)) };
    BODY_RSP.store(rsp, Ordering::Release);
    // Ordinary body setup must reuse the adopted owner, without waiting.
    if ToolRegion::reserve().is_err() {
        raw_exit(92);
    }
}

unsafe extern "C" fn recursive_body() {
    unsafe { constructor_entry(body) };
    raw_exit(93);
}

fn native() -> ConstructorStack {
    unsafe { constructor_entry(body) };
    let stack = constructor_stack().expect("actual native adoption must publish");
    assert!(stack.returned);
    assert_eq!(stack.bottom, STACK_BOTTOM);
    assert_eq!(stack.top, STACK_TOP);
    assert_eq!(stack.extent_start, BASE + DATA_FIRST * PAGE);
    assert_eq!(stack.extent_end, STACK_EXTENT_END);
    assert_eq!(stack.owner_tid as i64, raw(libc::SYS_gettid, [0; 6]));
    assert_eq!(stack.body_entry, body as *const () as usize);
    assert_eq!(stack.body_call_sample_rsp, STACK_TOP - 16);
    for rsp in [
        stack.first_rust_sample_rsp,
        stack.body_call_sample_rsp,
        BODY_RSP.load(Ordering::Acquire),
    ] {
        assert!((stack.bottom..stack.top).contains(&rsp), "RSP {rsp:#x}");
    }
    stack
}

#[test]
fn native_owned_stack_occupancy_guards_and_later_leases() {
    isolated(
        "constructor::native_owned_stack_occupancy_guards_and_later_leases",
        || {
            assert!(constructor_stack().is_none());
            let stack = native();
            let region = ToolRegion::reserve().unwrap();
            assert!(owns(region, DATA_FIRST, STACK_PAGES));
            let later = region.stack(64 * 1024).unwrap();
            assert!(BASE + later.start * PAGE >= stack.extent_end);
            assert_eq!(permissions_at(stack.bottom), "rw-p");
            assert_eq!(permissions_at(stack.top - 1), "rw-p");
            assert_eq!(permissions_at(stack.extent_start), "---p");
            assert_eq!(permissions_at(stack.top), "---p");
            guard(stack.extent_start);
            guard(stack.top);
            drop(later);
            assert!(owns(region, DATA_FIRST, STACK_PAGES));
        },
    );
}

#[cfg(feature = "allocator-fixture")]
#[test]
fn scalar_query_reports_samples_without_initializing_absent_owner() {
    isolated(
        "constructor::scalar_query_reports_samples_without_initializing_absent_owner",
        || {
            let mut bytes = [u64::MAX; 16];
            assert_eq!(
                size_of::<ConstructorStackRecord>(),
                core::mem::size_of_val(&bytes)
            );
            assert_eq!(
                unsafe { reverie_inguest_constructor_stack_query(bytes.as_mut_ptr().cast()) },
                -1
            );
            assert_eq!(bytes, [u64::MAX; 16]);
            assert!(REGION.get().is_none());
            assert_eq!(
                unsafe { reverie_inguest_constructor_stack_query(core::ptr::null_mut()) },
                -1
            );
            let stack = native();
            assert_eq!(
                unsafe { reverie_inguest_constructor_stack_query(bytes.as_mut_ptr().cast()) },
                0
            );
            assert_eq!(
                bytes[0..8],
                [
                    1,
                    RETURNED as u64,
                    u64::from(stack.owner_tid),
                    stack.extent_start as u64,
                    stack.extent_end as u64,
                    stack.bottom as u64,
                    stack.top as u64,
                    stack.caller_rsp as u64
                ]
            );
            assert_eq!(bytes[8], stack.adoption_entry as u64);
            assert_eq!(bytes[9], body as *const () as u64);
            assert_eq!(bytes[10], stack.first_rust_sample_rsp as u64);
            assert_eq!(bytes[11], stack.body_call_sample_rsp as u64);
            assert_eq!(
                bytes[12..],
                [
                    (BASE + PAGE) as u64,
                    RECORD_ADDRESS as u64,
                    BASE as u64,
                    END as u64
                ]
            );
        },
    );
}

extern "C" fn interrupt_initializer(_: i32) {
    let errno = ToolRegion::reserve()
        .err()
        .and_then(|error| error.raw_os_error())
        .unwrap_or(0);
    HANDLER_ERRNO.store(errno as usize, Ordering::Release);
}

#[test]
fn genuine_handler_observes_nonwaiting_initialization_gate() {
    isolated(
        "constructor::genuine_handler_observes_nonwaiting_initialization_gate",
        || {
            let guard = InitializationGuard::acquire().unwrap();
            assert_eq!(
                ToolRegion::reserve().unwrap_err().raw_os_error(),
                Some(libc::EAGAIN)
            );
            let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
            action.sa_sigaction = interrupt_initializer as *const () as usize;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGUSR1, &action, core::ptr::null_mut()) },
                0
            );
            assert_eq!(
                raw(
                    libc::SYS_tgkill,
                    [
                        raw(libc::SYS_getpid, [0; 6]) as u64,
                        raw(libc::SYS_gettid, [0; 6]) as u64,
                        libc::SIGUSR1 as u64,
                        0,
                        0,
                        0
                    ]
                ),
                0
            );
            assert_eq!(HANDLER_ERRNO.load(Ordering::Acquire), libc::EAGAIN as usize);
            assert!(REGION.get().is_none());
            drop(guard);
            let region = ToolRegion::reserve().unwrap();
            assert!(core::ptr::eq(region, ToolRegion::reserve().unwrap()));
            assert!(constructor_stack().is_none());
        },
    );
}

fn exited(status: i32, code: i32) {
    assert!(libc::WIFEXITED(status), "status {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), code);
}

#[test]
fn repeated_recursive_and_existing_owner_entries_are_terminal() {
    isolated(
        "constructor::repeated_recursive_and_existing_owner_entries_are_terminal",
        || {
            let first = raw(libc::SYS_fork, [0; 6]);
            assert!(first >= 0);
            if first == 0 {
                unsafe { constructor_entry(recursive_body) };
                raw_exit(94);
            }
            exited(wait_raw(first), 127);
            let stack = native();
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0);
            if child == 0 {
                unsafe { constructor_entry(body) };
                raw_exit(95);
            }
            exited(wait_raw(child), 127);
            assert!(owns(
                ToolRegion::reserve().unwrap(),
                DATA_FIRST,
                STACK_PAGES
            ));
            assert_eq!(constructor_stack().unwrap().caller_rsp, stack.caller_rsp);
            assert!(!INITIALIZING.load(Ordering::Acquire));
        },
    );
}

#[test]
fn plain_fork_retains_bootstrap_occupancy_and_cow_contents() {
    isolated(
        "constructor::plain_fork_retains_bootstrap_occupancy_and_cow_contents",
        || {
            let stack = native();
            unsafe { (stack.bottom as *mut u8).write_volatile(0x37) };
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0);
            if child == 0 {
                let region = ToolRegion::reserve().unwrap();
                if !owns(region, DATA_FIRST, STACK_PAGES)
                    || unsafe { (stack.bottom as *const u8).read_volatile() } != 0x37
                {
                    raw_exit(96);
                }
                unsafe { (stack.bottom as *mut u8).write_volatile(0xa9) };
                let Ok(later) = region.stack(PAGE) else {
                    raw_exit(97)
                };
                if BASE + later.start * PAGE < stack.extent_end {
                    raw_exit(98);
                }
                drop(later);
                raw_exit(0);
            }
            exited(wait_raw(child), 0);
            assert_eq!(unsafe { (stack.bottom as *const u8).read_volatile() }, 0x37);
            assert!(owns(
                ToolRegion::reserve().unwrap(),
                DATA_FIRST,
                STACK_PAGES
            ));
        },
    );
}

fn deny(number: i64) {
    filter(number, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
}

fn filter(number: i64, action: u32) {
    let mut filters = [
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
            k: number as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: action,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    if raw(
        libc::SYS_prctl,
        [libc::PR_SET_NO_NEW_PRIVS as u64, 1, 0, 0, 0, 0],
    ) != 0
        || raw(
            libc::SYS_seccomp,
            [
                libc::SECCOMP_SET_MODE_FILTER as u64,
                0,
                &program as *const _ as u64,
                0,
                0,
                0,
            ],
        ) != 0
    {
        raw_exit(99);
    }
}

extern "C" fn inspect_colliding_occupant(_: i32) {
    // Observe the actual colliding child's mapping, before its fatal exit.
    // A writable in-range control prevents EFAULT from being credited when
    // the syscall itself is unavailable or denied. No allocation or unwind.
    let mut source = 0x62_u8;
    let mut control = 0x11_u8;
    let local = libc::iovec {
        iov_base: (&raw mut source).cast(),
        iov_len: 1,
    };
    let remote = libc::iovec {
        iov_base: BASE as *mut libc::c_void,
        iov_len: 1,
    };
    let writable = libc::iovec {
        iov_base: (&raw mut control).cast(),
        iov_len: 1,
    };
    let pid = raw(libc::SYS_getpid, [0; 6]) as u64;
    let write = |target: &libc::iovec| {
        raw(
            libc::SYS_process_vm_writev,
            [
                pid,
                (&raw const local) as u64,
                1,
                target as *const _ as u64,
                1,
                0,
            ],
        )
    };
    let refused = write(&remote);
    let accepted = write(&writable);
    let correct = refused == -i64::from(libc::EFAULT)
        && accepted == 1
        && control == source
        && unsafe { (BASE as *const u8).read_volatile() } == 0x49
        && REGION.get().is_none();
    // The test filter traps exit_group; terminate this single-threaded raw
    // fork child through exit instead of recursively entering that filter.
    raw(
        libc::SYS_exit,
        [if correct { 0 } else { 103 }, 0, 0, 0, 0, 0],
    );
    unsafe { core::arch::asm!("ud2", options(noreturn)) }
}

#[test]
fn raw_kernel_errors_exit_and_denied_exit_reaches_ud2() {
    isolated(
        "constructor::raw_kernel_errors_exit_and_denied_exit_reaches_ud2",
        || {
            for number in [libc::SYS_mmap, libc::SYS_mprotect] {
                let child = raw(libc::SYS_fork, [0; 6]);
                assert!(child >= 0);
                if child == 0 {
                    deny(number);
                    unsafe { constructor_entry(body) };
                    raw_exit(100);
                }
                exited(wait_raw(child), 127);
            }
            let occupant = map(
                BASE,
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED_NOREPLACE,
            );
            unsafe { (occupant as *mut u8).write_volatile(0x49) };
            assert_eq!(protection(occupant, PAGE, libc::PROT_READ), 0);
            let observed = raw(libc::SYS_fork, [0; 6]);
            assert!(observed >= 0);
            if observed == 0 {
                let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
                action.sa_sigaction = inspect_colliding_occupant as *const () as usize;
                unsafe { libc::sigemptyset(&mut action.sa_mask) };
                if unsafe { libc::sigaction(libc::SIGSYS, &action, core::ptr::null_mut()) } != 0 {
                    raw_exit(104);
                }
                filter(libc::SYS_exit_group, libc::SECCOMP_RET_TRAP);
                unsafe { constructor_entry(body) };
                raw_exit(105);
            }
            exited(wait_raw(observed), 0);
            let child = raw(libc::SYS_fork, [0; 6]);
            assert!(child >= 0);
            if child == 0 {
                prepare_fault_child();
                deny(libc::SYS_exit_group);
                unsafe { constructor_entry(body) };
                raw_exit(101);
            }
            let status = wait_raw(child);
            assert!(libc::WIFSIGNALED(status), "status {status:#x}");
            assert_eq!(libc::WTERMSIG(status), libc::SIGILL);
            assert_eq!(unsafe { (occupant as *const u8).read_volatile() }, 0x49);
            assert_eq!(permissions_at(occupant), "r--p");
        },
    );
}

#[repr(C)]
struct AbiObservation {
    registers: [usize; 6],
    entry_rsp: usize,
    expected_return: usize,
    actual_return: usize,
    before: [u8; 264],
    after: [u8; 264],
}

const _: () = {
    assert!(offset_of!(AbiObservation, entry_rsp) == 48);
    assert!(offset_of!(AbiObservation, before) == 72);
    assert!(offset_of!(AbiObservation, after) == 336);
};

core::arch::global_asm!(
    r#"
    .text
    .hidden constructor_abi_observe
    .global constructor_abi_observe
    .type constructor_abi_observe,@function
constructor_abi_observe:
    endbr64
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 312
    mov r13, rsi
    mov r14, rdi
    mov [rsp + 280], rdx
    mov rdi, rsp
    mov ecx, 33
    movabs rax, 0xa5a5a5a5a5a5a5a5
    rep stosq
    mov rsi, rsp
    lea rdi, [r13 + 72]
    mov ecx, 264
    rep movsb
    lea rax, [rsp + 264]
    mov [r13 + 48], rax
    lea rax, [rip + .Lconstructor_abi_return]
    mov [r13 + 56], rax
    // The genuine CALL slot is separate from every watched red-zone byte.
    mov [rsp + 264], rax
    cmp qword ptr [rsp + 280], 0
    je .Lconstructor_abi_clean
    mov byte ptr [rsp + 100], 0x33
.Lconstructor_abi_clean:
    movabs rbx, 0x123456789abcdef0
    movabs rbp, 0x23456789abcdef01
    movabs r12, 0x3456789abcdef012
    movabs r15, 0x456789abcdef0123
    add rsp, 272
    mov rdi, r14
    call {entry}
.Lconstructor_abi_return:
    endbr64
    mov [r13], rbx
    mov [r13 + 8], rbp
    mov [r13 + 16], r12
    mov [r13 + 24], r13
    mov [r13 + 32], r14
    mov [r13 + 40], r15
    mov rax, [rsp - 8]
    mov [r13 + 64], rax
    sub rsp, 272
    mov rsi, rsp
    lea rdi, [r13 + 336]
    mov ecx, 264
    rep movsb
    add rsp, 312
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    .size constructor_abi_observe, .-constructor_abi_observe
"#,
    entry = sym constructor_entry,
);

unsafe extern "C" {
    fn constructor_abi_observe(
        body: unsafe extern "C" fn(),
        output: *mut AbiObservation,
        corrupt: usize,
    );
}

#[test]
fn scalar_abi_genuine_return_and_full_red_zone_are_preserved() {
    isolated(
        "constructor::scalar_abi_genuine_return_and_full_red_zone_are_preserved",
        || {
            // Each invocation needs a fresh process. The control writer must be
            // detected by the same literal comparator used by the clean case.
            for corrupt in [0, 1] {
                let child = raw(libc::SYS_fork, [0; 6]);
                assert!(child >= 0);
                if child == 0 {
                    let mut result = AbiObservation {
                        registers: [0; 6],
                        entry_rsp: 0,
                        expected_return: 0,
                        actual_return: 0,
                        before: [0; 264],
                        after: [0; 264],
                    };
                    let output = (&raw mut result) as usize;
                    unsafe { constructor_abi_observe(body, &raw mut result, corrupt) };
                    let correct = result.registers
                        == [
                            0x1234_5678_9abc_def0,
                            0x2345_6789_abcd_ef01,
                            0x3456_789a_bcde_f012,
                            output,
                            body as *const () as usize,
                            0x4567_89ab_cdef_0123,
                        ]
                        && result.entry_rsp % 16 == 8
                        && result.expected_return == result.actual_return
                        && constructor_stack().unwrap().caller_rsp == result.entry_rsp
                        && result.before == [0xa5; 264];
                    let changes = result
                        .before
                        .iter()
                        .zip(&result.after)
                        .filter(|(a, b)| a != b)
                        .count();
                    if !correct || changes != corrupt || (corrupt == 1 && result.after[100] != 0x33)
                    {
                        raw_exit(102);
                    }
                    raw_exit(0);
                }
                exited(wait_raw(child), 0);
            }
        },
    );
}

#[test]
fn malformed_native_tickets_refuse_before_publication() {
    isolated(
        "constructor::malformed_native_tickets_refuse_before_publication",
        || {
            malformed_ticket_control();
        },
    );
}
