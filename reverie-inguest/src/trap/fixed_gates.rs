/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */
//! Default-off, immutable fixed gate page. This does not enable exec.
//! This new source dependency needs an explicit fixed-artifact source binding;
//! it is not covered by or an excuse to relax the existing 15-source inventory.
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::io;
use std::ptr;

use super::FIXED_GATE_BASE;
use super::FIXED_GATE_BYTES;
use super::FIXED_GUEST_ENTRY;
use super::GuestSyscallResult;

/// Native assembly phase ABI: aligned x86-64 usize, zero before publication,
/// one after the entire page is validated and RX. Never reset after publication.
/// Native selectors read it before entering a memory-free syscall interval.
#[unsafe(no_mangle)]
pub static reverie_inguest_fixed_gates_published: AtomicUsize = AtomicUsize::new(0);
const _: () = {
    assert!(std::mem::size_of::<AtomicUsize>() == 8);
    assert!(std::mem::align_of::<AtomicUsize>() == 8);
};
static PREPARING: AtomicBool = AtomicBool::new(false);

core::arch::global_asm!(
    r#"
    .hidden reverie_inguest_fixed_gates_published
    .section .rodata.reverie_inguest_fixed_gate_template,"a",@progbits
    .balign 4096
    .global reverie_inguest_fixed_gate_template
    .hidden reverie_inguest_fixed_gate_template
    .type reverie_inguest_fixed_gate_template,@object
reverie_inguest_fixed_gate_template:
    // .org fixes every ABI label and fails assembly if a preceding body grows
    // beyond its band. Every indirectly reached entry starts with ENDBR64.
    .org 0x7c, 0xcc
.Lfixed_native_entry:
    endbr64
    .org 0x80, 0xcc
.Lfixed_native_syscall:
    syscall
    .org 0x82, 0xcc
.Lfixed_native_return:
    jmp r12
    .org 0x100, 0xcc
.Lfixed_guest_entry:
    endbr64
    push r12
    push r13
    push r14
    push r15
    mov r12d, edx
    mov r13, rdi
    mov r14, [rsi + 16]
    mov rdi, [rsi]
    mov rdx, [rsi + 8]
    mov r10, [rsi + 24]
    mov r8, [rsi + 32]
    mov r9, [rsi + 40]
    mov rsi, rdx
    xor ecx, ecx
    rdpkru
    mov r15d, eax
    mov eax, r12d
    xor edx, edx
    wrpkru
    lfence
    mov rax, r13
    mov rdx, r14
    jmp .Lfixed_guest_syscall
    .org 0x200, 0xcc
.Lfixed_guest_syscall:
    syscall
    .org 0x202, 0xcc
.Lfixed_guest_return:
    mov r12, rax
    // Actual post-syscall PKRU, including negative returns; caller access is
    // reopened entirely in registers before the first stack access.
    xor ecx, ecx
    rdpkru
    mov r14d, eax
    mov eax, r15d
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rax, r12
    mov edx, r14d
    pop r15
    pop r14
    pop r13
    pop r12
    ret
    .org 0x300, 0xcc
.Lfixed_signal_restorer:
    endbr64
    mov eax, 15
    .org 0x309, 0xcc
    syscall
    .org 0x30b, 0xcc
.Lfixed_signal_return:
    ud2
    .org 4096, 0xcc
    .global reverie_inguest_fixed_gate_template_end
    .hidden reverie_inguest_fixed_gate_template_end
reverie_inguest_fixed_gate_template_end:
    .size reverie_inguest_fixed_gate_template, .-reverie_inguest_fixed_gate_template

    .text
    .p2align 4
    .global reverie_inguest_fixed_trusted_syscall
    .hidden reverie_inguest_fixed_trusted_syscall
    .type reverie_inguest_fixed_trusted_syscall,@function
reverie_inguest_fixed_trusted_syscall:
    endbr64
    push r12
    lea r12, [rip + .Lfixed_trusted_continuation]
    mov rax, rdi
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov r10, r8
    mov r8, r9
    mov r9, [rsp + 16]
    movabs r11, 0x50000000007c
    jmp r11
.Lfixed_trusted_continuation:
    endbr64
    pop r12
    ret
    .size reverie_inguest_fixed_trusted_syscall, .-reverie_inguest_fixed_trusted_syscall
"#
);

unsafe extern "C" {
    static reverie_inguest_fixed_gate_template: u8;
    static reverie_inguest_fixed_gate_template_end: u8;
    fn reverie_inguest_fixed_trusted_syscall(
        number: u64,
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> i64;
}

pub(super) fn published() -> bool {
    reverie_inguest_fixed_gates_published.load(Ordering::Acquire) != 0
}

fn template() -> io::Result<&'static [u8]> {
    let start = ptr::addr_of!(reverie_inguest_fixed_gate_template) as usize;
    let end = ptr::addr_of!(reverie_inguest_fixed_gate_template_end) as usize;
    if end.checked_sub(start) != Some(FIXED_GATE_BYTES as usize) {
        return Err(io::Error::other(
            "fixed gate template has an invalid extent",
        ));
    }
    // SAFETY: the assembler owns this exact read-only, process-lifetime page.
    let bytes =
        unsafe { std::slice::from_raw_parts(start as *const u8, FIXED_GATE_BYTES as usize) };
    for offset in [0x7c, 0x100, 0x300] {
        if bytes[offset..offset + 4] != [0xf3, 0x0f, 0x1e, 0xfa] {
            return Err(io::Error::other("fixed gate entry lacks ENDBR64"));
        }
    }
    for offset in [0x80, 0x200, 0x309] {
        if bytes[offset..offset + 2] != [0x0f, 0x05] {
            return Err(io::Error::other("fixed gate syscall has an invalid offset"));
        }
    }
    if bytes[0x82..0x85] != [0x41, 0xff, 0xe4]
        || bytes[0x304..0x309] != [0xb8, 15, 0, 0, 0]
        || bytes[0x30b..0x30d] != [0x0f, 0x0b]
    {
        return Err(io::Error::other(
            "fixed gate return/restorer has invalid bytes",
        ));
    }
    Ok(bytes)
}

// Explicit legacy bootstrap: no selected helper is involved before publication.
unsafe fn bootstrap_call(number: i64, args: [u64; 6]) -> i64 {
    unsafe {
        super::reverie_inguest_trusted_syscall(
            number as u64,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
        )
    }
}
unsafe fn seal(address: u64) -> i64 {
    unsafe {
        bootstrap_call(
            libc::SYS_mprotect,
            [
                address,
                FIXED_GATE_BYTES,
                (libc::PROT_READ | libc::PROT_EXEC) as u64,
                0,
                0,
                0,
            ],
        )
    }
}
struct Preparing;
impl Drop for Preparing {
    fn drop(&mut self) {
        PREPARING.store(false, Ordering::Release);
    }
}

/// Caller supplies the single pre-handler/filter installation boundary.
pub(super) unsafe fn prepare() -> io::Result<()> {
    unsafe { prepare_with_sealer(seal) }
}
unsafe fn prepare_with_sealer(sealer: unsafe fn(u64) -> i64) -> io::Result<()> {
    if published() {
        return Ok(());
    }
    if PREPARING
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "fixed gates are being prepared",
        ));
    }
    let _preparing = Preparing;
    let bytes = template()?;
    let mapped = unsafe {
        bootstrap_call(
            libc::SYS_mmap,
            [
                FIXED_GATE_BASE,
                FIXED_GATE_BYTES,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                u64::MAX,
                0,
            ],
        )
    };
    if (-4095..0).contains(&mapped) {
        return Err(io::Error::from_raw_os_error(-mapped as i32));
    }
    let address = mapped as u64;
    if address != FIXED_GATE_BASE {
        // Old kernels may ignore NOREPLACE. We own only the mapping returned.
        unsafe {
            bootstrap_call(libc::SYS_munmap, [address, FIXED_GATE_BYTES, 0, 0, 0, 0]);
        }
        return Err(io::Error::other(
            "kernel did not honor fixed gate NOREPLACE address",
        ));
    }
    for (offset, byte) in bytes.iter().enumerate() {
        // No libc memcpy dependency during unpublished bootstrap.
        unsafe { ptr::write_volatile((address as *mut u8).add(offset), *byte) };
    }
    let sealed = unsafe { sealer(address) };
    if sealed != 0 {
        // Still unpublished: release exactly this attempt's owned mapping.
        unsafe {
            bootstrap_call(libc::SYS_munmap, [address, FIXED_GATE_BYTES, 0, 0, 0, 0]);
        }
        return Err(if sealed < 0 {
            io::Error::from_raw_os_error(-sealed as i32)
        } else {
            io::Error::other("fixed gate seal returned a nonzero result")
        });
    }
    reverie_inguest_fixed_gates_published.store(1, Ordering::Release);
    Ok(())
}

pub(super) unsafe fn scalar(number: i64, args: [u64; 6]) -> i64 {
    unsafe { scalar3_or6(number, args[0], args[1], args[2], args[3], args[4], args[5]) }
}
pub(super) unsafe fn scalar3_or6(
    number: i64,
    a: u64,
    b: u64,
    c: u64,
    d: u64,
    e: u64,
    f: u64,
) -> i64 {
    unsafe { reverie_inguest_fixed_trusted_syscall(number as u64, a, b, c, d, e, f) }
}
pub(super) unsafe fn guest(number: i64, args: &[u64; 6], pkru: u32) -> GuestSyscallResult {
    // Selected before entering the guest body, which denies caller memory.
    let entry: unsafe extern "C" fn(i64, *const u64, u32) -> GuestSyscallResult =
        unsafe { std::mem::transmute(FIXED_GUEST_ENTRY as usize) };
    unsafe { entry(number, args.as_ptr(), pkru) }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::AtomicU64;
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    // Test-only bridge into a copy whose syscall has identical low32 bits but
    // a different upper32 word. Its native interval matches the real ABI.
    core::arch::global_asm!(
        r#"
        .text
        .global reverie_inguest_fixed_gate_core_alternate
        .hidden reverie_inguest_fixed_gate_core_alternate
        .type reverie_inguest_fixed_gate_core_alternate,@function
reverie_inguest_fixed_gate_core_alternate:
        endbr64
        push r12
        mov r11, rdi
        lea r12, [rip + .Lfixed_gate_core_alternate_return]
        mov eax, 39
        jmp r11
.Lfixed_gate_core_alternate_return:
        endbr64
        pop r12
        ret
        .size reverie_inguest_fixed_gate_core_alternate, .-reverie_inguest_fixed_gate_core_alternate
"#
    );
    unsafe extern "C" {
        fn reverie_inguest_fixed_gate_core_alternate(entry: u64) -> i64;
    }

    static TRAPS: AtomicU64 = AtomicU64::new(0);
    static HANDLED: AtomicBool = AtomicBool::new(false);
    struct CountAndForward;
    impl crate::dispatch::SyscallDispatcher for CountAndForward {
        fn dispatch(&self, event: &mut crate::dispatch::SyscallEvent) {
            TRAPS.fetch_add(1, Ordering::Relaxed);
            crate::dispatch::PassthroughDispatcher::new().dispatch(event);
        }
    }
    unsafe extern "C" fn note_signal(_: i32, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
        HANDLED.store(true, Ordering::Release);
    }
    unsafe fn invalid_seal(address: u64) -> i64 {
        // Real kernel mprotect rejects an unsupported protection bit. This
        // reaches the actual owned-mapping rollback path, not a mocked errno.
        unsafe {
            bootstrap_call(
                libc::SYS_mprotect,
                [address, FIXED_GATE_BYTES, 0x8000_0000, 0, 0, 0],
            )
        }
    }
    unsafe fn occupy() -> i64 {
        unsafe {
            bootstrap_call(
                libc::SYS_mmap,
                [
                    FIXED_GATE_BASE,
                    FIXED_GATE_BYTES,
                    (libc::PROT_READ | libc::PROT_WRITE) as u64,
                    (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE) as u64,
                    u64::MAX,
                    0,
                ],
            )
        }
    }

    #[test]
    fn fixed_gate_core_template_layout() {
        let bytes = template().unwrap();
        assert_eq!(bytes.len(), 4096);
        assert_eq!(
            &bytes[0x7c..0x85],
            &[0xf3, 0x0f, 0x1e, 0xfa, 0x0f, 0x05, 0x41, 0xff, 0xe4]
        );
        assert_eq!(
            &bytes[0x300..0x30d],
            &[
                0xf3, 0x0f, 0x1e, 0xfa, 0xb8, 15, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b
            ]
        );
    }

    #[test]
    fn fixed_gate_core_physical_subprocesses() {
        const CHILD: &str = "REVERIE_FIXED_GATE_CORE_CHILD";
        if let Some(mode) = std::env::var_os(CHILD) {
            // Deliberate RX fault must not invoke a host core-dump helper.
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) }, 0);
            assert!(!published());
            assert_eq!(super::super::fixed_gate_region(), None);
            let legacy = super::super::trusted_gate();
            assert_ne!(legacy.syscall_ip, FIXED_GATE_BASE + 0x80);
            match mode.to_str().unwrap() {
                "collision" => unsafe {
                    assert_eq!(occupy(), FIXED_GATE_BASE as i64);
                    ptr::write_volatile(FIXED_GATE_BASE as *mut u64, 0x1234_5678_9abc_def0);
                    assert_eq!(prepare().unwrap_err().raw_os_error(), Some(libc::EEXIST));
                    assert!(!published());
                    assert_eq!(
                        ptr::read_volatile(FIXED_GATE_BASE as *const u64),
                        0x1234_5678_9abc_def0
                    );
                    assert_eq!(super::super::trusted_gate(), legacy);
                    assert_eq!(
                        bootstrap_call(
                            libc::SYS_munmap,
                            [FIXED_GATE_BASE, FIXED_GATE_BYTES, 0, 0, 0, 0]
                        ),
                        0
                    );
                },
                "seal-failure" => unsafe {
                    assert_eq!(
                        prepare_with_sealer(invalid_seal)
                            .unwrap_err()
                            .raw_os_error(),
                        Some(libc::EINVAL)
                    );
                    assert!(!published());
                    assert_eq!(super::super::trusted_gate(), legacy);
                    // Exact re-reservation proves rollback released our page.
                    assert_eq!(occupy(), FIXED_GATE_BASE as i64);
                    assert_eq!(
                        bootstrap_call(
                            libc::SYS_munmap,
                            [FIXED_GATE_BASE, FIXED_GATE_BYTES, 0, 0, 0, 0]
                        ),
                        0
                    );
                },
                "rx-write" => unsafe {
                    prepare().unwrap();
                    ptr::write_volatile(FIXED_GATE_BASE as *mut u8, 0);
                    panic!("fixed RX page accepted a CPU write");
                },
                "forward" => unsafe {
                    prepare().unwrap();
                    let mapped = std::slice::from_raw_parts(
                        FIXED_GATE_BASE as *const u8,
                        FIXED_GATE_BYTES as usize,
                    );
                    assert_eq!(mapped, template().unwrap());
                    assert!(published());
                    assert_eq!(
                        super::super::fixed_gate_region(),
                        Some((FIXED_GATE_BASE, FIXED_GATE_BASE + FIXED_GATE_BYTES))
                    );
                    assert_eq!(
                        super::super::trusted_gate(),
                        crate::seccomp::TrustedGate {
                            syscall_ip: FIXED_GATE_BASE + 0x80,
                            return_ip: FIXED_GATE_BASE + 0x82,
                        }
                    );
                    assert_eq!(
                        super::super::guest_syscall_gate(),
                        crate::seccomp::TrustedGate {
                            syscall_ip: FIXED_GATE_BASE + 0x200,
                            return_ip: FIXED_GATE_BASE + 0x202,
                        }
                    );
                    assert_eq!(crate::signal::signal_restorer(), FIXED_GATE_BASE + 0x300);
                    assert_eq!(
                        crate::signal::signal_restorer_return_ip(),
                        FIXED_GATE_BASE + 0x30b
                    );
                    // Publication is idempotent, never an attempt to replace/adopt.
                    prepare().unwrap();
                    let pid = super::super::raw_syscall6(libc::SYS_getpid, [0; 6]);
                    assert!(pid > 0);
                    assert_eq!(super::super::raw_syscall3(libc::SYS_getpid, 0, 0, 0), pid);
                    let scalar = super::super::raw_syscall6_with_result(
                        libc::SYS_close,
                        [u64::MAX, 0, 0, 0, 0, 0],
                        None,
                    );
                    assert_eq!(scalar.result, -i64::from(libc::EBADF));
                    assert_eq!(scalar.pkru, None);
                    // Nonzero fd and offset exercise arguments five and six.
                    let fd = super::super::raw_syscall6(
                        libc::SYS_memfd_create,
                        [c"fixed-gate-core".as_ptr() as u64, 0, 0, 0, 0, 0],
                    );
                    assert!(fd >= 0);
                    assert_eq!(
                        super::super::raw_syscall3(libc::SYS_ftruncate, fd as u64, 8192, 0),
                        0
                    );
                    let marker = 0xabc0_1234_5678_def9_u64;
                    assert_eq!(
                        super::super::raw_syscall6(
                            libc::SYS_pwrite64,
                            [fd as u64, (&raw const marker) as u64, 8, 4096, 0, 0]
                        ),
                        8
                    );
                    let args = [
                        0,
                        4096,
                        (libc::PROT_READ | libc::PROT_WRITE) as u64,
                        libc::MAP_PRIVATE as u64,
                        fd as u64,
                        4096,
                    ];
                    let address = super::super::raw_syscall6(libc::SYS_mmap, args);
                    assert!(address > 0);
                    assert_eq!(ptr::read_volatile(address as *const u64), marker);
                    assert_eq!(
                        super::super::raw_syscall3(libc::SYS_munmap, address as u64, 4096, 0),
                        0
                    );
                    let caps = std::arch::x86_64::__cpuid_count(7, 0);
                    if caps.ecx & (1 << 4) != 0 {
                        let caller: u32;
                        core::arch::asm!("xor ecx,ecx", "rdpkru", out("eax") caller, out("ecx") _, out("edx") _, options(nostack));
                        // Deny the unused highest key; caller rights must reopen.
                        let guest = caller | (3 << 30);
                        let returned = super::super::raw_syscall6_with_result(
                            libc::SYS_close,
                            [u64::MAX, 0, 0, 0, 0, 0],
                            Some(guest),
                        );
                        assert_eq!(returned.result, -i64::from(libc::EBADF));
                        assert_eq!(returned.pkru, Some(guest));
                        assert_eq!(
                            super::super::raw_syscall6_with_pkru(libc::SYS_getpid, [0; 6], guest),
                            pid
                        );
                        let address = super::super::raw_syscall6_with_result(
                            libc::SYS_mmap,
                            args,
                            Some(guest),
                        );
                        assert!(address.result > 0);
                        assert_eq!(address.pkru, Some(guest));
                        assert_eq!(ptr::read_volatile(address.result as *const u64), marker);
                        assert_eq!(
                            super::super::raw_syscall3(
                                libc::SYS_munmap,
                                address.result as u64,
                                4096,
                                0
                            ),
                            0
                        );
                        let restored: u32;
                        core::arch::asm!("xor ecx,ecx", "rdpkru", out("eax") restored, out("ecx") _, out("edx") _, options(nostack));
                        assert_eq!(restored, caller);
                    }
                    assert_eq!(
                        super::super::raw_syscall3(libc::SYS_close, fd as u64, 0, 0),
                        0
                    );
                    // Prepare the physical high-word negative before TSYNC.
                    let alternate = FIXED_GATE_BASE + (1_u64 << 32);
                    assert_eq!(
                        super::super::raw_syscall6(
                            libc::SYS_mmap,
                            [
                                alternate,
                                FIXED_GATE_BYTES,
                                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                                (libc::MAP_PRIVATE
                                    | libc::MAP_ANONYMOUS
                                    | libc::MAP_FIXED_NOREPLACE)
                                    as u64,
                                u64::MAX,
                                0
                            ]
                        ),
                        alternate as i64
                    );
                    for (offset, byte) in template().unwrap().iter().enumerate() {
                        ptr::write_volatile((alternate as *mut u8).add(offset), *byte);
                    }
                    assert_eq!(
                        super::super::raw_syscall3(
                            libc::SYS_mprotect,
                            alternate,
                            FIXED_GATE_BYTES,
                            (libc::PROT_READ | libc::PROT_EXEC) as u64
                        ),
                        0
                    );
                    let config = crate::lifecycle::RuntimeConfig {
                        use_alt_stack: true,
                        restrict_signal_return: true,
                    };
                    crate::install(
                        Box::new(CountAndForward),
                        &crate::lifecycle::InProcessSeccomp,
                        &config,
                    )
                    .unwrap();
                    assert_eq!(super::super::raw_syscall6(libc::SYS_getpid, [0; 6]), pid);
                    let before = TRAPS.load(Ordering::Relaxed);
                    // Deliberate OLD DSO gate: it must now trap exactly once.
                    assert_eq!(bootstrap_call(libc::SYS_getpid, [0; 6]), pid);
                    assert_eq!(TRAPS.load(Ordering::Relaxed), before + 1);
                    let before = TRAPS.load(Ordering::Relaxed);
                    assert_eq!(
                        reverie_inguest_fixed_gate_core_alternate(alternate + 0x7c),
                        pid
                    );
                    assert_eq!(
                        TRAPS.load(Ordering::Relaxed),
                        before + 1,
                        "matching low32 bits must not admit a different high32 word"
                    );
                    assert_eq!(
                        super::super::raw_syscall3(
                            libc::SYS_munmap,
                            alternate,
                            FIXED_GATE_BYTES,
                            0
                        ),
                        0
                    );
                    crate::signal::install_runtime_handler(libc::SIGURG, note_signal, 0).unwrap();
                    crate::signal::raw_raise(libc::SIGURG).unwrap();
                    assert!(HANDLED.load(Ordering::Acquire));
                    let child = super::super::raw_syscall6(libc::SYS_fork, [0; 6]);
                    assert!(child >= 0);
                    if child == 0 {
                        assert!(published());
                        assert_eq!(
                            super::super::trusted_gate().syscall_ip,
                            FIXED_GATE_BASE + 0x80
                        );
                        super::super::raw_syscall3(libc::SYS_exit_group, 42, 0, 0);
                        panic!("fixed child exit_group returned");
                    }
                    let mut status = 0;
                    assert_eq!(libc::waitpid(child as i32, &mut status, 0), child as i32);
                    assert!(libc::WIFEXITED(status));
                    assert_eq!(libc::WEXITSTATUS(status), 42);
                    // TSYNC affects libtest's other threads too. The fixture's
                    // installed handlers have permanent lifetime; do not return
                    // into unrelated harness/TLS teardown after these assertions.
                    // FullTool's normal-exit regression is separate and unchanged.
                    super::super::raw_syscall3(libc::SYS_exit_group, 0, 0, 0);
                    panic!("fixed fixture exit_group returned");
                },
                other => panic!("unknown fixed gate core child {other}"),
            }
            return;
        }
        for mode in ["collision", "seal-failure", "rx-write", "forward"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "trap::fixed_gates::tests::fixed_gate_core_physical_subprocesses",
                    "--nocapture",
                ])
                .env(CHILD, mode)
                .output()
                .unwrap();
            if mode == "rx-write" {
                assert_eq!(
                    output.status.signal(),
                    Some(libc::SIGSEGV),
                    "{mode} {output:?}"
                );
            } else {
                assert!(output.status.success(), "{mode} {output:?}");
            }
        }
    }
}
