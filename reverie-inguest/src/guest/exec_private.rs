/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 * This source code is licensed under the BSD-style license found in LICENSE.
 */
//! Native private-loader state for the opt-in InitialImage experiment.
//!
//! The control page is a mechanism, not authentication. Only an initializer
//! that has redeemed its one-use coordinator admission may publish this state.
//! Existing constructors and exec refusals do not consume it.
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;
use std::io;

/// Native control ABI shared with the private GNU runner.
#[repr(C, align(64))]
pub struct NativeControl {
    abi_version: u64,
    byte_len: u64,
    phase: u64,
    guest_fs: u64,
    tool_fs: u64,
    guest_rsp: u64,
    guest_ld_entry: u64,
    init_input: u64,
    init_input_len: u64,
    runtime_ready: u64,
    kernel_mask: u64,
    // Initially captured by the private loader, then updated only after an
    // actual successful guest registration syscall. Tool setters are refused.
    kernel_robust_head: u64,
    kernel_robust_len: u64,
    kernel_clear_tid: u64,
    kernel_brk: u64,
    native_tid: u64,
    private_brk_base: u64,
    private_brk_current: u64,
    private_brk_end: u64,
    private_stack_base: u64,
    private_stack_end: u64,
    tool_ld_entry: u64,
    tool_ld_bias: u64,
    runner_entry: u64,
    runner_phdr: u64,
    runner_phnum: u64,
    runner_phent: u64,
    runner_bias: u64,
    guest_ld_lo: u64,
    guest_ld_hi: u64,
    bootstrap_handler: u64,
    bootstrap_restorer: u64,
    bootstrap_stack_base: u64,
    bootstrap_stack_end: u64,
    native_traps: u64,
    private_map_count: u64,
    private_code_count: u64,
    private_clear_tid: u64,
    private_robust_head: u64,
    private_robust_len: u64,
    failure_code: u64,
    init_input_fd: u64,
    input_mapping_base: u64,
    input_mapping_end: u64,
    guest_resume_mask: u64,
    guest_pkru: u64,
    native_state: u64,
    native_config: u64,
    maps: [PrivateMap; 64],
    code: [PrivateCode; 64],
}
#[repr(C)]
struct PrivateMap {
    lo: u64,
    hi: u64,
    prot: u64,
    flags: u64,
}
#[repr(C)]
struct PrivateCode {
    lo: u64,
    hi: u64,
}
const _: () = {
    assert!(size_of::<NativeControl>() == 3456);
    assert!(align_of::<NativeControl>() == 64);
    assert!(core::mem::offset_of!(NativeControl, phase) == 16);
    assert!(core::mem::offset_of!(NativeControl, guest_fs) == 24);
    assert!(core::mem::offset_of!(NativeControl, tool_fs) == 32);
    assert!(core::mem::offset_of!(NativeControl, guest_resume_mask) == 352);
    assert!(core::mem::offset_of!(NativeControl, maps) == 384);
    assert!(core::mem::offset_of!(NativeControl, code) == 2432);
};

#[unsafe(no_mangle)]
static reverie_inguest_private_exec_control: AtomicUsize = AtomicUsize::new(0);
core::arch::global_asm!(".hidden reverie_inguest_private_exec_control");

/// Whether the authenticated initializer has published a private control.
pub fn active() -> bool {
    reverie_inguest_private_exec_control.load(Ordering::Acquire) != 0
}

/// The actual ready InitialImage thread while its Tool callback is active.
/// This is a read-only admission check for the experimental observation sink,
/// not authorization to change phase, registrations, FS or guest state.
pub fn callback_native_tid() -> Option<i32> {
    let control = control_pointer();
    if control.is_null() {
        return None;
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).phase }) != 4
        || read(unsafe { &raw const (*control).runtime_ready }) != 1
    {
        return None;
    }
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let mut fs = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    if tid <= 0
        || pid != tid
        || tid as u64 != read(unsafe { &raw const (*control).native_tid })
        || rc != 0
        || fs == 0
        || fs != read(unsafe { &raw const (*control).tool_fs })
    {
        return None;
    }
    i32::try_from(tid).ok()
}

/// Current guest registrations in the calling native thread.
///
/// Addresses are recorded kernel arguments, never dereferenced Tool pointers.
/// This value does not authorize an exec or a change to either registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestKernelRegistrations {
    /// Last successful guest clear-child-TID registration.
    pub clear_tid: u64,
    /// Last successful guest robust-list registration, checked against Linux.
    pub robust_head: u64,
    /// Kernel robust-list ABI length.
    pub robust_len: u64,
}

/// Inspect registrations only in the actual ready native Tool callback.
///
/// The robust-list query must agree with the success-only guest ledger. Linux
/// does not provide a generally available clear-TID query; its value comes
/// from the initial loader capture and every successful guest setter. This
/// check never uses a destructive setter as a query. A caller needing an exec
/// cut must repeat it at its final edge, without intervening guest execution.
pub fn callback_kernel_registrations() -> Option<GuestKernelRegistrations> {
    callback_native_tid()?;
    let control = control_pointer();
    let read = |p: *const u64| unsafe { p.read_volatile() };
    let recorded = GuestKernelRegistrations {
        clear_tid: read(unsafe { &raw const (*control).kernel_clear_tid }),
        robust_head: read(unsafe { &raw const (*control).kernel_robust_head }),
        robust_len: read(unsafe { &raw const (*control).kernel_robust_len }),
    };
    let mut head = 0_u64;
    let mut length = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_get_robust_list,
            [0, (&raw mut head) as u64, (&raw mut length) as u64, 0, 0, 0],
        )
    };
    (rc == 0 && head == recorded.robust_head && length == recorded.robust_len).then_some(recorded)
}

/// Read the bounded, immutable native input packet before coordinator redemption.
/// This validates placement and ABI only; request contents confer no authority.
///
/// # Safety
/// The controlled runner must own the fixed native control and read-only input
/// mapping, with Tool FS/stack active and the authenticated filter/gates live.
/// No guest code may have run and neither mapping may change while borrowed.
pub unsafe fn initial_packet(control: *const NativeControl) -> io::Result<&'static [u8]> {
    unsafe {
        checked_initial_control(control)?;
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    let address = read(unsafe { &raw const (*control).init_input });
    let length = read(unsafe { &raw const (*control).init_input_len });
    if address != 0x5300_0000_1000
        || length == 0
        || length > 4096
        || read(unsafe { &raw const (*control).input_mapping_base }) != address
        || read(unsafe { &raw const (*control).input_mapping_end }) != address + 4096
        || read(unsafe { &raw const (*control).init_input_fd }) != 201
    {
        return Err(io::Error::other(
            "invalid bounded native initialization packet",
        ));
    }
    Ok(unsafe { core::slice::from_raw_parts(address as *const u8, length as usize) })
}

/// The actual single native process/thread before InitialImage redemption.
///
/// # Safety
/// The control must satisfy the owned-mapping contract of [`initial_packet`].
pub unsafe fn native_tid(control: *const NativeControl) -> io::Result<i32> {
    unsafe {
        checked_initial_control(control)?;
    }
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    if tid <= 0
        || tid != pid
        || tid as u64 != unsafe { (&raw const (*control).native_tid).read_volatile() }
    {
        return Err(io::Error::other(
            "InitialImage native process identity differs",
        ));
    }
    Ok(tid as i32)
}

unsafe fn checked_initial_control(control: *const NativeControl) -> io::Result<()> {
    if control as usize != 0x5300_0000_0000 {
        return Err(io::Error::other(
            "InitialImage control is outside its owned page",
        ));
    }
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).phase }) != 2
        || read(unsafe { &raw const (*control).runtime_ready }) != 0
        || read(unsafe { &raw const (*control).native_state }) != 1
    {
        return Err(io::Error::other(
            "InitialImage native startup state differs",
        ));
    }
    Ok(())
}

/// End an explicit initialization failure without allocation, TLS or output.
/// This goes directly to the inherited fixed gate even before its Rust owner
/// is published. It never returns or attempts the legacy local syscall site.
///
/// # Safety
/// Only the controlled private runner may call this, with the exact inherited
/// fixed native gate already mapped and allowed by its initial filter.
pub unsafe fn initialization_failed(_control: *mut NativeControl) -> ! {
    unsafe { initial_terminal() }
}

#[unsafe(naked)]
unsafe extern "C" fn initial_terminal() -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "2:",
        "mov eax, 231",
        "mov edi, 127",
        "lea r12, [rip + 2b]",
        "movabs r11, 0x50000000007c",
        "jmp r11",
    );
}

/// Publish the one-thread native FS control after genuine coordinator admission.
///
/// # Safety
/// The caller must have authenticated this InitialImage against the launching
/// coordinator and verified the owned fixed gate, handler, filter and all
/// control extents. `control` must remain mapped, unaliased by Rust references,
/// and protected from guest mapping changes for the process lifetime. Native
/// entry must already use the private Tool FS. No guest code may have run.
/// This function does not establish any of those external facts. An armed
/// [`InitialImageAbortGuard`] must span this call through verified readiness;
/// errors after gate adoption cannot return to an unguarded initializer.
pub unsafe fn publish_authenticated_control(
    control: *mut NativeControl,
) -> io::Result<InitialImageControl> {
    if control.is_null() || (control as usize) & 63 != 0 {
        return Err(io::Error::other("unaligned native private control"));
    }
    // Raw reads: native signal entry owns disjoint mutable fields afterwards.
    let read = |p: *const u64| unsafe { p.read_volatile() };
    if read(unsafe { &raw const (*control).abi_version }) != 1
        || read(unsafe { &raw const (*control).byte_len }) != size_of::<NativeControl>() as u64
        || read(unsafe { &raw const (*control).phase }) != 2
        || read(unsafe { &raw const (*control).runtime_ready }) != 0
        || read(unsafe { &raw const (*control).tool_fs }) == 0
    {
        return Err(io::Error::other(
            "invalid private Tool initialization phase",
        ));
    }
    // Caller-context queries must use the qualified inherited gate. A query
    // relayed through bootstrap SIGSYS sees the handler mask and SS_ONSTACK.
    unsafe {
        crate::trap::adopt_authenticated_initial_gate()?;
        verify_bootstrap_signal(control)?;
    }
    reverie_inguest_private_exec_control
        .compare_exchange(0, control as usize, Ordering::Release, Ordering::Relaxed)
        .map_err(|_| io::Error::other("private Tool control published twice"))?;
    Ok(InitialImageControl::new(control as usize))
}

/// Fatal ownership from authenticated gate adoption until verified readiness.
/// This guard never writes diagnostics before its terminal syscall.
pub struct InitialImageAbortGuard {
    active: bool,
}

impl InitialImageAbortGuard {
    /// Arm before adopting the inherited gate and retain through initialization.
    ///
    /// # Safety
    /// The caller must have redeemed actual InitialImage authorization and own
    /// the native bootstrap's fixed terminal gate/phase. No Guest may run until
    /// the same control completes the existing full frontend/lifecycle checks.
    pub unsafe fn arm() -> Self {
        Self { active: true }
    }

    /// Disarm only after the actual control verifies and publishes readiness.
    /// Any error leaves the guard live, so destruction terminates this image.
    pub fn finish(mut self, control: &InitialImageControl) -> io::Result<()> {
        control.finish()?;
        self.active = false;
        Ok(())
    }
}

impl Drop for InitialImageAbortGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe { initial_terminal() }
        }
    }
}

/// Native syscall answer; permissions are meaningful only for the PKRU gate.
#[repr(C)]
pub struct PhysicalResult {
    /// The actual kernel return, including negative errno.
    pub result: i64,
    /// Actual post-syscall rights when a guest PKRU was supplied.
    pub pkru: u64,
}

unsafe extern "C" {
    fn reverie_inguest_private_guest_call(
        number: i64,
        args: *const u64,
        guest_pkru: u64,
        use_pkru: u64,
    ) -> PhysicalResult;
}

/// Execute a physical guest operation with its FS, restoring Tool FS before Rust.
/// Private bookkeeping must continue to use the ordinary trusted raw gate.
///
/// # Safety
/// Requires published, authenticated control in ToolCallback, owned surviving
/// stack/argument storage, and the same operation/PKRU constraints as
/// `trap::raw_syscall6_with_result`. Threads, exec, and user signal returns are
/// not admitted by this leaf. The caller must apply their existing guards.
pub unsafe fn physical_syscall(
    number: i64,
    args: [u64; 6],
    pkru: Option<u32>,
) -> crate::trap::NativeSyscallResult {
    let result = unsafe {
        reverie_inguest_private_guest_call(
            number,
            args.as_ptr(),
            u64::from(pkru.unwrap_or(0)),
            u64::from(pkru.is_some()),
        )
    };
    // The assembly leaf has restored Tool FS and callback phase before any
    // Rust executes. Preserve actual failed-call state; do not infer success
    // merely from the requested address or a Detcore-emulated return value.
    let control = control_pointer();
    unsafe {
        if number == libc::SYS_set_tid_address && result.result > 0 {
            (&raw mut (*control).kernel_clear_tid).write_volatile(args[0]);
        } else if number == libc::SYS_set_robust_list && result.result == 0 {
            (&raw mut (*control).kernel_robust_head).write_volatile(args[0]);
            (&raw mut (*control).kernel_robust_len).write_volatile(args[1]);
        }
    }
    crate::trap::NativeSyscallResult {
        result: result.result,
        pkru: pkru.map(|_| result.pkru as u32),
    }
}

// No Rust, TLS, libc or errno access is permitted between the two FS switches.
// All kernel transitions use the frozen fixed gate. GET_FS after the operation
// captures actual state even when ARCH_SET_FS returned an error.
core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global reverie_inguest_private_guest_call
    .hidden reverie_inguest_private_guest_call
    .type reverie_inguest_private_guest_call,@function
reverie_inguest_private_guest_call:
    endbr64
    push r12
    push r13
    push r14
    push r15
    push rbx
    sub rsp, 48
    mov [rsp], rdi
    mov [rsp + 8], rsi
    mov [rsp + 16], rdx
    mov [rsp + 24], rcx
    mov r13, [rip + reverie_inguest_private_exec_control]
    test r13, r13
    jz .Lprivate_terminal
    cmp qword ptr [r13 + 16], 4
    jne .Lprivate_terminal
    mov qword ptr [r13 + 16], 5
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 24]
    lea r12, [rip + .Lprivate_fs_guest_ready]
    movabs r11, 0x50000000007c
    jmp r11
.Lprivate_fs_guest_ready:
    endbr64
    test rax, rax
    jnz .Lprivate_terminal
    cmp qword ptr [rsp + 24], 0
    je .Lprivate_guest_scalar
    mov rdi, [rsp]
    mov rsi, [rsp + 8]
    mov rdx, [rsp + 16]
    movabs r11, 0x500000000100
    call r11
    mov r14, rax
    mov r15, rdx
    jmp .Lprivate_capture_guest_fs
.Lprivate_guest_scalar:
    mov rax, [rsp]
    mov rbx, [rsp + 8]
    mov rdi, [rbx]
    mov rsi, [rbx + 8]
    mov rdx, [rbx + 16]
    mov r10, [rbx + 24]
    mov r8, [rbx + 32]
    mov r9, [rbx + 40]
    lea r12, [rip + .Lprivate_guest_scalar_return]
    movabs r11, 0x50000000007c
    jmp r11
.Lprivate_guest_scalar_return:
    endbr64
    mov r14, rax
    xor r15d, r15d
.Lprivate_capture_guest_fs:
    mov eax, 158
    mov edi, 0x1003
    lea rsi, [rsp + 32]
    lea r12, [rip + .Lprivate_captured_guest_fs]
    movabs r11, 0x50000000007c
    jmp r11
.Lprivate_captured_guest_fs:
    endbr64
    test rax, rax
    jnz .Lprivate_terminal
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 32]
    lea r12, [rip + .Lprivate_restored_tool_fs]
    movabs r11, 0x50000000007c
    jmp r11
.Lprivate_restored_tool_fs:
    endbr64
    test rax, rax
    jnz .Lprivate_terminal
    mov rax, [rsp + 32]
    mov [r13 + 24], rax
    mov qword ptr [r13 + 16], 4
    mov rax, r14
    mov rdx, r15
    add rsp, 48
    pop rbx
    pop r15
    pop r14
    pop r13
    pop r12
    ret
.Lprivate_terminal:
    mov eax, 231
    mov edi, 127
    lea r12, [rip + .Lprivate_terminal]
    movabs r11, 0x50000000007c
    jmp r11
    .size reverie_inguest_private_guest_call, .-reverie_inguest_private_guest_call
"#
);

pub(crate) type SignalHandler = unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void);
unsafe extern "C" {
    fn private_sigsys_plain(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
    fn private_sigsys_pkru(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
    fn private_instruction_plain(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
    fn private_instruction_pkru(s: i32, i: *mut libc::siginfo_t, c: *mut libc::c_void);
}
pub(crate) fn signal_entry(instruction: bool, pkru: bool) -> SignalHandler {
    match (instruction, pkru) {
        (false, false) => private_sigsys_plain,
        (false, true) => private_sigsys_pkru,
        (true, false) => private_instruction_plain,
        (true, true) => private_instruction_pkru,
    }
}
fn control_pointer() -> *mut NativeControl {
    reverie_inguest_private_exec_control.load(Ordering::Acquire) as *mut NativeControl
}
fn terminal() -> ! {
    unsafe {
        crate::trap::raw_syscall6(libc::SYS_exit_group, [127, 0, 0, 0, 0, 0]);
    }
    loop {
        core::hint::spin_loop();
    }
}
pub(crate) fn callback_prepared() {
    let control = control_pointer();
    if control.is_null() {
        return;
    }
    unsafe {
        if (&raw const (*control).phase).read_volatile() != 3 {
            terminal();
        }
        (&raw mut (*control).phase).write_volatile(4);
    }
}
pub(crate) fn guest_completed() {
    let control = control_pointer();
    if control.is_null() {
        return;
    }
    unsafe {
        if (&raw const (*control).phase).read_volatile() != 4 {
            terminal();
        }
        (&raw mut (*control).phase).write_volatile(3);
    }
}
pub(crate) fn private_instruction(address: u64) -> bool {
    let control = control_pointer();
    if control.is_null() {
        return false;
    }
    unsafe {
        if !matches!((&raw const (*control).phase).read_volatile(), 2 | 4) {
            return false;
        }
        let count = (&raw const (*control).private_code_count).read_volatile();
        if count > 64 {
            terminal();
        }
        for i in 0..count as usize {
            let item = (&raw const (*control).code).cast::<PrivateCode>().add(i);
            let lo = (&raw const (*item).lo).read_volatile();
            let hi = (&raw const (*item).hi).read_volatile();
            if address >= lo && address < hi {
                return true;
            }
        }
    }
    false
}
// Only called after the normal SIGSYS provenance checks. Private libc has its
// own physical effects; it does not recursively enter Detcore. The genuine
// completion remains owned by continuation::complete, even inside Tool code.
pub(crate) unsafe fn relay_private_signal(
    signal: i32,
    info: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) -> bool {
    let ip = unsafe {
        (*context.cast::<libc::ucontext_t>()).uc_mcontext.gregs[libc::REG_RIP as usize] as u64
    };
    if super::continuation::is_completion_address(ip) || !private_instruction(ip.saturating_sub(2))
    {
        return false;
    }
    let control = control_pointer();
    let address = unsafe { (&raw const (*control).bootstrap_handler).read_volatile() };
    if address == 0 {
        terminal();
    }
    let handler: SignalHandler = unsafe { core::mem::transmute(address as usize) };
    unsafe {
        handler(signal, info, context);
    }
    true
}

// Native SA_SIGINFO bridges. The optional PKRU opening occurs before the first
// stack/global access. FS switches use only the fixed native gate. Rust sees
// only Tool FS, and no Rust/TLS access occurs after restoring guest FS.
core::arch::global_asm!(r#"
    .text
    .macro PRIVATE_SIGNAL_ENTRY name, handler, pkru
    .p2align 4
    .global \name
    .hidden \name
    .type \name,@function
\name:
    endbr64
    .if \pkru
    mov r8, rdx
    xor eax, eax
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    mov rdx, r8
    .endif
    lea rcx, [rip + \handler]
    jmp .Lprivate_signal_common
    .size \name, .-\name
    .endm
    PRIVATE_SIGNAL_ENTRY private_sigsys_plain, {syscall_handler}, 0
    PRIVATE_SIGNAL_ENTRY private_sigsys_pkru, {syscall_handler}, 1
    PRIVATE_SIGNAL_ENTRY private_instruction_plain, {instruction_handler}, 0
    PRIVATE_SIGNAL_ENTRY private_instruction_pkru, {instruction_handler}, 1
    .purgem PRIVATE_SIGNAL_ENTRY
.Lprivate_signal_common:
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push rdx
    sub rsp, 16
    mov r14, rcx
    mov r13, [rip + reverie_inguest_private_exec_control]
    test r13, r13
    jz .Lprivate_signal_terminal
    mov eax, 158
    mov edi, 0x1003
    mov rsi, rsp
    lea r12, [rip + .Lprivate_signal_have_fs]
    movabs r11, 0x50000000007c
    jmp r11
.Lprivate_signal_have_fs:
    endbr64
    test rax, rax
    jnz .Lprivate_signal_terminal
    mov r15, [r13 + 16]
    cmp r15, 3
    je .Lprivate_signal_from_guest
    cmp r15, 2
    je .Lprivate_signal_from_tool
    cmp r15, 4
    jne .Lprivate_signal_terminal
.Lprivate_signal_from_tool:
    mov rax, [rsp]
    cmp rax, [r13 + 32]
    jne .Lprivate_signal_terminal
    jmp .Lprivate_signal_set_tool
.Lprivate_signal_from_guest:
    mov rax, [rsp]
    mov [r13 + 24], rax
.Lprivate_signal_set_tool:
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 32]
    lea r12, [rip + .Lprivate_signal_tool_ready]
    movabs r11, 0x50000000007c
    jmp r11
.Lprivate_signal_tool_ready:
    endbr64
    test rax, rax
    jnz .Lprivate_signal_terminal
    mov rdi, [rsp + 32]
    mov rsi, [rsp + 24]
    mov rdx, [rsp + 16]
    call r14
    mov rax, [r13 + 16]
    cmp rax, 3
    je .Lprivate_signal_return_guest
    cmp rax, 2
    je .Lprivate_signal_return
    cmp rax, 4
    jne .Lprivate_signal_terminal
    jmp .Lprivate_signal_return
.Lprivate_signal_return_guest:
    mov eax, 158
    mov edi, 0x1002
    mov rsi, [r13 + 24]
    lea r12, [rip + .Lprivate_signal_guest_ready]
    movabs r11, 0x50000000007c
    jmp r11
.Lprivate_signal_guest_ready:
    endbr64
    test rax, rax
    jnz .Lprivate_signal_terminal
.Lprivate_signal_return:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    ret
.Lprivate_signal_terminal:
    mov eax, 231
    mov edi, 127
    lea r12, [rip + .Lprivate_signal_terminal]
    movabs r11, 0x50000000007c
    jmp r11
"#,
    syscall_handler = sym crate::trap::sigsys_handler,
    instruction_handler = sym super::instruction::instruction_sigsegv_handler,
);

#[cfg(test)]
pub(super) fn lifecycle_test_owner() -> (Box<NativeControl>, InitialImageControl) {
    // Component fixture only: this does not install a signal frontend, redeem
    // a coordinator authorization or authenticate a native launch. Run only
    // in the isolated child used by the lifecycle tests.
    unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
    let mut fs = 0_u64;
    assert_eq!(
        unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        },
        0
    );
    let mut native: Box<NativeControl> = Box::new(unsafe { core::mem::zeroed() });
    native.abi_version = 1;
    native.byte_len = size_of::<NativeControl>() as u64;
    native.phase = 2;
    native.tool_fs = fs;
    native.native_tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
    let address = core::ptr::from_mut(native.as_mut()) as usize;
    reverie_inguest_private_exec_control.store(address, Ordering::Release);
    (native, InitialImageControl::new(address))
}

#[cfg(test)]
pub(super) fn mark_lifecycle_test_frontend_installed(owner: &InitialImageControl) {
    assert_eq!(owner.installation.load(Ordering::Acquire), 0);
    // Exercises the lifecycle gate independently of the native installer;
    // finish's genuine kernel/frontend validation is never bypassed.
    owner.installation.store(2, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    thread_local! { static TOOL_SENTINEL: core::cell::Cell<u64> = const { core::cell::Cell::new(0) }; }
    fn isolated(body: fn(), expected: i32) {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if std::panic::catch_unwind(body).is_ok() {
                0
            } else {
                125
            };
            unsafe {
                libc::_exit(status);
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child wait status {status}");
        assert_eq!(libc::WEXITSTATUS(status), expected);
    }
    unsafe fn scalar_control() -> NativeControl {
        unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
        let mut fs = 0_u64;
        assert_eq!(
            unsafe {
                crate::trap::raw_syscall6(
                    libc::SYS_arch_prctl,
                    [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
                )
            },
            0
        );
        let mut control: NativeControl = unsafe { core::mem::zeroed() };
        control.abi_version = 1;
        control.byte_len = size_of::<NativeControl>() as u64;
        control.phase = 4;
        control.tool_fs = fs;
        control.guest_fs = 0;
        control
    }
    #[test]
    fn physical_guest_set_fs_preserves_tool_tls_and_keeps_actual_success_or_error() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                // A native-leaf-only fixture. This assignment is NOT initializer,
                // coordinator, filter adoption or guest-launch authentication.
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                TOOL_SENTINEL.set(0x54_4f_4f_4c);
                unsafe {
                    *libc::__errno_location() = libc::ENOMSG;
                }
                let mut guest_tls = [0_u64; 32];
                let selected_fs = guest_tls.as_mut_ptr() as u64;
                let result = unsafe {
                    physical_syscall(
                        libc::SYS_arch_prctl,
                        [0x1002, selected_fs, 0, 0, 0, 0],
                        None,
                    )
                };
                assert_eq!(result.result, 0);
                assert_eq!(control.guest_fs, selected_fs);
                assert_eq!(TOOL_SENTINEL.get(), 0x54_4f_4f_4c);
                assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOMSG);
                let mut observed = 0_u64;
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_arch_prctl,
                            [0x1003, (&raw mut observed) as u64, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(observed, selected_fs);
                let expected = unsafe {
                    crate::trap::raw_syscall6(libc::SYS_arch_prctl, [0x1002, u64::MAX, 0, 0, 0, 0])
                };
                assert!(expected < 0);
                let error = unsafe {
                    physical_syscall(libc::SYS_arch_prctl, [0x1002, u64::MAX, 0, 0, 0, 0], None)
                };
                assert_eq!(error.result, expected);
                assert_eq!(control.guest_fs, selected_fs);
                assert_eq!(TOOL_SENTINEL.get(), 0x54_4f_4f_4c);
                assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOMSG);
                assert_eq!(control.phase, 4);
            },
            0,
        );
    }
    #[test]
    fn guest_injection_outside_its_callback_ends_before_the_syscall() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                control.phase = 3;
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let _ =
                    unsafe { physical_syscall(libc::SYS_exit_group, [73, 0, 0, 0, 0, 0], None) };
            },
            127,
        );
    }
    #[test]
    fn physical_guest_registration_keeps_the_current_successful_kernel_values() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let mut clear_tid = 41_i32;
                let clear_address = (&raw mut clear_tid) as u64;
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_tid_address,
                            [clear_address, 0, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    tid
                );
                assert_eq!(control.kernel_clear_tid, clear_address);

                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let robust_len = size_of_val(&robust) as u64;
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [robust_address, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(control.kernel_robust_head, robust_address);
                assert_eq!(control.kernel_robust_len, robust_len);
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [0, robust_len - 1, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    -i64::from(libc::EINVAL)
                );
                assert_eq!(control.kernel_robust_head, robust_address);
                assert_eq!(control.kernel_robust_len, robust_len);
                let mut actual_head = 0_u64;
                let mut actual_len = 0_u64;
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_get_robust_list,
                            [
                                0,
                                (&raw mut actual_head) as u64,
                                (&raw mut actual_len) as u64,
                                0,
                                0,
                                0,
                            ],
                        )
                    },
                    0
                );
                assert_eq!((actual_head, actual_len), (robust_address, robust_len));
                assert_eq!(clear_tid, 41);
                // Remove only this isolated native-leaf fixture's registrations
                // before its local buffers go out of scope. This is not exec.
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [0, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(
                    unsafe { physical_syscall(libc::SYS_set_tid_address, [0; 6], None) }.result,
                    tid
                );
                assert_eq!(control.kernel_clear_tid, 0);
                assert_eq!(control.kernel_robust_head, 0);
            },
            0,
        );
    }

    #[test]
    fn native_nested_tool_registration_setters_are_refused_before_forwarding() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let mut clear_tid = 73_i32;
                let mut robust = [0_u64; 3];
                robust[0] = robust.as_mut_ptr() as u64;
                for (number, args) in [
                    (
                        libc::SYS_set_tid_address,
                        [(&raw mut clear_tid) as u64, 0, 0, 0, 0, 0],
                    ),
                    (
                        libc::SYS_set_robust_list,
                        [
                            robust.as_ptr() as u64,
                            size_of_val(&robust) as u64,
                            0,
                            0,
                            0,
                            0,
                        ],
                    ),
                ] {
                    let mut event = crate::guest::event::SyscallEvent {
                        number,
                        args,
                        instruction_pointer: 0,
                        result: i64::MIN,
                        context: 0,
                        dispatch: crate::guest::event::SyscallDispatch::Trap,
                        guest_pkru: None,
                    };
                    let mut observed = false;
                    unsafe {
                        crate::guest::trap_dispatch::forward_nested_tool_syscall(
                            &mut event,
                            |_| observed = true,
                        );
                    }
                    assert_eq!(event.result, -i64::from(libc::EPERM));
                    assert!(!observed);
                }
            },
            0,
        );
    }

    #[test]
    fn callback_kernel_registrations_requires_actual_owner_and_current_robust_list() {
        isolated(
            || {
                assert_eq!(callback_kernel_registrations(), None);
                let mut control = unsafe { scalar_control() };
                control.native_tid =
                    unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
                reverie_inguest_private_exec_control
                    .store((&raw mut control) as usize, Ordering::Release);
                let mut clear_tid = 73_i32;
                let clear_address = (&raw mut clear_tid) as u64;
                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let robust_len = size_of_val(&robust) as u64;
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_tid_address,
                            [clear_address, 0, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    control.native_tid as i64
                );
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [robust_address, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(callback_kernel_registrations(), None); // not ready
                unsafe { (&raw mut control.runtime_ready).write_volatile(1) };
                let expected = Some(GuestKernelRegistrations {
                    clear_tid: clear_address,
                    robust_head: robust_address,
                    robust_len,
                });
                assert_eq!(callback_kernel_registrations(), expected);
                assert_eq!(callback_kernel_registrations(), expected);
                assert_eq!(clear_tid, 73);
                assert_eq!(control.kernel_clear_tid, clear_address);
                unsafe { (&raw mut control.kernel_robust_head).write_volatile(0) };
                assert_eq!(callback_kernel_registrations(), None);
                unsafe {
                    (&raw mut control.kernel_robust_head).write_volatile(robust_address);
                    (&raw mut control.phase).write_volatile(3);
                }
                assert_eq!(callback_kernel_registrations(), None);
                unsafe { (&raw mut control.phase).write_volatile(4) };
                assert_eq!(callback_kernel_registrations(), expected);
                // Test-only cleanup before the stack buffers are dropped.
                assert_eq!(
                    unsafe {
                        physical_syscall(
                            libc::SYS_set_robust_list,
                            [0, robust_len, 0, 0, 0, 0],
                            None,
                        )
                    }
                    .result,
                    0
                );
                assert_eq!(
                    unsafe { physical_syscall(libc::SYS_set_tid_address, [0; 6], None) }.result,
                    control.native_tid as i64
                );
            },
            0,
        );
    }

    #[test]
    fn ordinary_nested_registration_setters_keep_their_existing_forwarding() {
        isolated(
            || {
                assert!(!active());
                let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
                let mut clear_tid = 73_i32;
                let mut robust = [0_u64; 3];
                let robust_address = robust.as_mut_ptr() as u64;
                robust[0] = robust_address;
                let robust_len = size_of_val(&robust) as u64;
                for (number, args, expected) in [
                    (
                        libc::SYS_set_tid_address,
                        [(&raw mut clear_tid) as u64, 0, 0, 0, 0, 0],
                        tid,
                    ),
                    (
                        libc::SYS_set_robust_list,
                        [robust_address, robust_len, 0, 0, 0, 0],
                        0,
                    ),
                ] {
                    let mut event = crate::guest::event::SyscallEvent {
                        number,
                        args,
                        instruction_pointer: 0,
                        result: i64::MIN,
                        context: 0,
                        dispatch: crate::guest::event::SyscallDispatch::Trap,
                        guest_pkru: None,
                    };
                    let mut observed = false;
                    unsafe {
                        crate::guest::trap_dispatch::forward_nested_tool_syscall(
                            &mut event,
                            |_| observed = true,
                        );
                    }
                    assert_eq!(event.result, expected);
                    assert!(observed);
                }
                let mut actual_head = 0_u64;
                let mut actual_len = 0_u64;
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_get_robust_list,
                            [
                                0,
                                (&raw mut actual_head) as u64,
                                (&raw mut actual_len) as u64,
                                0,
                                0,
                                0,
                            ],
                        )
                    },
                    0
                );
                assert_eq!((actual_head, actual_len), (robust_address, robust_len));
                assert_eq!(
                    unsafe {
                        crate::trap::raw_syscall6(
                            libc::SYS_set_robust_list,
                            [0, robust_len, 0, 0, 0, 0],
                        )
                    },
                    0
                );
                assert_eq!(
                    unsafe { crate::trap::raw_syscall6(libc::SYS_set_tid_address, [0; 6]) },
                    tid
                );
            },
            0,
        );
    }
    #[test]
    fn finish_refuses_software_flags_without_a_completed_native_frontend() {
        isolated(
            || {
                let mut control = unsafe { scalar_control() };
                control.phase = 2;
                crate::trap::set_dispatcher(
                    Box::new(crate::dispatch::PassthroughDispatcher::new()),
                );
                crate::trap::set_signal_return_restricted();
                // Deliberately only the old software prerequisites. This is
                // not an authenticated native owner or installed frontend.
                let owner = InitialImageControl::new((&raw mut control) as usize);
                assert!(owner.finish().is_err());
                assert_eq!(control.runtime_ready, 0);
            },
            0,
        );
    }
    #[test]
    fn isolated_assertion_failure_is_a_nonzero_child_exit() {
        isolated(|| panic!("deliberate child assertion failure"), 125);
    }

    #[test]
    fn initial_abort_owner_drop_never_returns_or_writes_to_full_stderr() {
        isolated(
            || {
                // Component fixture owns a real fixed terminal gate. It does
                // not claim coordinator authorization or a completed image.
                unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
                let mut pipe = [-1; 2];
                assert_eq!(
                    unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK) },
                    0
                );
                let bytes = [0_u8; 4096];
                loop {
                    let result =
                        unsafe { libc::write(pipe[1], bytes.as_ptr().cast(), bytes.len()) };
                    if result < 0 {
                        assert_eq!(
                            io::Error::last_os_error().raw_os_error(),
                            Some(libc::EAGAIN)
                        );
                        break;
                    }
                }
                assert_eq!(unsafe { libc::fcntl(pipe[1], libc::F_SETFL, 0) }, 0);
                assert_eq!(unsafe { libc::dup2(pipe[1], 2) }, 2);
                let fatal = unsafe { InitialImageAbortGuard::arm() };
                drop(fatal);
                unsafe { libc::_exit(91) };
            },
            127,
        );
    }

    #[test]
    fn initial_abort_owner_refuses_invalid_publication_and_failed_finish() {
        isolated(
            || {
                unsafe { crate::trap::prepare_fixed_gates() }.unwrap();
                let fatal = unsafe { InitialImageAbortGuard::arm() };
                assert!(unsafe { publish_authenticated_control(core::ptr::null_mut()) }.is_err());
                drop(fatal);
                unsafe { libc::_exit(92) };
            },
            127,
        );
        isolated(
            || {
                let mut native = unsafe { scalar_control() };
                native.phase = 2;
                let owner = InitialImageControl::new((&raw mut native) as usize);
                let fatal = unsafe { InitialImageAbortGuard::arm() };
                // No real frontend/lifecycle was installed. The existing
                // readiness checks must fail and fatal ownership must survive.
                let _ = fatal.finish(&owner);
                unsafe { libc::_exit(93) };
            },
            127,
        );
    }

    #[test]
    fn initial_vdso_context_requires_same_fresh_native_owner() {
        isolated(
            || {
                for mutation in 0..9 {
                    let (mut native, mut owner) = lifecycle_test_owner();
                    owner.check_initial_vdso_context().unwrap();
                    owner.check_initial_vdso_context().unwrap();
                    assert_eq!(native.runtime_ready, 0);
                    match mutation {
                        0 => native.phase = 3,
                        1 => native.runtime_ready = 1,
                        2 => native.native_tid += 1,
                        3 => native.tool_fs ^= 1,
                        4 => reverie_inguest_private_exec_control.store(0, Ordering::Release),
                        5 => owner.installation.store(1, Ordering::Release),
                        6 => owner.installed_host.store(1, Ordering::Release),
                        7 => owner.lifecycle.store(1, Ordering::Release),
                        8 => owner.control = 0,
                        _ => unreachable!(),
                    }
                    assert!(
                        owner.check_initial_vdso_context().is_err(),
                        "context mutation {mutation}"
                    );
                }
            },
            0,
        );
    }

    #[test]
    fn initial_lifecycle_is_affine_and_abandonment_prevents_finish() {
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                let permit = owner.begin_lifecycle(1).unwrap();
                drop(permit);
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert!(owner.begin_lifecycle(1).is_err());
                let error = owner.finish().unwrap_err();
                assert!(error.to_string().contains("lifecycle did not complete"));
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
    }

    #[test]
    fn initial_lifecycle_requires_completed_frontend_and_same_host() {
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                assert!(owner.begin_lifecycle(1).is_err());
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                let error = owner.begin_lifecycle(2).err().unwrap();
                assert!(error.to_string().contains("installed host/frontend"));
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
    }

    #[test]
    fn initial_lifecycle_revalidates_tid_fs_phase_and_never_reopens() {
        for mutation in 0..4 {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                let status = if std::panic::catch_unwind(|| {
                    let (mut native, owner) = lifecycle_test_owner();
                    owner.bind_lifecycle_host(1).unwrap();
                    mark_lifecycle_test_frontend_installed(&owner);
                    let permit = owner.begin_lifecycle(1).unwrap();
                    match mutation {
                        0 => native.native_tid += 1,
                        1 => native.tool_fs ^= 8,
                        2 => native.phase = 4,
                        3 => native.runtime_ready = 1,
                        _ => unreachable!(),
                    }
                    let error = permit.complete().unwrap_err();
                    assert!(error.to_string().contains("FS/process/phase differs"));
                    assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                    assert!(owner.begin_lifecycle(1).is_err());
                })
                .is_ok()
                {
                    0
                } else {
                    125
                };
                unsafe { libc::_exit(status) };
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }

    #[test]
    fn duplicate_initial_lifecycle_attempt_poison_is_not_a_completion_flag() {
        isolated(
            || {
                let (native, owner) = lifecycle_test_owner();
                owner.bind_lifecycle_host(1).unwrap();
                mark_lifecycle_test_frontend_installed(&owner);
                let permit = owner.begin_lifecycle(1).unwrap();
                assert!(owner.begin_lifecycle(1).is_err());
                assert!(permit.complete().is_err());
                assert_eq!(owner.lifecycle.load(Ordering::Acquire), 3);
                assert_eq!(native.runtime_ready, 0);
            },
            0,
        );
    }

    #[test]
    fn callback_native_tid_requires_actual_ready_callback_identity() {
        isolated(
            || {
                assert_eq!(callback_native_tid(), None);
                let mut native = unsafe { scalar_control() };
                native.native_tid =
                    unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) } as u64;
                reverie_inguest_private_exec_control
                    .store((&raw mut native) as usize, Ordering::Release);
                assert_eq!(callback_native_tid(), None); // ready is still zero
                unsafe { (&raw mut native.runtime_ready).write_volatile(1) };
                assert_eq!(callback_native_tid(), Some(native.native_tid as i32));
                unsafe { (&raw mut native.phase).write_volatile(2) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.phase).write_volatile(4) };
                unsafe { (&raw mut native.native_tid).write_volatile(native.native_tid + 1) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.native_tid).write_volatile(native.native_tid - 1) };
                unsafe { (&raw mut native.tool_fs).write_volatile(native.tool_fs ^ 8) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.tool_fs).write_volatile(native.tool_fs ^ 8) };
                unsafe { (&raw mut native.abi_version).write_volatile(2) };
                assert_eq!(callback_native_tid(), None);
                unsafe { (&raw mut native.abi_version).write_volatile(1) };
                unsafe { (&raw mut native.byte_len).write_volatile(native.byte_len - 8) };
                assert_eq!(callback_native_tid(), None);
            },
            0,
        );
    }
}

// Extents describe private native mappings, not guest ld.so or guest DSOs.
// Reuse the existing complete effective-range operation inventory, including
// huge-page rounding and Linux brk return semantics, through owner_overlaps.
pub(crate) fn overlaps_private(start: u64, length: u64) -> bool {
    let control = control_pointer();
    if control.is_null() || length == 0 {
        return false;
    }
    let lo = start & !4095;
    let hi = start.saturating_add(length);
    let overlaps = |first, end| lo < end && first < hi;
    if overlaps(0x5000_0000_0000, 0x5000_0008_0000)
        || overlaps(0x5300_0000_0000, 0x5300_0012_0000)
        || overlaps(0x5400_0000_0000, 0x5400_0080_0000)
    {
        return true;
    }
    unsafe {
        let count = (&raw const (*control).private_map_count).read_volatile();
        if count > 64 {
            terminal();
        }
        for i in 0..count as usize {
            let item = (&raw const (*control).maps).cast::<PrivateMap>().add(i);
            let first = (&raw const (*item).lo).read_volatile();
            let end = (&raw const (*item).hi).read_volatile();
            if overlaps(first, end) {
                return true;
            }
        }
    }
    false
}

/// One authenticated InitialImage's native handover. Not constructible from a
/// configuration flag, memfd seal or filter count alone.
pub struct InitialImageControl {
    control: usize,
    // 0 fresh, 1 installation attempted, 2 actual installation completed,
    // 3 final verification attempted, 4 ready. Failure never reopens a state.
    installation: AtomicUsize,
    region: core::sync::atomic::AtomicPtr<super::tool_region::ToolRegion>,
    installed_host: AtomicUsize,
    // 0 not started, 1 permit live, 2 callbacks completed, 3 refused/abandoned.
    // Neither a returned error nor dropping a permit reopens initialization.
    lifecycle: AtomicUsize,
}
impl InitialImageControl {
    fn new(control: usize) -> Self {
        Self {
            control,
            installation: AtomicUsize::new(0),
            region: core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
            installed_host: AtomicUsize::new(0),
            lifecycle: AtomicUsize::new(0),
        }
    }

    /// Check the authenticated initial Tool context before and after its one
    /// bounded vDSO rewrite, before any frontend or installed host is published.
    /// This grants no mapping or syscall exemption.
    pub fn check_initial_vdso_context(&self) -> io::Result<()> {
        if self.installation.load(Ordering::Acquire) != 0
            || self.installed_host.load(Ordering::Acquire) != 0
            || self.lifecycle.load(Ordering::Acquire) != 0
        {
            return Err(io::Error::other(
                "InitialImage vDSO rewrite is outside initial installation",
            ));
        }
        self.check_initial_thread()
    }

    /// Bind the actual stable installed ToolHost, before frontend installation.
    /// Only the backend's installed-handler bridge may supply this address.
    pub(super) fn bind_lifecycle_host(&self, host: usize) -> io::Result<()> {
        if host == 0 || self.installation.load(Ordering::Acquire) != 0 {
            return Err(io::Error::other(
                "InitialImage host binding is out of order",
            ));
        }
        self.check_initial_thread()?;
        self.installed_host
            .compare_exchange(0, host, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("InitialImage host was bound twice"))?;
        Ok(())
    }

    pub(super) fn begin_lifecycle(&self, host: usize) -> io::Result<InitialLifecyclePermit<'_>> {
        if self
            .lifecycle
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.lifecycle.store(3, Ordering::Release);
            return Err(io::Error::other(
                "InitialImage lifecycle was attempted twice",
            ));
        }
        let permit = InitialLifecyclePermit {
            owner: self,
            host,
            completed: false,
            _same_thread: core::marker::PhantomData,
        };
        if self.installation.load(Ordering::Acquire) != 2
            || host == 0
            || self.installed_host.load(Ordering::Acquire) != host
        {
            return Err(io::Error::other(
                "InitialImage lifecycle lacks its installed host/frontend",
            ));
        }
        self.check_initial_thread()?;
        Ok(permit)
    }

    fn check_initial_thread(&self) -> io::Result<()> {
        if self.control == 0
            || reverie_inguest_private_exec_control.load(Ordering::Acquire) != self.control
        {
            return Err(io::Error::other("InitialImage native owner differs"));
        }
        let control = self.control as *const NativeControl;
        let read = |p: *const u64| unsafe { p.read_volatile() };
        let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
        let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
        let mut fs = 0_u64;
        let rc = unsafe {
            crate::trap::raw_syscall6(
                libc::SYS_arch_prctl,
                [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
            )
        };
        if read(unsafe { &raw const (*control).phase }) != 2
            || read(unsafe { &raw const (*control).runtime_ready }) != 0
            || tid <= 0
            || pid != tid
            || tid as u64 != read(unsafe { &raw const (*control).native_tid })
            || rc != 0
            || fs == 0
            || fs != read(unsafe { &raw const (*control).tool_fs })
        {
            return Err(io::Error::other(
                "InitialImage lifecycle Tool FS/process/phase differs",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "coordinator-rpc")]
    pub(super) fn terminate_lifecycle(&self) -> ! {
        self.lifecycle.store(3, Ordering::Release);
        // The private constructor has already authenticated and adopted the
        // surviving fixed gate. No diagnostic I/O can precede this exit.
        unsafe { initialization_failed(self.control as *mut NativeControl) }
    }
    /// Select the already installed filter while replacing its owned frontend.
    /// The backing must belong to this initializer's fixed Tool region.
    pub fn controller(
        &self,
        backing: super::tool_region::StackBacking,
    ) -> impl crate::lifecycle::LifecycleController {
        InitialImageController {
            owner: self,
            backing,
        }
    }
    /// Save the real guest resume mask; keep bootstrap SIGSYS usable and
    /// inherited asynchronous signals blocked until native final resume.
    pub fn prepare_signal_state(
        &self,
        instructions: super::instruction::InstructionSubscriptions,
    ) -> io::Result<()> {
        let control = self.control as *mut NativeControl;
        unsafe {
            verify_bootstrap_signal(control)?;
        }
        let mut reserved = 1_u64 << (libc::SIGSYS - 1);
        if instructions.cpuid || instructions.rdtsc {
            reserved |= 1_u64 << (libc::SIGSEGV - 1);
        }
        unsafe {
            let mask = (&raw const (*control).kernel_mask).read_volatile() & !reserved;
            (&raw mut (*control).guest_resume_mask).write_volatile(mask);
        }
        for signal in 1..=64 {
            if matches!(signal, libc::SIGKILL | libc::SIGSTOP | libc::SIGSYS) {
                continue;
            }
            let mut action = crate::signal::KernelSigaction::default();
            unsafe { crate::signal::raw_sigaction(signal, None, Some(&mut action)) }
                .map_err(io::Error::from_raw_os_error)?;
            if action.handler != libc::SIG_DFL as u64 && action.handler != libc::SIG_IGN as u64 {
                unsafe {
                    crate::signal::raw_sigaction(
                        signal,
                        Some(&crate::signal::KernelSigaction::default()),
                        None,
                    )
                }
                .map_err(io::Error::from_raw_os_error)?;
            }
        }
        Ok(())
    }
    /// Mark genuine Detcore installation complete. This does not itself enter
    /// Guest; only the native runner restores registrations, FS, mask and RSP.
    pub fn finish(&self) -> io::Result<()> {
        self.installation
            .compare_exchange(2, 3, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("private frontend installation did not complete once"))?;
        if self.installed_host.load(Ordering::Acquire) == 0
            || self.lifecycle.load(Ordering::Acquire) != 2
        {
            self.lifecycle.store(3, Ordering::Release);
            return Err(io::Error::other(
                "InitialImage installed-host lifecycle did not complete",
            ));
        }
        let control = self.control as *mut NativeControl;
        if !crate::trap::has_dispatcher()
            || !crate::trap::signal_return_restricted()
            || unsafe { (&raw const (*control).phase).read_volatile() } != 2
            || unsafe { (&raw const (*control).runtime_ready).read_volatile() } != 0
        {
            return Err(io::Error::other("private Tool frontend is incomplete"));
        }
        let region = self.region.load(Ordering::Acquire);
        let region = unsafe { region.as_ref() }
            .ok_or_else(|| io::Error::other("private frontend has no owned signal stack"))?;
        unsafe { verify_final_frontend(control, region)? };
        unsafe {
            (&raw mut (*control).runtime_ready).write_volatile(1);
        }
        self.installation.store(4, Ordering::Release);
        Ok(())
    }
}

/// A single synchronous lifecycle attempt on the installed host and native
/// thread. Not exported: only the core host can mark successful completion.
pub(super) struct InitialLifecyclePermit<'a> {
    owner: &'a InitialImageControl,
    host: usize,
    completed: bool,
    _same_thread: core::marker::PhantomData<*mut ()>,
}

impl InitialLifecyclePermit<'_> {
    pub(super) fn complete(mut self) -> io::Result<()> {
        if self.owner.installation.load(Ordering::Acquire) != 2
            || self.owner.installed_host.load(Ordering::Acquire) != self.host
        {
            return Err(io::Error::other("InitialImage lifecycle owner changed"));
        }
        self.owner.check_initial_thread()?;
        self.owner
            .lifecycle
            .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("InitialImage lifecycle was refused"))?;
        self.completed = true;
        Ok(())
    }
}

impl Drop for InitialLifecyclePermit<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.lifecycle.store(3, Ordering::Release);
        }
    }
}

struct InitialImageController<'a> {
    owner: &'a InitialImageControl,
    backing: super::tool_region::StackBacking,
}
impl crate::lifecycle::LifecycleController for InitialImageController<'_> {
    fn name(&self) -> &'static str {
        "authenticated-initial-image"
    }
    unsafe fn install(&self, config: &crate::lifecycle::RuntimeConfig) -> io::Result<()> {
        self.owner
            .installation
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::other("private frontend installation attempted twice"))?;
        let super::tool_region::StackBacking::ToolRegion(region) = self.backing else {
            return Err(io::Error::other(
                "private frontend requires owned signal stack backing",
            ));
        };
        if !config.use_alt_stack || !config.restrict_signal_return || !crate::trap::has_dispatcher()
        {
            return Err(io::Error::other("invalid private frontend handover"));
        }
        unsafe {
            verify_bootstrap_signal(self.owner.control as *mut NativeControl)?;
        }
        // Prepare frame/PKRU/owned stack before the final single raw action
        // replacement. Bootstrap SIGSYS remains usable throughout preparation.
        unsafe {
            crate::trap::install_handler_with_backing(true, self.backing)?;
        }
        crate::trap::set_signal_return_restricted();
        // No new seccomp filter: the authenticated inherited one is the owner.
        let unblocked = super::signal::reserved_signal_mask();
        unsafe { crate::signal::raw_sigprocmask(libc::SIG_UNBLOCK, Some(&unblocked), None) }
            .map_err(io::Error::from_raw_os_error)?;
        self.owner
            .region
            .store(core::ptr::from_ref(region).cast_mut(), Ordering::Release);
        self.owner.installation.store(2, Ordering::Release);
        Ok(())
    }
}
unsafe fn verify_final_frontend(
    control: *mut NativeControl,
    region: &'static super::tool_region::ToolRegion,
) -> io::Result<()> {
    let mut fs = 0_u64;
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    if rc != 0
        || fs != unsafe { (&raw const (*control).tool_fs).read_volatile() }
        || tid <= 0
        || tid != pid
        || tid as u64 != unsafe { (&raw const (*control).native_tid).read_volatile() }
        || unsafe { super::sigalrm::seccomp_filter_count() } != Some(1)
    {
        return Err(io::Error::other(
            "private final Tool FS/process/filter differs",
        ));
    }
    let reserved = super::signal::reserved_signal_mask();
    let unmaskable = (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1));
    let mut mask = 0_u64;
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }
        .map_err(io::Error::from_raw_os_error)?;
    if mask != !(reserved | unmaskable) {
        return Err(io::Error::other(
            "private final startup signal mask differs",
        ));
    }
    for (signal, instruction) in [(libc::SIGSYS, false), (libc::SIGSEGV, true)] {
        if reserved & (1_u64 << (signal - 1)) == 0 {
            continue;
        }
        let mut action = crate::signal::KernelSigaction::default();
        unsafe { crate::signal::raw_sigaction(signal, None, Some(&mut action)) }
            .map_err(io::Error::from_raw_os_error)?;
        if action.handler
            != signal_entry(instruction, crate::trap::pkru_present()) as *const () as u64
            || action.restorer != crate::trap::FIXED_SIGNAL_RESTORER_ENTRY
            || action.flags
                != (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64
            || action.mask != 0
        {
            return Err(io::Error::other(
                "private final runtime signal action differs",
            ));
        }
    }
    let owned = region
        .registered_alternate_stack()
        .ok_or_else(|| io::Error::other("private final owned signal stack is unpublished"))?;
    let mut stack: libc::stack_t = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_sigaltstack,
            [0, (&raw mut stack) as u64, 0, 0, 0, 0],
        )
    };
    if rc != 0
        || stack.ss_flags != 0
        || stack.ss_sp as usize != owned.bottom
        || owned.top.checked_sub(owned.bottom) != Some(stack.ss_size)
    {
        return Err(io::Error::other(
            "private final runtime alternate stack differs",
        ));
    }
    Ok(())
}
unsafe fn verify_bootstrap_signal(control: *mut NativeControl) -> io::Result<()> {
    let read = |field: *const u64| unsafe { field.read_volatile() };
    let tid = unsafe { crate::trap::raw_syscall6(libc::SYS_gettid, [0; 6]) };
    let pid = unsafe { crate::trap::raw_syscall6(libc::SYS_getpid, [0; 6]) };
    if tid <= 0
        || tid != pid
        || tid as u64 != read(unsafe { &raw const (*control).native_tid })
        || read(unsafe { &raw const (*control).phase }) != 2
        || unsafe { super::sigalrm::seccomp_filter_count() } != Some(1)
    {
        return Err(io::Error::other(
            "private bootstrap process/filter identity differs",
        ));
    }
    let mut fs = 0_u64;
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_arch_prctl,
            [0x1003, (&raw mut fs) as u64, 0, 0, 0, 0],
        )
    };
    if rc != 0 || fs != read(unsafe { &raw const (*control).tool_fs }) {
        return Err(io::Error::other("private Tool FS differs at handover"));
    }
    let mut mask = 0_u64;
    unsafe { crate::signal::raw_sigprocmask(libc::SIG_SETMASK, None, Some(&mut mask)) }
        .map_err(io::Error::from_raw_os_error)?;
    let forced = 1_u64 << (libc::SIGSYS - 1);
    let unmaskable = (1_u64 << (libc::SIGKILL - 1)) | (1_u64 << (libc::SIGSTOP - 1));
    if mask != !(forced | unmaskable) {
        return Err(io::Error::other("private bootstrap startup mask differs"));
    }
    let mut action = crate::signal::KernelSigaction::default();
    unsafe { crate::signal::raw_sigaction(libc::SIGSYS, None, Some(&mut action)) }
        .map_err(io::Error::from_raw_os_error)?;
    if action.handler != read(unsafe { &raw const (*control).bootstrap_handler })
        || action.restorer != crate::trap::FIXED_SIGNAL_RESTORER_ENTRY
        || action.restorer != read(unsafe { &raw const (*control).bootstrap_restorer })
        || action.mask != 0
        || action.flags != (libc::SA_SIGINFO | libc::SA_ONSTACK | crate::signal::SA_RESTORER) as u64
    {
        return Err(io::Error::other(
            "private bootstrap SIGSYS ownership differs",
        ));
    }
    let mut stack: libc::stack_t = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        crate::trap::raw_syscall6(
            libc::SYS_sigaltstack,
            [0, (&raw mut stack) as u64, 0, 0, 0, 0],
        )
    };
    let first = read(unsafe { &raw const (*control).bootstrap_stack_base });
    let end = read(unsafe { &raw const (*control).bootstrap_stack_end });
    if rc != 0
        || stack.ss_flags != 0
        || stack.ss_sp as u64 != first
        || end.checked_sub(first) != Some(stack.ss_size as u64)
    {
        return Err(io::Error::other("private bootstrap signal stack differs"));
    }
    Ok(())
}
