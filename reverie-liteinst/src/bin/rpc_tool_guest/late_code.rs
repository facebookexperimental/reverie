/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! LiteInst coverage for CPUID/RDTSC/RDTSCP in code mapped after the runtime
//! started.
//!
//! The runtime records one trampoline arena per executable mapping when it
//! starts. Code mapped later (a `dlopen`ed library whose constructor runs
//! CPUID, as libcrypto's `OPENSSL_cpuid_setup` does, or JIT output) has no
//! arena, so a faulting instruction there can never be patched. These guests
//! require that such an instruction still reaches the Tool, in ordinary
//! context on the owned fallback continuation, with the same result the
//! patched path returns, and that an undecodable fault in such code still ends
//! the guest by a genuine `SIGSEGV`.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use std::ffi::CString;
use std::ffi::OsStr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use reverie::CpuIdResult;
use reverie::Guest;
use reverie::Rdtsc;
use reverie::RdtscResult;
use reverie::Subscription;
use reverie::Tool;

const TSC_BASE: u64 = 0x7e57_0000_0000_0000;
const CPUID_STUB: usize = 0;
const RDTSC_STUB: usize = 16;
const RDTSCP_STUB: usize = 32;
const GP_FAULT_STUB: usize = 48;
const GP_FAULT_OFFSET: usize = 10;
const NULL_LOAD_STUB: usize = 80;
const NULL_LOAD_OFFSET: usize = 2;
const REPEATS: usize = 32;
const LEAVES: [(u32, u32); 5] = [(0, 0), (1, 0), (7, 0), (0xd, 1), (0x8000_0000, 0)];

static CPUID_CALLBACKS: AtomicU64 = AtomicU64::new(0);
static TSC_CALLBACKS: AtomicU64 = AtomicU64::new(0);
static OWNED_STACK_CALLBACKS: AtomicU64 = AtomicU64::new(0);

/// The Tool's deterministic CPUID answer, distinct for every leaf/subleaf.
fn tool_cpuid(eax: u32, ecx: u32) -> CpuIdResult {
    CpuIdResult {
        eax: 0xc0de_0000 ^ eax,
        ebx: 0x0eb0_0000 ^ ecx,
        ecx: eax.rotate_left(8) ^ ecx,
        edx: 0xd00d_0000 | (eax & 0xffff),
    }
}

fn tool_tsc(callback: u64) -> u64 {
    TSC_BASE + callback
}

fn tool_aux(callback: u64) -> u32 {
    0x2468_0000 | callback as u32
}

/// Record whether this Tool callback runs on the owned fallback continuation
/// stack, as an unpatched instruction must, rather than on the guest stack the
/// patched hook uses.
#[inline(never)]
fn note_callback_stack() {
    let local = 0_u8;
    let address = core::ptr::addr_of!(local) as usize;
    if unsafe { reverie_liteinst_on_owned_fallback_stack(address) } {
        OWNED_STACK_CALLBACKS.fetch_add(1, Ordering::Relaxed);
    }
    std::hint::black_box(&local);
}

#[derive(Default)]
struct LateCodeTool;

#[reverie::tool]
impl Tool for LateCodeTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut subscriptions = Subscription::none();
        subscriptions.cpuid().rdtsc();
        subscriptions
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        eax: u32,
        ecx: u32,
    ) -> Result<CpuIdResult, reverie::Errno> {
        note_callback_stack();
        CPUID_CALLBACKS.fetch_add(1, Ordering::Relaxed);
        Ok(tool_cpuid(eax, ecx))
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, reverie::Errno> {
        note_callback_stack();
        let callback = TSC_CALLBACKS.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(RdtscResult {
            tsc: tool_tsc(callback),
            aux: (request == Rdtsc::Tscp).then_some(tool_aux(callback)),
        })
    }
}

/// Registers around one call into late code: `rax`/`rcx` are inputs, every
/// other field is loaded with [`sentinel`] by `late_code_invoke`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
struct Registers {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

const fn sentinel(index: u64) -> u64 {
    0x5e5e_0000_0000_0000 | index
}

fn invoke(page: *mut u8, offset: usize, rax: u64, rcx: u64) -> Registers {
    let mut registers = Registers {
        rax,
        rcx,
        ..Registers::default()
    };
    unsafe { late_code_invoke(page.add(offset), &mut registers) };
    registers
}

/// Every register the instruction does not define keeps its sentinel.
fn assert_untouched(registers: &Registers, label: &str) {
    for (index, value) in [
        (4, registers.rsi),
        (5, registers.rdi),
        (6, registers.rbp),
        (7, registers.r8),
        (8, registers.r9),
        (9, registers.r10),
        (10, registers.r12),
        (11, registers.r13),
        (12, registers.r14),
        (13, registers.r15),
    ] {
        assert_eq!(value, sentinel(index), "{label}: register {index} changed");
    }
}

/// Map one page of code after the runtime started, so no arena covers it.
fn map_late_code() -> *mut u8 {
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED);
    let page = page.cast::<u8>();
    let mut gp_fault = vec![0x48, 0xb8];
    gp_fault.extend_from_slice(&0x8000_0000_0000_0000_u64.to_le_bytes());
    gp_fault.extend_from_slice(&[0x48, 0x8b, 0x00, 0xc3]);
    assert_eq!(gp_fault.len(), GP_FAULT_OFFSET + 4);
    for (offset, code) in [
        // cpuid; ret
        (CPUID_STUB, &[0x0f, 0xa2, 0xc3][..]),
        // rdtsc; ret
        (RDTSC_STUB, &[0x0f, 0x31, 0xc3]),
        // rdtscp; ret
        (RDTSCP_STUB, &[0x0f, 0x01, 0xf9, 0xc3]),
        // movabs rax, 0x8000000000000000; mov rax, [rax]; ret: a kernel #GP
        // (SI_KERNEL) at bytes that are none of the emulated instructions.
        (GP_FAULT_STUB, &gp_fault),
        // xor eax, eax; mov rax, [rax]; ret: an ordinary NULL page fault.
        (NULL_LOAD_STUB, &[0x31, 0xc0, 0x48, 0x8b, 0x00, 0xc3]),
    ] {
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), page.add(offset), code.len()) };
    }
    assert_eq!(
        unsafe { libc::mprotect(page.cast(), 4096, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    page
}

fn install(path: &Path) {
    if let Err(error) = unsafe { reverie_liteinst::install_tool::<LateCodeTool>(path) } {
        super::fail_instruction_install(error);
    }
}

fn observations() -> [u64; 3] {
    core::array::from_fn(|selector| unsafe {
        reverie_liteinst_owned_fallback_observation(selector as u32)
    })
}

fn delta(after: [u64; 3], before: [u64; 3]) -> [u64; 3] {
    core::array::from_fn(|index| after[index] - before[index])
}

/// CPUID/RDTSC/RDTSCP in an anonymous executable page mapped after startup.
pub(super) fn run_instruction(path: &Path) {
    install(path);
    let page = map_late_code();
    let fallback_before = observations();
    let owned_before = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed);
    let cpuid_before = CPUID_CALLBACKS.load(Ordering::Relaxed);
    let mut late = 0;

    for (leaf, subleaf) in LEAVES {
        let expected = tool_cpuid(leaf, subleaf);
        // The patched path: a CPUID site in this executable, inside an arena.
        let patched = core::arch::x86_64::__cpuid_count(leaf, subleaf);
        for _ in 0..REPEATS {
            let registers = invoke(page, CPUID_STUB, u64::from(leaf), u64::from(subleaf));
            late += 1;
            assert_eq!(
                [registers.rax, registers.rbx, registers.rcx, registers.rdx],
                [patched.eax, patched.ebx, patched.ecx, patched.edx].map(u64::from),
                "late CPUID({leaf:#x}, {subleaf:#x}) must equal the patched path"
            );
            assert_eq!(
                [registers.rax, registers.rbx, registers.rcx, registers.rdx],
                [expected.eax, expected.ebx, expected.ecx, expected.edx].map(u64::from),
            );
            assert_untouched(&registers, "cpuid");
        }
    }
    let cpuid_callbacks = CPUID_CALLBACKS.load(Ordering::Relaxed) - cpuid_before;
    assert_eq!(
        cpuid_callbacks,
        (LEAVES.len() * (REPEATS + 1)) as u64,
        "every late and patched CPUID must reach the Tool exactly once"
    );

    // Interleave late and patched RDTSC: a per-callback TSC proves each one
    // reached the Tool exactly once, in program order.
    let first = TSC_CALLBACKS.load(Ordering::Relaxed);
    let rcx_input = 0x0123_4567_89ab_cdef;
    let registers = invoke(page, RDTSC_STUB, 0, rcx_input);
    late += 1;
    assert_eq!(registers.rax, tool_tsc(first + 1) & 0xffff_ffff);
    assert_eq!(registers.rdx, tool_tsc(first + 1) >> 32);
    assert_eq!(registers.rbx, sentinel(1), "RDTSC must not define rbx");
    assert_eq!(registers.rcx, rcx_input, "RDTSC must not define rcx");
    assert_untouched(&registers, "rdtsc");
    assert_eq!(unsafe { core::arch::x86_64::_rdtsc() }, tool_tsc(first + 2));
    let registers = invoke(page, RDTSC_STUB, 0, rcx_input);
    late += 1;
    assert_eq!((registers.rdx << 32) | registers.rax, tool_tsc(first + 3));
    let registers = invoke(page, RDTSCP_STUB, 0, rcx_input);
    late += 1;
    assert_eq!((registers.rdx << 32) | registers.rax, tool_tsc(first + 4));
    assert_eq!(registers.rcx, u64::from(tool_aux(first + 4)));
    assert_eq!(registers.rbx, sentinel(1), "RDTSCP must not define rbx");
    assert_untouched(&registers, "rdtscp");
    let mut aux = 0;
    let tscp = unsafe { core::arch::x86_64::__rdtscp(&mut aux) };
    assert_eq!((tscp, aux), (tool_tsc(first + 5), tool_aux(first + 5)));
    assert_eq!(TSC_CALLBACKS.load(Ordering::Relaxed) - first, 5);

    let fallback = delta(observations(), fallback_before);
    assert_eq!(
        fallback, [late; 3],
        "each late instruction is one continuation entry, callback and completion"
    );
    let owned = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed) - owned_before;
    assert_eq!(
        owned, late,
        "exactly the late instructions run the Tool on the owned continuation stack"
    );
    let sites = [CPUID_STUB, RDTSC_STUB, RDTSCP_STUB]
        .into_iter()
        .map(|offset| {
            let address = unsafe { page.add(offset) } as u64;
            reverie_liteinst::reverie_liteinst_site_trap_count(address)
                + reverie_liteinst::reverie_liteinst_site_hook_count(address)
        })
        .sum::<u64>();
    assert_eq!(sites, 0, "code without an arena must never claim a site");
    println!(
        "late-code cpuid=tool rdtsc=tool rdtscp=tool equals-patched=1 continuation={late} owned-stack={owned} sites={sites} registers=preserved"
    );
    std::io::stdout().flush().unwrap();
}

/// `dlopen` a library whose constructor runs CPUID and RDTSC: the libcrypto
/// `OPENSSL_cpuid_setup` shape that first exposed the crash.
pub(super) fn run_dlopen(path: &Path, library: &OsStr) {
    install(path);
    let owned_before = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed);
    let tsc_before = TSC_CALLBACKS.load(Ordering::Relaxed);
    let fallback_before = observations();
    let name = CString::new(library.as_bytes()).unwrap();
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let error = unsafe { std::ffi::CStr::from_ptr(libc::dlerror()) };
        panic!("dlopen {library:?} failed: {error:?}");
    }
    let fallback = delta(observations(), fallback_before);
    let owned = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed) - owned_before;
    let tsc_after = TSC_CALLBACKS.load(Ordering::Relaxed);
    let symbol = |name: &std::ffi::CStr| {
        let address = unsafe { libc::dlsym(handle, name.as_ptr()) };
        assert!(!address.is_null(), "missing {name:?}");
        address
    };
    let words: unsafe extern "C" fn(*mut u32) =
        unsafe { core::mem::transmute(symbol(c"late_code_constructor_cpuid")) };
    let tsc: unsafe extern "C" fn() -> u64 =
        unsafe { core::mem::transmute(symbol(c"late_code_constructor_tsc")) };
    let mut observed = [0_u32; 4];
    unsafe { words(observed.as_mut_ptr()) };
    let expected = tool_cpuid(0, 0);
    let patched = core::arch::x86_64::__cpuid_count(0, 0);
    assert_eq!(
        observed,
        [expected.eax, expected.ebx, expected.ecx, expected.edx],
        "the constructor's CPUID must return the Tool's result"
    );
    assert_eq!(
        observed,
        [patched.eax, patched.ebx, patched.ecx, patched.edx]
    );
    let constructor_tsc = unsafe { tsc() };
    let callback = constructor_tsc.wrapping_sub(TSC_BASE);
    assert!(
        callback > tsc_before && callback <= tsc_after,
        "the constructor's RDTSC must return a Tool result: {constructor_tsc:#x}"
    );
    // The constructor runs exactly one CPUID and one RDTSC in code without an
    // arena. Any loader instruction is in an arena and takes the patched hook.
    assert_eq!(
        owned, 2,
        "constructor instructions must use the continuation"
    );
    assert!(
        fallback[0] >= 2 && fallback[0] == fallback[1] && fallback[1] == fallback[2],
        "every continuation entry must complete: {fallback:?}"
    );
    println!("late-code dlopen constructor-cpuid=tool constructor-rdtsc=tool owned-stack={owned}");
    std::io::stdout().flush().unwrap();
}

/// `dlopen` the host's own libcrypto, whose initializer runs
/// `OPENSSL_cpuid_setup` (CPUID leaf 0 first) during the load. The number of
/// instructions it executes depends on the OpenSSL version, so this requires
/// only that the load completes and that at least one of them reached the Tool
/// on the continuation.
pub(super) fn run_dlopen_system(path: &Path, library: &OsStr) {
    install(path);
    let owned_before = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed);
    let fallback_before = observations();
    let name = CString::new(library.as_bytes()).unwrap();
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if handle.is_null() {
        let error = unsafe { std::ffi::CStr::from_ptr(libc::dlerror()) };
        panic!("dlopen {library:?} failed: {error:?}");
    }
    let fallback = delta(observations(), fallback_before);
    let owned = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed) - owned_before;
    assert!(owned >= 1, "the initializer's CPUID must reach the Tool");
    assert!(
        fallback[0] >= owned && fallback[0] == fallback[1] && fallback[1] == fallback[2],
        "every continuation entry must complete: {fallback:?}"
    );
    println!("late-code dlopen-system initializer-cpuid=tool");
    std::io::stdout().flush().unwrap();
}

/// An undecodable fault in late code must still kill the guest with SIGSEGV.
pub(super) fn run_fault(path: &Path, null_load: bool) -> ! {
    install(path);
    let page = map_late_code();
    let (stub, offset) = if null_load {
        (NULL_LOAD_STUB, NULL_LOAD_OFFSET)
    } else {
        (GP_FAULT_STUB, GP_FAULT_OFFSET)
    };
    println!("fault-rip={:#x}", page as usize + stub + offset);
    std::io::stdout().flush().unwrap();
    let registers = invoke(page, stub, 0, 0);
    println!("survived {registers:?}");
    std::process::exit(1);
}

unsafe extern "C" {
    fn late_code_invoke(code: *const u8, registers: *mut Registers);
    fn reverie_liteinst_on_owned_fallback_stack(address: usize) -> bool;
    fn reverie_liteinst_owned_fallback_observation(selector: u32) -> u64;
}

core::arch::global_asm!(
    r#"
    .text
    .p2align 4
    .global late_code_invoke
    .hidden late_code_invoke
    .type late_code_invoke,@function
late_code_invoke:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rsi
    mov r11, rdi
    mov rax, qword ptr [rsi]
    mov rcx, qword ptr [rsi + 16]
    movabs rbx, 0x5e5e000000000001
    movabs rdx, 0x5e5e000000000003
    movabs rsi, 0x5e5e000000000004
    movabs rdi, 0x5e5e000000000005
    movabs rbp, 0x5e5e000000000006
    movabs r8, 0x5e5e000000000007
    movabs r9, 0x5e5e000000000008
    movabs r10, 0x5e5e000000000009
    movabs r12, 0x5e5e00000000000a
    movabs r13, 0x5e5e00000000000b
    movabs r14, 0x5e5e00000000000c
    movabs r15, 0x5e5e00000000000d
    call r11
    mov r11, qword ptr [rsp]
    mov qword ptr [r11], rax
    mov qword ptr [r11 + 8], rbx
    mov qword ptr [r11 + 16], rcx
    mov qword ptr [r11 + 24], rdx
    mov qword ptr [r11 + 32], rsi
    mov qword ptr [r11 + 40], rdi
    mov qword ptr [r11 + 48], rbp
    mov qword ptr [r11 + 56], r8
    mov qword ptr [r11 + 64], r9
    mov qword ptr [r11 + 72], r10
    mov qword ptr [r11 + 80], r12
    mov qword ptr [r11 + 88], r13
    mov qword ptr [r11 + 96], r14
    mov qword ptr [r11 + 104], r15
    pop rsi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
    .size late_code_invoke, .-late_code_invoke
"#
);
