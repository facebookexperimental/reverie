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
const STRADDLER_REPEATS: usize = 8;
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
    invoke_at(unsafe { page.add(offset) }, rax, rcx)
}

fn invoke_at(code: *const u8, rax: u64, rcx: u64) -> Registers {
    let mut registers = Registers {
        rax,
        rcx,
        ..Registers::default()
    };
    unsafe { late_code_invoke(code, &mut registers) };
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
/// `trap_only`: the runtime runs with site patching off, so the in-arena
/// ("patched path") instructions take the continuation too.
pub(super) fn run_instruction(path: &Path, trap_only: bool) {
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

    // The in-arena instructions above: one CPUID per leaf, one RDTSC and one
    // RDTSCP. With site patching off they take the continuation as well.
    let in_arena = if trap_only {
        LEAVES.len() as u64 + 2
    } else {
        0
    };
    let fallback = delta(observations(), fallback_before);
    assert_eq!(
        fallback,
        [late + in_arena; 3],
        "each continued instruction is one continuation entry, callback and completion"
    );
    let owned = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed) - owned_before;
    assert_eq!(
        owned,
        late + in_arena,
        "exactly the continued instructions run the Tool on the owned continuation stack"
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
    if trap_only {
        println!(
            "late-code trap-only cpuid=tool rdtsc=tool rdtscp=tool equals-in-arena=1 continuation={late}+{in_arena} owned-stack={owned} sites={sites} registers=preserved"
        );
    } else {
        println!(
            "late-code cpuid=tool rdtsc=tool rdtscp=tool equals-patched=1 continuation={late} owned-stack={owned} sites={sites} registers=preserved"
        );
    }
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

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(liteinst-straddler-cpuid): Review the cross-line instruction guest.
/// CPUID/RDTSC/RDTSCP inside this executable's text, where an arena exists,
/// each placed so LiteInst's 8-byte word patch would cross a 64-byte cache
/// line. With cross-line publication disabled the hook is refused before any
/// byte changes, so every execution must trap and reach the Tool through the
/// continuation. Nix's coreutils runs the same shape in `__cpu_indicator_init`
/// (CPUID at line offset 58) before `main`.
pub(super) fn run_straddler(path: &Path) {
    install(path);
    let stubs = [
        (straddler_cpuid as *const u8, 58),
        (straddler_rdtsc as *const u8, 61),
        (straddler_rdtscp as *const u8, 63),
    ];
    for (stub, offset) in stubs {
        assert_eq!(stub as usize % 64, offset, "stub {stub:?} is misplaced");
    }
    let [(cpuid, _), (rdtsc, _), (rdtscp, _)] = stubs;
    let fallback_before = observations();
    let owned_before = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed);
    let cpuid_before = CPUID_CALLBACKS.load(Ordering::Relaxed);
    let mut calls = [0_u64; 3];

    for (leaf, subleaf) in LEAVES {
        let expected = tool_cpuid(leaf, subleaf);
        for _ in 0..STRADDLER_REPEATS {
            let registers = invoke_at(cpuid, u64::from(leaf), u64::from(subleaf));
            calls[0] += 1;
            assert_eq!(
                [registers.rax, registers.rbx, registers.rcx, registers.rdx],
                [expected.eax, expected.ebx, expected.ecx, expected.edx].map(u64::from),
                "cross-line CPUID({leaf:#x}, {subleaf:#x}) must return the Tool's result"
            );
            assert_untouched(&registers, "cpuid");
        }
    }
    assert_eq!(
        CPUID_CALLBACKS.load(Ordering::Relaxed) - cpuid_before,
        calls[0],
        "every cross-line CPUID must reach the Tool exactly once"
    );

    let first = TSC_CALLBACKS.load(Ordering::Relaxed);
    let rcx_input = 0x0123_4567_89ab_cdef;
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(rdtsc, 0, rcx_input);
        calls[1] += 1;
        let callback = TSC_CALLBACKS.load(Ordering::Relaxed);
        assert_eq!(callback - first, calls[1] + calls[2]);
        assert_eq!((registers.rdx << 32) | registers.rax, tool_tsc(callback));
        assert_eq!(registers.rbx, sentinel(1), "RDTSC must not define rbx");
        assert_eq!(registers.rcx, rcx_input, "RDTSC must not define rcx");
        assert_untouched(&registers, "rdtsc");

        let registers = invoke_at(rdtscp, 0, rcx_input);
        calls[2] += 1;
        let callback = TSC_CALLBACKS.load(Ordering::Relaxed);
        assert_eq!(callback - first, calls[1] + calls[2]);
        assert_eq!((registers.rdx << 32) | registers.rax, tool_tsc(callback));
        assert_eq!(registers.rcx, u64::from(tool_aux(callback)));
        assert_eq!(registers.rbx, sentinel(1), "RDTSCP must not define rbx");
        assert_untouched(&registers, "rdtscp");
    }

    let total = calls.iter().sum::<u64>();
    let fallback = delta(observations(), fallback_before);
    assert_eq!(
        fallback, [total; 3],
        "each cross-line instruction is one continuation entry, callback and completion"
    );
    let owned = OWNED_STACK_CALLBACKS.load(Ordering::Relaxed) - owned_before;
    assert_eq!(
        owned, total,
        "every cross-line instruction runs the Tool on the owned continuation stack"
    );
    for ((stub, offset), expected) in stubs.into_iter().zip(calls) {
        let address = stub as u64;
        assert_eq!(
            reverie_liteinst::reverie_liteinst_site_trap_count(address),
            expected,
            "the site at line offset {offset} must trap on every execution"
        );
        assert_eq!(
            reverie_liteinst::reverie_liteinst_site_hook_count(address),
            0,
            "the site at line offset {offset} must never be patched"
        );
    }
    println!(
        "straddler cpuid=tool rdtsc=tool rdtscp=tool calls={total} continuation={} owned-stack={owned} hooks=0 registers=preserved",
        fallback[0]
    );
    run_straddler_neighbour();
    run_stale_jump_neighbour();
    std::io::stdout().flush().unwrap();
}

/// A CPUID whose patch would overwrite the start of a neighbour's jump that
/// survived a no-op mremap (the neighbour is then STALE, but its jump bytes
/// are unchanged) must not be patched: the stale jump still counts as
/// published. It runs through the continuation and falls into the
/// neighbour's surviving jump, which still reaches the Tool.
fn run_stale_jump_neighbour() {
    let before = straddler_stale_before as *const u8;
    let patched = straddler_stale_patched as *const u8;
    assert_eq!(before as usize % 64, 16, "stale-jump stub is misplaced");
    assert_eq!(patched as usize, before as usize + 4);
    let (leaf, subleaf) = (1, 0);
    let first = tool_cpuid(leaf, subleaf);
    let second = tool_cpuid(first.eax, first.ecx);
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(patched, u64::from(leaf), u64::from(subleaf));
        assert_eq!(
            [registers.rax, registers.rbx, registers.rcx, registers.rdx],
            [first.eax, first.ebx, first.ecx, first.edx].map(u64::from),
        );
        assert_untouched(&registers, "patched");
    }
    let patched_hooks = reverie_liteinst::reverie_liteinst_site_hook_count(patched as u64);
    assert!(patched_hooks > 0, "the neighbour must be patched first");
    let page = (patched as usize & !4095) as *mut libc::c_void;
    let remapped = unsafe { libc::mremap(page, 4096, 4096, 0) };
    assert_eq!(remapped, page, "no-op mremap must keep the page in place");
    let cpuid_before = CPUID_CALLBACKS.load(Ordering::Relaxed);
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(before, u64::from(leaf), u64::from(subleaf));
        assert_eq!(
            [registers.rax, registers.rbx, registers.rcx, registers.rdx],
            [second.eax, second.ebx, second.ecx, second.edx].map(u64::from),
            "both CPUIDs must return the Tool's results"
        );
        assert_untouched(&registers, "before");
    }
    let calls = STRADDLER_REPEATS as u64;
    assert_eq!(
        CPUID_CALLBACKS.load(Ordering::Relaxed) - cpuid_before,
        2 * calls,
        "every CPUID must reach the Tool once"
    );
    let address = before as u64;
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(address);
    let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(address);
    assert_eq!(
        (traps, hooks),
        (calls, 0),
        "the site before the stale jump must trap every time and never be patched"
    );
    println!("straddler-stale-jump cpuid=tool traps={traps} hooks=0");
}

/// A patchable CPUID whose word patch would cover a cross-line CPUID that
/// already executes through the continuation. A thread there resumes after
/// that instruction, which would then be inside the neighbour's jump, so the
/// neighbour must not be patched either, even after a no-op mremap of the
/// page: both keep reaching the Tool, and entering the covered site directly
/// afterwards still runs its original bytes.
fn run_straddler_neighbour() {
    let neighbour = straddler_neighbour as *const u8;
    let covered = straddler_covered as *const u8;
    assert_eq!(neighbour as usize % 64, 54, "neighbour stub is misplaced");
    assert_eq!(covered as usize, neighbour as usize + 4);
    let cpuid_before = CPUID_CALLBACKS.load(Ordering::Relaxed);
    let (leaf, subleaf) = (1, 0);
    let first = tool_cpuid(leaf, subleaf);
    // The neighbour runs CPUID twice: its own, then the covered one on the
    // first one's outputs.
    let second = tool_cpuid(first.eax, first.ecx);
    let check_covered = |label: &str| {
        let registers = invoke_at(covered, u64::from(leaf), u64::from(subleaf));
        assert_eq!(
            [registers.rax, registers.rbx, registers.rcx, registers.rdx],
            [first.eax, first.ebx, first.ecx, first.edx].map(u64::from),
            "{label}: the covered CPUID must return the Tool's result"
        );
        assert_untouched(&registers, label);
    };
    for _ in 0..STRADDLER_REPEATS {
        check_covered("covered before");
    }
    // A no-op mremap of the page invalidates every site in it; that must
    // not lift the covered site's reservation against the neighbour's patch.
    let page = (covered as usize & !4095) as *mut libc::c_void;
    let remapped = unsafe { libc::mremap(page, 4096, 4096, 0) };
    assert_eq!(remapped, page, "no-op mremap must keep the page in place");
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(neighbour, u64::from(leaf), u64::from(subleaf));
        assert_eq!(
            [registers.rax, registers.rbx, registers.rcx, registers.rdx],
            [second.eax, second.ebx, second.ecx, second.edx].map(u64::from),
            "both CPUIDs in the neighbour must return the Tool's results"
        );
        assert_untouched(&registers, "neighbour");
    }
    for _ in 0..STRADDLER_REPEATS {
        check_covered("covered after");
    }
    let calls = STRADDLER_REPEATS as u64;
    let callbacks = CPUID_CALLBACKS.load(Ordering::Relaxed) - cpuid_before;
    assert_eq!(callbacks, 4 * calls, "every CPUID must reach the Tool once");
    let traps = [neighbour, covered]
        .map(|site| reverie_liteinst::reverie_liteinst_site_trap_count(site as u64));
    let hooks = [neighbour, covered]
        .map(|site| reverie_liteinst::reverie_liteinst_site_hook_count(site as u64));
    assert_eq!(
        traps,
        [calls, 3 * calls],
        "both sites must trap on every execution"
    );
    assert_eq!(hooks, [0, 0], "neither site may be patched");
    println!(
        "straddler-neighbour cpuid=tool callbacks={callbacks} traps={}+{} hooks=0",
        traps[0], traps[1]
    );
}

#[derive(Default)]
struct SyscallReservationTool;

#[reverie::tool]
impl Tool for SyscallReservationTool {
    type GlobalState = super::CounterGlobal;
    type ThreadState = ();

    fn subscriptions(_cfg: &()) -> Subscription {
        let mut subscriptions: Subscription =
            [reverie::syscalls::Sysno::getpid].into_iter().collect();
        subscriptions.cpuid().rdtsc();
        subscriptions
    }

    async fn handle_cpuid_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        eax: u32,
        ecx: u32,
    ) -> Result<CpuIdResult, reverie::Errno> {
        Ok(tool_cpuid(eax, ecx))
    }

    async fn handle_rdtsc_event<G: Guest<Self>>(
        &self,
        _guest: &mut G,
        request: Rdtsc,
    ) -> Result<RdtscResult, reverie::Errno> {
        let callback = TSC_CALLBACKS.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(RdtscResult {
            tsc: tool_tsc(callback),
            aux: (request == Rdtsc::Tscp).then_some(tool_aux(callback)),
        })
    }
}
/// Map `code` into a fresh private anonymous executable page, before the
/// runtime starts, and return the page.
fn map_startup_code(code: &[u8]) -> *mut u8 {
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
    assert_ne!(page, libc::MAP_FAILED, "private mmap failed");
    let page = page.cast::<u8>();
    unsafe {
        core::ptr::write_bytes(page, 0xcc, 4096);
        core::ptr::copy_nonoverlapping(code.as_ptr(), page, code.len());
    }
    assert_eq!(
        unsafe { libc::mprotect(page.cast(), 4096, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    page
}

/// A getpid syscall at line offset 63 cannot be patched (its word would cross
/// the line) and is refused before anything is written, so it runs through
/// the SIGSYS continuation and leaves no footprint. The RDTSC right after it
/// (offset 65, starting exactly at the syscall's resume point) fits in the
/// next line and must still be patched, as before this commit.
pub(super) fn run_syscall_then_rdtsc(path: &Path) {
    let mut code = vec![0xcc_u8; 74];
    // mov eax, 39; syscall; rdtsc; six NOPs; ret
    code[58..74].copy_from_slice(&[
        0xb8, 0x27, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x0f, 0x31, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xc3,
    ]);
    let page = map_startup_code(&code);
    if let Err(error) = unsafe { reverie_liteinst::install_tool::<SyscallReservationTool>(path) } {
        super::fail_instruction_install(error);
    }
    let stub = unsafe { page.add(58) };
    let rdtsc_site = unsafe { page.add(65) } as u64;
    let first = TSC_CALLBACKS.load(Ordering::Relaxed);
    for call in 1..=STRADDLER_REPEATS as u64 {
        let registers = invoke_at(stub, 0, 0);
        assert_eq!(
            (registers.rdx << 32) | registers.rax,
            tool_tsc(first + call),
            "the RDTSC after the syscall must return the Tool's value"
        );
        assert_untouched(&registers, "syscall then rdtsc");
    }
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(rdtsc_site);
    let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(rdtsc_site);
    assert_eq!(traps, 1, "the RDTSC must trap once and then be patched");
    assert!(hooks > 0, "the RDTSC must be patched");
    println!("fallback-syscall-then-rdtsc rdtsc=tool traps=1 patched=1");
    std::io::stdout().flush().unwrap();
}

/// One memfd page mapped twice before the runtime starts: private X and
/// shared Y. Y+56 is a CPUID whose word fits the line; X+58 is one whose word
/// would cross it. Y executes first: LiteInst must not publish into the
/// shared mapping (that would change the page cache that clean X still
/// executes), so Y+56 traps every time. X+58 then runs through the
/// continuation on its original bytes, and neither page changes.
pub(super) fn run_private_alias(path: &Path) {
    let fd = unsafe { libc::memfd_create(c"liteinst-alias-code".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create failed");
    let mut code = vec![0xcc_u8; 4096];
    // cpuid; cpuid; six NOPs; ret
    let original = [0x0f, 0xa2, 0x0f, 0xa2, 0x90, 0x90, 0x90, 0x90];
    code[56..64].copy_from_slice(&original);
    code[64..67].copy_from_slice(&[0x90, 0x90, 0xc3]);
    let written = unsafe { libc::pwrite(fd, code.as_ptr().cast(), 4096, 0) };
    assert_eq!(written, 4096, "pwrite to the memfd failed");
    let map = |flags| {
        let page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
                flags,
                fd,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED, "memfd mmap failed");
        page.cast::<u8>()
    };
    let private = map(libc::MAP_PRIVATE);
    let shared = map(libc::MAP_SHARED);
    install(path);
    let (leaf, subleaf) = (1, 0);
    let first = tool_cpuid(leaf, subleaf);
    let second = tool_cpuid(first.eax, first.ecx);
    let alias = unsafe { shared.add(56) };
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(alias, u64::from(leaf), u64::from(subleaf));
        assert_eq!(
            [registers.rax, registers.rbx, registers.rcx, registers.rdx],
            [second.eax, second.ebx, second.ecx, second.edx].map(u64::from),
            "both CPUIDs through the shared alias must return the Tool's results"
        );
    }
    let alias_traps = reverie_liteinst::reverie_liteinst_site_trap_count(alias as u64);
    let alias_hooks = reverie_liteinst::reverie_liteinst_site_hook_count(alias as u64);
    assert_eq!(
        (alias_traps, alias_hooks),
        (STRADDLER_REPEATS as u64, 0),
        "the shared alias must trap every time and never be patched"
    );
    let covered = unsafe { private.add(58) };
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(covered, u64::from(leaf), u64::from(subleaf));
        assert_eq!(
            [registers.rax, registers.rbx, registers.rcx, registers.rdx],
            [first.eax, first.ebx, first.ecx, first.edx].map(u64::from),
            "the private CPUID must return the Tool's result"
        );
        assert_untouched(&registers, "private cpuid");
    }
    for (label, page) in [("shared", shared), ("private", private)] {
        let bytes = unsafe { core::ptr::read_unaligned(page.add(56).cast::<[u8; 8]>()) };
        assert_eq!(
            bytes, original,
            "the {label} page must keep the original bytes"
        );
    }
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(covered as u64);
    println!(
        "private-alias shared=unpatched private=original cpuid=tool traps={alias_traps}+{traps}"
    );
    std::io::stdout().flush().unwrap();
}

/// A subscribed syscall at line offset 59 cannot be patched (its word would
/// cross the line) and runs through the SIGSYS continuation, which resumes
/// after it. A no-op mremap makes that site STALE; a CPUID at offset 52,
/// whose patch would cover the syscall, must still not be patched, and both
/// keep working when entered directly afterwards.
pub(super) fn run_syscall_reservation(path: &Path) {
    if let Err(error) = unsafe { reverie_liteinst::install_tool::<SyscallReservationTool>(path) } {
        super::fail_instruction_install(error);
    }
    let cpuid_site = reservation_cpuid as *const u8;
    let syscall_site = reservation_syscall as *const u8;
    assert_eq!(
        cpuid_site as usize % 64,
        52,
        "reservation stub is misplaced"
    );
    assert_eq!(syscall_site as usize, cpuid_site as usize + 7);
    let pid = unsafe { libc::getpid() } as u64;
    let call_syscall = || {
        let registers = invoke_at(syscall_site, libc::SYS_getpid as u64, 0);
        assert_eq!(registers.rax, pid, "the syscall must return getpid");
        assert_untouched(&registers, "syscall");
    };
    for _ in 0..STRADDLER_REPEATS {
        call_syscall();
    }
    let count = |site: *const u8| {
        (
            reverie_liteinst::reverie_liteinst_site_trap_count(site as u64),
            reverie_liteinst::reverie_liteinst_site_hook_count(site as u64),
        )
    };
    let (syscall_traps, syscall_hooks) = count(syscall_site);
    assert!(syscall_traps > 0, "the syscall site must have trapped");
    assert_eq!(syscall_hooks, 0, "the syscall site must not be patched");
    let page = (syscall_site as usize & !4095) as *mut libc::c_void;
    let remapped = unsafe { libc::mremap(page, 4096, 4096, 0) };
    assert_eq!(remapped, page, "no-op mremap must keep the page in place");
    let expected = tool_cpuid(1, 0);
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(cpuid_site, 1, 0);
        assert_eq!(
            registers.rax, pid,
            "the syscall after the CPUID must return getpid"
        );
        assert_eq!(
            [registers.rbx, registers.rdx],
            [expected.ebx, expected.edx].map(u64::from),
            "the CPUID must return the Tool's result"
        );
        assert_untouched(&registers, "cpuid then syscall");
    }
    for _ in 0..STRADDLER_REPEATS {
        call_syscall();
    }
    let (cpuid_traps, cpuid_hooks) = count(cpuid_site);
    let (_, syscall_hooks) = count(syscall_site);
    assert_eq!(cpuid_traps, STRADDLER_REPEATS as u64);
    assert_eq!(
        (cpuid_hooks, syscall_hooks),
        (0, 0),
        "neither site may be patched"
    );
    println!(
        "straddler-syscall-reservation cpuid=tool syscall=getpid traps={cpuid_traps} hooks=0+0"
    );
    std::io::stdout().flush().unwrap();
}

/// A CPUID two bytes before a page end is patched with a cross-line jump
/// that spans into the next page. Replacing only its first page with the
/// original bytes restores the CPUID while the jump's displacement survives
/// on the second page. Executing the CPUID again reclaims the site; it must
/// fail closed (the earlier patch may survive) instead of resuming through
/// the continuation into the surviving displacement.
pub(super) fn run_reclaim_partial(path: &Path) -> ! {
    install(path);
    let site = straddler_page_end as *const u8;
    let page = site as usize & !4095;
    assert_eq!(site as usize - page, 4094, "page-end stub is misplaced");
    let mut original = vec![0_u8; 4096];
    unsafe { core::ptr::copy_nonoverlapping(page as *const u8, original.as_mut_ptr(), 4096) };
    let expected = tool_cpuid(1, 0);
    let registers = invoke_at(site, 1, 0);
    assert_eq!(
        [registers.rax, registers.rbx, registers.rcx, registers.rdx],
        [expected.eax, expected.ebx, expected.ecx, expected.edx].map(u64::from),
    );
    let hooks = || reverie_liteinst::reverie_liteinst_site_hook_count(site as u64);
    let _ = invoke_at(site, 1, 0);
    assert!(hooks() > 0, "the page-end CPUID must be patched first");
    let tail = unsafe { core::ptr::read_unaligned((page + 4096) as *const u16) };
    assert_ne!(tail, 0x9090, "the jump must reach into the second page");
    let mapped = unsafe {
        libc::mmap(
            page as *mut libc::c_void,
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_eq!(
        mapped as usize, page,
        "MAP_FIXED must replace the first page"
    );
    unsafe { core::ptr::copy_nonoverlapping(original.as_ptr(), page as *mut u8, 4096) };
    assert_eq!(
        unsafe {
            libc::mprotect(
                page as *mut libc::c_void,
                4096,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        },
        0
    );
    println!("reclaim-partial ready");
    std::io::stdout().flush().unwrap();
    let registers = invoke_at(site, 1, 0);
    println!("survived {registers:?}");
    std::process::exit(1);
}

/// A shared executable mapping, present when the runtime starts (so it has
/// an arena), holding a CPUID at line offset 16 (its word fits the line) and
/// one at offset 58 (its word would cross the line). LiteInst publishes only
/// into private mappings, because a write through a shared one would change
/// the page cache that every alias and every other process executes. Both
/// sites must therefore trap on every execution, return the Tool's results
/// through the continuation, and leave the shared page unchanged.
pub(super) fn run_shared_mapping(path: &Path) {
    let fd = unsafe { libc::memfd_create(c"liteinst-shared-code".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create failed");
    let mut code = vec![0xcc_u8; 4096];
    let stub = [0x0f, 0xa2, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3];
    code[16..25].copy_from_slice(&stub);
    code[58..67].copy_from_slice(&stub);
    let written = unsafe { libc::pwrite(fd, code.as_ptr().cast(), code.len(), 0) };
    assert_eq!(written, 4096, "pwrite to the memfd failed");
    let page = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED, "shared executable mmap failed");
    let page = page.cast::<u8>();
    install(path);
    let expected = tool_cpuid(1, 0);
    for offset in [16, 58] {
        let site = unsafe { page.add(offset) };
        for _ in 0..STRADDLER_REPEATS {
            let registers = invoke_at(site, 1, 0);
            assert_eq!(
                [registers.rax, registers.rbx, registers.rcx, registers.rdx],
                [expected.eax, expected.ebx, expected.ecx, expected.edx].map(u64::from),
                "the shared CPUID at offset {offset} must return the Tool's result"
            );
            assert_untouched(&registers, "shared cpuid");
        }
        let traps = reverie_liteinst::reverie_liteinst_site_trap_count(site as u64);
        let hooks = reverie_liteinst::reverie_liteinst_site_hook_count(site as u64);
        assert_eq!(
            (traps, hooks),
            (STRADDLER_REPEATS as u64, 0),
            "the shared CPUID at offset {offset} must trap every time and never be patched"
        );
    }
    let now = unsafe { core::slice::from_raw_parts(page, 4096) };
    assert_eq!(now, &code[..], "the shared page must stay unchanged");
    println!("shared-mapping cpuid=tool traps=8+8 hooks=0+0 page=unchanged");
    std::io::stdout().flush().unwrap();
}

/// A CPUID in the last two bytes of a private executable page whose next
/// page is a shared executable mapping, both mapped before the runtime
/// starts. The CPUID cannot be patched (fewer than eight bytes remain in its
/// mapping) and resumes in the shared page; because LiteInst never publishes
/// into a shared mapping, those bytes are the original ones and the
/// continuation must work.
pub(super) fn run_split_mapping(path: &Path) {
    let fd = unsafe { libc::memfd_create(c"liteinst-split-code".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create failed");
    let mut shared_code = vec![0xcc_u8; 4096];
    shared_code[..7].copy_from_slice(&[0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]);
    let written = unsafe { libc::pwrite(fd, shared_code.as_ptr().cast(), 4096, 0) };
    assert_eq!(written, 4096, "pwrite to the memfd failed");
    let private = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            8192,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(private, libc::MAP_FAILED, "private mmap failed");
    let private = private.cast::<u8>();
    unsafe {
        core::ptr::write_bytes(private, 0xcc, 4096);
        core::ptr::copy_nonoverlapping([0x0f_u8, 0xa2].as_ptr(), private.add(4094), 2);
    }
    assert_eq!(
        unsafe { libc::mprotect(private.cast(), 4096, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    let shared = unsafe {
        libc::mmap(
            private.add(4096).cast(),
            4096,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED | libc::MAP_FIXED,
            fd,
            0,
        )
    };
    assert_eq!(
        shared,
        unsafe { private.add(4096) }.cast(),
        "shared MAP_FIXED failed"
    );
    install(path);
    let site = unsafe { private.add(4094) };
    let expected = tool_cpuid(1, 0);
    for _ in 0..STRADDLER_REPEATS {
        let registers = invoke_at(site, 1, 0);
        assert_eq!(
            [registers.rax, registers.rbx, registers.rcx, registers.rdx],
            [expected.eax, expected.ebx, expected.ecx, expected.edx].map(u64::from),
            "the page-end CPUID must return the Tool's result"
        );
        assert_untouched(&registers, "page-end cpuid");
    }
    let traps = reverie_liteinst::reverie_liteinst_site_trap_count(site as u64);
    assert_eq!(traps, STRADDLER_REPEATS as u64);
    println!("split-mapping cpuid=tool traps={traps}");
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
    fn straddler_cpuid();
    fn straddler_rdtsc();
    fn straddler_rdtscp();
    fn straddler_neighbour();
    fn straddler_covered();
    fn straddler_stale_before();
    fn straddler_stale_patched();
    fn straddler_page_end();
    fn reservation_cpuid();
    fn reservation_syscall();
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

// Each stub starts at the named offset of a 64-byte line, so the 8-byte word
// patch at its first byte would cross into the next line; the neighbour at
// offset 54 fits in its line, and its patch would cover the CPUID at 58. The
// stale-jump pair at offsets 16 and 20 fits in its line: the CPUID at 20 is
// patched first, and the one at 16 would overwrite the start of its jump. The INT3 padding
// before a stub is never executed; the NOPs after it give the patcher whole
// instructions to cover, as ordinary code would.
core::arch::global_asm!(
    r#"
    .text
    .p2align 6
    .skip 58, 0xcc
    .global straddler_cpuid
    .hidden straddler_cpuid
    .type straddler_cpuid,@function
straddler_cpuid:
    cpuid
    nop
    nop
    nop
    nop
    nop
    nop
    ret
    .size straddler_cpuid, .-straddler_cpuid

    .p2align 6
    .skip 61, 0xcc
    .global straddler_rdtsc
    .hidden straddler_rdtsc
    .type straddler_rdtsc,@function
straddler_rdtsc:
    rdtsc
    nop
    nop
    nop
    nop
    nop
    nop
    ret
    .size straddler_rdtsc, .-straddler_rdtsc

    .p2align 6
    .skip 63, 0xcc
    .global straddler_rdtscp
    .hidden straddler_rdtscp
    .type straddler_rdtscp,@function
straddler_rdtscp:
    rdtscp
    nop
    nop
    nop
    nop
    nop
    ret
    .size straddler_rdtscp, .-straddler_rdtscp

    .p2align 6
    .skip 54, 0xcc
    .global straddler_neighbour
    .hidden straddler_neighbour
    .type straddler_neighbour,@function
straddler_neighbour:
    cpuid
    nop
    nop
    .global straddler_covered
    .hidden straddler_covered
straddler_covered:
    cpuid
    nop
    nop
    nop
    nop
    nop
    nop
    ret
    .size straddler_neighbour, .-straddler_neighbour

    .p2align 6
    .skip 16, 0xcc
    .global straddler_stale_before
    .hidden straddler_stale_before
    .type straddler_stale_before,@function
straddler_stale_before:
    cpuid
    nop
    nop
    .global straddler_stale_patched
    .hidden straddler_stale_patched
straddler_stale_patched:
    cpuid
    nop
    nop
    nop
    nop
    nop
    nop
    ret
    .size straddler_stale_before, .-straddler_stale_before

    .p2align 12
    .skip 4094, 0xcc
    .global straddler_page_end
    .hidden straddler_page_end
    .type straddler_page_end,@function
straddler_page_end:
    cpuid
    nop
    nop
    nop
    nop
    nop
    nop
    ret
    .size straddler_page_end, .-straddler_page_end

    .p2align 6
    .skip 52, 0xcc
    .global reservation_cpuid
    .hidden reservation_cpuid
    .type reservation_cpuid,@function
reservation_cpuid:
    cpuid
    mov eax, 39
    .global reservation_syscall
    .hidden reservation_syscall
reservation_syscall:
    syscall
    nop
    nop
    nop
    nop
    nop
    nop
    ret
    .size reservation_cpuid, .-reservation_cpuid
"#
);
