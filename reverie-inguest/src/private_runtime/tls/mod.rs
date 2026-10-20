//! Exact private musl TLS setup; no ToolRegion adoption or runtime readiness.
//! The retained musl __init_libc calls our strong source-bound __init_tls.

mod abi;
pub mod layout;

use core::ffi::c_char;

pub(crate) use abi::Failure;
pub use abi::IndexedAux;

unsafe extern "C" {
    fn __init_libc(envp: *mut *mut c_char, program_name: *mut c_char);
}

core::arch::global_asm!(
    ".hidden {tls_init}",
    tls_init = sym abi::__init_tls,
);

/// Initialize the actual private libc/TLS once, without running constructors.
///
/// This does not reserve/adopt memory, initialize Rust std or Detcore, install
/// ordinary dispatch, or authorize any guest instruction. Allocation after
/// return still fails with ENOMEM until the real Fixed owner is published.
///
/// # Safety
/// The genuine sole bootstrap leader runs on its retained owned Tool stack;
/// no thread/asynchronous handler may access these initialization globals.
/// The final source-bound private musl1.2.5 image/state is pristine and resolves
/// our strong __init_tls plus its actual __init_libc/__copy_tls/__init_tp and
/// __libc. No libc constructor or allocation has run. `plan` describes the
/// authentic final ET_EXEC's sole PT_TLS, with exclusively owned permanent,
/// prezeroed RW backing disjoint from ALL image/control/stack/guard extents.
/// All plan, template, environment, auxiliary and program-name bytes remain
/// mapped/readable for libc's required lifetime, never point into guest libc
/// state, and cannot be concurrently changed. The region is the actual retained
/// ToolRegion reservation, not authority invented by the numeric Plan.
///
/// `envp` points to the complete authentic private environment pointer vector,
/// terminated by NULL and IMMEDIATELY followed by the valid terminated Elf64_auxv
/// pairs that real __init_libc parses. Their AT_PHDR/PHENT/PHNUM/PAGESZ equal
/// `aux` and refer to the actual mapped private image. AT_RANDOM supplies at
/// least16 permanent readable bytes; AT_EXECFN and nonnull program_name are
/// valid terminated private strings. UID/EUID/GID/EGID/AT_SECURE and every other
/// aux value must be genuine source-bound private-launch inputs, not fabricated
/// to bypass libc security setup. `gnu_stack_bytes` is the actual PT_GNU_STACK
/// hint. The caller has separately bounded every vector/string/source read.
///
/// Before entry, the exact qualified bootstrap gate, SIGSYS relay/site table,
/// owned altstack/restorer and signal-mask/phase/reentrancy protocol are live.
/// The relay must preserve the actual FS transition performed by __init_tp and
/// retain real clear-tid ownership. The abort leaf must work with absent/old/new
/// FS and retain host kill/wait/mapping ownership. Private libc inline syscalls
/// (including any secure-input poll/open path) must follow the qualified relay;
/// no failure may release a guest. This is a lower-level primitive inside the
/// same exec-unshared descriptor-table, sole-leader transaction: the caller
/// captures original descriptor state before entry; the relay retains every
/// successful open as an actual owned lease. Immediately after return, before
/// constructors, std/Detcore descriptor enumeration or guest transfer, the
/// caller verifies and retires only those leases, preserving original entries,
/// closed slots and OFD flags. Any ambiguous or failed restoration is terminal
/// under the retained host owner. Returning and publishing TLS availability
/// do not complete that descriptor transaction.
/// All later nontrivial C allocator calls on
/// every thread run with this genuine private FS, never guest/host FS.
///
/// Final emitted code must satisfy the pre-TLS no-unwind/no-allocator/helper
/// closure and exact libc/alias/source authority. This function's unsafe
/// contract is not evidence that any of those physical inputs exist.
#[inline(never)]
pub unsafe fn initialize_private_libc(
    plan: layout::Plan,
    aux: IndexedAux,
    gnu_stack_bytes: usize,
    envp: *mut *mut c_char,
    program_name: *mut c_char,
) {
    // SAFETY: the caller supplies the authentic retained owner/ELF/TLS/relay
    // inputs required by the unchanged source-bound v3 installer.
    if unsafe { abi::install_before_libc(plan, aux, gnu_stack_bytes) }.is_err() {
        super::abort();
    }
    // SAFETY: exact private musl function and authentic private env/aux/name.
    // It genuinely calls __init_tls, then completes SSP/security initialization;
    // this does not call __libc_start_init or any application constructors.
    unsafe { __init_libc(envp, program_name) };
    abi::require_tls_returned();
    // SAFETY: the real __init_libc just returned after its genuine TLS and
    // SSP/security path. This publishes C errno usability only, not ownership.
    unsafe { super::c_allocator::publish_private_tls_initialized() };
}
