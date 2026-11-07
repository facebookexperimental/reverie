//! The actual preload's native selector and fixed-stack constructor root.
//!
//! Only the named active Tool initialization is covered. Earlier loader/CRT
//! work and the inert compatibility path retain their existing placement.

#[cfg(target_env = "gnu")]
use crate::glibc_compat::resolve_real_dl_find_object as resolve_compatibility;

// Non-glibc targets have no compatibility resolver to call.
#[cfg(not(target_env = "gnu"))]
#[unsafe(naked)]
extern "C" fn resolve_compatibility() {
    core::arch::naked_asm!("ret");
}

static SELECTOR: [u8; 22] = *b"REVERIE_LITEINST_TOOL=";

#[used]
#[unsafe(link_section = ".init_array")]
static REVERIE_LITEINST_INIT: unsafe extern "C" fn() = standalone_entry;

// Both paths retain the loader's real CALL/RET. There is no guest-stack store,
// Rust/libc call, TLS access or callee-saved-register change in this prefix.
// The environment is the current dynamically resolved environ, not loader
// envp. Bytewise NUL checking also handles a short string at a page boundary.
#[unsafe(naked)]
#[unsafe(export_name = "reverie_liteinst_standalone_entry")]
unsafe extern "C" fn standalone_entry() {
    core::arch::naked_asm!(
        "endbr64",
        "mov rax, qword ptr [rip + environ@GOTPCREL]",
        "mov rdx, qword ptr [rax]",
        "test rdx, rdx",
        "jz 5f",
        "lea r8, [rip + {selector}]",
        "2:",
        "mov r10, qword ptr [rdx]",
        "test r10, r10",
        "jz 5f",
        "xor r9d, r9d",
        "3:",
        "mov al, byte ptr [r10 + r9]",
        "test al, al",
        "jz 4f",
        "cmp al, byte ptr [r8 + r9]",
        "jne 4f",
        "inc r9d",
        "cmp r9d, {selector_len}",
        "jne 3b",
        "lea rdi, [rip + {body}]",
        "jmp {bootstrap}",
        "4:",
        "add rdx, 8",
        "jmp 2b",
        "5:",
        "jmp {resolver}",
        selector = sym SELECTOR,
        selector_len = const SELECTOR.len(),
        body = sym standalone_body,
        bootstrap = sym reverie_liteinst::constructor_entry,
        resolver = sym resolve_compatibility,
    );
}

#[inline(never)]
#[unsafe(export_name = "reverie_liteinst_standalone_body")]
unsafe extern "C" fn standalone_body() {
    // The helper owns the original dispatch/preflight/error lifetime. Only a
    // successful return drops that scope and reaches the resolver, preserving
    // the old core-then-resolver initialization and refusal ordering.
    unsafe { reverie_liteinst::initialize_standalone() };
    resolve_compatibility();
}

core::arch::global_asm!(
    ".hidden reverie_liteinst_standalone_entry",
    ".hidden reverie_liteinst_standalone_body",
);
