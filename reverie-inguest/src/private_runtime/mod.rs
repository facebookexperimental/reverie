//! Explicit private-musl libc/TLS mechanism for the retained Rust loader.
//! Feature/target selection alone admits no image and calls no initializer.
//! Actual mapped owner, qualified gate/relay, source-bound libc and pure-Rust
//! producer/entry are required; no guest or readiness path is supplied here.

mod c_allocator;
pub mod tls;

// A single nonreturning terminal leaf; never calls libc, reads TLS, allocates,
// unwinds, unmaps the image, or releases the retained host cleanup owner.
// The trusted caller must have mapped/sealed the exact selected native gate
// and allowed exit_group through it before ANY adapter entry can fail.
#[unsafe(naked)]
unsafe extern "C" fn terminal_gate() -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "2:",
        "mov eax, 231",
        "mov edi, 127",
        "lea r12, [rip + 2b]",
        "movabs r11, {native_gate}",
        "jmp r11",
        native_gate = const crate::trap::FIXED_NATIVE_ENTRY,
    );
}

pub(super) fn abort() -> ! {
    // SAFETY: every public unsafe initializer/adapter entry requires this exact
    // retained mapped gate/filter and host fatal lifetime before entry.
    unsafe { terminal_gate() }
}

// Preserve the reviewed distinct reason ABIs: arbitrary u32 allocator reasons
// are never reinterpreted as a Rust Failure enum. Both symbols are final-link
// required actual terminal code, not a successful bootstrap placeholder.
#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn hermit_loader_bootstrap_abort(_reason: tls::Failure) -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "jmp {terminal}",
        terminal = sym terminal_gate,
    );
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
unsafe extern "C" fn hermit_loader_c_allocator_abort(_reason: u32) -> ! {
    core::arch::naked_asm!(
        "endbr64",
        "jmp {terminal}",
        terminal = sym terminal_gate,
    );
}

core::arch::global_asm!(
    ".hidden {tls_abort}",
    ".hidden {allocator_abort}",
    tls_abort = sym hermit_loader_bootstrap_abort,
    allocator_abort = sym hermit_loader_c_allocator_abort,
);
