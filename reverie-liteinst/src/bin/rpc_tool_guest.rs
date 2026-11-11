// Legacy embedded Tool root: intentionally retains scoped allocation behavior.
reverie_liteinst::declare_legacy_scoped_tool_allocator!();

// Dispatcher: the real guest body is x86-64 only (x86 asm and syscall
// idioms). Other targets get the named stub.

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("reverie-liteinst-rpc-tool-guest is not supported on aarch64");
    std::process::exit(2);
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", not(test)))]
mod real {
    include!("real_bodies/rpc_tool_guest.rs");
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", not(test)))]
use real::main;
