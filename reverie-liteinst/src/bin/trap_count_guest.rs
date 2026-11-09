//! Dispatcher: the real guest body is x86-64 only (fixed getpid site in
//! x86 asm). Other targets get the named stub.

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("reverie-liteinst-trap-count-guest is not supported on aarch64");
    std::process::exit(2);
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
mod real {
    include!("real_bodies/trap_count_guest.rs");
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use real::main;
