//! Dispatcher: the real guest body is x86-64 only (raw SYS_fork /
//! SYS_vfork probes with x86 asm). Other targets get the named stub.

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn main() {
    eprintln!("reverie-liteinst-fork-guest is not supported on aarch64");
    std::process::exit(2);
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", not(test)))]
mod real {
    include!("real_bodies/fork_guest.rs");
}

#[cfg(all(target_arch = "x86_64", target_os = "linux", not(test)))]
use real::main;
