// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-252): Review shared built-in spoof guest fixture.
//! Guest fixture proving the LiteInst trap path can service and MUTATE a
//! syscall result through a shared `reverie-preload` built-in.
//!
//! It issues a raw `getpid` syscall (bypassing glibc's cached PID so the value
//! comes from the trapped syscall, not a userspace cache) and prints
//! `getpid=<value>`. Under the `spoof-getpid` built-in the runtime rewrites the
//! result to `reverie_preload::SPOOF_PID`; under `passthrough` (or no tool) the
//! real PID is preserved.

fn main() {
    // SAFETY: SYS_getpid takes no arguments and cannot fail; issuing it raw
    // avoids glibc's userspace PID cache so the printed value reflects the
    // trapped syscall result.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    println!("getpid={pid}");
}
