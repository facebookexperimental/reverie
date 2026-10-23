//! Keeps libreverie_liteinst.so loadable by guests whose glibc is not the
//! build root's (https://github.com/rrnewton/reverie/issues/980), as Hermit's
//! detcore-sabre and detcore-liteinst build scripts do for its other guest
//! preloads (https://github.com/rrnewton/hermit/issues/3652,
//! https://github.com/rrnewton/hermit/issues/3967).
//!
//! Each guest's own dynamic loader preloads this library, against the libc
//! that guest already has, so it may depend only on libraries every glibc
//! provides and may search no build-root directory for them:
//!
//! - The unwinder is linked from libgcc_eh.a instead of libgcc_s.so.1. A
//!   host guest has no libgcc_s loaded, and a Nix build root's copy (gcc 15)
//!   needs GLIBC_2.35, which glibc 2.34 hosts lack. `-u
//!   _Unwind_RaiseException` makes the linker extract the unwinder when it
//!   reaches libgcc_eh.a, which precedes the standard library's `-lgcc_s`;
//!   `--as-needed` then drops libgcc_s.so.1. The cdylib's version script
//!   keeps the unwinder's symbols local.
//! - `NIX_DONT_SET_RPATH_<target>` stops the Nix linker wrapper from
//!   recording its glibc, gcc, libunwind and xz library directories as the
//!   library's RUNPATH, through which a host guest would load the build root's
//!   libraries. The wrapper reads only the name suffixed with the target
//!   triple, `-` spelled `_`; other linkers ignore it.
//!
//! src/glibc_compat.rs defines `_dl_find_object`, which gcc 15's libgcc_eh.a
//! imports at GLIBC_2.35.
//!
//! This package is the actual cdylib leaf. The shared reverie-liteinst rlib
//! has no build script or static unwinder under any feature union. Its explicit
//! non-PIE compatibility fixture uses this same linker policy.

use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "linux" || target_env != "gnu" {
        return;
    }
    // `-bundle`: the archive is found by the C compiler driver at link time,
    // not by rustc while it writes the rlib, as in the standard library's own
    // `unwind` crate.
    println!("cargo:rustc-link-lib=static:-bundle=gcc_eh");
    println!("cargo:rustc-link-arg-cdylib=-Wl,-u,_Unwind_RaiseException");
    // The glibc_compat test guest: non-PIE, so its executable holds libc
    // functions' canonical PLT entries, with the preload's static unwinder.
    for flag in ["-no-pie", "-Wl,-u,_Unwind_RaiseException"] {
        println!("cargo:rustc-link-arg-bin=reverie-liteinst-glibc-compat-guest={flag}");
    }
    let target = env::var("TARGET").unwrap_or_default().replace('-', "_");
    println!("cargo:rustc-env=NIX_DONT_SET_RPATH_{target}=1");
}
