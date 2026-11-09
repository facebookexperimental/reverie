//! The private-static runtime TLS source list must name this checkout.
//!
//! An integration test, not a unit test: Hermit compiles src/lib.rs into a
//! script package whose CARGO_MANIFEST_DIR is not this crate, and that harness
//! never builds tests/.

use std::path::Path;

use reverie_liteinst_artifact::private_static::tls_sources_self_check;

#[test]
fn tls_source_declarations_include_this_checkout() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("artifact crate sits inside the Reverie workspace");
    if let Err(error) = tls_sources_self_check(root) {
        panic!("{error}");
    }
}
