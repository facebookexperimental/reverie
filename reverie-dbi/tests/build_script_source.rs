#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script;

use std::path::Path;

#[test]
fn vendored_dynamorio_source_is_complete() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/dynamorio");
    assert_eq!(
        std::fs::read_to_string(source.join("REVISION"))
            .unwrap()
            .trim(),
        "929840ad9190e5086775e8debc0f0b79b4208d59"
    );
    for required in [
        "CMakeLists.txt",
        "core/lib/globals_shared.h",
        "core/unix/memcache.c",
        "tools/drdeploy.c",
        "ext/drmgr/drmgr.c",
        "ext/drreg/drreg.c",
        "ext/drwrap/drwrap.c",
        "ext/drx/drx.c",
    ] {
        assert!(source.join(required).is_file(), "missing {required}");
    }
}

#[test]
fn build_script_never_populates_source_over_the_network() {
    let build_script = include_str!("../build.rs");
    for forbidden in [
        "Command::new(\"git\")",
        "git submodule",
        "DYNAMORIO_URL",
        "clone_dynamorio",
        "populate_dynamorio",
    ] {
        assert!(
            !build_script.contains(forbidden),
            "build script contains forbidden source-fetch path {forbidden:?}"
        );
    }
}
