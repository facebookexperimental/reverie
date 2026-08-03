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

#[test]
fn build_cache_is_content_addressed_and_visible() {
    let build_script = include_str!("../build.rs");
    for required in [
        "let source_key = source_recipe_key(",
        "dynamorio-build-{source_key}",
        "CMAKE_GENERATOR",
        "DynamoRIO build cache HIT key=sha256:",
        "DynamoRIO build cache MISS key=sha256:",
    ] {
        assert!(
            build_script.contains(required),
            "build script lacks cache invariant {required:?}"
        );
    }
}

#[test]
fn ci_uses_the_vendored_content_addressed_cache() {
    let workflow = include_str!("../../.github/workflows/ci.yml");
    assert!(workflow.contains("out/dynamorio-install-*"));
    assert!(
        workflow.contains("hashFiles('reverie-dbi/vendor/dynamorio/**', 'reverie-dbi/build.rs')")
    );
    for obsolete in [
        "scripts/backend-submodule.sh activate dynamorio",
        "out/dynamorio-revision",
        "steps.dynamorio.outputs.rev",
    ] {
        assert!(
            !workflow.contains(obsolete),
            "CI still contains obsolete cache input {obsolete:?}"
        );
    }
}
