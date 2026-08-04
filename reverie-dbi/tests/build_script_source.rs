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

/// Walk every regular file under a vendored source tree.
fn vendored_files(root: &Path) -> Vec<std::path::PathBuf> {
    fn walk(dir: &Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("failed to walk the vendored source") {
            let entry = entry.expect("failed to read a vendored directory entry");
            let path = entry.path();
            let kind = entry.file_type().expect("failed to stat a vendored path");
            if kind.is_dir() {
                walk(&path, found);
            } else if kind.is_file() {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    walk(root, &mut found);
    assert!(
        found.len() > 100,
        "the vendored DynamoRIO walk found only {} files",
        found.len()
    );
    found
}

/// The vendored DynamoRIO tree is source, not payload.
///
/// The curated tree originally carried thirteen upstream documentation and
/// Windows-resource images (`api/docs/**/*.png|ico`, `tools/DR*/res/*.ico|bmp`,
/// 302 kB total) that no build step reads. Detection is a NUL-byte scan over
/// the real bytes, so a renamed blob is still caught.
#[test]
fn vendored_dynamorio_source_contains_no_binary_files() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/dynamorio");
    let mut offenders = Vec::new();
    for path in vendored_files(&root) {
        let bytes = std::fs::read(&path).expect("failed to read a vendored DynamoRIO file");
        if bytes.contains(&0) {
            let relative = path.strip_prefix(&root).unwrap_or(&path);
            offenders.push(format!("{} ({} bytes)", relative.display(), bytes.len()));
        }
    }
    assert!(
        offenders.is_empty(),
        "the vendored DynamoRIO source must not contain binary files: {}",
        offenders.join(", ")
    );
}

/// No vendored text file may exceed the 2 MiB coordinator-approval ceiling.
///
/// Unlike the e9patch tree there is no approved exception here, so the
/// allowlist is empty and any oversized file is a regression.
#[test]
fn vendored_dynamorio_source_has_no_oversized_text_files() {
    const LARGE_TEXT_LIMIT: u64 = 2 * 1024 * 1024;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/dynamorio");
    let mut offenders = Vec::new();
    for path in vendored_files(&root) {
        let size = path
            .metadata()
            .expect("failed to stat a vendored DynamoRIO file")
            .len();
        if size > LARGE_TEXT_LIMIT {
            let relative = path.strip_prefix(&root).unwrap_or(&path);
            offenders.push(format!("{} ({size} bytes)", relative.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "vendored text files over {LARGE_TEXT_LIMIT} bytes need coordinator approval: {}",
        offenders.join(", ")
    );
}
