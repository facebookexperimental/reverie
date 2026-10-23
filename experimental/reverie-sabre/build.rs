use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

const SABRE_REVISION: &str = "41113f849f8799932ed8c7883f5a4de616b9e9fa";
const MAX_PARALLEL_JOBS: usize = 16;
const CMAKE_HOME_DIRECTORY_PREFIX: &str = "CMAKE_HOME_DIRECTORY:INTERNAL=";

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo sets target architecture");
    assert_eq!(
        target_arch, "x86_64",
        "the vendored SaBRe plugin API currently supports only x86_64"
    );

    println!("cargo:rerun-if-changed=src/ffi/recursion_protector.c");
    println!("cargo:rerun-if-changed=src/ffi/vfork_syscall.S");
    println!("cargo:rerun-if-changed=vendor/sabre");
    println!("cargo:rerun-if-changed=vendor/libelf");
    println!("cargo:rerun-if-env-changed=CMAKE");
    println!("cargo:rerun-if-env-changed=CMAKE_GENERATOR");

    cc::Build::new()
        .file("src/ffi/recursion_protector.c")
        .file("src/ffi/vfork_syscall.S")
        .compile("reverie_sabre_plugin_api");

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join("vendor/sabre");
    let revision = std::fs::read_to_string(source.join("REVISION"))
        .expect("the vendored SaBRe source is missing its REVISION marker");
    assert_eq!(
        revision.trim(),
        SABRE_REVISION,
        "the vendored SaBRe source revision marker changed"
    );
    for required in [
        "CMakeLists.txt",
        "loader/loader.c",
        "loader/rewriter.c",
        "arch/x86_64/rewriter.c",
    ] {
        assert!(
            source.join(required).is_file(),
            "the vendored SaBRe source is incomplete: missing {required}"
        );
    }

    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let libelf = manifest.join("vendor/libelf");
    let libelf_link = build_libelf(&libelf, &output.join("libelf-build-v2"));
    // Keep cached CMake state tied to this build recipe. Bump the suffix when
    // configure or link inputs change so Cargo cannot reuse incompatible state.
    let loader = build_sabre(
        &source,
        &output.join("sabre-build-v4"),
        &libelf,
        &libelf_link,
    );
    println!("cargo:rustc-env=REVERIE_SABRE_LOADER={}", loader.display());
    println!("cargo:rustc-env=REVERIE_SABRE_SOURCE={}", source.display());
}

fn build_libelf(source: &Path, output: &Path) -> PathBuf {
    let mut sources = fs::read_dir(source)
        .expect("failed to read the vendored libelf source")
        .map(|entry| {
            entry
                .expect("failed to inspect a vendored libelf file")
                .path()
        })
        .filter(|path| {
            path.extension().is_some_and(|extension| extension == "c")
                && path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with("elf") || name.starts_with("gelf")
                })
        })
        .collect::<Vec<_>>();
    sources.sort();
    assert!(
        sources.iter().any(|path| path.ends_with("gelf_getsym.c"))
            && sources.iter().any(|path| path.ends_with("gelf_getnote.c")),
        "the vendored libelf source is incomplete"
    );

    fs::create_dir_all(output).expect("failed to create the libelf build directory");
    cc::Build::new()
        .cargo_metadata(false)
        .out_dir(output)
        .include(source)
        .include(source.join("include"))
        .define("HAVE_CONFIG_H", None)
        .flag_if_supported("-fPIC")
        .opt_level(2)
        .files(sources)
        .compile("elf");

    // SaBRe links with `-lelf`. Prefer this script to the adjacent archive so
    // zlib follows the static libelf objects that reference it.
    fs::write(output.join("libelf.so"), "GROUP ( libelf.a -lz )\n")
        .expect("failed to write the static libelf linker script");
    output.to_path_buf()
}

fn build_sabre(source: &Path, build: &Path, libelf: &Path, libelf_link: &Path) -> PathBuf {
    reset_relocated_cmake_build(source, build);
    let started = Instant::now();
    let cmake = env::var_os("CMAKE").unwrap_or_else(|| "cmake".into());
    let mut configure = Command::new(&cmake);
    configure
        .arg("-S")
        .arg(source)
        .arg("-B")
        .arg(build)
        .arg("-DCMAKE_BUILD_TYPE=Release")
        .arg(format!("-DCMAKE_C_FLAGS=-I{}", libelf.display()))
        .arg(format!(
            "-DCMAKE_EXE_LINKER_FLAGS=-L{}",
            libelf_link.display()
        ));
    if let Some(generator) = env::var_os("CMAKE_GENERATOR") {
        configure.arg("-G").arg(generator);
    }
    run(&mut configure, "configure SaBRe");

    let jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|jobs| jobs.parse::<usize>().ok())
        .unwrap_or(1)
        .clamp(1, MAX_PARALLEL_JOBS);
    run(
        Command::new(cmake)
            .arg("--build")
            .arg(build)
            .args(["--config", "Release", "--target", "sabre", "--parallel"])
            .arg(jobs.to_string()),
        "build SaBRe",
    );

    let loader = build.join("sabre");
    assert!(
        loader.is_file(),
        "SaBRe build did not produce {}",
        loader.display()
    );
    println!(
        "cargo:warning=SaBRe source build completed in {:.2}s (jobs={jobs})",
        started.elapsed().as_secs_f64()
    );
    loader
}

/// Reset package-owned CMake state when Cargo relocates this dependency.
///
/// Cargo can reuse an `OUT_DIR` while checking out the same dependency beneath
/// a different `CARGO_HOME`. CMake records the absolute source directory in
/// `CMakeCache.txt` and refuses to configure that build directory from the new
/// location. Generated build files also contain absolute paths, so discard the
/// complete package-owned directory rather than only its cache file.
fn reset_relocated_cmake_build(source: &Path, build: &Path) {
    let cache = build.join("CMakeCache.txt");
    let contents = match fs::read_to_string(&cache) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!(
            "failed to read the SaBRe CMake cache {}: {error}",
            cache.display()
        ),
    };
    let recorded_source = contents
        .lines()
        .find_map(|line| line.strip_prefix(CMAKE_HOME_DIRECTORY_PREFIX));
    if recorded_source.is_some_and(|recorded| Path::new(recorded) == source) {
        return;
    }

    fs::remove_dir_all(build).unwrap_or_else(|error| {
        panic!(
            "failed to discard relocated SaBRe CMake state {}: {error}",
            build.display()
        )
    });
    println!(
        "cargo:warning=Discarded relocated SaBRe CMake state at {}",
        build.display()
    );
}

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {description}: {error}"));
    assert!(status.success(), "failed to {description}: {status}");
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    use super::*;

    static NEXT_SCRATCH: AtomicU64 = AtomicU64::new(0);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(case: &str) -> Self {
            let sequence = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "reverie-sabre-build-cache-{case}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("failed to create test scratch directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_cache(build: &Path, source: Option<&Path>) {
        fs::create_dir_all(build).unwrap();
        let home = source
            .map(|source| format!("{CMAKE_HOME_DIRECTORY_PREFIX}{}\n", source.display()))
            .unwrap_or_default();
        fs::write(
            build.join("CMakeCache.txt"),
            format!("# CMake cache fixture\n{home}CMAKE_BUILD_TYPE:STRING=Release\n"),
        )
        .unwrap();
        fs::write(build.join("compiled-object"), b"preserve unless relocated").unwrap();
    }

    #[test]
    fn same_source_preserves_cached_objects() {
        let scratch = Scratch::new("same-source");
        let source = scratch.path().join("source = current");
        let build = scratch.path().join("build");
        fs::create_dir(&source).unwrap();
        write_cache(&build, Some(&source));

        reset_relocated_cmake_build(&source, &build);
        assert_eq!(
            fs::read(build.join("compiled-object")).unwrap(),
            b"preserve unless relocated"
        );
    }

    #[test]
    fn moved_source_discards_only_the_package_build_directory() {
        let scratch = Scratch::new("moved-source");
        let old_source = scratch.path().join("old-cargo-home/source");
        let source = scratch.path().join("new-cargo-home/source");
        let build = scratch.path().join("out/sabre-build-v4");
        fs::create_dir_all(&old_source).unwrap();
        fs::create_dir_all(&source).unwrap();
        write_cache(&build, Some(&old_source));
        let adjacent = scratch.path().join("out/adjacent-artifact");
        fs::write(&adjacent, b"must remain").unwrap();

        reset_relocated_cmake_build(&source, &build);
        assert!(!build.exists());
        assert_eq!(fs::read(adjacent).unwrap(), b"must remain");
        assert!(
            old_source.exists(),
            "source existence must not define freshness"
        );
    }

    #[test]
    fn missing_cache_preserves_partial_build_state() {
        let scratch = Scratch::new("missing-cache");
        let source = scratch.path().join("source");
        let build = scratch.path().join("build");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&build).unwrap();
        fs::write(build.join("partial-object"), b"keep").unwrap();

        reset_relocated_cmake_build(&source, &build);
        assert_eq!(fs::read(build.join("partial-object")).unwrap(), b"keep");
    }

    #[test]
    fn cache_without_source_identity_is_rebuilt() {
        let scratch = Scratch::new("malformed-cache");
        let source = scratch.path().join("source");
        let build = scratch.path().join("build");
        fs::create_dir(&source).unwrap();
        write_cache(&build, None);

        reset_relocated_cmake_build(&source, &build);
        assert!(!build.exists());
    }
}
