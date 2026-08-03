use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

const SABRE_REVISION: &str = "41113f849f8799932ed8c7883f5a4de616b9e9fa";
const MAX_PARALLEL_JOBS: usize = 16;

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

fn run(command: &mut Command, description: &str) {
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("failed to {description}: {error}"));
    assert!(status.success(), "failed to {description}: {status}");
}
