// The seed interpreter is a source-built mechanism, not a guest-selected
// executable or a runtime compiler invocation. The launcher feature builds its
// bytes, including consumers that currently share that feature with a preload.
use std::path::PathBuf;
use std::process::Command;

fn run(command: &mut Command) {
    let status = command.status().expect("run initial auxv compiler");
    assert!(
        status.success(),
        "initial auxv compiler failed: {command:?}"
    );
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=LD");
    if std::env::var_os("CARGO_FEATURE_LAUNCHER").is_none() {
        return;
    }
    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let linker = std::env::var_os("LD").unwrap_or_else(|| "ld".into());
    let mut objects = Vec::new();
    for source in ["seed-entry.S", "seed-bootstrap.c", "bootstrap-image.c"] {
        println!("cargo:rerun-if-changed=native_exec/{source}");
        let object = output.join(format!("{source}.o"));
        run(Command::new(&compiler)
            .args([
                "-c",
                "-fPIE",
                "-fno-plt",
                "-fno-stack-protector",
                "-fno-asynchronous-unwind-tables",
                "-fno-unwind-tables",
                "-fno-builtin",
                "-ffreestanding",
                // The interpreter must leave the kernel's FP/SIMD state
                // untouched; its assembly saves only general registers.
                "-mgeneral-regs-only",
                "-fvisibility=hidden",
                "-nostdlib",
                "-O2",
                "-Werror",
                "-Wall",
                "-Wextra",
            ])
            .arg(format!("native_exec/{source}"))
            .arg("-o")
            .arg(&object));
        objects.push(object);
    }
    for source in ["seed-control.h", "seed-bootstrap.ld", "bootstrap-image.h"] {
        println!("cargo:rerun-if-changed=native_exec/{source}");
    }
    run(Command::new(linker)
        .args([
            "-pie",
            "--no-dynamic-linker",
            "-Bsymbolic",
            "--no-undefined",
            "-z",
            "noexecstack",
            "-z",
            "max-page-size=4096",
            "-T",
            "native_exec/seed-bootstrap.ld",
        ])
        .args(objects)
        .arg("-o")
        .arg(output.join("initial-auxv-seed.elf")));
}
