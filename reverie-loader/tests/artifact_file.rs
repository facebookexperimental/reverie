/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The artifact check on real image files: a fixed-address image linked by
//! the toolchain the way the runtime will be (a linker script placing the
//! gate at the first page of the window), read back from disk. The fixture
//! images are only checked, never run.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

use reverie_loader::artifact::ArtifactError;
use reverie_loader::artifact::RUNTIME_GATE;
use reverie_loader::artifact::RUNTIME_WINDOW;
use reverie_loader::artifact::check_runtime;
use reverie_loader::audit::StraySyscall;
use reverie_loader::audit::stray_syscall;
use reverie_loader::image::ImageError;

/// A `no_std` program whose only `syscall` is in `.gate`, or, with
/// `STRAY`, a second one in `.text`.
const SOURCE: &str = r#"
#![no_std]
#![no_main]

// Without `inline(never)` the optimizer copies the gate's `syscall` into
// its callers in `.text`, which the audit refuses.
#[inline(never)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".gate")]
pub extern "C" fn gate_exit() -> ! {
    unsafe { core::arch::asm!("syscall", in("rax") 60, in("rdi") 0, options(noreturn)) }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    #[cfg(stray)]
    unsafe {
        core::arch::asm!("syscall", in("rax") 39, lateout("rcx") _, lateout("r11") _);
    }
    gate_exit()
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    gate_exit()
}
"#;

/// The gate page, then everything else from the next page, each in its own
/// page-aligned `PT_LOAD`; no headers are loaded.
fn linker_script() -> String {
    format!(
        "ENTRY(_start)
PHDRS {{ gate PT_LOAD FLAGS(5); text PT_LOAD FLAGS(5); }}
SECTIONS {{
  . = {gate:#x};
  .gate : {{ KEEP(*(.gate)) }} :gate
  . = ALIGN(4096);
  .text : {{ *(.text .text.*) *(.rodata .rodata.*) }} :text
  /DISCARD/ : {{ *(.eh_frame*) *(.note*) *(.comment) *(.data*) *(.bss*) }}
}}
",
        gate = RUNTIME_GATE.start
    )
}

/// A directory this test creates itself, owner-only, under a name nothing
/// else holds: creation fails rather than reuse an existing path or follow
/// a planted link.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        for attempt in 0..100 {
            let dir = std::env::temp_dir().join(format!(
                "reverie-loader-artifact-{name}-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Self(dir),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("creating {}: {error}", dir.display()),
            }
        }
        panic!("no fresh scratch directory after 100 attempts");
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Links [`SOURCE`] at the runtime window with the system linker and returns
/// the image file's path.
fn link(dir: &Path, stray: bool) -> PathBuf {
    let source = dir.join("fixture.rs");
    let script = dir.join("fixture.ld");
    let output = dir.join("fixture");
    std::fs::write(&source, SOURCE).unwrap();
    std::fs::write(&script, linker_script()).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let mut command = Command::new(rustc);
    command
        .args(["--edition", "2024", "--crate-type", "bin", "-O"])
        .args(["-C", "panic=abort", "-C", "relocation-model=static"])
        .args(["-C", "link-arg=-nostartfiles", "-C", "link-arg=-nostdlib"])
        .args([
            "-C",
            "link-arg=-static",
            "-C",
            "link-arg=-Wl,--build-id=none",
        ])
        .arg("-C")
        .arg(format!("link-arg=-T{}", script.display()))
        .arg("-o")
        .arg(&output)
        .arg(&source);
    if stray {
        command.args(["--cfg", "stray"]);
    }
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "linking the fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

/// The ELF type (`e_type`) of `bytes`: 2 is `ET_EXEC`, 3 is `ET_DYN`.
fn elf_type(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[16], bytes[17]])
}

/// Whether `bytes` names an interpreter (a `PT_INTERP` program header, 3).
fn has_interpreter(bytes: &[u8]) -> bool {
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes([bytes[54], bytes[55]]) as usize;
    let phnum = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    (0..phnum).any(|index| {
        let start = phoff + index * phentsize;
        u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) == 3
    })
}

/// Links [`SOURCE`] as an ordinary position-independent executable: a
/// static PIE (`ET_DYN`) with no interpreter. The image is only parsed,
/// never run.
fn link_pie(dir: &Path) -> PathBuf {
    let source = dir.join("pie.rs");
    let output = dir.join("pie");
    std::fs::write(&source, SOURCE).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let result = Command::new(rustc)
        .args(["--edition", "2024", "--crate-type", "bin", "-O"])
        .args(["-C", "panic=abort", "-C", "relocation-model=pic"])
        .args(["-C", "link-arg=-nostartfiles", "-C", "link-arg=-nostdlib"])
        .args([
            "-C",
            "link-arg=-static-pie",
            "-C",
            "link-arg=-Wl,--build-id=none",
        ])
        .arg("-o")
        .arg(&output)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "linking the PIE fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

/// The interpreter path carried by the interpreter fixture below.
const INTERP_PATH: &str = "/lib64/ld-linux-x86-64.so.2";

/// Links [`SOURCE`] as a fixed-address executable that names an
/// interpreter (`ET_EXEC` with `PT_INTERP`): the same no_std pattern as
/// [`link`], with a linker script whose `PHDRS` declares the `PT_INTERP`
/// segment over a `.interp` string the source carries. No host startup
/// files or libraries are linked. The image is only parsed, never run.
fn link_interpreter(dir: &Path) -> PathBuf {
    let source = dir.join("interp.rs");
    let script = dir.join("interp.ld");
    let output = dir.join("interp");
    let mut text = SOURCE.to_owned();
    text.push_str(
        "\n#[used]\n#[unsafe(link_section = \".interp\")]\nstatic INTERP_PATH: [u8; 28] = *b\"",
    );
    text.push_str(INTERP_PATH);
    text.push_str("\\0\";\n");
    std::fs::write(&source, text).unwrap();
    std::fs::write(
        &script,
        "ENTRY(_start)\nPHDRS\n{\n  interp PT_INTERP ;\n  text PT_LOAD FILEHDR PHDRS ;\n}\n\
         SECTIONS\n{\n  . = SIZEOF_HEADERS;\n\
         \x20 .interp : { KEEP(*(.interp)) } :text :interp\n\
         \x20 .text : { *(.text*) } :text\n\
         \x20 .rodata : { *(.rodata*) *(.data.rel.ro*) } :text\n\
         \x20 .eh_frame : { *(.eh_frame*) } :text\n\
         \x20 .data : { *(.data*) } :text\n\
         \x20 .bss : { *(.bss*) *(COMMON) } :text\n}\n",
    )
    .unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let result = Command::new(rustc)
        .args(["--edition", "2024", "--crate-type", "bin", "-O"])
        .args(["-C", "panic=abort", "-C", "relocation-model=static"])
        .args(["-C", "link-arg=-nostartfiles", "-C", "link-arg=-nostdlib"])
        .args(["-C", "link-arg=-static"])
        .arg("-C")
        .arg(format!("link-arg=-T{}", script.display()))
        .args(["-C", "link-arg=-Wl,--build-id=none"])
        .arg("-o")
        .arg(&output)
        .arg(&source)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "linking the interpreter fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    output
}

#[test]
fn a_linked_image_with_its_syscall_in_the_gate_passes() {
    let scratch = Scratch::new("gate");
    let bytes = std::fs::read(link(&scratch.0, false)).unwrap();
    let image = check_runtime(&bytes).unwrap();
    assert!(RUNTIME_WINDOW.contains(&image.entry()));
    assert!(!RUNTIME_GATE.contains(&image.entry()));
    // One segment maps exactly the gate page, read and execute only.
    let gate: Vec<_> = image
        .segments()
        .filter(|s| s.pages().unwrap() == RUNTIME_GATE)
        .collect();
    assert_eq!(gate.len(), 1);
    let permissions = gate[0].permissions;
    assert!(permissions.read && permissions.execute && !permissions.write);
    // The gate really holds the image's syscall: with no gate allowed, the
    // audit finds it there.
    let found = stray_syscall(&image, &[]).unwrap().unwrap();
    assert!(RUNTIME_GATE.contains(&found.address));
}

#[test]
fn a_linked_image_with_a_syscall_outside_the_gate_is_refused() {
    let scratch = Scratch::new("stray");
    let bytes = std::fs::read(link(&scratch.0, true)).unwrap();
    match check_runtime(&bytes) {
        Err(ArtifactError::StraySyscall(StraySyscall { address })) => {
            assert!(!RUNTIME_GATE.contains(&address));
            assert!(RUNTIME_WINDOW.contains(&address));
        }
        other => panic!("expected a stray syscall, got {other:?}"),
    }
}

#[test]
fn an_ordinary_position_independent_executable_is_refused() {
    let scratch = Scratch::new("pie");
    let bytes = std::fs::read(link_pie(&scratch.0)).unwrap();
    // The fixture must really be an ordinary PIE: ET_DYN and no PT_INTERP.
    // A different shape is a fixture failure here, not another expectation.
    assert_eq!(elf_type(&bytes), 3, "the PIE fixture is not ET_DYN");
    assert!(
        !has_interpreter(&bytes),
        "the PIE fixture names an interpreter"
    );
    assert_eq!(
        check_runtime(&bytes).map(|_| ()),
        Err(ArtifactError::Image(ImageError::NotFixedAddress))
    );
}

#[test]
fn an_executable_naming_an_interpreter_is_refused() {
    let scratch = Scratch::new("interp");
    let bytes = std::fs::read(link_interpreter(&scratch.0)).unwrap();
    // The fixture must really be ET_EXEC naming a PT_INTERP interpreter.
    assert_eq!(
        elf_type(&bytes),
        2,
        "the interpreter fixture is not ET_EXEC"
    );
    assert!(
        has_interpreter(&bytes),
        "the interpreter fixture has no PT_INTERP"
    );
    assert_eq!(
        check_runtime(&bytes).map(|_| ()),
        Err(ArtifactError::Image(ImageError::HasInterpreter))
    );
}
