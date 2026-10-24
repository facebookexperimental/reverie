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
    // This test binary is linked the default way.
    let bytes = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    assert_eq!(
        check_runtime(&bytes).map(|_| ()),
        Err(ArtifactError::Image(ImageError::NotFixedAddress))
    );
}
