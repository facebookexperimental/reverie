#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::process::Command;

/// The actual loader leaves free address space above a PIE client's image,
/// where its program break starts, halves that headroom under RLIMIT_AS, and
/// maps a fixed-address client at its link-time address.
#[test]
fn actual_loader_keeps_room_above_a_pie_clients_image() {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // The target directory, not /tmp, which may be mounted noexec.
    let out = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("reverie-brk-headroom-{}", std::process::id()));
    std::fs::create_dir(&out).unwrap();
    let build = || {
        cc::Build::new()
            .cargo_metadata(false)
            .opt_level(2)
            .host("x86_64-unknown-linux-gnu")
            .target("x86_64-unknown-linux-gnu")
            .get_compiler()
    };
    let fixture = out.join("fixture.c");
    std::fs::write(&fixture, "int main(void) { return 0; }\n").unwrap();
    let pie = out.join("pie");
    let exec = out.join("exec");
    for (target, flags) in [
        (&pie, &["-fPIE", "-pie"][..]),
        (&exec, &["-no-pie", "-Wl,-Ttext-segment=0x20000000"][..]),
    ] {
        let output = build()
            .to_command()
            .args(flags)
            .arg(&fixture)
            .arg("-o")
            .arg(target)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
    let binary = out.join("brk-headroom");
    let output = build()
        .to_command()
        // Compile the real loader file; functions it defines that this test
        // does not call are discarded, so libelf need not be linked.
        .args([
            "-std=gnu99",
            "-UNDEBUG",
            "-fPIE",
            "-pie",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
        ])
        .arg("-I")
        .arg(source.join("vendor/sabre/includes"))
        .arg("-I")
        .arg(source.join("vendor/sabre/includes/loader"))
        .arg("-I")
        .arg(source.join("vendor/libelf"))
        .arg(source.join("tests/loader_brk_headroom.c"))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    for (mode, client, expected) in [
        ("pie", &pie, "PASS pie gap"),
        ("pie-limited", &pie, "PASS pie-limited gap="),
        ("exec", &exec, "PASS exec bias=0\n"),
    ] {
        let output = Command::new(&binary)
            .arg(mode)
            .arg(client)
            .output()
            .unwrap();
        assert!(output.status.success(), "mode={mode}: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.starts_with(expected), "mode={mode}: {output:?}");
        println!("{mode}: {}", stdout.trim_end());
    }
    std::fs::remove_dir_all(&out).unwrap();
}
