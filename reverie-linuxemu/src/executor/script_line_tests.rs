// Tests that an in-guest exec reads a `#!` line exactly as the host kernel
// does (`load_script`, fs/binfmt_script.c): each script also runs natively,
// under the host kernel's own script loader, and the two must agree.

/// Writes `body` to `path`, executable by its owner.
fn script_line_write_executable(path: &std::path::Path, body: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// What `resolve_exec_shebang` makes of an exec of the script at `path` with
/// the argument `tail`: the interpreter and the rewritten argv, or the errno.
fn script_line_resolve(path: &std::path::Path) -> Result<(std::path::PathBuf, Vec<String>), i64> {
    resolve_exec_shebang(
        path.to_owned(),
        std::fs::read(path).unwrap(),
        vec![path.to_str().unwrap().to_owned(), "tail".to_owned()],
        |interpreter| std::fs::read(interpreter).map_err(io_error),
    )
    .map(|(interpreter, _, argv)| (interpreter, argv))
}

/// Each script's interpreter is printf, whose format is the line's optional
/// argument, so what it prints shows exactly which arguments it was given:
/// split into several, a line's tokens would be formatted one at a time. Each
/// script runs natively with the argument `tail`, and printf run with the argv
/// `resolve_exec_shebang` rewrites must print the same, byte for byte. That
/// holds for one argument, for many tokens (Linux passes them as one
/// argument, spaces and tabs included), for a line longer than Linux's
/// 256-byte buffer (whose argument Linux cuts at the buffer's end) and for
/// trailing spaces and tabs (which Linux drops). The rewritten argv grows by
/// at most two entries, whatever the line holds.
#[test]
fn a_script_line_resolves_as_the_host_kernel_resolves_it() {
    let printf = std::path::Path::new("/usr/bin/printf");
    assert!(printf.exists(), "this check runs printf from /usr/bin");
    let root = TestDir::new();
    let long = format!("#!/usr/bin/printf [%s]{}\n", " t".repeat(200));
    for (name, line) in [
        ("one-argument", "#!/usr/bin/printf [%s]\n"),
        (
            "many-tokens",
            "#! /usr/bin/printf [%s] a b\tc  d\necho unused\n",
        ),
        ("long-line", long.as_str()),
        ("trailing-blanks", "#!/usr/bin/printf [%s]-x \t \n"),
    ] {
        let script = root.0.join(name);
        script_line_write_executable(&script, line.as_bytes());
        let native = std::process::Command::new(&script)
            .arg("tail")
            .output()
            .unwrap();
        let (interpreter, argv) = script_line_resolve(&script).unwrap();
        assert_eq!(interpreter, printf, "{name}");
        assert!(argv.len() <= 2 + 2, "{name}: {argv:?}");
        let rewritten = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .unwrap();
        assert!(native.status.success(), "{name}: {native:?}");
        assert_eq!(
            String::from_utf8_lossy(&rewritten.stdout),
            String::from_utf8_lossy(&native.stdout),
            "{name}: {argv:?}"
        );
        assert_eq!(rewritten.status.code(), native.status.code(), "{name}");
    }
}

/// The lines Linux refuses are refused with the same errno: an interpreter
/// that Linux's 256-byte buffer cuts off is ENOEXEC natively and here, and a
/// carriage return is part of the interpreter's name, which then names no
/// file (ENOENT) natively and here.
#[test]
fn a_script_line_linux_refuses_is_refused_with_the_same_errno() {
    let root = TestDir::new();
    for (name, line, errno) in [
        (
            "cut-interpreter",
            format!("#!/{}\n", "a".repeat(300)),
            libc::ENOEXEC,
        ),
        (
            "carriage-return",
            "#!/usr/bin/printf\r\n".to_owned(),
            libc::ENOENT,
        ),
    ] {
        let script = root.0.join(name);
        script_line_write_executable(&script, line.as_bytes());
        let native = std::process::Command::new(&script)
            .output()
            .expect_err("Linux refuses the exec");
        assert_eq!(native.raw_os_error(), Some(errno), "{name}: {native}");
        assert_eq!(
            script_line_resolve(&script).unwrap_err(),
            negative_errno(errno),
            "{name}"
        );
    }
}
