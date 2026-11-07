#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::Path;
use std::process::Command;
use std::process::Output;

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

#[test]
fn late_detours_preserve_tls_original_calls_and_reject_aliases() {
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let fixtures =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/late_function_registration");
    let out = std::env::temp_dir().join(format!("reverie-late-detours-{}", std::process::id()));
    std::fs::create_dir(&out).unwrap();
    eprintln!("late detour fixture retained at {}", out.display());
    let compiler = cc::Build::new()
        .cargo_metadata(false)
        .opt_level(1)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler();
    let search = format!("-L{}", out.display());
    let runpath = format!("-Wl,-rpath,{}", out.display());
    checked(
        compiler
            .to_command()
            .args(["-fPIC", "-shared"])
            .arg(fixtures.join("library.c"))
            .args(["-Wl,-soname,liblate_probe.so", "-o"])
            .arg(out.join("liblate_probe.so"))
            .arg("-UNDEBUG"),
    );
    checked(
        compiler
            .to_command()
            .arg(fixtures.join("client.c"))
            .args([&search, &runpath, "-llate_probe", "-o"])
            .arg(out.join("client"))
            .arg("-UNDEBUG"),
    );
    checked(
        compiler
            .to_command()
            .args(["-nostdlib", "-static-pie", "-Wl,-E,--no-dynamic-linker"])
            .arg(fixtures.join("client-static.S"))
            .arg("-o")
            .arg(out.join("client-static"))
            .arg("-UNDEBUG"),
    );
    let headers = checked(
        Command::new("readelf")
            .args(["-lW"])
            .arg(out.join("client-static")),
    );
    assert!(!String::from_utf8_lossy(&headers.stdout).contains("INTERP"));
    let symbols = checked(
        Command::new("readelf")
            .args(["--dyn-syms", "-W"])
            .arg(out.join("client-static")),
    );
    assert!(
        String::from_utf8_lossy(&symbols.stdout)
            .lines()
            .any(|line| line.contains("FUNC") && line.ends_with(" late_probe"))
    );
    checked(
        compiler
            .to_command()
            .args(["-fPIC", "-shared", "-D__NX_INTERCEPT_RDTSC", "-I"])
            .arg(source.join("includes/plugins"))
            .arg(fixtures.join("plugin.c"))
            .arg(source.join("plugin_api/recursion_protector.c"))
            .arg(loader.parent().unwrap().join("plugin_api/libplugin_api.a"))
            // The static-loader namespace exports data objects with the same names
            // as the plugin's recursion functions. Bind its own functions locally.
            .args([&search, &runpath, "-Wl,-z,now", "-llate_probe", "-o"])
            .arg(out.join("plugin.so"))
            .args([
                "-UNDEBUG",
                "-Wl,-Bsymbolic-functions",
                "-Wl,-fini,finalizer_last",
            ]),
    );
    for (mode, code, text) in [
        ("dynamic", 0, "CLIENT_OK\n"),
        ("static", 0, "STATIC_OK\n"),
        ("conflict", 1, "conflicting function intercept registration"),
        ("capacity", 1, "function intercept table is full"),
        ("alias-prefix", 127, "overlapping function intercept target"),
        ("alias-elf", 127, "overlapping function intercept target"),
        (
            "alias-conflict",
            127,
            "overlapping function intercept target",
        ),
        ("static-alias", 127, "overlapping function intercept target"),
    ] {
        let client = if mode.starts_with("static") {
            "client-static"
        } else {
            "client"
        };
        let output = Command::new("timeout")
            .args(["--kill-after=2s", "20s"])
            .arg(loader)
            .arg(out.join("plugin.so"))
            .arg(mode)
            .arg("--")
            .arg(out.join(client))
            .output()
            .unwrap();
        eprintln!("late detour {mode}: {output:?}");
        assert_eq!(output.status.code(), Some(code), "{mode}: {output:?}");
        if code == 0 {
            assert_eq!(output.stdout, text.as_bytes(), "{mode}: {output:?}");
        } else {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(text),
                "{mode}: {output:?}"
            );
        }
    }
}

struct RegistrationOrderTool;
impl reverie_sabre::Tool for RegistrationOrderTool {
    type Client = ();
    fn new(_: ()) -> Self {
        panic!("registration constructed the tool")
    }
    fn detours() -> &'static [reverie_sabre::ffi::fn_icept] {
        static DETOURS: [reverie_sabre::ffi::fn_icept; 1] = [reverie_sabre::ffi::fn_icept {
            lib_name: c"libunused".as_ptr(),
            fn_name: c"unused".as_ptr(),
            icept_callback: unchanged_callback,
        }];
        &DETOURS
    }
}
impl reverie_sabre::ToolGlobal for RegistrationOrderTool {
    type Target = Self;
    fn global() -> &'static Self {
        panic!("registration accessed the global tool")
    }
}
extern "C" fn unchanged_callback(
    f: reverie_sabre::ffi::void_void_fn,
) -> reverie_sabre::ffi::void_void_fn {
    f
}
static REGISTRATIONS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
extern "C" fn observe_registration(descriptor: *const reverie_sabre::ffi::fn_icept) {
    assert!(!descriptor.is_null());
    assert!(
        !unsafe { libc::getenv(c"REVERIE_SABRE_BACKEND_STATS_FD".as_ptr()) }.is_null(),
        "registration ran after stats environment consumption"
    );
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut action) },
        0
    );
    assert_eq!(action.sa_sigaction, libc::SIG_IGN);
    REGISTRATIONS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

#[test]
fn declared_detours_register_before_actual_stats_initialization() {
    use reverie::BackendStatsSource;
    use reverie_sabre::stats::BACKEND_STATS_ENV;
    use reverie_sabre::stats::SabreSlowPath;
    use reverie_sabre::stats::SabreStats;
    const CHILD: &str = "REVERIE_TEST_REGISTRATION_ORDER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let stats = SabreStats::create(reverie::BackendStatsRequest::ENABLED)
            .unwrap()
            .unwrap();
        let output = Command::new("timeout")
            .args(["--kill-after=2s", "20s"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "declared_detours_register_before_actual_stats_initialization",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(BACKEND_STATS_ENV, stats.raw_fd().to_string())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(
            stats
                .backend_stats()
                .slow_paths
                .count(&SabreSlowPath::PtraceSyscallEntry),
            1
        );
        return;
    }
    unsafe {
        libc::signal(libc::SIGUSR1, libc::SIG_IGN);
    }
    let mut argc = 1;
    let mut arguments = [c"plugin".as_ptr().cast_mut(), std::ptr::null_mut()];
    let mut argv = arguments.as_mut_ptr();
    let (mut vdso, mut syscall, mut rdtsc, mut post_load) = (None, None, None, None);
    reverie_sabre::internal::sbr_init::<RegistrationOrderTool>(
        &mut argc,
        &mut argv,
        observe_registration,
        &mut vdso,
        &mut syscall,
        &mut rdtsc,
        &mut post_load,
        c"/native/sabre".as_ptr(),
        c"/native/client".as_ptr(),
    );
    assert_eq!(REGISTRATIONS.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(unsafe { libc::getenv(c"REVERIE_SABRE_BACKEND_STATS_FD".as_ptr()) }.is_null());
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut action) },
        0
    );
    assert_ne!(action.sa_sigaction, libc::SIG_IGN);
    assert!(vdso.is_some() && syscall.is_some() && rdtsc.is_some() && post_load.is_some());
    assert_eq!(argc, 0);
    reverie_sabre::stats::increment_guest_slow_path(SabreSlowPath::PtraceSyscallEntry);
}
