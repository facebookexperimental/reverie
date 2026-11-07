#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! A prefixed SYSCALL (for example REX.W 0F 05), which the decoder reports as
//! SYSCALL with a longer length, is intercepted correctly by both rewrite
//! routes: a jump rewrite, and, at a site too short to relocate, the UD0
//! marker, which goes on the final 0F 05 with the prefixes turned into NOPs so
//! the guest resumes after the whole instruction. A SYSCALL the CPU would not
//! execute natively (LOCK-prefixed, or longer than 15 bytes) is left as it is.
//! The patch statistics measure a marker patch's shape from the instruction's
//! start, and recognize its SIGILL by the marker's address. Under the launch
//! setting `REVERIE_SABRE_SHORT_SYSCALL_SITES=raw` a short site keeps its
//! original bytes instead of getting the marker.

use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use reverie::BackendStatsSource;
use reverie_sabre::stats::BACKEND_STATS_ENV;
use reverie_sabre::stats::SabreSlowPath;
use reverie_sabre::stats::SabreStats;
use reverie_sabre::stats::SabreStatsSnapshot;

/// Held while a child that could inherit a launch specification is created,
/// and by `launched` from creating its specification until its child exits:
/// the specification descriptor is inheritable, and the tests run in parallel
/// threads, so another test's loader would otherwise read it.
static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn checked(command: &mut Command) -> Output {
    let output = spawned(command);
    assert!(output.status.success(), "{command:?}: {output:?}");
    output
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/prefixed_syscall")
}

fn compiler() -> cc::Tool {
    cc::Build::new()
        .cargo_metadata(false)
        .opt_level(1)
        .host("x86_64-unknown-linux-gnu")
        .target("x86_64-unknown-linux-gnu")
        .get_compiler()
}

/// Builds the client with its aligned short site at byte `aligned_offset` of
/// a 64-byte cache line.
fn build_client(out: &Path, name: &str, aligned_offset: u32) -> PathBuf {
    let client = out.join(name);
    checked(
        compiler()
            .to_command()
            .arg(format!("-DALIGNED_SITE_OFFSET={aligned_offset}"))
            .arg(fixtures().join("client.c"))
            .arg(fixtures().join("probe.S"))
            .arg("-o")
            .arg(&client),
    );
    client
}

fn build_plugin(out: &Path) -> PathBuf {
    build_plugin_as(out, "plugin.so", None)
}

/// The fixture plugin, built with `define` (for example `-DPOST_ARM`).
fn build_plugin_as(out: &Path, name: &str, define: Option<&str>) -> PathBuf {
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let plugin = out.join(name);
    let mut command = compiler().to_command();
    if let Some(define) = define {
        command.arg(define);
    }
    checked(
        command
            .args(["-fPIC", "-shared", "-D__NX_INTERCEPT_RDTSC", "-I"])
            .arg(source.join("includes/plugins"))
            .arg(fixtures().join("plugin.c"))
            .arg(source.join("plugin_api/recursion_protector.c"))
            .arg(loader.parent().unwrap().join("plugin_api/libplugin_api.a"))
            .args(["-Wl,-z,now", "-o"])
            .arg(&plugin)
            .args(["-UNDEBUG", "-Wl,-Bsymbolic-functions"]),
    );
    plugin
}

fn spawned(command: &mut Command) -> Output {
    let _spawn = SPAWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    command.output().unwrap()
}

fn under_loader(plugin: &Path, client: &Path) -> Command {
    let mut command = Command::new("timeout");
    command
        .args(["--kill-after=2s", "20s"])
        .arg(reverie_sabre::bundled_sabre_path())
        .arg(plugin)
        .arg("--")
        .arg(client);
    command
}

#[test]
fn prefixed_syscalls_are_intercepted_and_resume_after_the_instruction() {
    let out = tempfile::tempdir().unwrap();
    let client = build_client(out.path(), "client", 0);
    let plugin = build_plugin(out.path());

    // Natively every call returns the real parent process ID.
    let native = checked(&mut Command::new(&client));
    assert_eq!(
        String::from_utf8(native.stdout).unwrap(),
        "plain=NATIVE prefixed=NATIVE prefixed_short=NATIVE aligned_short=NATIVE\n\
         plain=NATIVE prefixed=NATIVE prefixed_short=NATIVE aligned_short=NATIVE\n\
         prefixed_code=b86e000000909090480f05909090c3\n\
         short_site=480f05\n\
         aligned_site=66480f05\n\
         lock_site=66f00f05\n\
         overlong_site=3e3e3e3e3e3e3e3e3e3e3e3e3e3e0f05\n"
    );

    let output = spawned(&mut under_loader(&plugin, &client));
    assert!(output.status.success(), "{output:?}");
    // Each site is routed on both rounds. The long prefixed site is a jump
    // rewrite: a JMP rel32 (e9) replaces the two NOPs and 48 0F 05 in front of
    // the trailing NOPs, whatever its displacement. The short sites carry the
    // marker on their final two bytes, after one NOP per prefix. The LOCK and
    // overlong sites are untouched.
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 7, "{stdout}");
    assert_eq!(
        lines[..2],
        ["plain=ROUTED prefixed=ROUTED prefixed_short=ROUTED aligned_short=ROUTED"; 2],
        "{stdout}"
    );
    let code = lines[2].strip_prefix("prefixed_code=").unwrap();
    assert!(
        code.len() == 30 && code.starts_with("b86e00000090e9") && code.ends_with("909090c3"),
        "{stdout}"
    );
    assert_eq!(
        lines[3..],
        [
            "short_site=900fff",
            "aligned_site=90900fff",
            "lock_site=66f00f05",
            "overlong_site=3e3e3e3e3e3e3e3e3e3e3e3e3e3e0f05",
        ],
        "{stdout}"
    );
}

/// Runs `client`, which calls its aligned short site `calls` times, under the
/// loader with statistics enabled.
fn stats_of(plugin: &Path, client: &Path, calls: u32) -> SabreStatsSnapshot {
    let stats = SabreStats::create(reverie::BackendStatsRequest::ENABLED)
        .unwrap()
        .unwrap();
    checked(
        under_loader(plugin, client)
            .arg(calls.to_string())
            .env(BACKEND_STATS_ENV, stats.raw_fd().to_string()),
    );
    stats.backend_stats()
}

#[test]
fn a_marker_patch_is_measured_from_its_instruction_and_found_by_its_marker() {
    let out = tempfile::tempdir().unwrap();
    let plugin = build_plugin(out.path());
    // The aligned site is 66 48 0F 05, four bytes. At byte 60 of a cache line
    // it ends exactly at the line's end; its marker, at byte 62, would not. At
    // byte 61 it straddles with three bytes before the boundary.
    let at_0 = build_client(out.path(), "client-0", 0);
    let at_60 = build_client(out.path(), "client-60", 60);
    let at_61 = build_client(out.path(), "client-61", 61);

    // The site takes the marker route at every offset (its patch routes
    // equal those at 0, where the dispatch counts below prove the marker), so
    // the comparison measures a marker patch.
    let base = stats_of(&plugin, &at_0, 0);
    let ending = stats_of(&plugin, &at_60, 0);
    assert_eq!(ending.patch_routes, base.patch_routes);
    assert_eq!(ending.patch_shapes, base.patch_shapes);
    let straddling = stats_of(&plugin, &at_61, 0);
    assert_eq!(straddling.patch_routes, base.patch_routes);
    let mut expected = base.patch_shapes.clone();
    expected.cacheline_straddlers += 1;
    expected.non_straddling -= 1;
    expected.straddle_after[2] += 1;
    assert_eq!(straddling.patch_shapes, expected);

    // Two calls through the marker are two SIGILL dispatches of a
    // rewriter-installed marker, none of a supervisor-installed one.
    let called = stats_of(&plugin, &at_0, 2);
    assert_eq!(called.patch_shapes, base.patch_shapes);
    assert_eq!(
        called
            .slow_paths
            .count(&SabreSlowPath::RewriteSigillDispatch),
        base.slow_paths.count(&SabreSlowPath::RewriteSigillDispatch) + 2
    );
    assert_eq!(
        called
            .slow_paths
            .count(&SabreSlowPath::PtraceInstalledSigillDispatch),
        base.slow_paths
            .count(&SabreSlowPath::PtraceInstalledSigillDispatch)
    );
}

/// Runs `client` under the loader through a launch specification carrying
/// `settings`, as Hermit launches a guest.
fn launched(plugin: &Path, client: &Path, settings: &[&str]) -> Output {
    use std::os::unix::ffi::OsStrExt;
    let _spawn = SPAWN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let settings: Vec<&[u8]> = settings.iter().map(|setting| setting.as_bytes()).collect();
    let spec = reverie_sabre::launch::spec_bytes(
        plugin.as_os_str().as_bytes(),
        client.as_os_str().as_bytes(),
        &settings,
    )
    .unwrap();
    // The descriptor is inherited (no close-on-exec) and stays open until the
    // child has run.
    let spec = reverie_sabre::launch::spec_fd(&spec).unwrap();
    assert!(spec.as_raw_fd() > 2);
    let output = Command::new("timeout")
        .args(["--kill-after=2s", "20s"])
        .arg(reverie_sabre::bundled_sabre_path())
        .output()
        .unwrap();
    drop(spec);
    output
}

#[test]
fn the_raw_short_site_setting_leaves_short_sites_as_they_are() {
    let out = tempfile::tempdir().unwrap();
    let client = build_client(out.path(), "client", 0);
    // "raw" needs a plugin that reports post-arm routing.
    let plugin = build_plugin_as(out.path(), "plugin-post-arm.so", Some("-DPOST_ARM"));
    let unarmed = build_plugin(out.path());
    const SETTING: &str = "REVERIE_SABRE_SHORT_SYSCALL_SITES";

    // The jump-rewritten sites are still routed; the two short sites keep
    // their original bytes and run natively here (this plugin arms no trap
    // path of its own; the shared runtime's would take them).
    let raw = launched(&plugin, &client, &[&format!("{SETTING}=raw")]);
    assert!(raw.status.success(), "{raw:?}");
    let stdout = String::from_utf8(raw.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 7, "{stdout}");
    assert_eq!(
        lines[..2],
        ["plain=ROUTED prefixed=ROUTED prefixed_short=NATIVE aligned_short=NATIVE"; 2],
        "{stdout}"
    );
    assert_eq!(
        lines[3..],
        [
            "short_site=480f05",
            "aligned_site=66480f05",
            "lock_site=66f00f05",
            "overlong_site=3e3e3e3e3e3e3e3e3e3e3e3e3e3e0f05",
        ],
        "{stdout}"
    );

    // "marker" is the default behaviour, through the same launch path.
    let marker = launched(&plugin, &client, &[&format!("{SETTING}=marker")]);
    assert!(marker.status.success(), "{marker:?}");
    let stdout = String::from_utf8(marker.stdout).unwrap();
    assert!(
        stdout.starts_with(
            "plain=ROUTED prefixed=ROUTED prefixed_short=ROUTED aligned_short=ROUTED\n"
        ) && stdout.contains("short_site=900fff\naligned_site=90900fff\n"),
        "{stdout}"
    );

    // With a plugin that cannot report post-arm routing, the short sites
    // would run unmonitored. A plugin that does not define the report is
    // refused before the client is loaded: not even the client's own
    // .preinit_array function runs (natively it prints PREINIT).
    let preinit_client = out.path().join("preinit-client");
    checked(
        compiler()
            .to_command()
            .arg(fixtures().join("preinit_client.c"))
            .arg("-o")
            .arg(&preinit_client),
    );
    assert_eq!(
        checked(&mut Command::new(&preinit_client)).stdout,
        b"PREINIT\nMAIN\n"
    );
    let refused = launched(&unarmed, &preinit_client, &[&format!("{SETTING}=raw")]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains(
            "refused: REVERIE_SABRE_SHORT_SYSCALL_SITES=raw needs a plugin that reports \
             post-arm routing"
        ) && stderr.contains("does not define it"),
        "{refused:?}"
    );
    // Even with a plugin that reports post-arm routing, a client with its own
    // .preinit_array is refused, before ld.so runs any of it: those functions
    // would run before the plugin arms its trap path.
    let refused = launched(&plugin, &preinit_client, &[&format!("{SETTING}=raw")]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains(
            "refused: REVERIE_SABRE_SHORT_SYSCALL_SITES=raw: the client has a \
             DT_PREINIT_ARRAY, whose functions would run before the plugin arms its trap \
             path"
        ),
        "{refused:?}"
    );
    // A plugin that defines the report but returns zero is refused after its
    // sbr_init, before the client's constructors and main.
    let zero = build_plugin_as(out.path(), "plugin-zero.so", Some("-DPOST_ARM_ZERO"));
    let refused = launched(&zero, &client, &[&format!("{SETTING}=raw")]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains(
            "refused: REVERIE_SABRE_SHORT_SYSCALL_SITES=raw needs a plugin that reports \
             post-arm routing (reverie_sabre_post_arm_routing_v1); its short syscall sites \
             would otherwise run unmonitored"
        ),
        "{refused:?}"
    );
    // The plugin without the report runs as before with "marker".
    let marked = launched(&unarmed, &client, &[&format!("{SETTING}=marker")]);
    assert!(marked.status.success(), "{marked:?}");
    assert!(
        String::from_utf8_lossy(&marked.stdout).starts_with(
            "plain=ROUTED prefixed=ROUTED prefixed_short=ROUTED aligned_short=ROUTED\n"
        ),
        "{marked:?}"
    );

    // Any other value is refused before the client runs.
    let refused = launched(&plugin, &client, &[&format!("{SETTING}=sometimes")]);
    assert!(!refused.status.success(), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains(
            "refused: invalid REVERIE_SABRE_SHORT_SYSCALL_SITES value \"sometimes\" \
             (expected \"marker\" or \"raw\")"
        ),
        "{refused:?}"
    );
}
