#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

//! A prefixed SYSCALL (for example REX.W 0F 05), which the decoder reports as
//! SYSCALL with a longer length, is intercepted correctly by both rewrite
//! routes: a jump rewrite, and, at a site too short to relocate, the UD0
//! marker, which goes on the final 0F 05 with the prefixes turned into NOPs so
//! the guest resumes after the whole instruction. A SYSCALL the CPU would not
//! execute natively (LOCK-prefixed, or longer than 15 bytes) is left as it is.
//! The patch statistics measure a marker patch's shape from the instruction's
//! start, and recognize its SIGILL by the marker's address.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use reverie::BackendStatsSource;
use reverie_sabre::stats::BACKEND_STATS_ENV;
use reverie_sabre::stats::SabreSlowPath;
use reverie_sabre::stats::SabreStats;
use reverie_sabre::stats::SabreStatsSnapshot;

fn checked(command: &mut Command) -> Output {
    let output = command.output().unwrap();
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
    let source = reverie_sabre::bundled_sabre_source_dir();
    let loader = reverie_sabre::bundled_sabre_path();
    let plugin = out.join("plugin.so");
    checked(
        compiler()
            .to_command()
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

    let output = under_loader(&plugin, &client).output().unwrap();
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
