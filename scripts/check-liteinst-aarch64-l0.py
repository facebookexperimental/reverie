#!/usr/bin/env python3
"""Run the aarch64 L0 gates for reverie-liteinst.

This deliberately fails, rather than skips, when the aarch64 std targets,
rust-lld, or the fb qemu-user runner are unavailable. It starts from the
repository root regardless of the caller's directory.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "reverie-liteinst" / "src"
QEMU = Path("/opt/fb-qemu-user/bin/qemu-aarch64")
GNU = "aarch64-unknown-linux-gnu"
MUSL = "aarch64-unknown-linux-musl"
FEATURE_SETS = [
    (),
    ("--no-default-features",),
    ("--no-default-features", "--features", "allocator-fixture"),
    ("--no-default-features", "--features", "fixed-syscall-gates"),
]
REFUSAL_MESSAGE = (
    "reverie-inguest exec-private features are not supported on aarch64 "
    "(exec_private is x86-64 only)"
)
ALLOWED_QEMU_FAILURES = {
    "lazy_promote::tests::proc_mem_store_changes_word_in_rx_text",
    "lazy_promote::tests::retry_requalifies_under_second_lease",
    "lazy_promote::tests::stores_run_under_the_real_seccomp_filter",
}
REFUSAL_TESTS = {
    "tests::aarch64_c_entry_refuses_selected_tool_as_subprocess",
    "tests::aarch64_install_surfaces_refuse_by_name",
}
EXPECTED_QEMU_TESTS = frozenset(
    """
allocator_backing::tests::unknown_allocator_contracts_refuse
lazy_promote::tests::admit_accepts_aligned_windowable_contained
lazy_promote::tests::admit_refuses_misaligned
lazy_promote::tests::admit_refuses_non_windowable
lazy_promote::tests::admit_refuses_outside_span
lazy_promote::tests::admit_refuses_runtime_gate_text
lazy_promote::tests::bti_guard_survives_a_store_cycle
lazy_promote::tests::classify_rejects_post_store_error_with_unpatched_state
lazy_promote::tests::classify_separates_pre_store_from_custody
lazy_promote::tests::custody_site_blocks_all_new_work_until_settled
lazy_promote::tests::deferred_batch_survives_custody_block
lazy_promote::tests::deferred_replay_requeues_current_candidate_at_front
lazy_promote::tests::drain_pending_consumes_s5a_table
lazy_promote::tests::drain_promotes_in_order_and_retains_refusals
lazy_promote::tests::drop_leaks_unsettled_custody_fail_closed
lazy_promote::tests::empty_resume_is_a_shortfall
lazy_promote::tests::flipped_site_island_is_denylisted_in_s5a_table
lazy_promote::tests::global_custody_blocks_other_promoters
lazy_promote::tests::mask_failure_does_no_work_and_is_reported
lazy_promote::tests::mprotect_store_windows_restores_exact_protection
lazy_promote::tests::proc_mem_pwrite_failure_completes_to_unpatched
lazy_promote::tests::proc_mem_store_changes_word_in_rx_text
lazy_promote::tests::promote_one_flips_svc_and_call_result_is_unchanged
lazy_promote::tests::refused_attempt_releases_island_range_slot
lazy_promote::tests::restore_failure_is_custody_then_completes
lazy_promote::tests::resume_shortfall_is_custody_then_completes
lazy_promote::tests::retry_requalifies_under_second_lease
lazy_promote::tests::settled_unpatched_site_leaves_custody_and_ranges
lazy_promote::tests::stores_run_under_the_real_seccomp_filter
lazy_promote::tests::toctou_guest_change_inside_acquire_refuses
patch_alloc::tests::dispatch_allocations_go_to_the_tool_heap
patch_alloc::tests::installation_allocations_stay_in_the_installation_heap
patch_alloc::tests::installation_takes_precedence_over_dispatch
patch_alloc::tests::other_allocations_go_to_the_system_allocator
patch_alloc::tests::patch_heap_is_largest_page_aligned_and_anonymous
patch_alloc::tests::private_allocations_keep_their_owner_across_scope_changes
patch_alloc::tests::private_exhaustion_has_no_system_fallback
runtime::tests::alt_stack_defaults_to_the_shared_default_when_unset
runtime::tests::alt_stack_env_is_distinct_from_the_other_selectors
runtime::tests::alt_stack_parses_truthy_and_falsy_spellings
runtime::tests::alt_stack_rejects_unknown_values
runtime::tests::builtin_tool_selector_maps_shared_values_only
runtime::tests::clone_accepts_only_fork_like_flags
runtime::tests::disabled_dispatch_does_not_classify_fallback_sites
runtime::tests::fallback_counter_reset_zeroes_total_and_per_number_counts
runtime::tests::fork_child_reset_zeroes_per_site_counts_but_preserves_patch_state
runtime::tests::fork_hook_runs_the_observability_reset
runtime::tests::maps_line_private_reads_the_sharing_flag_of_the_containing_mapping
runtime::tests::out_of_range_syscall_numbers_count_in_the_total_only
runtime::tests::recording_a_fallback_bumps_total_and_the_matching_syscall
runtime::tests::reused_address_claims_a_new_site_generation
runtime::tests::strace_and_compat_refuse_vfork_and_clone3_by_number
tests::aarch64_c_entry_refuses_selected_tool_as_subprocess
tests::aarch64_install_surfaces_refuse_by_name
tests::alt_stack_setter_round_trips_through_the_parser
tests::generated_preload_leaves_precede_a_stale_canonical_artifact
tests::trap_only_build_defaults_off_and_refuses_explicit_patching
""".split()
)


class GateFailure(RuntimeError):
    pass


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    full_env = dict(os.environ)
    # validate.sh exports RUSTFLAGS="-D warnings -C link-arg=<host lzma>".
    # The x86 link argument must never reach aarch64 links, and -D warnings
    # must not turn path-dependency warnings into errors here (warnings in
    # reverie-liteinst itself are enforced by G5 and by the G3 output check
    # in main()). Pin an explicit empty RUSTFLAGS for every cargo call.
    full_env["RUSTFLAGS"] = ""
    full_env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    if env:
        full_env.update(env)
    print("$", " ".join(cmd), flush=True)
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        env=full_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    print(result.stdout, end="")
    return result


def require_success(
    label: str, cmd: list[str], *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    result = run(cmd, env=env)
    if result.returncode != 0:
        raise GateFailure(f"{label} failed with rc={result.returncode}")
    return result


def require_no_liteinst_warnings(label: str, output: str) -> None:
    lines = output.splitlines()
    offenders = []
    for i, line in enumerate(lines):
        if line.startswith("warning:") and "generated" not in line:
            span = " ".join(lines[i : i + 3])
            if "reverie-liteinst/src/" in span or "reverie-liteinst/Cargo.toml" in span:
                offenders.append(line.strip())
    if offenders:
        raise GateFailure(f"{label} emitted reverie-liteinst warnings: {offenders[:5]}")


def require_prerequisites() -> None:
    for target in (GNU, MUSL):
        result = subprocess.run(
            ["rustc", "--print", "target-libdir", "--target", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        libdir = Path(result.stdout.strip())
        if result.returncode != 0 or not libdir.is_dir():
            raise GateFailure(f"missing Rust std target {target}: {result.stderr.strip()}")
    sysroot = subprocess.run(
        ["rustc", "--print", "sysroot"], stdout=subprocess.PIPE, text=True, check=False
    ).stdout.strip()
    bundled_lld = list(Path(sysroot).glob("lib/rustlib/*/bin/rust-lld"))
    if shutil.which("rust-lld") is None and not bundled_lld:
        raise GateFailure("missing rust-lld (required; refusing to skip)")
    if not QEMU.is_file() or not os.access(QEMU, os.X_OK):
        raise GateFailure(f"missing qemu-aarch64 runner {QEMU} (refusing to skip)")
    binfmt = Path("/proc/sys/fs/binfmt_misc/qemu-aarch64")
    if not binfmt.is_file() or "enabled" not in binfmt.read_text():
        raise GateFailure(
            "binfmt_misc is not registered/enabled for qemu-aarch64 "
            "(the C-entry subprocess test execs the aarch64 test binary; refusing to skip)"
        )


def alias_and_lazy_ref_checks() -> None:
    text = ""
    for path in sorted(SRC.rglob("*.rs")):
        text += path.read_text() + "\n"
    joined = re.sub(r"\s+", " ", text)
    feature_count = len(re.findall(r'feature = "liteinst"', joined))
    alias_count = len(
        re.findall(r'all\(feature = "liteinst", target_arch = "x86_64"\)', joined)
    )
    print(f"alias check: feature_liteinst={feature_count} alias={alias_count}")
    if feature_count != 223 or alias_count != feature_count:
        raise GateFailure("liteinst alias count differs from pinned 223/exact-alias form")
    offenders = []
    for path in sorted(SRC.rglob("*.rs")):
        if path.name == "lazy_promote.rs":
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if "lazy_promote::" in line:
                offenders.append(f"{path.relative_to(ROOT)}:{lineno}:{line.strip()}")
    if offenders:
        raise GateFailure("non-test lazy_promote references outside lazy_promote.rs:\n" + "\n".join(offenders))


def negative_compile_checks() -> None:
    cases = [
        (GNU, ("--no-default-features", "--features", "exec-private-init")),
        (GNU, ("--no-default-features", "--features", "exec-native-injection")),
        (GNU, ("--no-default-features", "--features", "exec-private-successor")),
        (MUSL, ("--no-default-features", "--features", "loader-private-runtime")),
    ]
    for target, features in cases:
        result = run(
            [
                "cargo",
                "check",
                "--locked",
                "-p",
                "reverie-liteinst",
                "--lib",
                "--target",
                target,
                *features,
            ]
        )
        if result.returncode == 0 or REFUSAL_MESSAGE not in result.stdout:
            raise GateFailure(
                f"negative compile gate did not produce the exact refusal for {target} {features}"
            )
    result = run(
        [
            "cargo",
            "check",
            "--locked",
            "-p",
            "reverie-liteinst-preload",
            "--target",
            GNU,
        ]
    )
    message = "reverie-liteinst-preload is not supported on aarch64 (no aarch64 native bootstrap)"
    if result.returncode == 0 or message not in result.stdout:
        raise GateFailure("preload negative compile gate did not produce the exact refusal")


def qemu_run(features: tuple[str, ...]) -> tuple[set[str], set[str]]:
    env = {
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": "rust-lld",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER": str(QEMU),
        "QEMU_CPU": "cortex-a72",
    }
    result = run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "reverie-liteinst",
            "--lib",
            "--target",
            MUSL,
            *features,
            "--",
            "--test-threads",
            "1",
        ],
        env=env,
    )
    seen: set[str] = set()
    failed: set[str] = set()
    for match in re.finditer(r"^test ([A-Za-z0-9_:]+) \.\.\. (ok|FAILED)$", result.stdout, re.M):
        seen.add(match.group(1))
        if match.group(2) == "FAILED":
            failed.add(match.group(1))
    return seen, failed


def qemu_gate() -> None:
    nodef_seen, nodef_failed = qemu_run(("--no-default-features",))
    default_seen, default_failed = qemu_run(())
    for label, seen, failed in [
        ("no-default-features", nodef_seen, nodef_failed),
        ("default", default_seen, default_failed),
    ]:
        if seen != EXPECTED_QEMU_TESTS:
            missing = sorted(EXPECTED_QEMU_TESTS - seen)
            extra = sorted(seen - EXPECTED_QEMU_TESTS)
            raise GateFailure(f"{label} qemu list drift: missing={missing} extra={extra}")
        if failed != ALLOWED_QEMU_FAILURES:
            raise GateFailure(f"{label} qemu failures differ: {sorted(failed)}")
        if not REFUSAL_TESTS <= seen - failed:
            raise GateFailure(f"{label} refusal tests did not run and pass")
        print(f"qemu {label}: listed={len(seen)} passed={len(seen) - len(failed)} failed={len(failed)}")
    if nodef_seen != default_seen:
        raise GateFailure("default/no-default qemu test lists differ (default is not liteinst-on coverage)")


def main() -> int:
    try:
        require_prerequisites()
        alias_and_lazy_ref_checks()
        for features in FEATURE_SETS:
            flags = list(features)
            # G2: gnu check, lib + bins.
            require_success(
                "G2 gnu check",
                ["cargo", "check", "--locked", "-p", "reverie-liteinst", "--lib", "--bins", "--target", GNU, *flags],
            )
            # G3: musl codegen/build, lib + bins. RUSTFLAGS is pinned empty
            # (path dependencies warn on aarch64), so warnings from
            # reverie-liteinst itself are enforced here by output check;
            # G5 clippy -D warnings is the lint-level twin.
            built = require_success(
                "G3 musl build",
                ["cargo", "build", "--locked", "-p", "reverie-liteinst", "--lib", "--bins", "--target", MUSL, *flags],
                env={"CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": "rust-lld"},
            )
            require_no_liteinst_warnings("G3 musl build", built.stdout)
            # G5: aarch64 clippy, no deps.
            require_success(
                "G5 clippy",
                [
                    "cargo", "clippy", "--locked", "-p", "reverie-liteinst", "--no-deps", "--lib",
                    "--target", GNU, *flags, "--", "-D", "warnings",
                ],
            )
        # G4: exact named compile refusals.
        negative_compile_checks()
        # G6: qemu execution with pinned names and failures.
        qemu_gate()
    except GateFailure as error:
        print(f"L0 GATE FAILED: {error}", file=sys.stderr)
        return 1
    print("L0 aarch64 gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
