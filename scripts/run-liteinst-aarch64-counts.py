#!/usr/bin/env python3
"""Count the LiteInst aarch64 test surface under qemu-user or natively.

The runner is a baseline counter, not a pass/fail test gate by default:
it fails when prerequisites are missing, when Cargo metadata names a
test target the pinned manifest does not classify, or when any listed,
passed, failed, or ignored count drifts from the manifest.  Known test
failures at the manifest base are therefore reported as exact counts,
not hidden.  Use --require-pass to turn any counted failure into a
runner failure.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "scripts" / "liteinst-aarch64-counts.json"


class RunnerFailure(RuntimeError):
    pass


def fail(message: str) -> None:
    raise RunnerFailure(message)


def command_text(cmd: list[str]) -> str:
    return " ".join(cmd)


def run_capture(
    label: str,
    cmd: list[str],
    *,
    env: dict[str, str],
    timeout: int | None = None,
    log_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    print(f"$ {command_text(cmd)}", flush=True)
    try:
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout if isinstance(error.stdout, str) else ""
        stderr = error.stderr if isinstance(error.stderr, str) else ""
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(stdout + stderr)
        fail(f"{label} timed out after {timeout}s: {command_text(cmd)}")
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(result.stdout + result.stderr)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    return result


def require_success(
    label: str,
    cmd: list[str],
    *,
    env: dict[str, str],
    timeout: int | None = None,
    log_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    result = run_capture(label, cmd, env=env, timeout=timeout, log_path=log_path)
    if result.returncode != 0:
        fail(f"{label} failed with rc={result.returncode}: {command_text(cmd)}")
    return result


def base_env(manifest: dict, execution_mode: str) -> dict[str, str]:
    env = dict(os.environ)
    # A caller may be validate.sh, which exports x86-oriented RUSTFLAGS.
    # This counter is not a warnings gate; keep aarch64 cargo calls from
    # inheriting an x86 link argument or encoded rustflags.
    env["RUSTFLAGS"] = ""
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    if execution_mode == "qemu":
        env["QEMU_CPU"] = manifest["qemu"]["cpu"]
    env["CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER"] = manifest[execution_mode]["linker"]
    env.setdefault("CARGO_TERM_COLOR", "never")
    return env


def parse_toolchain() -> tuple[str, list[str]]:
    text = (ROOT / "rust-toolchain.toml").read_text()
    channel = re.search(r'^channel\s*=\s*"([^"]+)"', text, re.M)
    targets = re.search(r'^targets\s*=\s*\[([^\]]*)\]', text, re.M)
    if channel is None or targets is None:
        fail("rust-toolchain.toml must declare channel and targets for the aarch64 counting runner")
    return channel.group(1), re.findall(r'"([^"]+)"', targets.group(1))


def require_prerequisites(
    manifest: dict,
    env: dict[str, str],
    execution_mode: str,
    *,
    prebuilt: bool = False,
) -> None:
    if prebuilt:
        if execution_mode != "native":
            fail("--prebuilt-target-dir is only valid with --mode native")
        if platform.machine() not in ("aarch64", "arm64"):
            fail(f"native mode requires an aarch64 host, got {platform.machine()} (refusing to skip)")
        page_size = os.sysconf("SC_PAGE_SIZE")
        if page_size != manifest["native"]["page_size"]:
            fail(f"native mode requires page size {manifest['native']['page_size']}, got {page_size}")
        return
    want_toolchain = manifest["rust_toolchain"]
    channel, declared_targets = parse_toolchain()
    if channel != want_toolchain["channel"]:
        fail(
            f"rust-toolchain.toml channel is {channel}, manifest requires "
            f"{want_toolchain['channel']}"
        )
    missing_declared = [t for t in want_toolchain["targets"] if t not in declared_targets]
    if missing_declared:
        fail(f"rust-toolchain.toml does not declare targets {missing_declared}")
    rustc = require_success("rustc --version", ["rustc", "--version"], env=env)
    if not rustc.stdout.startswith(f"rustc {channel} "):
        fail(f"rustc version does not match pinned channel {channel}: {rustc.stdout.strip()}")
    for target in want_toolchain["targets"]:
        result = run_capture(
            f"rustc target-libdir {target}",
            ["rustc", "--print", "target-libdir", "--target", target],
            env=env,
        )
        libdir = Path(result.stdout.strip())
        if result.returncode != 0 or not libdir.is_dir() or not list(libdir.glob("libcore-*.rlib")):
            fail(f"missing Rust std target {target} (refusing to skip)")
    sysroot = require_success("rustc --print sysroot", ["rustc", "--print", "sysroot"], env=env).stdout.strip()
    if shutil.which("rust-lld") is None and not list(Path(sysroot).glob("lib/rustlib/*/bin/rust-lld")):
        fail("missing rust-lld (refusing to skip)")
    page_size = os.sysconf("SC_PAGE_SIZE")
    if execution_mode == "qemu":
        if page_size != manifest["qemu"]["page_size"]:
            fail(f"qemu mode requires host page size {manifest['qemu']['page_size']}, got {page_size}")
        qemu = Path(manifest["qemu"]["path"])
        if not qemu.is_file() or not os.access(qemu, os.X_OK):
            fail(f"missing qemu-aarch64 runner {qemu} (refusing to skip)")
        binfmt = Path("/proc/sys/fs/binfmt_misc/qemu-aarch64")
        if not binfmt.is_file() or "enabled" not in binfmt.read_text():
            fail("binfmt_misc is not registered/enabled for qemu-aarch64 (refusing to skip)")
    elif execution_mode == "native":
        if platform.machine() not in ("aarch64", "arm64"):
            fail(f"native mode requires an aarch64 host, got {platform.machine()} (refusing to skip)")
        if page_size != manifest["native"]["page_size"]:
            fail(f"native mode requires page size {manifest['native']['page_size']}, got {page_size}")
    else:
        fail(f"unknown execution mode {execution_mode!r}")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cargo_target_dir(env: dict[str, str]) -> Path:
    target_dir = Path(env.get("CARGO_TARGET_DIR") or ROOT / "target")
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    return target_dir.resolve()


def source_identity(env: dict[str, str], target_dir: Path) -> dict:
    def git_value(args: list[str], label: str) -> str:
        result = run_capture(label, ["git", "-C", str(ROOT), *args], env=env)
        if result.returncode != 0:
            fail(f"cannot bind artifacts to source: {label} failed with rc={result.returncode}")
        return result.stdout.strip()

    status = git_value(
        ["status", "--porcelain=v1", "--untracked-files=no"],
        "git status for artifact provenance",
    )
    return {
        "commit": git_value(["rev-parse", "HEAD"], "git rev-parse HEAD for artifact provenance"),
        "tree": git_value(["rev-parse", "HEAD^{tree}"], "git rev-parse HEAD tree for artifact provenance"),
        "workspace_root": str(ROOT.resolve()),
        "target_root": str(target_dir.resolve()),
        "working_tree_clean": status == "",
    }


def load_artifacts(
    path: Path,
    prebuilt_target_dir: Path,
    *,
    env: dict[str, str],
    expected_target: str,
) -> tuple[dict[str, str], dict]:
    try:
        payload = json.loads(path.read_text())
    except Exception as error:
        fail(f"cannot read artifacts file {path}: {error}")
    if (
        payload.get("schema_version") != 4
        or not isinstance(payload.get("artifacts"), dict)
        or not isinstance(payload.get("guest_executables"), dict)
    ):
        fail(f"unsupported artifacts schema in {path}; expected schema_version 4")
    if payload.get("producing_mode") != "qemu":
        fail(
            "prebuilt artifacts producing_mode mismatch: "
            f"artifacts={payload.get('producing_mode')!r} expected='qemu'"
        )
    x86_reference = payload.get("x86_64_reference")
    if not isinstance(x86_reference, dict) or x86_reference.get("status") != "measured":
        status = x86_reference.get("status") if isinstance(x86_reference, dict) else None
        fail(
            "prebuilt artifacts x86_64_reference status mismatch: "
            f"artifacts={status!r} expected='measured'"
        )
    if payload.get("target") != expected_target:
        fail(
            f"prebuilt artifacts target mismatch: artifacts={payload.get('target')!r} "
            f"expected={expected_target!r}"
        )
    recorded = payload.get("source")
    if not isinstance(recorded, dict):
        fail("prebuilt artifacts have no source provenance")
    if recorded.get("working_tree_clean") is not True:
        fail("prebuilt artifacts were not built from a clean tracked worktree")
    current = source_identity(env, prebuilt_target_dir.resolve())
    # The tests read this checkout at run time (C fixtures compiled from
    # CARGO_MANIFEST_DIR), so a matching commit means nothing when it is dirty.
    if current["working_tree_clean"] is not True:
        fail("runner host checkout is dirty; refusing prebuilt artifacts (working_tree_clean=false)")
    for field in ("commit", "tree", "workspace_root", "target_root"):
        if recorded.get(field) != current[field]:
            fail(
                f"prebuilt artifacts source {field} mismatch: "
                f"artifacts={recorded.get(field)!r} current={current[field]!r}"
            )
    def verify(key: str, entry: object, role: str) -> str:
        relative = entry.get("executable") if isinstance(entry, dict) else None
        recorded_sha256 = entry.get("sha256") if isinstance(entry, dict) else None
        if not relative:
            fail(f"artifacts {role} entry {key} has no executable path")
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            fail(f"artifacts {role} entry {key} executable path escapes the target dir: {relative}")
        if not recorded_sha256:
            fail(f"prebuilt {role} {key} has no recorded sha256")
        executable = prebuilt_target_dir / relative
        if not executable.is_file() or not os.access(executable, os.X_OK):
            fail(f"prebuilt {role} for {key} is missing or not executable: {executable}")
        actual_sha256 = file_sha256(executable)
        if actual_sha256 != recorded_sha256:
            fail(
                f"prebuilt {role} {key} sha256 mismatch: "
                f"artifacts={recorded_sha256} current={actual_sha256}"
            )
        return str(executable)

    artifacts = {key: verify(key, entry, "artifact") for key, entry in payload["artifacts"].items()}
    guests = {
        key: verify(key, entry, "guest executable")
        for key, entry in payload["guest_executables"].items()
    }
    if not isinstance(payload.get("packages"), list):
        fail("prebuilt artifacts do not record their producing packages")
    metadata = {
        "producing_mode": payload["producing_mode"],
        "packages": payload["packages"],
        "guests": guests,
        "x86_64_reference": x86_reference,
        "source": recorded,
    }
    return artifacts, metadata


def write_artifacts(
    results: Path,
    *,
    env: dict[str, str],
    target_triple: str,
    artifacts: dict[str, str],
    guests: dict[str, str],
    build_hashes: dict[str, str],
    kinds: dict[str, list[str]],
    source: dict,
    producing_mode: str,
    packages: list[str],
    x86_reference: dict,
) -> None:
    # Never leave an earlier run's artifacts.json beside binaries this run
    # may have rebuilt; every refusal below must leave no artifacts.json.
    artifacts_path = results / "artifacts.json"
    artifacts_path.unlink(missing_ok=True)
    target_dir = cargo_target_dir(env)
    current = source_identity(env, target_dir)
    if not source["working_tree_clean"] or not current["working_tree_clean"]:
        fail(
            "refusing to bind artifacts built from a dirty tracked worktree: "
            f"working_tree_clean at_build={source['working_tree_clean']} "
            f"at_write={current['working_tree_clean']}"
        )
    if current != source:
        fail(
            "source identity changed during the build: "
            f"at_build={source!r} at_write={current!r}"
        )

    def bind(key: str, path: str) -> dict:
        executable = Path(path)
        try:
            relative = executable.relative_to(target_dir)
        except ValueError:
            fail(f"artifact for {key} is outside CARGO_TARGET_DIR {target_dir}: {executable}")
        if not executable.is_file():
            fail(f"artifact for {key} disappeared during the run: {executable}")
        digest = file_sha256(executable)
        if digest != build_hashes.get(key):
            fail(
                f"artifact {key} changed during the run: "
                f"at_build={build_hashes.get(key)} at_write={digest}"
            )
        return {"executable": str(relative), "sha256": digest}

    payload_artifacts = {
        key: {**bind(key, artifacts[key]), "kind": kinds.get(key, [])} for key in sorted(artifacts)
    }
    payload_guests = {key: bind(key, guests[key]) for key in sorted(guests)}
    payload = {
        "schema_version": 4,
        "target": target_triple,
        "producing_mode": producing_mode,
        "packages": packages,
        "x86_64_reference": x86_reference,
        "source": source,
        "artifacts": payload_artifacts,
        "guest_executables": payload_guests,
    }
    results.mkdir(parents=True, exist_ok=True)
    partial = results / "artifacts.json.partial"
    partial.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(partial, artifacts_path)
    print(f"artifacts: {artifacts_path}")


def load_manifest(path: Path) -> dict:
    try:
        manifest = json.loads(path.read_text())
    except Exception as error:
        fail(f"cannot read manifest {path}: {error}")
    if manifest.get("schema_version") != 1:
        fail(f"unsupported manifest schema in {path}")
    if not isinstance(manifest.get("packages"), list) or not manifest["packages"]:
        fail("manifest has no packages")
    return manifest


def metadata_inventory(env: dict[str, str]) -> dict[str, dict[str, dict]]:
    result = require_success(
        "cargo metadata",
        ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
        env=env,
    )
    try:
        metadata = json.loads(result.stdout)
    except Exception as error:
        fail(f"cargo metadata did not emit JSON: {error}")
    inventory: dict[str, dict[str, dict]] = {}
    for package in metadata.get("packages", []):
        targets: dict[str, dict] = {}
        for target in package.get("targets", []):
            if target.get("test"):
                targets[target["name"]] = target
        inventory[package["name"]] = targets
    return inventory


def validate_inventory(manifest: dict, inventory: dict[str, dict[str, dict]]) -> None:
    for package in manifest["packages"]:
        name = package["name"]
        if name not in inventory:
            fail(f"manifest package {name} is not in cargo metadata")
        actual = inventory[name]
        expected = {target["name"]: target for target in package["targets"]}
        if set(actual) != set(expected):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            fail(f"{name} test-target inventory drift: missing={missing} extra={extra}")
        for target_name, target in expected.items():
            got = actual[target_name]
            if got.get("kind") != target["kind"]:
                fail(f"{name}:{target_name} kind drift: metadata={got.get('kind')} manifest={target['kind']}")
            got_required = got.get("required-features") or []
            if got_required != target.get("required_features", []):
                fail(
                    f"{name}:{target_name} required-features drift: "
                    f"metadata={got_required} manifest={target.get('required_features', [])}"
                )


def parse_list(output: str, label: str) -> list[str]:
    names: list[str] = []
    benchmarks = 0
    footers: list[tuple[int, int]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        footer = re.fullmatch(r"(\d+) tests?, (\d+) benchmarks?", line.strip())
        if footer:
            footers.append((int(footer.group(1)), int(footer.group(2))))
            continue
        if line.endswith(": test"):
            names.append(line[:-6])
            continue
        if line.endswith(": bench"):
            benchmarks += 1
            continue
        fail(f"{label} emitted an unrecognized libtest list line: {line!r}")
    if len(footers) != 1:
        fail(f"{label} emitted {len(footers)} discovery footers, expected exactly one")
    listed_tests, listed_benchmarks = footers[0]
    if listed_tests != len(names) or listed_benchmarks != benchmarks:
        fail(
            f"{label} discovery footer reports {listed_tests} tests/{listed_benchmarks} benchmarks "
            f"but parsed {len(names)} tests/{benchmarks} benchmarks"
        )
    if benchmarks:
        fail(f"{label} lists benchmarks, which this counting manifest does not pin")
    return names


def parse_logfile(path: Path, label: str, *, listed: int) -> tuple[int, int, int, list[str]]:
    if not path.exists():
        if listed == 0:
            return 0, 0, 0, []
        fail(f"{label} did not write its libtest logfile {path}")
    passed = failed = ignored = 0
    failed_tests: list[str] = []
    for line in path.read_text(errors="replace").splitlines():
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) != 2:
            fail(f"{label} emitted a malformed libtest record: {line!r}")
        outcome, name = parts[0].removesuffix(":"), parts[1]
        if outcome == "ok":
            passed += 1
        elif outcome == "failed":
            failed += 1
            failed_tests.append(name)
        elif outcome == "ignored":
            ignored += 1
        else:
            fail(f"{label} emitted unknown libtest outcome {outcome!r}")
    return passed, failed, ignored, failed_tests


def parse_build_output(
    output: str, package_name: str
) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Return (test executables, non-test bin executables, errors by target).

    The non-test bins are the guest programs integration tests launch
    through env!("CARGO_BIN_EXE_<name>"), a fixed path outside deps/.
    """
    artifacts: dict[str, str] = {}
    guests: dict[str, str] = {}
    errors: dict[str, list[str]] = {}
    for line in output.splitlines():
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except Exception:
            continue
        if value.get("reason") == "compiler-artifact":
            if f"{package_name}#" not in value.get("package_id", ""):
                continue
            if not value.get("executable"):
                continue
            if value.get("profile", {}).get("test"):
                artifacts[value["target"]["name"]] = value["executable"]
            elif "bin" in value.get("target", {}).get("kind", []):
                guests[value["target"]["name"]] = value["executable"]
        elif value.get("reason") == "compiler-message":
            if f"{package_name}#" not in value.get("package_id", ""):
                continue
            message = value.get("message", {})
            if message.get("level") == "error":
                target = value.get("target", {}).get("name", "")
                rendered = message.get("rendered") or message.get("message") or ""
                errors.setdefault(target, []).append(rendered)
    return artifacts, guests, {name: "\n".join(parts) for name, parts in errors.items()}


def build_package(
    package: dict,
    *,
    target_triple: str | None,
    env: dict[str, str],
    results: Path,
    timeout: int,
    log_name: str | None = None,
    profile_args: list[str] | None = None,
    selector_args: list[str] | None = None,
) -> tuple[dict[str, str], dict[str, str], dict[str, str], str, int]:
    if profile_args is None:
        profile_args = package["profile"].get("cargo_args", [])
    if selector_args:
        # One named target: `cargo build --lib`/`--bin` would not build the
        # test harness, and adding `--tests` would build every test target
        # with this target's feature set.
        cmd = ["cargo", "test", "--locked", "--no-run", "-p", package["name"]]
    else:
        # `cargo test --no-run` stops at the first broken target even with
        # --no-fail-fast; --keep-going builds every target so each one's
        # compile errors are attributed to it.
        cmd = ["cargo", "build", "--locked", "--tests", "--keep-going", "-p", package["name"]]
    if target_triple is not None:
        cmd.extend(["--target", target_triple])
    cmd.extend(profile_args)
    cmd.extend(selector_args or [])
    cmd.append("--message-format=json")
    result = run_capture(
        f"build {package['name']}",
        cmd,
        env=env,
        timeout=timeout,
        log_path=results / "logs" / (log_name or f"{package['name']}-build.log"),
    )
    combined = result.stdout + result.stderr
    artifacts, guests, errors = parse_build_output(combined, package["name"])
    return artifacts, guests, errors, combined, result.returncode


def require_signatures(label: str, output: str, signatures: list[str]) -> None:
    missing = [signature for signature in signatures if signature not in output]
    if missing:
        fail(f"{label} did not produce pinned compile signatures {missing}")


def negative_probe(
    package: dict,
    targets: list[dict],
    *,
    env: dict[str, str],
    results: Path,
    timeout: int,
) -> None:
    signatures: list[str] = []
    for target in targets:
        signatures.extend(target.get("compile_signatures", []))
    signatures = list(dict.fromkeys(signatures))
    if not signatures:
        fail(f"{package['name']} negative probe has no pinned signatures")
    probe = package.get("negative_probe", {})
    target_triple = probe.get("target", "aarch64-unknown-linux-gnu")
    cargo_args = probe.get("cargo_args", package["profile"].get("cargo_args", []))
    cmd = ["cargo", "check", "--locked", "-p", package["name"], "--target", target_triple, *cargo_args]
    result = run_capture(
        f"negative probe {package['name']}",
        cmd,
        env=env,
        timeout=timeout,
        log_path=results / "logs" / f"{package['name']}-negative-probe.log",
    )
    if result.returncode == 0:
        fail(f"{package['name']} negative probe unexpectedly succeeded")
    require_signatures(package["name"], result.stdout + result.stderr, signatures)


def feature_negative_probe(
    package: dict,
    target: dict,
    *,
    env: dict[str, str],
    results: Path,
    timeout: int,
) -> None:
    required = target.get("required_features", [])
    if not required:
        fail(f"{package['name']}:{target['name']} is compile-refused-feature with no required feature")
    cmd = [
        "cargo", "check", "--locked", "-p", package["name"], "--lib",
        "--target", "aarch64-unknown-linux-gnu", "--no-default-features",
        "--features", ",".join(required),
    ]
    result = run_capture(
        f"feature negative probe {package['name']}:{target['name']}",
        cmd,
        env=env,
        timeout=timeout,
        log_path=results / "logs" / f"{package['name']}-{target['name']}-feature-negative.log",
    )
    if result.returncode == 0:
        fail(f"{package['name']}:{target['name']} feature negative probe unexpectedly succeeded")
    require_signatures(
        f"{package['name']}:{target['name']}",
        result.stdout + result.stderr,
        target.get("compile_signatures", []),
    )


def target_selector_args(target: dict) -> list[str]:
    if "test" in target["kind"]:
        return ["--test", target["name"]]
    if "bin" in target["kind"]:
        return ["--bin", target["name"]]
    return ["--lib"]


def build_x86_package(
    package: dict,
    *,
    env: dict[str, str],
    results: Path,
    timeout: int,
) -> dict[str, str]:
    artifacts, _guests, _errors, _combined, build_rc = build_package(
        package,
        target_triple=None,
        env=env,
        results=results,
        timeout=timeout,
        log_name=f"{package['name']}-x86-build.log",
    )
    if build_rc != 0:
        fail(f"{package['name']} x86_64 reference build failed with rc={build_rc}")
    expected = {target["name"] for target in package["targets"]}
    extra = sorted(set(artifacts) - expected)
    if extra:
        fail(f"{package['name']} x86_64 build produced unclassified test artifacts {extra}")
    for target in package["targets"]:
        if target["name"] in artifacts:
            continue
        required = target.get("required_features", [])
        profile_args = (
            ["--no-default-features", "--features", ",".join(required)]
            if required
            else package["profile"].get("cargo_args", [])
        )
        extra_artifacts, _guests, _errors, _combined, extra_rc = build_package(
            package,
            target_triple=None,
            env=env,
            results=results,
            timeout=timeout,
            log_name=f"{package['name']}-x86-{target['name']}-build.log",
            profile_args=profile_args,
            selector_args=target_selector_args(target),
        )
        if extra_rc != 0 or target["name"] not in extra_artifacts:
            fail(
                f"{package['name']}:{target['name']} x86_64 reference target did not build "
                f"(rc={extra_rc})"
            )
        artifacts[target["name"]] = extra_artifacts[target["name"]]
    return artifacts


def validate_name_lists(packages: list[dict]) -> None:
    """Refuse manifest name lists that a set comparison would silently absorb."""
    for package in packages:
        for target in package["targets"]:
            label = f"{package['name']}:{target['name']}"
            x86_only = target.get("x86_only_tests", [])
            aarch64_only = target.get("aarch64_only_tests", [])
            for field, names in (("x86_only_tests", x86_only), ("aarch64_only_tests", aarch64_only)):
                duplicates = sorted({name for name in names if names.count(name) > 1})
                if duplicates:
                    fail(f"{label} manifest {field} has duplicate names: {duplicates}")
            if target["disposition"] != "qemu":
                if aarch64_only:
                    fail(f"{label} manifest aarch64_only_tests on a target that does not run on aarch64")
                if x86_only and len(x86_only) != target["x86_64"]["listed"]:
                    fail(
                        f"{label} manifest x86_only_tests names {len(x86_only)} tests but "
                        f"x86_64 listed is {target['x86_64']['listed']}"
                    )
                continue
            aarch64_names = target["aarch64"]["tests"]
            if not set(aarch64_only) <= set(aarch64_names):
                fail(f"{label} manifest aarch64_only_tests are not in the aarch64 list")
            overlap = sorted(set(x86_only) & set(aarch64_names))
            if overlap:
                fail(f"{label} manifest x86_only_tests overlap the aarch64 list: {overlap}")


def run_x86_reference(
    packages: list[dict],
    *,
    manifest: dict,
    env: dict[str, str],
    results: Path,
    build_timeout: int,
    target_timeout: int,
    validate_totals: bool,
) -> dict:
    if platform.machine() != "x86_64":
        fail(f"x86_64 reference pass requires an x86_64 host, got {platform.machine()}")
    validate_name_lists(packages)
    all_names: list[str] = []
    all_ignored: list[str] = []
    for package in packages:
        artifacts = build_x86_package(
            package, env=env, results=results, timeout=build_timeout
        )
        for target in package["targets"]:
            label = f"x86_64:{package['name']}:{target['name']}"
            executable = artifacts.get(target["name"])
            if executable is None:
                fail(f"{label} produced no x86_64 test artifact")
            names = binary_list(
                [], executable, env=env, label=label, ignored_only=False,
                results=results, timeout=target_timeout,
            )
            ignored = binary_list(
                [], executable, env=env, label=label, ignored_only=True,
                results=results, timeout=target_timeout,
            )
            if len(set(names)) != len(names):
                fail(f"{label} x86_64 list contains duplicate test names")
            expected_counts = target["x86_64"]
            if len(names) != expected_counts["listed"] or len(ignored) != expected_counts["ignored"]:
                fail(
                    f"{label} x86_64 list count drift: got listed={len(names)} "
                    f"ignored={len(ignored)}, manifest listed={expected_counts['listed']} "
                    f"ignored={expected_counts['ignored']}; names={names}"
                )
            x86_only = target.get("x86_only_tests", [])
            if target["disposition"] == "qemu":
                aarch64_names = target["aarch64"]["tests"]
                aarch64_only = target.get("aarch64_only_tests", [])
                expected_names = (set(aarch64_names) - set(aarch64_only)) | set(x86_only)
            elif x86_only:
                # A target that never runs on aarch64 pins its whole x86 list here.
                expected_names = set(x86_only)
            else:
                expected_names = None
            if expected_names is not None and set(names) != expected_names:
                missing = sorted(expected_names - set(names))
                extra = sorted(set(names) - expected_names)
                fail(f"{label} x86_64 name drift: missing={missing} extra={extra}")
            all_names.extend(names)
            all_ignored.extend(ignored)
    reference = {
        "status": "measured",
        "totals_validated": validate_totals,
        "listed": len(all_names),
        "ignored": len(all_ignored),
        "deduplicated_listed": len(set(all_names)),
        "deduplicated_ignored": len(set(all_ignored)),
    }
    if validate_totals:
        expected = manifest["x86_64_reference"]
        for key in ("listed", "ignored", "deduplicated_listed", "deduplicated_ignored"):
            if reference[key] != expected[key]:
                fail(
                    f"x86_64 reference {key} drift: got {reference[key]}, "
                    f"manifest {expected[key]}"
                )
    return reference


def binary_list(
    prefix: list[str],
    executable: str,
    *,
    env: dict[str, str],
    label: str,
    ignored_only: bool,
    results: Path,
    timeout: int,
) -> list[str]:
    args = [*prefix, executable]
    if ignored_only:
        args.append("--ignored")
    args.append("--list")
    suffix = "ignored-list" if ignored_only else "list"
    result = run_capture(
        f"{label} {suffix}",
        args,
        env=env,
        timeout=timeout,
        log_path=results / "logs" / f"{label.replace(':', '-')}-{suffix}.log",
    )
    if result.returncode != 0:
        fail(f"{label} {suffix} failed with rc={result.returncode}")
    return parse_list(result.stdout, f"{label} {suffix}")


def run_counted_target(
    package: dict,
    target: dict,
    executable: str,
    *,
    manifest: dict,
    execution_mode: str,
    allow_unpinned_native: bool,
    env: dict[str, str],
    results: Path,
    list_only: bool,
    target_timeout: int,
) -> dict:
    label = f"{package['name']}:{target['name']}"
    prefix = [manifest["qemu"]["path"]] if execution_mode == "qemu" else []
    start = time.monotonic()
    listed_names = binary_list(
        prefix, executable, env=env, label=label, ignored_only=False,
        results=results, timeout=target_timeout,
    )
    ignored_names = binary_list(
        prefix, executable, env=env, label=label, ignored_only=True,
        results=results, timeout=target_timeout,
    )
    expected = target["aarch64"]
    if listed_names != expected["tests"]:
        missing = [name for name in expected["tests"] if name not in listed_names]
        extra = [name for name in listed_names if name not in expected["tests"]]
        fail(f"{label} aarch64 list drift: missing={missing} extra={extra}")
    if len(ignored_names) != expected["ignored"]:
        fail(f"{label} ignored count drift: got {len(ignored_names)}, manifest {expected['ignored']}")
    row = {
        "package": package["name"],
        "target": target["name"],
        "kind": ",".join(target["kind"]),
        "disposition": target["disposition"],
        "x86_64_listed": target["x86_64"]["listed"],
        "x86_64_ignored": target["x86_64"]["ignored"],
        "aarch64_listed": len(listed_names),
        "aarch64_passed": None,
        "aarch64_failed": None,
        "aarch64_ignored": len(ignored_names),
        "aarch64_failed_tests": [],
        "status": "listed" if list_only else "counted",
        "wall_s": 0.0,
    }
    if list_only:
        row["wall_s"] = round(time.monotonic() - start, 3)
        return row
    logfile = results / "libtest" / f"{package['name']}-{target['name']}.log"
    logfile.parent.mkdir(parents=True, exist_ok=True)
    if logfile.exists():
        logfile.unlink()
    result = run_capture(
        f"{label} {execution_mode} run",
        [*prefix, executable, "--test-threads=1", "--logfile", str(logfile)],
        env=env,
        timeout=target_timeout,
        log_path=results / "logs" / f"{label.replace(':', '-')}-run.log",
    )
    passed, failed, ignored, failed_tests = parse_logfile(logfile, label, listed=len(listed_names))
    if passed + failed + ignored != len(listed_names):
        fail(
            f"{label} counted {passed}+{failed}+{ignored} outcomes for "
            f"{len(listed_names)} listed tests"
        )
    if ignored != len(ignored_names):
        fail(f"{label} execution ignored {ignored}, discovery ignored {len(ignored_names)}")
    if (result.returncode == 0 and failed) or (result.returncode not in (0, 101)):
        fail(f"{label} {execution_mode} run rc={result.returncode} is inconsistent with {failed} failures")
    got = {"listed": len(listed_names), "passed": passed, "failed": failed, "ignored": ignored}
    if execution_mode == "native":
        expected_counts = target.get("native")
        if expected_counts is None:
            if not allow_unpinned_native:
                fail(f"{label} native counts are not pinned in the manifest")
            row["status"] = "native-unpinned"
        else:
            want = {key: expected_counts[key] for key in ("listed", "passed", "failed", "ignored")}
            if got != want or failed_tests != expected_counts["failed_tests"]:
                fail(
                    f"{label} native count drift: got {got} failed_tests={failed_tests}, "
                    f"manifest {want} failed_tests={expected_counts['failed_tests']}"
                )
            row["status"] = "native-counted"
    else:
        want = {key: expected[key] for key in ("listed", "passed", "failed", "ignored")}
        if got != want or failed_tests != expected["failed_tests"]:
            fail(
                f"{label} count drift: got {got} failed_tests={failed_tests}, "
                f"manifest {want} failed_tests={expected['failed_tests']}"
            )
    row.update(
        {
            "aarch64_passed": passed,
            "aarch64_failed": failed,
            "aarch64_ignored": ignored,
            "aarch64_failed_tests": failed_tests,
            "wall_s": round(time.monotonic() - start, 3),
        }
    )
    return row


def guest_names(package: dict) -> set[str]:
    """Bin targets the build must also produce as non-test guest executables."""
    return {
        target["name"]
        for target in package["targets"]
        if target["disposition"] == "qemu" and "bin" in target["kind"]
    }


def guest_key(package: dict, name: str) -> str:
    return f"{package['name']}:bin:{name}"


def expected_zero_row(package: dict, target: dict, status: str) -> dict:
    return {
        "package": package["name"],
        "target": target["name"],
        "kind": ",".join(target["kind"]),
        "disposition": target["disposition"],
        "x86_64_listed": target["x86_64"]["listed"],
        "x86_64_ignored": target["x86_64"]["ignored"],
        "aarch64_listed": target["aarch64"]["listed"],
        "aarch64_passed": target["aarch64"]["passed"],
        "aarch64_failed": target["aarch64"]["failed"],
        "aarch64_ignored": target["aarch64"]["ignored"],
        "aarch64_failed_tests": target["aarch64"].get("failed_tests", []),
        "status": status,
        "wall_s": 0.0,
    }


def write_outputs(
    results: Path,
    manifest: dict,
    rows: list[dict],
    *,
    list_only: bool,
    execution_mode: str,
    x86_reference: dict,
) -> None:
    results.mkdir(parents=True, exist_ok=True)
    totals = {
        "targets": len(rows),
        "x86_64_listed": sum(row["x86_64_listed"] for row in rows),
        "x86_64_ignored": sum(row["x86_64_ignored"] for row in rows),
        "x86_64_listed_deduplicated": x86_reference.get("deduplicated_listed"),
        "x86_64_ignored_deduplicated": x86_reference.get("deduplicated_ignored"),
        "aarch64_listed": sum(row["aarch64_listed"] for row in rows),
        "aarch64_passed": None if list_only else sum(row["aarch64_passed"] or 0 for row in rows),
        "aarch64_failed": None if list_only else sum(row["aarch64_failed"] or 0 for row in rows),
        "aarch64_ignored": sum(row["aarch64_ignored"] or 0 for row in rows),
    }
    payload = {
        "schema_version": 1,
        "base_commit": manifest["base_commit"],
        "mode": "list-only" if list_only else "counted",
        "execution_mode": execution_mode,
        "x86_64_reference": x86_reference,
        "totals": totals,
        "rows": rows,
    }
    (results / "counts.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    with (results / "scorecard.tsv").open("w") as scorecard:
        scorecard.write(
            "package\ttarget\tkind\tdisposition\tx86_listed\tx86_ignored\t"
            "aarch64_listed\tpassed\tfailed\tignored\tstatus\twall_s\n"
        )
        for row in rows:
            passed = "?" if row["aarch64_passed"] is None else str(row["aarch64_passed"])
            failed = "?" if row["aarch64_failed"] is None else str(row["aarch64_failed"])
            scorecard.write(
                f"{row['package']}\t{row['target']}\t{row['kind']}\t{row['disposition']}\t"
                f"{row['x86_64_listed']}\t{row['x86_64_ignored']}\t{row['aarch64_listed']}\t"
                f"{passed}\t{failed}\t{row['aarch64_ignored']}\t{row['status']}\t{row['wall_s']}\n"
            )
    print(f"counts: {results / 'counts.json'}")
    print(f"scorecard: {results / 'scorecard.tsv'}")
    print(f"totals: {totals}")


def run_package(
    package: dict,
    *,
    manifest: dict,
    execution_mode: str,
    allow_unpinned_native: bool,
    prebuilt_artifacts: dict[str, str] | None,
    env: dict[str, str],
    results: Path,
    list_only: bool,
    build_timeout: int,
    target_timeout: int,
) -> tuple[list[dict], dict[str, str], dict[str, str], dict[str, str]]:
    """Return (rows, test executables, guest executables, sha256 at build time)."""
    rows: list[dict] = []
    if prebuilt_artifacts is not None:
        for target in package["targets"]:
            if target["disposition"] == "qemu":
                key = f"{package['name']}:{target['name']}"
                executable = prebuilt_artifacts.get(key)
                if executable is None:
                    fail(f"{key} has no prebuilt artifact")
                rows.append(
                    run_counted_target(
                        package,
                        target,
                        executable,
                        manifest=manifest,
                        execution_mode=execution_mode,
                        allow_unpinned_native=allow_unpinned_native,
                        env=env,
                        results=results,
                        list_only=list_only,
                        target_timeout=target_timeout,
                    )
                )
            else:
                rows.append(expected_zero_row(package, target, "shared-from-qemu-build"))
        return rows, {}, {}, {}
    by_disposition: dict[str, list[dict]] = {}
    for target in package["targets"]:
        by_disposition.setdefault(target["disposition"], []).append(target)
    refused_package = by_disposition.get("compile-refused-package", [])
    if refused_package:
        if len(refused_package) != len(package["targets"]):
            fail(f"{package['name']} mixes compile-refused-package with other dispositions")
        negative_probe(package, refused_package, env=env, results=results, timeout=build_timeout)
        return [expected_zero_row(package, target, "compile-refused") for target in refused_package], {}, {}, {}

    artifacts, guest_artifacts, errors, combined, build_rc = build_package(
        package,
        target_triple=manifest[execution_mode]["target"],
        env=env,
        results=results,
        timeout=build_timeout,
    )
    expected_artifacts = {
        target["name"]
        for target in package["targets"]
        if target["disposition"] in ("qemu", "compile-blocked")
    }
    # Cargo may emit artifacts for dependencies and for this package's
    # non-test binaries; parse_build_output already keeps only test-profile
    # artifacts from this package.  Every such artifact must be classified.
    extra_artifacts = sorted(set(artifacts) - expected_artifacts)
    if extra_artifacts:
        fail(f"{package['name']} produced unclassified test artifacts {extra_artifacts}")
    if build_rc not in (0, 101):
        fail(f"{package['name']} aarch64 test build failed with rc={build_rc}")
    built = {
        f"{package['name']}:{target['name']}": artifacts[target["name"]]
        for target in package["targets"]
        if target["disposition"] == "qemu" and target["name"] in artifacts
    }
    # The counted tests run these guest programs from their fixed
    # CARGO_BIN_EXE path, so they are bound like the test executables.
    expected_guests = guest_names(package)
    if set(guest_artifacts) != expected_guests:
        missing = sorted(expected_guests - set(guest_artifacts))
        extra = sorted(set(guest_artifacts) - expected_guests)
        fail(f"{package['name']} guest executable drift: missing={missing} extra={extra}")
    # A bin's 0-test unittest shares its target name, so guests get their own keys.
    guests = {guest_key(package, name): exe for name, exe in guest_artifacts.items()}
    # Hash before any test runs; write_artifacts refuses if a binary changed.
    build_hashes = {key: file_sha256(Path(exe)) for key, exe in {**built, **guests}.items()}

    for target in package["targets"]:
        disposition = target["disposition"]
        if disposition == "qemu":
            executable = artifacts.get(target["name"])
            if executable is None:
                fail(f"{package['name']}:{target['name']} is qemu-runnable but produced no test artifact")
            rows.append(
                run_counted_target(
                    package,
                    target,
                    executable,
                    manifest=manifest,
                    execution_mode=execution_mode,
                    allow_unpinned_native=allow_unpinned_native,
                    env=env,
                    results=results,
                    list_only=list_only,
                    target_timeout=target_timeout,
                )
            )
        elif disposition == "compile-blocked":
            if target["name"] in artifacts:
                fail(f"{package['name']}:{target['name']} unexpectedly compiled for aarch64; update the manifest")
            target_errors = errors.get(target["name"], "")
            require_signatures(
                f"{package['name']}:{target['name']}",
                target_errors,
                target.get("compile_signatures", []),
            )
            rows.append(expected_zero_row(package, target, "compile-blocked"))
        elif disposition == "compile-refused-feature":
            if target["name"] in artifacts:
                fail(f"{package['name']}:{target['name']} unexpectedly built in the L1c profile")
            feature_negative_probe(
                package, target, env=env, results=results, timeout=build_timeout
            )
            rows.append(expected_zero_row(package, target, "compile-refused"))
        else:
            fail(f"{package['name']}:{target['name']} has unknown disposition {disposition!r}")
    return rows, built, guests, build_hashes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--results", type=Path, default=ROOT / "target" / "liteinst-aarch64-counts")
    parser.add_argument("--mode", choices=("qemu", "native"), default="qemu", help="execution mode (default: qemu)")
    parser.add_argument("--list-only", action="store_true", help="build and list, but do not execute tests")
    parser.add_argument("--require-pass", action="store_true", help="fail if any counted aarch64 test fails")
    parser.add_argument(
        "--allow-unpinned-native",
        action="store_true",
        help="in native mode, record counts for targets whose native counts are not pinned yet",
    )
    parser.add_argument(
        "--prebuilt-target-dir",
        type=Path,
        default=None,
        help="native mode only: execute prebuilt aarch64-musl test binaries from this Cargo target dir",
    )
    parser.add_argument(
        "--artifacts-json",
        type=Path,
        default=None,
        help="artifacts.json written by a qemu-mode run (with --prebuilt-target-dir)",
    )
    parser.add_argument("--packages", default="", help="space-separated package subset from the manifest")
    parser.add_argument("--build-timeout", type=int, default=1200)
    parser.add_argument("--target-timeout", type=int, default=600)
    args = parser.parse_args()
    if args.build_timeout <= 0 or args.target_timeout <= 0:
        parser.error("timeouts must be positive")
    if args.require_pass and args.list_only:
        parser.error("--require-pass requires a counted run, not --list-only")
    if args.allow_unpinned_native and args.mode != "native":
        parser.error("--allow-unpinned-native is only valid with --mode native")
    if args.allow_unpinned_native and args.list_only:
        parser.error("--allow-unpinned-native requires a counted run, not --list-only")
    if (args.prebuilt_target_dir is None) != (args.artifacts_json is None):
        parser.error("--prebuilt-target-dir and --artifacts-json must be given together")
    if args.prebuilt_target_dir is not None and args.mode != "native":
        parser.error("--prebuilt-target-dir is only valid with --mode native")
    manifest_path = args.manifest if args.manifest.is_absolute() else ROOT / args.manifest
    results = args.results if args.results.is_absolute() else (Path.cwd() / args.results).resolve()
    prebuilt = args.prebuilt_target_dir is not None
    try:
        manifest = load_manifest(manifest_path)
        env = base_env(manifest, args.mode)
        prebuilt_artifacts = None
        prebuilt_metadata: dict = {}
        if prebuilt:
            prebuilt_dir = (
                args.prebuilt_target_dir
                if args.prebuilt_target_dir.is_absolute()
                else (Path.cwd() / args.prebuilt_target_dir).resolve()
            )
            artifacts_path = (
                args.artifacts_json
                if args.artifacts_json.is_absolute()
                else (Path.cwd() / args.artifacts_json).resolve()
            )
            prebuilt_artifacts, prebuilt_metadata = load_artifacts(
                artifacts_path,
                prebuilt_dir,
                env=env,
                expected_target=manifest["native"]["target"],
            )
        packages = manifest["packages"]
        if args.packages:
            wanted = args.packages.split()
            known = {package["name"] for package in packages}
            unknown = [name for name in wanted if name not in known]
            if unknown:
                fail(f"--packages names packages outside the manifest: {unknown}")
            packages = [package for package in packages if package["name"] in set(wanted)]
        if prebuilt:
            expected_keys = {
                f"{package['name']}:{target['name']}"
                for package in packages
                for target in package["targets"]
                if target["disposition"] == "qemu"
            }
            selected = [package["name"] for package in packages]
            unbuilt = sorted(set(selected) - set(prebuilt_metadata["packages"]))
            if unbuilt:
                fail(
                    f"prebuilt run selects packages the producing run did not build: {unbuilt} "
                    f"(producing packages={prebuilt_metadata['packages']})"
                )
            if not args.packages and prebuilt_metadata["x86_64_reference"].get("totals_validated") is not True:
                fail("full prebuilt run requires a producing run whose x86_64 totals were validated")
            missing_keys = sorted(expected_keys - set(prebuilt_artifacts or {}))
            if missing_keys:
                fail(f"prebuilt artifacts are missing qemu targets {missing_keys}")
            expected_guests = {
                guest_key(package, name) for package in packages for name in guest_names(package)
            }
            missing_guests = sorted(expected_guests - set(prebuilt_metadata["guests"]))
            if missing_guests:
                fail(f"prebuilt artifacts are missing guest executables {missing_guests}")
            if not args.packages:
                extra_keys = sorted(set(prebuilt_artifacts or {}) - expected_keys)
                if extra_keys:
                    fail(f"prebuilt artifacts name unclassified targets {extra_keys}")
                extra_guests = sorted(set(prebuilt_metadata["guests"]) - expected_guests)
                if extra_guests:
                    fail(f"prebuilt artifacts name unclassified guest executables {extra_guests}")
        require_prerequisites(manifest, env, args.mode, prebuilt=prebuilt)
        build_source: dict = {}
        if not prebuilt:
            # Bind artifacts to the source as it was BEFORE the build, and drop
            # any artifacts.json an earlier run left here: this run may rebuild
            # the binaries it names and then fail before writing a new one.
            (results / "artifacts.json").unlink(missing_ok=True)
            build_source = source_identity(env, cargo_target_dir(env))
        if args.mode == "native" and not args.list_only and not args.allow_unpinned_native:
            unpinned = [
                f"{package['name']}:{target['name']}"
                for package in manifest["packages"]
                for target in package["targets"]
                if target["disposition"] == "qemu" and "native" not in target
            ]
            if unpinned:
                fail(
                    "native counts are not pinned yet for "
                    f"{len(unpinned)} targets (first: {unpinned[0]}); "
                    "rerun with --allow-unpinned-native for the first measurement"
                )
        if not prebuilt:
            inventory = metadata_inventory(env)
            validate_inventory(manifest, inventory)
        if args.mode == "qemu" and not prebuilt:
            x86_reference = run_x86_reference(
                packages,
                manifest=manifest,
                env=env,
                results=results,
                build_timeout=args.build_timeout,
                target_timeout=args.target_timeout,
                validate_totals=not args.packages,
            )
        elif prebuilt:
            # Measured by the qemu run that wrote artifacts.json, not here.
            x86_reference = {
                **prebuilt_metadata["x86_64_reference"],
                "status": "measured-by-producing-qemu-run",
                "producing_packages": prebuilt_metadata["packages"],
            }
        else:
            x86_reference = {
                **manifest["x86_64_reference"],
                "status": "not-run-native-host",
                "values_from": "manifest",
            }
        rows: list[dict] = []
        built_artifacts: dict[str, str] = {}
        built_guests: dict[str, str] = {}
        build_hashes: dict[str, str] = {}
        built_kinds: dict[str, list[str]] = {}
        for package in packages:
            package_rows, package_artifacts, package_guests, package_hashes = run_package(
                package,
                manifest=manifest,
                execution_mode=args.mode,
                allow_unpinned_native=args.allow_unpinned_native,
                prebuilt_artifacts=prebuilt_artifacts,
                env=env,
                results=results,
                list_only=args.list_only,
                build_timeout=args.build_timeout,
                target_timeout=args.target_timeout,
            )
            rows.extend(package_rows)
            built_artifacts.update(package_artifacts)
            built_guests.update(package_guests)
            build_hashes.update(package_hashes)
            for target in package["targets"]:
                built_kinds[f"{package['name']}:{target['name']}"] = target["kind"]
        rows.sort(key=lambda row: (row["package"], row["target"]))
        write_outputs(
            results,
            manifest,
            rows,
            list_only=args.list_only,
            execution_mode=args.mode,
            x86_reference=x86_reference,
        )
        if not prebuilt and built_artifacts:
            write_artifacts(
                results,
                env=env,
                target_triple=manifest[args.mode]["target"],
                artifacts=built_artifacts,
                guests=built_guests,
                build_hashes=build_hashes,
                kinds=built_kinds,
                source=build_source,
                producing_mode=args.mode,
                packages=[package["name"] for package in packages],
                x86_reference=x86_reference,
            )
        failed = sum(row["aarch64_failed"] or 0 for row in rows)
        if args.require_pass and failed:
            fail(f"--require-pass set but {failed} counted aarch64 tests failed")
    except RunnerFailure as error:
        print(f"AARCH64 COUNT FAILED: {error}", file=sys.stderr)
        return 1
    print("LiteInst aarch64 counts match the pinned manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())



