#!/usr/bin/env python3
"""Run the non-CI counter2 cross-backend performance shootout."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import random
import re
import socket
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BACKENDS = ("ptrace", "kvm", "liteinst", "dbt", "sabre", "e9patch")
COUNTER_PATTERNS = (
    re.compile(
        rb"Total system calls in process tree: (?P<total>[0-9]+), "
        rb"from (?P<processes>[0-9]+) processes, (?P<threads>[0-9]+) thread"
    ),
    re.compile(
        rb"counter2-global syscalls=(?P<total>[0-9]+) "
        rb"processes=(?P<processes>[0-9]+) threads=(?P<threads>[0-9]+)"
    ),
    re.compile(
        rb"counter2 exact\] Process-local system calls: (?P<total>[0-9]+), "
        rb"exited threads: (?P<threads>[0-9]+)"
    ),
)


@dataclass(frozen=True)
class Execution:
    workload: str
    backend: str
    variant: str
    iterations: int
    stride: int


@dataclass
class Outcome:
    command: list[str]
    duration_ms: float
    returncode: int
    stdout: bytes
    stderr: bytes
    counter_total: int | None
    counter_processes: int | None
    counter_threads: int | None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Measure exact counter2 overhead only on the selected backends' "
            "known-green workload intersection."
        )
    )
    parser.add_argument(
        "--backends",
        default=",".join(BACKENDS),
        help="comma-separated backend set (default: all)",
    )
    parser.add_argument(
        "--workloads",
        help="optional comma-separated workload IDs from known-green.json",
    )
    parser.add_argument("--target-seconds", type=float, default=5.0)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=float, default=180.0)
    parser.add_argument("--profile", choices=("debug", "release"), default="release")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--seed", type=int, default=1)
    return parser.parse_args()


def fail(message: str) -> None:
    raise SystemExit(f"counter2-shootout: {message}")


def require_file(path: Path, description: str) -> Path:
    if not path.is_file():
        fail(f"missing {description}: {path}; run prepare.sh first")
    return path


def parse_counter(stderr: bytes) -> tuple[int | None, int | None, int | None]:
    for pattern in COUNTER_PATTERNS:
        matches = list(pattern.finditer(stderr))
        if not matches:
            continue
        groups = matches[-1].groupdict()
        total = int(groups["total"])
        processes = int(groups["processes"]) if groups.get("processes") else None
        threads = int(groups["threads"]) if groups.get("threads") else None
        return total, processes, threads
    return None, None, None


def run_process(
    command: list[str], env: dict[str, str], timeout_seconds: float, root: Path
) -> Outcome:
    started = time.perf_counter_ns()
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        raise RuntimeError(
            f"timeout after {timeout_seconds:.1f}s: {' '.join(command)}\n"
            f"stdout:\n{stdout.decode(errors='replace')}\n"
            f"stderr:\n{stderr.decode(errors='replace')}"
        ) from error
    duration_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    total, processes, threads = parse_counter(completed.stderr)
    return Outcome(
        command=command,
        duration_ms=duration_ms,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        counter_total=total,
        counter_processes=processes,
        counter_threads=threads,
    )


def compile_workloads(root: Path, build: Path) -> dict[str, Path]:
    build.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).with_name("workload.c")
    common = [
        os.environ.get("CC", "cc"),
        "-std=c11",
        "-O2",
        "-g",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-pie",
        "-no-pie",
        str(source),
    ]
    variants = {
        "dynamic": build / "counter2-workload-dynamic",
        "static": build / "counter2-workload-static",
    }
    for variant, output in variants.items():
        command = [*common]
        if variant == "static":
            command.extend(
                [
                    "-static",
                    "-nostdlib",
                    "-fno-stack-protector",
                    "-fno-builtin",
                    "-DSHOOTOUT_FREESTANDING",
                    "-Wl,-e,_start",
                ]
            )
        command.extend(["-o", str(output)])
        completed = subprocess.run(command, cwd=root, check=False)
        if completed.returncode != 0:
            fail(f"failed to compile {variant} workload")
    return variants


def base_environment() -> dict[str, str]:
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC", "RUST_LOG": "off"})
    return env


def backend_environment(
    backend: str, env: dict[str, str], root: Path, target: Path
) -> dict[str, str]:
    result = env.copy()
    if backend == "dbt":
        helper = require_file(
            target / "reverie-dbt-dynamorio-path", "DBT DynamoRIO path helper"
        )
        if not result.get("DYNAMORIO_HOME"):
            result["DYNAMORIO_HOME"] = subprocess.check_output(
                [str(helper), "home"], cwd=root, text=True
            ).strip()
        result.setdefault(
            "REVERIE_DBT_CLIENT",
            str(target / "reverie-dbt-native" / "libreverie_dbt_client.so"),
        )
        require_file(Path(result["REVERIE_DBT_CLIENT"]), "DBT native client")
    elif backend == "e9patch":
        result.setdefault("REVERIE_E9TOOL", str(root / "third-party/e9patch/e9tool"))
        result.setdefault(
            "REVERIE_E9PATCH_BACKEND", str(root / "third-party/e9patch/e9patch")
        )
        require_file(Path(result["REVERIE_E9TOOL"]), "e9tool")
        require_file(Path(result["REVERIE_E9PATCH_BACKEND"]), "e9patch backend")
    elif backend == "sabre":
        result["REVERIE_SABRE_STRACE_QUIET"] = "1"
    return result


def backend_command(
    backend: str, artifact: Path, arguments: list[str], root: Path, target: Path
) -> list[str]:
    if backend == "ptrace":
        return [str(require_file(target / "counter2", "ptrace counter2")), "--", str(artifact), *arguments]
    if backend == "kvm":
        if not Path("/dev/kvm").exists():
            fail("/dev/kvm is unavailable")
        return [
            str(require_file(target / "reverie-kvm-counter2", "KVM counter2")),
            str(artifact),
            *arguments,
        ]
    if backend == "liteinst":
        return [
            str(require_file(target / "reverie-liteinst-examples", "LiteInst examples")),
            "--tool",
            "counter2",
            "--",
            str(artifact),
            *arguments,
        ]
    if backend == "dbt":
        return [
            str(require_file(target / "reverie-dbt-counter2-exact", "DBT exact counter2")),
            "--",
            str(artifact),
            *arguments,
        ]
    if backend == "sabre":
        return [
            str(require_file(target / "reverie-sabre-strace", "SaBRe counter2 host")),
            "--sabre",
            str(require_file(root / "target/sabre/sabre", "SaBRe loader")),
            "--plugin",
            str(
                require_file(
                    target / "libreverie_sabre_strace_plugin.so", "SaBRe plugin"
                )
            ),
            "--tool",
            "counter2-exact",
            "--",
            str(artifact),
            *arguments,
        ]
    if backend == "e9patch":
        return [
            str(require_file(target / "reverie-e9patch-counter2", "e9patch counter2")),
            "--",
            str(artifact),
            *arguments,
        ]
    fail(f"unknown backend {backend}")


def command_for(
    execution: Execution,
    artifacts: dict[str, Path],
    root: Path,
    target: Path,
) -> list[str]:
    artifact = artifacts[execution.variant]
    arguments = [
        "--iterations",
        str(execution.iterations),
        "--stride",
        str(execution.stride),
    ]
    if execution.backend == "native":
        return [str(artifact), *arguments]
    return backend_command(execution.backend, artifact, arguments, root, target)


def check_outcome(
    execution: Execution, outcome: Outcome, expected_stdout: bytes | None
) -> None:
    label = f"{execution.workload}/{execution.backend}/{execution.variant}"
    if outcome.returncode != 0:
        raise RuntimeError(
            f"{label} exited {outcome.returncode}\n"
            f"command: {' '.join(outcome.command)}\n"
            f"stdout:\n{outcome.stdout.decode(errors='replace')}\n"
            f"stderr:\n{outcome.stderr.decode(errors='replace')}"
        )
    if expected_stdout is not None and outcome.stdout != expected_stdout:
        raise RuntimeError(
            f"{label} stdout differs from matching native workload\n"
            f"expected: {expected_stdout!r}\nactual: {outcome.stdout!r}"
        )
    if execution.backend != "native" and not outcome.counter_total:
        raise RuntimeError(
            f"{label} did not emit a nonzero exact-counter2 summary\n"
            f"stderr:\n{outcome.stderr.decode(errors='replace')}"
        )


def geometric_mean(values: list[float]) -> float:
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def git_output(root: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=root, text=True).strip()


def main() -> None:
    args = parse_args()
    if not 3.0 <= args.target_seconds <= 10.0:
        fail("--target-seconds must be between 3 and 10")
    if args.repetitions < 1 or args.warmups < 0:
        fail("repetitions must be positive and warmups nonnegative")

    root = Path(__file__).resolve().parents[2]
    target = root / "target" / args.profile
    selected = [item.strip() for item in args.backends.split(",") if item.strip()]
    if len(set(selected)) != len(selected) or any(item not in BACKENDS for item in selected):
        fail(f"invalid --backends value: {args.backends}")
    if not selected:
        fail("select at least one backend")

    manifest_path = Path(__file__).with_name("known-green.json")
    manifest = json.loads(manifest_path.read_text())
    requested_workloads = (
        {item.strip() for item in args.workloads.split(",") if item.strip()}
        if args.workloads
        else None
    )
    workloads = []
    for workload in manifest["workloads"]:
        if requested_workloads is not None and workload["id"] not in requested_workloads:
            continue
        if all(backend in workload["backends"] for backend in selected):
            workloads.append(workload)
    if requested_workloads is not None:
        found = {workload["id"] for workload in workloads}
        missing = requested_workloads - found
        if missing:
            fail(
                "requested workload is not in the selected backends' known-green "
                f"intersection: {', '.join(sorted(missing))}"
            )
    if not workloads:
        fail("selected backends have no known-green workload intersection")

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_start_utc = datetime.now(timezone.utc).isoformat()
    start_load_average = os.getloadavg()
    output = args.output or root / "target/counter2-shootout" / run_id
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    artifacts = compile_workloads(root, root / "target/counter2-shootout/workloads")
    env = base_environment()

    iterations: dict[str, int] = {}
    for workload in workloads:
        calibration = subprocess.run(
            [
                str(artifacts["dynamic"]),
                "--calibrate-ms",
                str(round(args.target_seconds * 1000)),
                "--stride",
                str(workload["syscall_stride"]),
            ],
            cwd=root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        match = re.fullmatch(r"iterations=([0-9]+)\n", calibration.stdout)
        if not match:
            fail(f"cannot parse calibration output: {calibration.stdout!r}")
        iterations[workload["id"]] = int(match.group(1))
        print(
            f"CALIBRATE {workload['id']}: {calibration.stdout.strip()} "
            f"({calibration.stderr.strip()})",
            flush=True,
        )

    executions: list[Execution] = []
    for workload in workloads:
        variants = sorted({workload["backends"][backend] for backend in selected})
        for variant in variants:
            executions.append(
                Execution(
                    workload["id"],
                    "native",
                    variant,
                    iterations[workload["id"]],
                    workload["syscall_stride"],
                )
            )
        for backend in selected:
            executions.append(
                Execution(
                    workload["id"],
                    backend,
                    workload["backends"][backend],
                    iterations[workload["id"]],
                    workload["syscall_stride"],
                )
            )

    expected: dict[tuple[str, str], bytes] = {}
    probes: list[dict[str, Any]] = []
    print("PROBE: validating every known-green cell before timing", flush=True)
    for execution in executions:
        command = command_for(execution, artifacts, root, target)
        run_env = backend_environment(execution.backend, env, root, target)
        outcome = run_process(command, run_env, args.timeout_seconds, root)
        key = (execution.workload, execution.variant)
        if execution.backend == "native":
            expected[key] = outcome.stdout
            check_outcome(execution, outcome, None)
        else:
            check_outcome(execution, outcome, expected[key])
        probes.append(
            {
                "workload": execution.workload,
                "backend": execution.backend,
                "variant": execution.variant,
                "duration_ms": outcome.duration_ms,
                "counter_total": outcome.counter_total,
                "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
            }
        )
        print(
            f"  PASS {execution.workload}/{execution.backend}/{execution.variant} "
            f"{outcome.duration_ms:.1f} ms counter={outcome.counter_total or '-'}",
            flush=True,
        )
    with (output / "probes.jsonl").open("w") as stream:
        for probe in probes:
            stream.write(json.dumps(probe, sort_keys=True) + "\n")

    for warmup in range(args.warmups):
        print(f"WARMUP {warmup + 1}/{args.warmups}", flush=True)
        for execution in executions:
            outcome = run_process(
                command_for(execution, artifacts, root, target),
                backend_environment(execution.backend, env, root, target),
                args.timeout_seconds,
                root,
            )
            check_outcome(execution, outcome, expected[(execution.workload, execution.variant)])

    schedule = [
        (repetition, execution)
        for repetition in range(1, args.repetitions + 1)
        for execution in executions
    ]
    random.Random(args.seed).shuffle(schedule)
    samples: list[dict[str, Any]] = []
    sample_path = output / "samples.jsonl"
    with sample_path.open("w") as stream:
        for index, (repetition, execution) in enumerate(schedule, 1):
            outcome = run_process(
                command_for(execution, artifacts, root, target),
                backend_environment(execution.backend, env, root, target),
                args.timeout_seconds,
                root,
            )
            check_outcome(execution, outcome, expected[(execution.workload, execution.variant)])
            sample = {
                "run_id": run_id,
                "sequence": index,
                "repetition": repetition,
                "workload": execution.workload,
                "backend": execution.backend,
                "variant": execution.variant,
                "iterations": execution.iterations,
                "syscall_stride": execution.stride,
                "duration_ms": round(outcome.duration_ms, 6),
                "counter_total": outcome.counter_total,
                "counter_processes": outcome.counter_processes,
                "counter_threads": outcome.counter_threads,
                "stdout_sha256": hashlib.sha256(outcome.stdout).hexdigest(),
            }
            samples.append(sample)
            stream.write(json.dumps(sample, sort_keys=True) + "\n")
            stream.flush()
            print(
                f"SAMPLE {index}/{len(schedule)} {execution.workload}/"
                f"{execution.backend}/{execution.variant}: {outcome.duration_ms:.1f} ms",
                flush=True,
            )

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for sample in samples:
        key = (sample["workload"], sample["backend"], sample["variant"])
        groups.setdefault(key, []).append(sample)
    native_medians = {
        (workload, variant): statistics.median(item["duration_ms"] for item in group)
        for (workload, backend, variant), group in groups.items()
        if backend == "native"
    }

    summary_rows: list[dict[str, Any]] = []
    for (workload, backend, variant), group in sorted(groups.items()):
        durations = [item["duration_ms"] for item in group]
        native_median = native_medians[(workload, variant)]
        counters = sorted(
            {item["counter_total"] for item in group if item["counter_total"] is not None}
        )
        summary_rows.append(
            {
                "workload": workload,
                "backend": backend,
                "variant": variant,
                "repetitions": len(group),
                "median_ms": round(statistics.median(durations), 3),
                "geomean_ms": round(geometric_mean(durations), 3),
                "native_median_ms": round(native_median, 3),
                "slowdown": round(statistics.median(durations) / native_median, 6),
                "counter_total": ";".join(str(value) for value in counters),
            }
        )
    with (output / "summary.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=list(summary_rows[0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(summary_rows)

    overall_rows = []
    for backend in selected:
        backend_rows = [row for row in summary_rows if row["backend"] == backend]
        overall_rows.append(
            {
                "backend": backend,
                "workloads": len(backend_rows),
                "geomean_slowdown": round(
                    geometric_mean([row["slowdown"] for row in backend_rows]), 6
                ),
            }
        )
    with (output / "overall.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=list(overall_rows[0]), lineterminator="\n"
        )
        writer.writeheader()
        writer.writerows(overall_rows)

    metadata = {
        "schema": 1,
        "run_id": run_id,
        "run_start_utc": run_start_utc,
        "run_utc": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "logical_cpus": os.cpu_count(),
        "start_load_average": start_load_average,
        "reverie_sha": git_output(root, "rev-parse", "HEAD"),
        "source_dirty": bool(git_output(root, "status", "--short")),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "backends": selected,
        "workloads": [workload["id"] for workload in workloads],
        "target_seconds": args.target_seconds,
        "repetitions": args.repetitions,
        "warmups": args.warmups,
        "timeout_seconds": args.timeout_seconds,
        "seed": args.seed,
    }
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")

    lines = [
        "# Counter2 shootout",
        "",
        f"Run `{run_id}` on `{metadata['host']}` at Reverie `{metadata['reverie_sha']}`.",
        f"Each workload has {args.repetitions} measured repetitions after {args.warmups} warmup(s).",
        "Slowdown is median backend wall time / median matching native-variant wall time.",
        "",
        "| Backend | Workloads | Geomean slowdown |",
        "| --- | ---: | ---: |",
    ]
    for row in sorted(overall_rows, key=lambda item: item["geomean_slowdown"]):
        lines.append(
            f"| {row['backend']} | {row['workloads']} | {row['geomean_slowdown']:.3f}x |"
        )
    lines.extend(
        [
            "",
            "| Workload | Backend | Variant | Median ms | Native ms | Slowdown | Counter2 calls |",
            "| --- | --- | --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in summary_rows:
        if row["backend"] == "native":
            continue
        lines.append(
            f"| {row['workload']} | {row['backend']} | {row['variant']} | "
            f"{row['median_ms']:.1f} | {row['native_median_ms']:.1f} | "
            f"{row['slowdown']:.3f}x | {row['counter_total']} |"
        )
    report = "\n".join(lines) + "\n"
    (output / "report.md").write_text(report)
    print(f"\nRESULTS {output}\n")
    print(report)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        fail(str(error))
