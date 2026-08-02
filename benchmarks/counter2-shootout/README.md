# Counter2 backend performance shootout

This is a manual performance experiment, not a correctness suite and not a CI
target. It measures the instrumentation overhead of Reverie's exact shared
[`counter2`](../../reverie-examples/counter2_tool.rs) Tool over calibrated
multi-second fixed-work guests.

The runner supports `ptrace`, `kvm`, `liteinst`, `dbi`, `sabre`, and `e9patch`.
It reports each backend against the matching native executable rather than
comparing raw times from unlike static and dynamic binaries.

## Safety and comparison rules

`known-green.json` is the comparison contract. Each logical workload maps a
backend to the binary variant previously proven to preserve its exit status,
stdout, and nonzero counter2 result. The KVM runner needs a static ELF; the
in-process preload runners use the matching dynamic ET_EXEC. Both variants are
built from the same source and execute the same calibrated iteration count.

For a requested backend set, `run.py` takes only the workload intersection in
which every backend is listed. Before warmups or measurements it reruns every
native/backend cell and requires:

1. exit status zero;
2. stdout byte-identical to the matching native variant; and
3. a parseable, nonzero exact-counter2 summary.

Any failed probe aborts the whole run. The runner never measures a failed cell
or silently shrinks the intersection. Changing `known-green.json` therefore
requires new evidence in `INITIAL_RESULTS.md`.

The first published all-backend run and its raw text artifacts are in
[`INITIAL_RESULTS.md`](INITIAL_RESULTS.md) and
[`results/20260802T042358Z/`](results/20260802T042358Z/).

## Workloads

`workload.c` is a deterministic integer workload with direct x86-64 Linux
syscall sites in the main executable. Direct sites let KVM, LiteInst, SaBRe,
and e9patch all exercise real interception rather than a libc-only fast path.
The two cells differ only in syscall density:

| Workload | Direct `getpid` frequency | Purpose |
| --- | ---: | --- |
| `counter2-cpu-heavy` | every 65,536 iterations | amortized instrumentation and lifecycle overhead |
| `counter2-syscall-mix` | every 4,096 iterations | sustained syscall interception overhead |

The runner calibrates a fixed iteration count from a native pilot. The measured
guest does not stop on elapsed time, so a slower backend performs exactly the
same work rather than less work during a fixed time window. `--target-seconds`
is constrained to 3-10 seconds.

## Build

Optional backend sources are pinned submodules. Build selected adapters and
their native dependencies through the proxy:

```bash
with-proxy benchmarks/counter2-shootout/prepare.sh
```

Pass a comma-separated subset to build less, for example:

```bash
with-proxy benchmarks/counter2-shootout/prepare.sh ptrace,kvm,liteinst
```

The full build needs a working C/C++ toolchain, CMake, and the upstream e9patch
build dependencies. The KVM variant is a freestanding `-nostdlib` ELF, so it
does not require static glibc; KVM measurements do require usable `/dev/kvm`.

## Run

The default is five measured repetitions, one warmup, five seconds of native
work, and all six backends:

```bash
benchmarks/counter2-shootout/run.py
```

Compare a pair on only its known-green intersection:

```bash
benchmarks/counter2-shootout/run.py \
  --backends ptrace,kvm --repetitions 7 --target-seconds 5
```

Ordinary run artifacts are intentionally untracked under
`target/counter2-shootout/<UTC run id>/`:

- `probes.jsonl`: pre-measurement correctness gates;
- `samples.jsonl`: randomized per-repetition wall times and counter totals;
- `summary.csv`: per-workload median/geomean time and native slowdown;
- `overall.csv`: geomean slowdown across workload medians;
- `metadata.json`: source SHA, manifest digest, host, and run settings; and
- `report.md`: human-readable tables.

Only explicitly reviewed publication runs, such as the initial result above,
are copied into `results/`.

## Interpretation

The metric includes backend startup, binary rewriting, VM/client launch, the
guest workload, and teardown. Multi-second native work amortizes startup but
does not erase it. Results are end-to-end wall-clock overhead, not isolated
per-syscall latency. Use multiple repetitions on an otherwise idle host and
retain the raw JSONL when making optimization claims.
