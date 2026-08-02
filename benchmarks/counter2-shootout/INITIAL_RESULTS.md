# Initial counter2 backend results

This is the first publication run of the manual counter2 shootout. It is a
performance baseline, not a CI ratchet.

## Run identity

- Framework commit: `36ce950a5c4207046c62efbd2904d5c808a4238f`
- Run: `20260802T042358Z`
- Host: `devbig014.atn7.facebook.com`, 316 logical CPUs
- Host load immediately before launch: 70.88 / 93.51 / 102.71
- Command: `benchmarks/counter2-shootout/run.py`
- Configuration: 5 second native target, 1 warmup, 5 measured repetitions,
  180 second per-run timeout, randomized schedule seed 1
- Source state: clean (`source_dirty=false`)
- Correctness gate: all 4 native-variant probes and all 12 backend/workload
  probes passed; all 80 measured samples also preserved exit zero, exact native
  stdout, and a nonzero exact-counter2 summary

Raw evidence is in [`results/20260802T042358Z`](results/20260802T042358Z):
`metadata.json`, `probes.jsonl`, `samples.jsonl`, `summary.csv`, and
`overall.csv`.

## Overall slowdown

Each value is the geometric mean of the two per-workload slowdowns. A
per-workload slowdown is median backend wall time divided by the median native
time of that backend's matching binary variant.

| Rank | Backend | Workloads | Geomean slowdown |
| ---: | --- | ---: | ---: |
| 1 | LiteInst | 2 | **1.032x** |
| 2 | e9patch | 2 | **1.036x** |
| 3 | SaBRe | 2 | **1.056x** |
| 4 | KVM | 2 | **1.597x** |
| 5 | ptrace | 2 | **1.687x** |
| 6 | DBI | 2 | **5.433x** |

## Per-workload medians

| Workload | Backend | Variant | Backend ms | Native ms | Slowdown | Counter2 calls |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| CPU-heavy | ptrace | dynamic | 5,615.6 | 5,030.1 | 1.116x | 28,300 |
| CPU-heavy | KVM | static | 5,526.5 | 5,021.4 | 1.101x | 28,269 |
| CPU-heavy | LiteInst | dynamic | 5,070.2 | 5,030.1 | 1.008x | 28,268 |
| CPU-heavy | DBI | dynamic | 27,056.8 | 5,030.1 | 5.379x | 28,299 |
| CPU-heavy | SaBRe | dynamic | 5,103.5 | 5,030.1 | 1.015x | 28,269 |
| CPU-heavy | e9patch | dynamic | 5,059.6 | 5,030.1 | 1.006x | 28,268 |
| Syscall-mix | ptrace | dynamic | 12,846.4 | 5,036.4 | 2.551x | 450,751 |
| Syscall-mix | KVM | static | 11,660.7 | 5,029.9 | 2.318x | 450,720 |
| Syscall-mix | LiteInst | dynamic | 5,322.7 | 5,036.4 | 1.057x | 450,719 |
| Syscall-mix | DBI | dynamic | 27,638.6 | 5,036.4 | 5.488x | 450,750 |
| Syscall-mix | SaBRe | dynamic | 5,530.7 | 5,036.4 | 1.098x | 450,720 |
| Syscall-mix | e9patch | dynamic | 5,375.9 | 5,036.4 | 1.067x | 450,719 |

## Interpretation

The multi-second CPU-heavy cell amortizes launch cost: LiteInst, e9patch, and
SaBRe are within 1.5% of native, while ptrace and KVM are about 10-12% slower.
On the denser 450k-syscall cell, LiteInst/e9patch/SaBRe remain within 10% of
native, KVM is 2.32x, and ptrace is 2.55x. KVM is therefore modestly faster
than ptrace for this counter2 syscall workload, but neither approaches the
in-process patching paths.

The current DBI client is different: it instruments application branches in
addition to dispatching the exact counter2 Tool. Its roughly 5.4x slowdown is
almost flat across the two syscall densities, so this run measures that broad
instruction-instrumentation floor rather than only counter2 syscall traffic.

The Tool implementation is shared, but backend interception boundaries are not
identical. LiteInst and e9patch report exactly the workload-body floor; KVM and
SaBRe report one additional call; ptrace and DBI report 31-32 additional
startup/lifecycle calls. The framework requires nonzero Tool output and exact
guest behavior rather than pretending those backend-specific event surfaces
are identical.

These are end-to-end wall times from one loaded host, not isolated per-syscall
latencies or confidence-bounded population estimates. Dynamic and static guest
times are never compared raw: KVM's static result is normalized to the native
static binary, while every other backend is normalized to the native dynamic
binary built from the same source and fixed iteration count.
