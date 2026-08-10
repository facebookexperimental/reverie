# Reverie DynamoRIO Backend Prototype

This crate is an x86-64 Linux prototype of an in-process Reverie backend. Its
native DynamoRIO client:

- inserts an atomic 64-bit counter update before every application branch via
  DynamoRIO's `drx` instruction-rewriting helper;
- replaces application `CPUID` instructions with Hermit's deterministic CPU
  identity, masking RDRAND, RDSEED, TSX, and AVX-512 features;
- receives all application syscall entry events without ptrace;
- rewrites every host-derived `uname` field (including `nodename` and `version`)
  and zero-port `bind` calls with Hermit's deterministic values;
- disables guest ASLR so non-fixed mappings remain stable;
- substitutes minimal stable snapshots for volatile `/proc` views;
- derives `getrandom` and random-device bytes from Hermit's configured RNG seed
  using a layout-independent stream (indexed by seed and position, not by the
  destination address), and follows random descriptors across the `read`/`pread`/
  `readv`/`preadv` family and `dup`/`fcntl(F_DUPFD)` duplication;
- virtualizes `getrusage` and `sysinfo` process metadata;
- routes `open`/`openat`/`creat`, `read`/`write`/`close`, the legacy and modern
  stat variants, `lseek`, and `access`/`faccessat`/`faccessat2` through the Rust
  `PrototypeTool` and `Guest::inject`, returning the injected result while
  suppressing the original syscall;
- launches shebang programs through their interpreter while preserving the exact
  guest environment; and
- optionally reports process totals when the application exits.

## Build

DynamoRIO's build-required source is vendored in this crate at the pinned
revision recorded in `vendor/dynamorio/REVISION`. Build normally:

```bash
cargo build -p reverie-dbt
```

Cargo configures and builds the pinned source in a temporary directory beside
the package `OUT_DIR`, then atomically publishes a content-addressed install in
the Cargo target profile. Distinct package fingerprints (such as `cargo build`
and `cargo doc`) reuse that immutable install; it never mutates its source
checkout and does not fetch a runtime or source bundle. No external SDK or
`DYNAMORIO_HOME` is used. The vendored tree is
pruned to DynamoRIO core, deployment tools, build support, and the five
extensions used by the native client (`drcontainers`, `drmgr`, `drreg`, `drwrap`,
and `drx`).

The first build compiles DynamoRIO with its tests, samples, and documentation
disabled. Cargo reuses that install until the build script, build tool recipe,
or pinned source changes. Concurrent first builds publish by atomic rename, so
no consumer can observe or overwrite a partial install.

Clean CI builds enforce a concurrency-normalized source-build ratchet. Three
clean builds measured on 2026-08-03 were 13.91s and 14.54s with 16 jobs on
devbig014 and 71.49s with 4 jobs on a GitHub-hosted runner (`n=3`). Their
elapsed-seconds times requested-jobs proxies were 222.56, 232.64, and 285.96
job-seconds. CI rejects a value above 572 job-seconds, twice the slowest
observation rounded up. This is a build-throughput regression guard, not a CPU
time measurement or an ETA. Set `REVERIE_DBT_MAX_BUILD_SECONDS` to enforce an
explicit wall-time limit on a controlled machine; local builds otherwise report
actual duration without enforcing a machine-independent wall-time guess.

Run the native client smoke tests directly:

```bash
reverie-dbt/scripts/test-echo.sh
reverie-dbt/scripts/test-cpuid.sh
```

Set `REVERIE_DBT_SUMMARY=1` when using `DbtRunner` to print branch and syscall
totals. The summary is opt-in because its branch count is diagnostic and can
vary between otherwise equivalent runs.

The Rust runtime and native client still have two link phases. Cargo first
builds DynamoRIO and `libreverie_dbt.so`; `build-client.sh` then asks the
Cargo-built path helper for `DynamoRIOConfig.cmake` and links the native client
against that Rust runtime. This ordering is required because Cargo build scripts
run before their package's Rust library exists. Per-thread tool state is
allocated by DynamoRIO and stored in `drmgr` TLS. The Rust runtime receives
that state through an explicit C ABI pointer, avoiding dynamic Rust TLS inside
DynamoRIO's private loader.

## Prototype Boundaries

- `DbtGuest` implements Reverie's shared `Guest` contract, local memory,
  register reads, syscall injection, in-process global RPC, and a branch clock.
- Tail injection, stack allocation, timers, signals, clone/exec lifecycle, and
  exact post-branch threshold traps remain production-backend work.
- The process-wide branch counter is sampled at syscall boundaries, so the
  displayed total may omit branches after the process's final syscall.
- The synthetic `/proc` snapshots expose only the stable fields needed by the
  current deterministic policy; they are not complete Linux procfs emulation.
- Restartable sequences are disabled in the smoke test so libc selects its
  supported fallback path.

## Third-party licenses

Building this crate compiles the curated DynamoRIO source and links the host's
build prerequisites. The vendored copyright, license, and acknowledgement files
are included under `vendor/dynamorio`; see those files and the repository
[`NOTICE`](../NOTICE) for attribution and distribution obligations.
