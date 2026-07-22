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
- forwards `write` to a Rust `PrototypeTool`, which executes it through
  `Guest::inject`, returns its result, and suppresses the original syscall;
- launches shebang programs through their interpreter while preserving the exact
  guest environment; and
- optionally reports process totals when the application exits.

## Build

DynamoRIO is pinned as a recursive git submodule. Clone Reverie with submodules,
or initialize them in an existing checkout:

```bash
git clone --recurse-submodules https://github.com/rrnewton/reverie.git
# Existing checkout:
git submodule update --init --recursive
```

A normal package build configures, builds, and installs the pinned DynamoRIO
source automatically. No external SDK or `DYNAMORIO_HOME` is used:

```bash
cargo build -p reverie-dbi
```

The first build compiles DynamoRIO in Cargo's package `OUT_DIR` with its tests,
samples, and documentation disabled. Cargo reuses that install until the build
script or pinned submodule revision changes.

Run the native client smoke tests directly:

```bash
reverie-dbi/scripts/test-echo.sh
reverie-dbi/scripts/test-cpuid.sh
```

Set `REVERIE_DBI_SUMMARY=1` when using `DbiRunner` to print branch and syscall
totals. The summary is opt-in because its branch count is diagnostic and can
vary between otherwise equivalent runs.

The Rust runtime and native client still have two link phases. Cargo first
builds DynamoRIO and `libreverie_dbi.so`; `build-client.sh` then asks the
Cargo-built path helper for `DynamoRIOConfig.cmake` and links the native client
against that Rust runtime. This ordering is required because Cargo build scripts
run before their package's Rust library exists. Per-thread tool state is
allocated by DynamoRIO and stored in `drmgr` TLS. The Rust runtime receives
that state through an explicit C ABI pointer, avoiding dynamic Rust TLS inside
DynamoRIO's private loader.

## Prototype Boundaries

- `DbiGuest` implements Reverie's shared `Guest` contract, local memory,
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

Building this crate compiles DynamoRIO and the projects it vendors (elfutils,
libipt, zlib). DynamoRIO is BSD-3-Clause but its extensions/tools include
LGPL-licensed components (and elfutils is LGPL/GPL). See the [`NOTICE`](../NOTICE)
file at the repository root for attribution and the distribution obligations
that apply to binaries produced from this build.
