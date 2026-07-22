# Reverie DynamoRIO Backend Prototype

This crate is an x86-64 Linux prototype of an in-process Reverie backend. Its
native DynamoRIO client:

- inserts an atomic 64-bit counter update before every application branch via
  DynamoRIO's `drx` instruction-rewriting helper;
- replaces application `CPUID` instructions with Hermit's deterministic CPU
  identity, masking RDRAND, RDSEED, TSX, and AVX-512 features;
- receives all application syscall entry events without ptrace;
- forwards `write` to a Rust `PrototypeTool`, which executes it through
  `Guest::inject`, returns its result, and suppresses the original syscall; and
- reports process totals when the application exits.

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
- Restartable sequences are disabled in the smoke test so libc selects its
  supported fallback path.
