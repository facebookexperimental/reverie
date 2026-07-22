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

Build DynamoRIO first:

```bash
with-proxy git clone --recursive https://github.com/DynamoRIO/dynamorio.git
cmake -S dynamorio -B dynamorio/build \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DBUILD_SAMPLES=ON
cmake --build dynamorio/build --parallel
cmake --install dynamorio/build --prefix dynamorio/install
```

Then build and test the client:

```bash
DYNAMORIO_HOME=$PWD/dynamorio reverie-dbi/scripts/test-echo.sh
DYNAMORIO_HOME=$PWD/dynamorio reverie-dbi/scripts/test-cpuid.sh
```

The native client is intentionally separate from Cargo because DynamoRIO's
CMake package supplies required client linker flags. The script first builds
`libreverie_dbi.so`, then links the native client against that Rust runtime.
Per-thread tool state is allocated by DynamoRIO and stored in `drmgr` TLS. The
Rust runtime receives that state through an explicit C ABI pointer, avoiding
dynamic Rust TLS inside DynamoRIO's private loader.

## Prototype Boundaries

- `DbiGuest` implements Reverie's shared `Guest` contract, local memory,
  register reads, syscall injection, in-process global RPC, and a branch clock.
- Tail injection, stack allocation, timers, signals, clone/exec lifecycle, and
  exact post-branch threshold traps remain production-backend work.
- The process-wide branch counter is sampled at syscall boundaries, so the
  displayed total may omit branches after the process's final syscall.
- Restartable sequences are disabled in the smoke test so libc selects its
  supported fallback path.
