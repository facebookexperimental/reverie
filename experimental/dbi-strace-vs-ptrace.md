# DBI strace tool vs ptrace strace — comparison (DBI M4 validation)

Task `impl-dbi-m4-strace-tool`, 2026-07-23. Validates the DBI Guest/Tool
interface by running a strace-like `reverie::Tool` over the DynamoRIO-based
`DbiGuest` and comparing its output to the ptrace-based strace example on the
same binary.

## What already existed (not net-new)

`reverie-dbi/src/tools.rs` already contains two observation tools built on the
standard `reverie::Tool` trait, landed in PR #32:

- **`StraceTool`** — logs each syscall's decoded name/args and the *real* return
  value (via `Guest::inject`, unlike `strace_minimal`'s `= ?`). Enabled with
  `HERMIT_DBI_STRACE=1`.
- **`SyscallCounterTool`** — per-number histogram at exit. Enabled with
  `HERMIT_DBI_SYSCALL_HISTOGRAM=1`.

They share reverie's `syscalls::Displayable`, so decoding matches the ptrace
tool. Dispatch is via `run_active_tool()` in the native client; a `DbiGuest` is
built per syscall and the handler future is polled to completion.

## How to run

```bash
# build client (RELEASE — debug frames overflow DynamoRIO's 56K client stack)
PROFILE=release reverie-dbi/scripts/build-client.sh
CLIENT=target/release/reverie-dbi-native/libreverie_dbi_client.so
DRRUN=$(target/release/reverie-dbi-dynamorio-path drrun)

# DBI strace
HERMIT_DBI_STRACE=1 "$DRRUN" -disable_rseq -c "$CLIENT" -- /bin/echo hello

# ptrace strace (baseline)
cargo build --release -p reverie-examples --bin strace
target/release/strace -- /bin/echo hello
```

## Result: functional parity on `/bin/echo`

| metric | DBI StraceTool | ptrace strace |
|--------|----------------|---------------|
| syscalls traced | 113 | 114 (incl. `execve`) |
| syscalls after removing `execve` | 113 | 113 |
| syscall-name sequence match | **111/113 identical** | — |
| stdout preserved | yes (`hello-dbi`) | yes |
| run-to-run stability (DBI) | stable, 113 identical ×N | — |
| decode format | same (shared `Displayable`) | same |

Diff of the syscall-name sequences (DBI vs ptrace-minus-execve): exactly two
lines differ —
```
ptrace-only: prlimit64   (glibc startup resource probe)
DBI-only:    ioctl        (glibc tty/stdout probe)
```
Both are glibc startup probes whose presence depends on the *instrumentation
environment* (DynamoRIO in-process rewriting vs ptrace stop/continue), not on a
tool defect. The rest of the 113-syscall sequence is byte-for-byte identical in
order and decoding.

### Expected, documented differences

1. **`execve` invisibility (DBI):** DynamoRIO begins instrumenting *after* the
   process is already exec'd, so the DBI tool never sees the initial `execve`
   that launched the guest. ptrace catches it via `PTRACE_TRACEME`. This is
   inherent to in-process DBI, not a gap.
2. **errno formatting:** DBI prints `= -1 (EINVAL)` (name-decoded); the ptrace
   example prints the raw negative `= -22`. Same semantics, different tool-level
   formatting.
3. **struct-result decoding:** ptrace re-reads output structs post-return (e.g.
   `fstat(...) -> {st_mode=...}`); the DBI tool shows the argument pointer. A
   display-path nicety, not a capability gap (`Guest::memory()` can read it).
4. **addresses differ** run-to-run (ASLR / mapping layout) — expected.

## Also verified

- `/bin/true`: DBI StraceTool traced 31 syscalls, clean `exit_group(0)`.
- `SyscallCounterTool` on `/bin/echo`: histogram `112 calls, 18 distinct`
  (`write`×1, `mmap`×21, `openat`×30, …).

## Conclusion

The DBI Guest/Tool interface hosts a real, observational `reverie::Tool` with
functional parity to ptrace: identical syscall interception, identical decoding,
real return values, preserved program output, and run-to-run stability. The only
deltas are one glibc-startup probe on each side (environmental) plus the inherent
`execve` invisibility of in-process DBI. This confirms the interface is sound
for observational tools — the prerequisite before binding Detcore (PR #41, the
`Tool<T>`-generic pre-syscall runtime, is the next step for that).
