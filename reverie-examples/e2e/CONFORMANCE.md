# Cross-backend conformance

The same example `Tool`s run the same programs on every first-party backend
through the shared runner (`../backend.rs`), and their observations are
checked against each other and against native Linux. A backend only
intercepts and injects, so a difference a program or a tool can observe is a
backend defect unless it is written down here or in an expected-mismatch
ledger with its issue.

## Combinations

Backends are the shared runner's `BackendKind` values:

- `ptrace`: the tool runs in the tracer.
- `kvm`: the program runs in a KVM guest, the tool in the host. The guest's
  Linux personality is an internal part of this backend; it is not a
  separate backend and has no separate conformance column.
- `liteinst`: the tool runs in the program through a preload, with syscall
  site patching on.
- `in-guest-trap`: the same preload hosting with site patching off, so every
  syscall traps. It is the reference for the patching mode: patching may
  change how a syscall reaches the tool, never what the tool observes.

No page-fault trapping mode is selectable today, so this matrix names a
page-fault gate as absent, not as skipped; when such a mode becomes
a `BackendKind` it joins this matrix like any other backend.

External backends hosted by extension repositories reuse the recorder
comparator from their own entries (see `README.md`); they are outside this
repository's matrix.

Candidate tools are the example tools whose launchers accept `--backend`:
the pass-through `recorder`, `counter1`, `counter2`, `strace_minimal`,
`noop`, `chaos`, `strace`, `chunky_print`, and `chrome_trace`. The `debug`
tool is excluded: its protocol needs an external controller by design.
Only some rows are enforced today: the recorder in the judged e2e run,
and `counter1`, `strace_minimal`, and `noop` in `cargo test`. The remaining
oracles below are designs for later rows, marked as not yet enforced.

## Oracles

Native equality of the raw syscall stream is the recorder's oracle. Other
tools are checked against the recorder's record for the same backend and
program, because in-guest tools start at their preload's constructor (after
the dynamic loader's calls, and again after each `execve`), so they
legitimately observe a suffix of the native stream. The recorder's
comparable record also omits the calls the vDSO normally answers in the
process (`clock_gettime`, `clock_getres`, `gettimeofday`, `time`, `getcpu`),
which a backend may turn into syscalls a tool can see.

- **recorder** (in `run.sh` today): exit code, thread count, and each
  thread's syscalls with their results match a native baseline run twice,
  exactly, or after the late-start alignment for in-guest backends. Known
  mismatches are ledger rows; a stale row fails.
- **counter1** (enforced in `cargo test`): the reported total equals the
  recorder's call count for the same run plus the vDSO calls the record
  omits. The program's stdout and exit status are its own.
- **counter2** (designed, not yet enforced): the same counting oracle,
  plus its process and thread totals matching the record's thread
  structure.
- **strace_minimal**: with the vDSO calls removed, its printed call-name
  sequence equals the recorder's. One named exception: an in-guest tool
  prints through the guest's own stderr, so a print for a final call made
  after the guest closed stderr (for example `/bin/echo` closes descriptors
  1 and 2 before `exit_group`) has nowhere to go. Tools that must not lose
  terminal events report through tool RPC, as the recorder and counters do.
- **noop**: subscribes to nothing, so it is a transparency bound: stdout,
  stderr, and exit status are the program's own on every backend.
- **chaos** (designed, not yet enforced): this tool mutates results on
  purpose (short reads, injected `EINTR`), so stream equality does not
  apply. Its oracle is a property: the program still produces its correct
  output and exit status, and every read the tool clipped returns at most
  one byte, on every backend.
- **strace**, **chunky_print**, **chrome_trace** (not yet in the matrix):
  their outputs need normalization first (decoded arguments and addresses,
  output ordering under concurrency, trace timestamps), so no oracle is
  enforced for them yet.

A backend that cannot host a tool or a program must refuse by name
(`REFUSED:`), never fail silently or pass vacuously. A refusal is its own
scorecard verdict, separate from a mismatch.

## Corpus

`corpus.tsv` is the base corpus for the recorder: single-threaded system
programs, shell fork/exec and pipes, and interpreter startups. Each program
must first agree with itself in two native runs or it has no baseline.

Still missing, in order: a multi-threaded program, a signal-handling
program, a program whose exit closes its standard streams (covered by
`echo` above only as a tool-output case), a statically linked program
(expected result: the in-guest backends refuse by name, since a preload
needs a dynamic loader), and a program exercising the intercepted
instruction events (`cpuid`, `rdtsc`). Compiled fixture programs for these
belong beside the existing fixture guests, built by the run that needs
them.

## Where each check runs

- `cargo test` runs the environment-independent part
  (`../tests/recorder.rs`, `../tests/conformance.rs`): a few stable
  programs, every backend this host has, no ledger.
- `run.sh` runs the full recorder corpus against the ledger for this
  host's environment; `validate.sh` and CI call it. Its output is the
  conformance scorecard for the recorder row: per backend, counts of
  `match`, `mismatch` (ledgered or unexpected), `refused`, and
  `no_result` over the corpus.
- The LiteInst allocator-fixture producer
  (`scripts/build-liteinst-test-runtime.rs --for-ci`) is part of
  conformance, not a local side step: it qualifies the compiled fixture
  cohort the in-guest tests then consume. `cargo test -p
  reverie-liteinst-artifact` is NOT a substitute for the producer: unit
  tests use synthetic witnesses and cannot catch producer/cohort drift in
  real compiled bodies. The producer therefore also runs in CI on the
  pinned toolchain, including for bot-authored changes, reporting red or
  green truthfully as best-effort signal. CI is never the merge gate: the
  gate is local validation (`validate.sh` hard-fails on a producer
  refusal) and its validation ledger. The ledger's consumer should treat
  a missing or failing producer row for a main head as a red main, not a
  skip; that alert lives outside this repository.
- Extending the judged corpus run from the recorder to the counting and
  printing tools above is the next step after the cargo-test oracles: the
  comparator gains a tool dimension and the ledger a tool column, so a
  known difference names its tool, cell, backend, and issue.
