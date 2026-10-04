# KVM baseline process execution and random-stream repair

Base: `96598dc07490ec15411845d27ed5bfd5c0a34076` (tree
`685b7f660f65b4d3679ac648d94ff8c67470de5a`). Work was isolated in the registered
`kvm-baseline-failures-20260924` slot on devbig014. This report records bounded
diagnostics; canonical full-workspace qualification and independent review are
separate requirements before landing.

## Defects and repair

The direct ELF runner entered a second futures LocalPool when an inline fork
child performed another process action. The unchanged
`static_elf_forks_execs_and_waits_for_child` test reproduced its EnterError on
the untouched base. Inline descendants now await the same async driver. The
synchronous boundary first polls a borrowed pin and retains that same future
if it needs a blocking executor. This preserves ready-only synchronous calls
inside an existing executor; it does not promise nested blocking-executor
support. Guest execution stays on its existing host thread.

The unchanged
`leader_exit::panicked_worker_interrupts_natural_join_without_losing_panic`
also failed on the base. A caught worker execution panic was classified as
ordinary callback cleanup, logged again, and sent through its own consuming
exit hook. The repair distinguishes local worker execution panics from
transferred payloads, ordinary errors, and consuming-hook panics. It preserves
the original payload and typed primary cause, bypasses only the panicked
worker's own hook, and still consumes independently retained children and
other workers. Destructors are caught separately. Late deferred worker panics
notify the natural-join failure protocol before resuming the original payload.
The Tool API explicitly permits panic unwinding to bypass exit hooks.

GCC's temporary-file retry loop exposed a third baseline defect: every
`getrandom` call restarted the same thread's bytes. The installed glibc's
eight-byte refills eventually cycled through five six-character suffixes.
All five predicted `/tmp/cc*.s` files existed before this task. They were not
deleted or modified to make the test pass. An independent source/binary audit
and a bounded Tool trace establish this mechanism.

`getrandom` now advances a private byte position. Equal fresh seed/TID states
reproduce equal streams, request partitioning preserves the byte sequence,
new fork/thread identities start their own streams, and exec preserves the
same task's position. Seed-zero output retains the original first 256 bytes;
later blocks use a separately mixed salt. Successful copyout commits the
cursor. Existing rejected requests and zero-length requests do not advance it;
exhaustion returns EOVERFLOW rather than silently repeating the stream.

## Evidence and goalposts

The original fork/exec, register/FPU preservation, leader-exit event vectors,
panic count, failure text, and cleanup assertions were retained. The original
direct GCC test and its exit-status/object-existence requirements remain.
An existing entry-owner test only gained the no-op argument required by the
extended cleanup helper. Serde is a development dependency for the added
destructor-observation state.

One existing getrandom test has a deliberate semantic correction: its equality
assertion now compares two fresh equal states, rather than requiring two
consecutive calls in one state to repeat. Retaining the assertion's spelling
does not by itself establish unchanged evidence. The former requirement caused
the GCC retry defect. Six new controls require progress across 128 eight-byte
refills, the original initial-byte oracle, exact request-partition equivalence,
seed/TID separation, fork/thread independence, exec continuation, and unchanged
failure/size/cursor boundaries. Review must assess this changed requirement
explicitly.

Nine additional panic/cleanup controls check primary-error and payload identity,
drop counts, transferred versus local panics, configuration destruction, and
both orders of failure versus natural join. A new integration case preserves
both ready-only synchronous APIs inside an outer executor. Another compiles
the same GCC input natively and through StraceTool with the same environment
and flags, then compares stdout, stderr, and object bytes exactly.

## Bounded run history

All runs used the published parent tool revision
`abe1c60609fb49140ef050675646f0cf66e2f74e`, supported agent-tool/dagrun admission,
active cgroups, required KVM, four Cargo jobs, and one libtest thread. No
test inventory, ignore, comparator, assertion tolerance, or validation gate was
relaxed. Logs and failed attempts remain under the slot's
`target/coordinator-20260924/` evidence directory.

* `baseline-repro`: both exact original regressions failed on the untouched
  base; DAG duration 52.4 seconds. Neither case was skipped.
* `repaired-kvm-suite` (candidate v2): library compilation failed before tests
  because a test dependency and one helper argument were missing. Integration
  ran all 342 cases: 341 passed and direct GCC failed with exit 134 and
  `Cannot create temporary file in /tmp/: File exists`. Both original
  regressions and the new executor-compatibility case passed.
* `repaired-kvm-lib-gcc-v3`: all 826 library cases passed after the compile
  repairs. The new GCC comparison failed after native compilation succeeded.
  Its Tool trace retained 135,637 getrandom calls and repeated EEXIST results.
  Stderr exceeded its 32 MiB cap: 1,822,485 bytes were dropped, including the
  final assertion text. This is explicitly incomplete trace evidence.
* `repaired-kvm-full-v4`: all 832 library and all 343 integration cases passed,
  with zero failures, ignores, or filtered cases at each top-level target.
  Both GCC tests passed. Library test time was 32.71 seconds; integration test
  time was 68.48 seconds; the complete DAG took 150.4 seconds. No timeout, OOM,
  or log truncation occurred. The 23 subprocess-fixture summaries are internal
  executions and are not added to the top-level case counts.

The full KVM commands were:

```text
cargo test -j 4 -p reverie-kvm --all-features --lib -- --test-threads=1
cargo test -j 4 -p reverie-kvm --all-features --test static_elf -- --test-threads=1
```

V4 used a 1,800-second whole-run bound, 900-second node bounds, 8 GiB admitted
memory with 6 GiB node bounds, and 32 MiB per node stream. Its eleven-file
source manifest SHA256 is
`f959ddf4f30c4967b593b8c2670966e03d4f1e26768ea19d6b0c7fb507285b50`;
the complete code/test patch artifact SHA256 is
`e21aa4b4eba5a8c4ec68434dd0b53e23056bde54e972525723b454ff023f0287`.
All source, diff, and Cargo.lock identities remained unchanged during that run.
This report was added afterward; it does not claim canonical qualification.

## Scope limits

This repairs progress in the existing deterministic random model. It does not
provide unpredictable CSPRNG output. Existing getrandom limitations remain:
ignored flags, E2BIG above 16 MiB, whole-buffer accessible-range validation
rather than Linux partial copyout, incomplete guest writable-permission
enforcement, and the existing zero-length pointer behavior. Virtual random
devices retain their separate existing behavior. No claim of complete Linux
randomness, backend parity, or record/replay qualification follows from these
KVM diagnostics.

Independent baseline/primary-source reports were preserved with SHA256:

* Lifecycle contracts: `d8fe723a63e643232bb0d0147d385389f9f2f03bafbbe9b1b5a46af8d328911f`.
* Rust/Linux/POSIX sources: `86397cf4cdaef757830699756c206e098c11f2089ec8b460971cbdcf92848fa8`.
* GCC/glibc collision audit: `0a3e67bffac95165e72f720dec06f813774c00bf0011304102755007c62d4693`.
* Randomness semantics: `008d21d1cc30023a99537bf15979a9dd40881d3ebcb111e5976f1e61c5671a25`.
