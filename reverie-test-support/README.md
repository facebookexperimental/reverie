# Generic command tests

This package registers the existing `tests/basics.rs` source. Its command
helpers delegate to ptrace's existing runtime, output capture and caller-owned
Tool configuration. The Tools live once in `tests/tool_fixtures/basics.rs`.
Inherited function tests still use the original ptrace helpers.
The test dependency enables ptrace's existing `nightly` output-capture reset,
so inherited `println!` output reaches the guest pipe under ordinary libtest
capture. The workspace's pinned nightly toolchain supplies that API.

Run the complete registered target with ordinary libtest capture:

```sh
cargo test -p reverie-test-support --test basics
```

The initial command selection is:

```sh
cargo test -p reverie-test-support --test basics -- \
  --exact noop_tool_test counter_tool_test error_exit_test \
  run_guest_command_test run_guest_command_test_closure
```

The target also discovers the other existing basics declarations; running the
five command tests does not establish those other results. Sanitizer exclusions
remain unchanged.

The optional `dbt` feature adds five `dbt_` command identities, sharing all
thirteen original command assertions. The original thirteen basics tests and
the default command helpers keep using ptrace. Their inherited-function
invocations remain ptrace-only; `run_fn_test` additionally executes its shared
Rust body as an ordinary command under the `dbt` feature.

Produce the two concrete caller artifacts before selecting DBT tests:

```sh
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/basics-noop-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/basics-counter-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
cargo test -p reverie-test-support --features dbt --test basics --test dbt_command -- \
  --test-threads=1
```

The producers must use the consumer's profile and target directory. The tests
select `reverie-dbt-callers/basics-{noop,counter}/manifest.json` beside that
profile's `deps` directory. Each thin runtime alias exports the actual shared
fixture Tool; CounterLocal's existing RPC handler updates the returned real
CounterGlobal. The explicit `test_dbt_cmd_with_config` helper preserves inherited
stdin, cwd and the application environment and captures stdout/stderr. Missing
artifacts and caller activation errors are returned without a fallback.

The `dbt_command` target contains three controls: inherited stdin plus the
unchanged null-input method's negative control; the original count oracle
against actual CounterLocal and actual Noop runtimes; and missing-manifest
refusal. The count control requires successful guest execution and rejects a
setup refusal as evidence. The caller protocol's initial-process domain still
applies; signal termination is a launch error, not supported signal-status
fidelity. These command cases do not establish raw-environment transparency,
function-guest execution, or arbitrary-program support.

## Original basic Rust command body

The existing `run_fn_test` retains its inherited ptrace invocation and all
three assertions: exit0, empty stderr, and actual returned CounterGlobal count
strictly greater than one. Its literal getpid/println/raw-write/getgid body is
also shared with a Cargo-built ordinary Rust command. With `dbt`, the same
image runs natively, through ptrace, authenticated CounterLocal, and the real
Noop caller. All existing basics and `dbt_command` tests remain; the basics
feature/default listings stay 18/13, and the support controls stay three.

Only the command wrapper adds the exact `basics-rust-body-complete\n` marker,
using one raw write after the shared body returns. Every command must exit0,
have empty stderr, and contain exactly one complete marker. A short or failed
marker write exits97, with a nonreturning trap if that exit returns. Full raw
stdout is retained; buffering order and different process IDs are not compared
or normalized. The marker witnesses return from the shared body, not a syscall
instruction trace. Startup and wrapper syscalls can contribute to the count.

Both traced CounterLocal runs must satisfy the original count oracle using the
real returned state. The authenticated Noop run must first succeed with that
same image, marker and empty stderr, return actual CounterGlobal count zero,
and then fail the unchanged positive count oracle. No state is synthesized;
this reuses the existing support control's unit-Config compatibility. Both
caller manifests are authenticated before the commands run. Setup refusal is
not a successful negative witness.

Cargo discovers `basics-rust-command-guest` only with `dbt`. The ordinary binary
uses the same libc/nix versions and features as the original tests, promoted to
normal dependencies and mirrored in BUCK. Default and Buck ptrace cases do not
need Cargo's binary-path environment variable. Rust/libc/loader startup is part
of command execution, not inherited-function execution. No Tool policy or
caller lifecycle/signal contract changes.

The existing `run_guest_func_write_test` and `run_guest_func_print_test`
also retain their inherited ptrace calls, captured `"abcd"` messages and
literal exit/stdout assertions. Their original write_all/flush and println
statements are shared with the ordinary binary. Both new shared helpers have
`cfg(not(sanitized))`, matching the original tests; the write helper imports
`std::io::Write` locally. No new lint allowance or sanitized runtime claim is
introduced.

With `dbt`, each of these same identities runs one Cargo-discovered image
natively, through ptrace CounterLocal and through the authenticated DBT
CounterLocal caller. Selector `write` must exit0 with exactly `abcd` on stdout;
`print` must exit0 with exactly `abcd\n`. Both require empty stderr, and actual
image/status/full raw streams are printed before assertions. No marker is added
to either output. Each identity also runs that same image through DBT with the
opposite selector: the real result must first pass its own byte oracle, then
be rejected by the identical selected-mode predicate. A rejection record is
printed only after those assertions. Newline bytes are never trimmed or
normalized. These are eight ordinary children inside two existing identities,
not new tests or a replacement for the inherited function calls.

Empty arguments preserve the existing `run_fn_body` command and its marker and
failure path. Exactly one `write` or `print` argument selects the corresponding
shared body. Every other argument vector is refused before a body with exit2,
empty stdout and exactly `usage: basics-rust-command-guest [write|print]\n` on
stderr. This selector/refusal behavior is new; the previous binary ignored
arguments. The direct invalid-selector control checks that refusal, not Tool
dispatch.

The two original output tests ignore returned state. This extension adds no
Counter threshold/equality or Noop rejection; existing `run_fn_test` and
support count controls remain separate. Literal output and real opposite-mode
rejection distinguish these two routes, not syscall-PC attribution, callback
multiplicity or a separately fabricated output wrapper.
Feature/default basics identities remain 18/13 and support identities three.

## Injected-exit commands

The `exit` target keeps the original ptrace function guest and adds a command
that issues `getpid` followed by `exit_group(0)`. The actual shared
`InjectExitTool` replaces `getpid` with `exit_group(42)`. Both ptrace and the
optional authenticated DBT caller must return exit42 and exactly one exit42
process-hook RPC in the real returned GlobalState. Under DBT the RPC carries
the admitted terminal request; the child wait status separately checks the
actual exit. The original function-guest invocation remains ptrace-only.

With `dbt`, the existing `smoke` identity also runs the same two-statement Rust
body in an ordinary Cargo-built command image: native, ptrace, authenticated
InjectExit, and authenticated Noop. The shared body is not reimplemented in
assembly. All runs require the exact `inject-exit-rust-body\n` stdout marker
and empty stderr. Native and Noop must exit0; ptrace and InjectExit must exit42
and satisfy the unchanged real-state oracle (one exit42 RPC, no remainder).
The Noop's real state must be empty before the same injected-exit oracle is
required to reject it. The original three smoke assertions and all existing
assembly and missing-artifact tests remain unchanged; the five/two feature and
default identities do not change.

The Rust wrapper makes one raw write immediately before calling the shared
body, with no formatting, argument parsing or other library work between.
A failed or short marker write exits97; an unexpectedly returning body exits98.
If either refusal syscall unexpectedly returns, a nonreturning x86-64 trap
fails without making another getpid call.
Missing/partial markers fail, so an early startup getpid causing exit42 cannot
masquerade as reaching the intended body. Rust/libc/loader startup is part of
this command, not inherited-function execution. This marker establishes reaching the direct-call boundary, not a separate
instruction-PC trace; lazy libc resolution inside the body is not excluded. Cargo supplies the dbt-only binary
path; default/Buck ptrace tests do not need that Cargo environment variable.
The normal libc dependency and bin metadata are mirrored in BUCK.

The command fixture embeds its assembly and writes it into a test-owned
TempDir, so it needs no Cargo-specific runtime paths. Running these command
cases requires an x86-64 Linux C toolchain selected by `CC` or `cc`, supporting
`-nostdlib -static -no-pie -Wl,-e,_start -Wl,--build-id=none`. Missing compiler
capability fails the test. Every compiled image first runs natively and must
exit0 with empty streams; the TempDir lives through the native and traced run.

```sh
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/basics-noop-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/exit-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
cargo test -p reverie-test-support --features dbt --test exit -- \
  --test-threads=1
```

The default target has two tests; `dbt` adds the actual caller positive, a real
Noop negative and a missing-manifest guard. The Noop guest must first succeed
with exit0, empty streams and no application RPCs, then fail the same exit42
oracle. That control tests the first assertion's sensitivity; it does not
independently test each later RPC assertion. The missing-manifest guard first
authenticates the valid exit pair and does not run a guest. Caller initial-process
and signal-error restrictions remain. The helper installs `reverie=trace`
logging independently of `RUST_LOG`; these tests have no local timeout.

## Stat-family commands

The `stat` target preserves the two original ptrace function tests and adds
command forms using the same `LocalState` Tool. It subscribes to all syscalls
and uses the default identical tail forwarding; these tests do not establish
stat-to-fstatat conversion or a separate reinjection mechanism.

The two original Rust bodies and raw statx helper live in
`tests/support/stat_rust_guest.rs`. Their original test identities still call
ptrace's `check_fn`. With `dbt` enabled, each identity also runs the same shared
body through the plain Rust `stat-rust-command-guest` binary: native first,
then ptrace and the authenticated DBT caller, using the same command image.
The binary accepts exactly `stat` or `statx`; it is not a libtest self-exec.
All three command runs retain their raw outputs before requiring exit0 and
empty streams. The original inode assertions and the separate C command tests
remain intact. The returned unit global state is not application-RPC evidence.

The first C guest checks that `open("/proc/self/exe", O_RDONLY)` returns a
positive descriptor, that `stat`, `lstat` and `fstat` succeed, and that the
followed inode equals the descriptor inode but differs from the symlink inode.
The second checks successful `fstatat` and raw `SYS_statx`, both with
`AT_SYMLINK_NOFOLLOW`, and equal returned inodes using `STATX_INO`.
These relations do not prove which executable `/proc/self/exe` names under
instrumentation.

The checked C sources are embedded and compiled in a test-owned TempDir using
`CC` or `cc`. They require an x86-64 Linux C toolchain and libc headers,
with assertions enabled. Dynamic loader and libc startup remain part of each
command run. Each compiled image must first run natively with exit0 and empty
streams, then satisfy the same guest assertions under ptrace or DBT with exit0
and empty streams. No inode values are compared across processes.

```sh
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/stat-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
cargo test -p reverie-test-support --features dbt --test stat -- \
  --test-threads=1
```

The default target lists four tests. The optional `dbt` feature adds two
actual-caller positives and a missing-manifest guard that first authenticates
the real stat artifact. It does not provide function-guest execution through
DBT or extend the caller's lifecycle/signal support. The default forwarding
Tool is behaviorally equivalent to Noop for these assertions, so no wrong-Tool
sensitivity is claimed. The existing helper installs `reverie=trace` logging;
these tests have no local timeout.

## vDSO commands

The original Rust `run_guest_vdso_clock_getres_test` keeps its ptrace function
invocation and shares the literal body with `vdso-rust-command-guest`. With
`dbt`, that same test also runs this ordinary Cargo-discovered image through
ptrace and the authenticated DBT caller, using the same `LocalState`. The body
starts with `(1,0)`, calls libc `clock_getres(CLOCK_MONOTONIC)`, and requires
return 0 and `(0,42)`. Each command must exit 0 with empty streams; actual status
and streams are printed before the assertions. The default and Buck function
tests do not need Cargo's binary-path environment variable.

The 42 ns result is Tool-specific; this Rust command is not a native-success
control. Existing native-first C commands and the missing-manifest guard remain
unchanged. Unit GlobalState does not provide application RPC evidence. This
checks libc-mediated original-body execution, not DBT inherited-function
support, deterministic time, exact syscall parity, or the unresolved libc/rseq
getcpu path.

The original Rust `run_guest_vdso_gettimeofday_test` likewise keeps its ptrace
function invocation and shares its literal body with the ordinary command.
The body zeroes the timeval and timezone, calls libc `gettimeofday`, and
requires return 0 and `tv_usec % 1000 == 345`. With `dbt`, that same test also
runs one Cargo-discovered image with argument `gettimeofday` through ptrace
and the authenticated DBT caller using the existing `LocalState`. The selected
command enters a fixture-only wrapper that calls the unchanged shared body and,
only after its assertions return, writes exactly
`vdso-rust-gettimeofday-complete\n`. Both runs require exit 0, that exact stdout,
and empty stderr; actual image, status and streams are printed before assertions.
The inherited function invocation still calls the original body directly.

Within the same selection, one additional real DBT command runs the same image
with empty arguments. Its clock_getres result must first satisfy the unchanged
exit 0 and empty-stream checks, then fail the identical gettimeofday result
predicate used by the two positive commands. This deterministically rejects a
passing clock_getres route substituted for the selected completion wrapper. The
marker is a post-body completion witness, not syscall-PC attribution, callback
multiplicity or wrong-Tool evidence. These are command executions within the
existing identity, without a new libtest selection or independent RPC-count
witness.

Native microseconds can also end in 345, so native or Noop failure of the Rust
gettimeofday body is not a negative control. The existing native-first C
controls and typed missing-manifest refusal remain; their results are not
substituted for execution of the original Rust body. No timestamps are
compared or normalized across processes, and no wrong-Tool sensitivity is
claimed.

The original Rust `run_guest_vdso_getcpu_test` also shares its literal body
with the ordinary command. Its inherited ptrace function still uses the
versioned entry resolved in the parent before the fork, keeping the handle
alive through the call. With `dbt`, the same identity additionally runs the
ordinary image with `getcpu` through ptrace and authenticated DBT. That command
resolves `__vdso_getcpu@LINUX_2.6` in its own address space, checks its mapping
against `AT_SYSINFO_EHDR`, and calls the shared body. The original mapping,
return-zero and CPU-zero assertions remain unchanged.

After the body returns, the wrapper writes exactly
`vdso-rust-getcpu-complete\n`. Both traced commands require exit 0, that whole
26-byte stdout and empty stderr. Actual status and streams are printed before
assertions. A real DBT child of the same image with no arguments first passes
the unchanged quiet `clock_getres` oracle, then must fail the same getcpu
output predicate. This checks body/route completion sensitivity, not callback
counts or arbitrary wrong-Tool detection. A native execution of the original
CPU-zero body can legitimately pass or fail; it is not a native success or
Noop negative control, and no affinity is forced. Existing native C controls
remain separate.

The original Rust `run_guest_vdso_tod_test` retains its broad `should_panic`
attribute and ptrace `check_fn` path. Its literal `Instant::now` body is shared
with the ordinary command, but the inherited guest still lets the unwind reach
the tracer and trigger the parent check's panic. That outer panic alone does
not identify the inner error.

The separate feature-only `rust_vdso_tod_command` runs the same Cargo image
with `tod` through ptrace and authenticated DBT. Only this ordinary fixture
temporarily silences the panic hook and catches the shared body; it restores
the prior hook before validation or output. A normal return, an unknown payload
type, or a payload other than the exact String or `&str` EINVAL panic fails.
After validation, the fixture writes the actual 109-byte caught payload,
a newline, then `vdso-rust-tod-unwind-complete\n`. Both traced children must
exit 0 with exactly those 140 stdout bytes and empty stderr. Actual image,
status and streams are recorded before assertions; an abort, signal, Tool or
launcher failure is not an accepted unwind.

The same selection then runs a real DBT child with empty arguments. It must
first pass the unchanged quiet clock_getres oracle, then fail the identical
TOD output predicate used by both positives. The rejection record follows
those assertions. This adds precise body-unwind and route evidence without
replacing the inherited expected-panic test. Native TOD execution, callback
counts and wrong-Tool sensitivity are not claimed.

The ordinary command keeps empty arguments as its quiet `clock_getres` mode
and accepts exactly one `gettimeofday`, `getcpu` or `tod` selector for the
corresponding shared body. All other argument vectors are refused before any
body with exit 2, empty stdout, and exactly
`usage: vdso-rust-command-guest [gettimeofday|getcpu|tod]\n` on stderr (57 bytes).
This argument validation is new relative to the earlier fixture that ignored
arguments. The direct `invalid` selector control checks the exact combined
refusal using the same Cargo-built image; it does not exercise a body or prove
Tool dispatch. Each accepted mode retains its own post-body marker and real
passing-clock rejection predicate.

The `vdso` target retains all four original ptrace function tests and shares
their actual `LocalState` with a command fixture. The fixture resolves the
versioned `LINUX_2.6` clock_gettime, gettimeofday, getcpu and clock_getres entries
from `linux-vdso.so.1`, and checks their mapping against `AT_SYSINFO_EHDR`.
Missing entries fail without substituting libc calls or raw syscalls.

The Tool returns EINVAL for clock_gettime, changes gettimeofday's microsecond
suffix to 345 after injection, writes CPU0, and supplies resolution `(0,42)`.
The direct-entry command checks those exact results. Direct vDSO errors use
negative errno, while the unchanged Rust Instant test still expects a panic.
Its broad `should_panic` attribute is not a precise error-cause assertion.
These tests do not compare timestamps or establish deterministic time.

The embedded C fixture requires an x86-64 Linux C toolchain selected by `CC`
or `cc`, libc headers and libdl, with assertions enabled. Its owned TempDir
lives through both runs. Each compiled image first runs natively, checking
successful calls and valid output ranges. The same image then runs through
ptrace or authenticated DBT with the Tool-specific expectations. Each mode
requires exit0 and empty streams. Native and traced values are not compared
across processes; dynamic startup remains part of each run.

```sh
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/vdso-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
cargo test -p reverie-test-support --features dbt --test vdso -- \
  --test-threads=1
```

The default target has five tests. The optional `dbt` feature adds the actual
caller command, the separate Rust TOD command and a missing-manifest guard,
for eight tests. The missing-manifest guard authenticates the valid
pair before checking refusal. Unit global state alone does not authenticate
the selected Tool. No wrong-Tool sensitivity, DBT function-guest execution,
or expanded lifecycle/signal support is claimed. The helper installs
`reverie=trace` independently of `RUST_LOG`; these tests have no local timeout.

## Returning injections followed by identical tail forwarding

The `inject_then_tail` target reuses the standalone example's actual `TestTool`
with config 3. It performs three returning injections of selected identity and
getrandom calls, then forwards the original call with `tail_inject`. The original
standalone guest body is shared unchanged with an ordinary Rust command; its
host and main bodies remain unchanged. The command runs that guest body without
using the standalone program's Tokio host entry point.

Each backend test compiles a checked C fixture using `CC` (or `cc`) in an owned
executable temporary directory, runs that same image natively first, and then
uses the actual Tool through ptrace or an explicit authenticated DBT caller.
The guest checks six identity results and an exact eight-byte getrandom result.
These C runs require exit 0, stdout `inject-then-tail=ok\n`, and empty stderr. Numeric
IDs and random bytes are not compared across processes. Image bytes are retained
before each launch; independently compiled images need not have the same hash.
A C compiler and executable temporary storage are required; there is no local
timeout in these helpers.

The existing DBT positive test also runs one Cargo-built Rust command image
natively, through ptrace, and through the authenticated DBT caller, using config
3 for both traced runs. It shares the original six ID calls, aligned allocation,
eight-byte getrandom, error and short-read checks, deallocation, and three printed
records. The original `RAND_SIZE` expression has one shared constants file inside
the caller's existing source-input root. Complete child status, stdout and stderr
are printed before checks. The Rust runs require exit 0 and the original ordered
record formats, retaining the actual IDs and random value without comparing or
normalizing them across processes. Their stderr is retained without an empty
stream requirement. No C marker or synthetic injection count replaces the Rust
body's checks.

The default target contains one ptrace test. The `dbt` feature adds the actual
caller test and a separate missing-manifest guard, for three tests total. The
real returned global state is `TestTool`. Its empty state does not authenticate
the exported Tool or independently count injections: caller source/artifact
identity and config bind the path, while the guest checks its results. Neither
Noop equivalence nor measured kernel-call multiplicity is claimed.

```sh
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/inject-then-tail-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
cargo test -p reverie-test-support --features dbt --test inject_then_tail -- \
  --test-threads=1
```

DBT keeps the existing initial-process restrictions and signal-error contract.
Buck registers the ptrace target; the optional DBT producer is explicit in the
Cargo validation and CI paths.

## AT_RANDOM through the initial post-exec hook

The `at_random` target reuses the standalone example's actual `TestTool` and
16-byte `PRNG_SEED`. Its post-exec hook writes that seed through the guest's
auxiliary vector. The original standalone guest body is shared with an ordinary
Rust command; the standalone host and main remain unchanged.

Each positive compiles the embedded C fixture with `CC` (or `cc`) in an owned,
executable temporary directory. The same image and empty argument list run
natively first, then through ptrace or the authenticated DBT caller. Every run
requires exit 0, exactly 16 stdout bytes and empty stderr. Native entropy is
unconstrained; the Tool runs compare every byte with the shared seed. The C
fixture contains no copy of the seed. Compiler output and image bytes are
retained before launch; independent compilations need not produce equal hashes.
These helpers have no local timeout.

The DBT positive also runs the same Cargo-built `at-random-rust-command-guest`
image through ptrace and the authenticated DBT caller with unit configuration.
It retains the original `getauxval(AT_RANDOM)`, 16-byte slice, both printed
records, and exact seed assertion. Each command requires exit 0, the complete
original two stdout lines, and empty stderr; raw results are printed before
assertions. The seed has one constants owner inside the caller's authenticated
input root. This Rust body is not a native-success control: unmodified native
entropy is not expected to equal the Tool's seed. The standalone Tokio host
path is preserved but is not a separate command test.

The default target has one ptrace test. Feature `dbt` adds the actual caller
positive and an independent missing-manifest guard, for three tests total.
The guard authenticates the current pair before requiring refusal. Unit global
state alone does not authenticate the selected Tool. No probabilistic Noop
negative, initial libc-canary timing, auxv-source branch or exec/re-exec support
is claimed. The existing DBT initial-process and signal-error limits remain.

```sh
reverie-dbt/scripts/build-client.sh \
  --caller-manifest tests/fixtures/at-random-dbt-runtime/Cargo.toml \
  --profile debug --jobs 4 --check
cargo test -p reverie-test-support --features dbt --test at_random -- \
  --test-threads=1
```

Buck registers the ptrace target; Cargo validation and both CI jobs explicitly
produce the DBT caller before its consumers. The maintained testing helper
installs `reverie=trace` independently of `RUST_LOG`.

## Returning thread-start injection

The `thread_start` target retains both original ptrace function tests. The
returning `thread_start_inject` Tool still injects `Getpid` during startup and
asserts that its returned PID equals `guest.pid()`. It now sends an awaited unit
RPC immediately after that assertion. A shared global Tool records a boolean,
and the test checks the actual returned global state. This is an additive test
observation, not a hook-count or Noop-sensitivity assertion.

With `dbt`, the same test also runs the ordinary `thread-start-rust-command-guest`
image natively, through ptrace, and through DBT. The command and original
function test share the empty guest body and returning Tool. Native exit zero
and empty streams only establish the command launch control; each traced run
also requires the real post-assertion RPC flag. The raw status, streams and flag
are recorded before assertions. The separate missing-manifest test requires a
real `NotFound` error. Produce the authenticated caller before selecting these
tests:

```bash
reverie-dbt/scripts/build-client.sh --caller-manifest tests/fixtures/thread-start-dbt-runtime/Cargo.toml --profile validate --jobs 4 --check
```

The alias exports the shared test Tool with its mandatory producer-supplied
input identity. Its existing `tool_fixtures` input root covers the observing
Tool; the producer authenticates the complete current dependency closure.
The registered default target has the two inherited ptrace identities and four
returning-frame controls described below (six identities). The `dbt` feature
also includes the missing-artifact control, `rust_thread_start_tail_command`
and four DBT returning-frame controls (twelve identities). The tail command uses the
original tail Tool from `tests/tool_fixtures/thread_start_tail.rs`, preserving
its `Getpid` injection and the inherited test's empty closure and exit assertion.
Its ordinary ptrace and DBT children use the same empty ELF and must exit 0 with
empty streams. The new tail alias must be produced in the consumer's profile:

```sh
reverie-dbt/scripts/build-client.sh --caller-manifest tests/fixtures/thread-start-tail-dbt-runtime/Cargo.toml --profile validate --jobs 4 --check
reverie-dbt/scripts/build-client.sh --caller-manifest tests/fixtures/thread-start-tail-witness-dbt-runtime/Cargo.toml --profile validate --jobs 4 --check
```

The separate `caller_thread_start_tail` native integration uses a fixture Tool
and authenticated fixed-entry ELF to check effect-before-continuation, actual
Getpid and write results, raw kernel errno, register/PC preservation and startup
future abandonment. A real no-effect child must first pass its own successful
frame oracle and then fail the same write-effect predicate. Copied-record
controls supplement the real children. This witness does not replace the
original ptrace test or establish inherited-function execution under DBT.
Post-exec tails and unsupported startup lifecycle effects still refuse.

The returning-frame controls use the same additive witness Tool with `/bin/true`
through ptrace and the actual DBT caller. They require the real Getpid result,
handled Close(-1)/EBADF, and equality of all 27 Guest register fields immediately
before and after each call. A sequence explicitly changes RAX between calls,
then checks that the next call restores that new entry frame. The startup and
post_exec sequences each inject one Write of `T`, require exit 0, exactly that
one output byte and empty stderr, and run a successful NoEffect child that must
fail the same effect predicate. Their temporary byte is saved/restored below
the x86-64 red zone with readback checks. Raw streams, results and frames precede
assertions. The original Tool/body and all legacy tail modes remain unchanged.

The failing-first ptrace baseline retained the correct Getpid and EBADF results
while observing RAX change from 0 to the PID and from 0 to -9 respectively; the
other 26 fields were equal. The EBADF child exited 1 before post_exec, so it did
not establish a successful ordinary launch. The fix applies to public returning
injections without a pending syscall, outside direct/held signal callbacks and
injected-frame ownership. It also covers later calls after a syscall callback
consumes its pending event. On x86-64 the saved computational/control fields are
restored while actual post-call `fs_base`, `gs_base`, `cs`, `ss`, `ds`, `es`, `fs`
and `gs` are retained. These three witness syscalls do not change those fields;
their 27-field equality checks have no exclusions. A local control forces all
eight post-call fields to differ, preserving effects such as ARCH_SET_FS/GS.

Restoration uses the actual stopped completion and returns the kernel result
separately; a saved frame is not stop authority. Tail/private defaults and
signal/frame/restart precedence remain unchanged. This does not repair the
NewChild parent-RAX path, the separate Event::Syscall no-restore arm, injected
rt_sigreturn, direct-signal #892 or held restart-block #845 behavior. General
restart-block and SIGSYS-frame equivalence remain unqualified. Timer, CPUID and
preinit/vDSO callers use the public route, but routing checks do not establish
independent runtime coverage of each callback. The new controls depend on the
queued, unlanded thread-start-tail slice (dh-72uih); neither source registration
nor these predicates establish landing or whole-backend contract completion.

## Guarded stack allocations through the shared Tool

The `stack` target registers all three original ptrace identities in both default
and `dbt` modes. `tests::stack_two_allocs_good` shares its original raw
`exit_group(0)` guest and `LocalState3` with an ordinary Rust command image.
The Tool preserves both scoped stack guards and the exact write/read assertions
for 3333 and 4444. Only after both scopes have ended, before the existing terminal
exit injection, it sends an awaited unit RPC. A shared test-only GlobalTool records
that message in a default-false `AtomicBool`. The original function test and the
ptrace/DBT command runs check the actual returned flag; this is an additive Tool
observation, not an unchanged-Tool claim. The same native image is an exit-zero,
empty-stream launch control without a Tool receipt. Raw command output, status
and returned flag are printed before assertions.

The default target has three tests; feature `dbt` adds an independent typed
missing-manifest guard, for four. The good identity additionally runs native,
ptrace and authenticated DBT commands. The other two original Tools, guest bodies
and the broad `#[should_panic]` predicate remain unchanged and ptrace-only.
Focused validation must retain the bad case's raw panic and require the intended
live-guard checkout invariant from `reverie-ptrace/src/stack.rs`, rather than
accepting an unrelated setup panic as the negative control.

This tests Tool-accessible scratch memory while each guard is alive. It does not
establish application stack layout, kernel pointer marshalling, exact hook counts,
Noop sensitivity or general Stack parity. The allocator sibling drops guards
before using addresses, while DBT guards own their arena. The bad sibling expects
ptrace's single-live-checkout invariant; DBT uses independent arenas. Neither is
ported to DBT here.

## Original Rust Tgkill suppression guest

The `suppression` target retains `tests::suppress_tgkill`: raw PID/TID reads,
100 `tgkill(SIGTERM)` calls and an exact `Ok(0)` assertion for every call. Its
shared Tool intentionally adds one awaited unit RPC before each suppressed
answer. The original ptrace function route and the ordinary Rust command routes
check the actual returned global count is 100. The function helper also retains
its exit-zero check; only the command helpers expose raw child streams.

With the `dbt` feature, the same Cargo ordinary image runs under ptrace and the
`suppression-tgkill` caller. The positive expectation remains exit zero, empty
child streams and count 100. The same original test runs without the feature
under ptrace. A separate missing-manifest test requires a typed NotFound error;
an authenticated basics Noop caller must refuse the same image with actual
child status 101 and the exact Tgkill tail-injection diagnostic. Failed-launch
capture retains actual optional status and streams without inventing state.
The feature/default listings contain three/one identities. The original
SIGTERM guest is not an ordinary native-success control.

The count witnesses Tool/RPC participation; it alone does not prove absence of
native signal effects. The selected Tool may complete a Tgkill answer, while
unselected forwarding, returning Tgkill injection and tail/deferred Tgkill
remain refused. **Original Tgkill rewritten to any nonterminal deferred call,
even an otherwise safe call, is also unsupported.** The early caller guard
runs before protected-descriptor rewrites can execute. Supported independent
returning injections followed by suppression and existing admitted terminal
owners retain their behavior. This is suppression conformance, not general
signal or full ptrace parity; no signal validation/delivery policy is added.
Synthetic caller tests distinguish guest-operation effects from real RPC I/O,
and source guards bind the native action boundaries. These controls do not
claim a physical signal-delivery or pending-signal measurement.

The caller artifact is produced with
`reverie-dbt/scripts/build-client.sh --caller-manifest tests/fixtures/suppression-dbt-runtime/Cargo.toml --profile debug --jobs 8 --check`
before its feature tests, matching `validate.sh` and both CI jobs.

The wrong-Tool control additionally requires the maintained
`tests/fixtures/basics-noop-dbt-runtime/Cargo.toml` producer, already included in
those validation routes. Both helpers explicitly install `reverie=trace` even
when `RUST_LOG` is unset. Focused validate-profile evidence does not establish
full workspace validation, CI or debug-profile route execution.

### Initial-image stack observation

`initial_stack_pointer` shares the original ptrace test's argc/argv/NULL memory
reads and success predicates. Its collection is explicitly adapted to awaited
typed RPC; the original `reverie-ptrace/tests/initial_stack_pointer.rs` remains
the unchanged reference. The default support context has one ptrace test; the
`dbt` context additionally has a real DBT positive and a successful reversed-argv
run rejected by the same positive predicate. These are source registrations,
not measured results or full image-lifecycle coverage.

Before DBT consumers, produce the explicit caller pair with
`reverie-dbt/scripts/build-client.sh --caller-manifest tests/fixtures/initial-stack-dbt-runtime/Cargo.toml --profile debug --jobs 4 --check`.
The caller reports only an authenticated first-block application RSP retained
on its initial-image owner. Late or missing observations return `None`; copied
processes and successor exec remain outside the caller's admitted domain. This
does not complete each-exec/fork initial-stack semantics or the generic state
suite's 21-thread contract, and it provides no Detcore assurance claim.
