# Cross-backend end-to-end check

One set of Reverie tools runs the same programs on every backend through
Reverie's public entry points, and the results are compared with native
Linux. A backend only intercepts and injects, so every difference is a backend
defect: it must be a row of the expected-mismatch ledger, naming its issue, or
the check fails. A row that no longer describes what a backend does fails too.

Run it with `run.sh` (Reverie's `validate.sh` does, and so does Reverie CI).
It builds what each requested first-party backend needs, refuses by name a
backend whose inputs the host lacks (including `/dev/kvm`), and runs the
comparator against the ledger for this host's environment. Its backend set is
`ptrace,kvm,liteinst,in-guest-trap`.

- `../recorder.rs` (binary `recorder`): runs a program under the pass-through
  recorder (`../recorder_tool.rs`) on `--backend native|ptrace|kvm|liteinst|
  in-guest-trap` and writes each syscall with its result.
  `native` observes the program with plain ptrace syscall stops, with no
  Reverie. The in-guest backends (LiteInst and in-guest-trap) host the
  recorder in the example preload, `libreverie_examples.so`, which selects it
  by name. A backend that cannot run the tool refuses by name (`REFUSED:`).
- `../backend.rs`: the run-time backend selector the tools share.
- `run.sh`: the entry point; `run.sh --help` lists its options.
- `compare.rs` (binary `reverie-e2e-compare`): runs each program of
  `corpus.tsv` natively twice (an unstable native baseline is its own
  verdict) and on each backend, compares call by call, and checks every
  verdict other than `match` against the ledger. An in-guest tool starts at its preload's
  constructor, after the loader's calls, at the start and after each
  `execve`, and DBT's and SaBRe's start late in the same way: for those
  backends the comparator first moves the native record to where the
  backend's next calls appear by name, then compares exactly. Every run,
  native or on a backend, gets `LC_ALL=C` whatever the host's locale (see
  "Locale" below).

## Locale

A program's `/proc/self/maps` lists each of its mappings on one line, and a
read of it returns whole lines up to one page; awk and grep read it at
startup (libsigsegv). In a UTF-8 locale glibc maps locale files
(`gconv-modules.cache`, `SYS_LC_MESSAGES`), and whether they land in the hole
the loader leaves after unmapping `/etc/ld.so.cache` depends on that cache's
size in pages. So the native byte counts, and their difference from a
backend that adds mappings of its own (reverie-ptrace lists two private pages
first), moved whenever a rewrite of the host's cache changed its size in
pages. In the C locale glibc maps no locale file, so the comparator gives
every run `LC_ALL=C`. The counts still follow the libraries a program maps
and the kernel's special mappings, which belong to the environment a ledger
is measured for. The host's locale also reached other rows: under a UTF-8
locale the shell and env look up locale files, which moved the in-guest
backends' first differences for sh and python3. The pin costs coverage: the
corpus no longer exercises locale-file loading (the lookups of locale files,
their small mappings and the shared mapping of `gconv-modules.cache`),
although no verdict depended on it, since all 92 cell and backend verdicts
were the same under en_US.UTF-8 and C when the pin was introduced.

## External backends

[hermit-dynamorio](https://github.com/rrnewton/hermit-dynamorio) and
[hermit-3rdparty-patching](https://github.com/rrnewton/hermit-3rdparty-patching)
own the DynamoRIO and SaBRe/e9patch recorders, physical prerequisites and
backend ledger rows. Their E2E entries require explicit `--core-comparator`
and `--core-e2e-dir` inputs, and reuse this comparator and corpus. The legacy
`dbt` and renamed `dynamorio` identities retain the same late-start alignment
as SaBRe; the 300-second timeout and eight-call alignment are unchanged.
Moving a ledger row is not a new execution or a passing qualification.

A ledger row records a program's first difference, which depends on the
host's libraries and tools (glibc's loader, coreutils, `/proc`). So a ledger
belongs to one environment: `ledgers/<os id>-<os version>-glibc<version>.tsv`,
which `run.sh` picks from `/etc/os-release` and `getconf GNU_LIBC_VERSION`
(or `--environment NAME`). With no ledger for the environment nothing can be
judged, so `run.sh` fails by name (`NO LEDGER`) before it builds anything;
only an explicit `--report-only` reports the verdicts without judging them,
or `--report-only-if-no-ledger`, which judges where the environment has a
ledger and reports where it has none (the rule `run.sh` had before it failed
closed; the self-hosted `hardware` CI job uses it).
To add an environment, run `run.sh --report-only --write-ledger FILE` there
twice, check that the rows agree, and commit them under `ledgers/` with a
comment naming each group's defect. `--require-compared LIST` also requires
every corpus cell to be compared (`match` or `mismatch`) on each listed
backend: a refusal, a failed run or an unstable native baseline fails the
run, with or without a ledger.

| Ledger for the environment | `--report-only` | `--write-ledger` | What runs | Exit |
|---|---|---|---|---|
| present | no | no | judged | the comparator's: 0 only if every verdict is in the ledger and no row is stale |
| present | no | yes | judged; rows written | the comparator's |
| present | yes | no | reported | 0 |
| present | yes | yes | reported; rows written | 0 |
| absent | no | no | nothing: `NO LEDGER`, before the build | 1 |
| absent | no | yes | measured in report mode; rows written; then `NO LEDGER` | 1 |
| absent | yes | no | reported (`NO LEDGER ...: report only, by request`) | 0 |
| absent | yes | yes | reported; rows written (the measurement form) | 0 |

`--report-only-if-no-ledger` without `--report-only` leaves every `present`
row above as it is, and makes the `absent` rows report only:

| Ledger for the environment | `--write-ledger` | What runs | Exit |
|---|---|---|---|
| present | no | judged | the comparator's |
| present | yes | judged; rows written | the comparator's |
| absent | no | reported (`NO LEDGER ...: report only, --report-only-if-no-ledger`) | 0 |
| absent | yes | reported; rows written | 0 |

In every row a usage or build error exits 2, and a `--require-compared` gap
exits 1. A backend this host refuses is named (`REFUSED`). If no requested
backend can run, the run exits 1 by name ("no requested backend can run on
this host"); otherwise a refused backend listed in `--require-compared`
fails the run by name (`COVERAGE`). Either way this happens before the
comparator runs, so no rows are written and no `NO LEDGER` line follows.
An empty item in
`--require-compared` (a leading, trailing or doubled comma) is a usage
error. `cargo test` runs the environment-independent part
(`../tests/recorder.rs`, `../tests/conformance.rs`) and this directory's own
tests (`../tests/e2e_run_ledger.rs` for `run.sh`'s decision above,
`../tests/e2e_compare_coverage.rs` for the comparator's
`--require-compared`). `CONFORMANCE.md` defines the tool-by-backend matrix
and each tool's oracle beyond the recorder row this directory judges today.

```text
reverie-examples/e2e/run.sh                      # every backend this host has
reverie-examples/e2e/run.sh --backends kvm
reverie-examples/e2e/run.sh --report-only --write-ledger /tmp/ledger.tsv
```
