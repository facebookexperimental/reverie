# Cross-backend end-to-end check

One set of Reverie tools runs the same programs on every backend through
Reverie's public entry points, and the results are compared with native
Linux. A backend only intercepts and injects, so every difference is a backend
defect: it must be a row of the expected-mismatch ledger, naming its issue, or
the check fails. A row that no longer describes what a backend does fails too.

Run it with `run.sh` (Reverie's `validate.sh` does, and so does Reverie CI).
It builds what each requested backend needs, refuses by name a backend whose
inputs the host lacks (`/dev/kvm`; cmake and the vendored DynamoRIO source;
the SaBRe loader), and runs the comparator against the ledger for this host's
environment.

- `../recorder.rs` (binary `recorder`): runs a program under the pass-through
  recorder (`../recorder_tool.rs`) on `--backend native|ptrace|kvm|liteinst|
  in-guest-trap|e9patch|dbt|sabre` and writes each syscall with its result.
  `native` observes the program with plain ptrace syscall stops, with no
  Reverie. The in-guest backends (LiteInst, in-guest-trap, e9patch) host the
  recorder in the example preload, `libreverie_examples.so`, which selects it
  by name. DBT hosts it in reverie-dbt's prototype runtime and needs the
  DynamoRIO client (`reverie-dbt/scripts/build-client.sh`, found beside the
  recorder or through `REVERIE_DBT_CLIENT`). SaBRe hosts it in the example-tool
  plugin of `experimental/reverie-sabre-strace` and needs SaBRe's loader
  (`SABRE_BINARY`, which `reverie-sabre-strace --print-sabre` names, or `sabre`
  beside the recorder) and the plugin (`SABRE_PLUGIN`, or
  `libreverie_sabre_strace_plugin.so` beside the recorder). For DBT and SaBRe
  the tool's GlobalState is in the recorder, served to the program's
  processes over a socket. A backend that cannot run the tool refuses by name
  (`REFUSED:`).
- `../backend.rs`: the run-time backend selector the tools share.
- `run.sh`: the entry point; `run.sh --help` lists its options.
- `compare.rs` (binary `reverie-e2e-compare`): runs each program of
  `corpus.tsv` natively twice (an unstable native baseline is its own
  verdict) and on each backend, compares call by call, and checks every
  verdict other than `match` against the ledger. An in-guest tool starts at its preload's
  constructor, after the loader's calls, at the start and after each
  `execve`, and DBT's and SaBRe's start late in the same way: for those
  backends the comparator first moves the native record to where the
  backend's next calls appear by name, then compares exactly.

A ledger row records a program's first difference, which depends on the
host's libraries and tools (glibc's loader, coreutils, `/proc`). So a ledger
belongs to one environment: `ledgers/<os id>-<os version>-glibc<version>.tsv`,
which `run.sh` picks from `/etc/os-release` and `getconf GNU_LIBC_VERSION`
(or `--environment NAME`). On a host with no ledger, `run.sh` reports the
verdicts without judging them and says so (`NO LEDGER`). To add an
environment, run `run.sh --write-ledger FILE` there twice, check that the
rows agree, and commit them under `ledgers/` with a comment naming each
group's defect. `cargo test` runs the environment-independent part
(`../tests/recorder.rs`).

```text
reverie-examples/e2e/run.sh                      # every backend this host has
reverie-examples/e2e/run.sh --backends kvm
reverie-examples/e2e/run.sh --report-only --write-ledger /tmp/ledger.tsv
```
