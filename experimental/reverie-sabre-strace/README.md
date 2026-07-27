# Reverie SaBRe example tools

This package contains a SaBRe host executable and plugin that drive a shared
`reverie::Tool` through `reverie_sabre::ReverieAdapter`.

## Build and run

Build the host and plugin from the Reverie workspace:

```sh
cargo build -p reverie-sabre-strace
```

Run them directly:

```sh
target/debug/reverie-sabre-strace \
  --sabre /path/to/sabre \
  --plugin target/debug/libreverie_sabre_strace_plugin.so \
  -- /bin/echo hello
```

Choose another example with `--tool`:

```sh
target/debug/reverie-sabre-strace \
  --sabre /path/to/sabre \
  --plugin target/debug/libreverie_sabre_strace_plugin.so \
  --tool counter1 \
  -- /bin/echo hello
```

Supported values are:

- `chaos`: run the production chaos tool. `--skip`, `--no-read`, `--no-recv`,
  and `--no-interrupt` configure its intervention window.
- `chrome-trace`: run the production Chrome Trace tool. `--out PATH` writes
  its JSON artifact after the guest exits.
- `chunky-print`: run the production chunky-print tool and flush buffered
  output after the guest exits.
- `strace` (default): decode and print syscalls and results. Exec paths and
  argv are decoded, while envp is redacted because it commonly contains
  credentials.
- `counter1`: print one process-tree total of intercepted syscalls.
- `counter1-exact`: run the backend-neutral `counter1` example unchanged and
  print its process-tree total through the host coordinator.
- `counter2`: print one process-tree total with observed process and thread
  identities.
- `counter2-exact`: run the backend-neutral `counter2` example and publish
  per-process exit totals to the host coordinator.
- `noop`: forward syscalls through the default shared Tool handler.

Hermit uses the same artifacts through `HERMIT_SABRE_RUNNER`,
`HERMIT_SABRE_BINARY`, and `HERMIT_SABRE_PLUGIN`:

```sh
hermit --backend sabre strace -- /bin/echo hello
```

Hermit's generic compatibility path uses the same `StraceTool` and suppresses
only its diagnostic lines:

```sh
hermit run --backend sabre --strict --verify -- /bin/echo hello
```

Set `REVERIE_SABRE_STRACE_QUIET=1` when invoking the host directly to
suppress syscall diagnostics while retaining syscall interception.

## M2 boundaries

This is a syscall-tracing milestone, not a deterministic Detcore backend.
It targets dynamically linked Linux x86-64 guests and synchronous Reverie
handlers. A handler must complete on its first poll; `tail_inject` is the only
supported pending future.

The host owns one external `GlobalTool` for every production selector that
needs global state. Fork and exec children reconnect their process-local
adapters to that coordinator. Exact counter2 publishes each process-local total
at the loader's process-exit boundary; Chrome Trace and chunky-print publish
their final artifacts after all guest connections close.

`noop` requests `Subscription::none()`, but the legacy SaBRe loader does not
yet consult subscriptions, so rewritten syscall sites still enter the default
shared Tool handler before being forwarded.

`execve` and supported `execveat` forms re-enter the pinned SaBRe loader and
keep the selected plugin active for the new image. Loader post-load events are
deferred until the first rewritten syscall so client environment and tool
selection are available. Parent thread-state snapshots, accurate
parent-process metadata, full registers, timers, shared signal callbacks,
fatal-signal process-exit callbacks, and precise thread exit statuses are not
implemented. The legacy runtime also keeps stderr open for plugin diagnostics.
