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

- `strace` (default): decode and print syscalls and results. Exec paths and
  argv are decoded, while envp is redacted because it commonly contains
  credentials.
- `counter1`: print one process-tree total of intercepted syscalls.
- `counter2`: print one process-tree total with observed process and thread
  identities.
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

The counter host owns one external `GlobalTool` and emits its process-tree
summary after the root guest exits. Fork and exec children reconnect their
process-local adapters to that coordinator, so counter state is shared without
copying process-local plugin state.

`noop` requests `Subscription::none()`, but the legacy SaBRe loader does not
yet consult subscriptions, so rewritten syscall sites still enter the default
shared Tool handler before being forwarded.

`execve` and supported `execveat` forms re-enter the pinned SaBRe loader and
keep the selected plugin active for the new image. Parent thread-state
snapshots, accurate parent-process metadata, full registers, timers, shared
signal callbacks, process-exit callbacks, and precise thread exit statuses are
not implemented. The legacy runtime also keeps stderr open for plugin
diagnostics.
