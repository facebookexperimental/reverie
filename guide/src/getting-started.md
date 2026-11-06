# Getting started

By the end of this chapter you will have run a real program under a
Reverie tool and watched its syscalls stream past.

## System dependencies

Reverie needs a few system libraries (they provide guest backtraces):

```console
$ sudo apt-get install -y build-essential pkg-config libunwind-dev liblzma-dev
```

That is the Ubuntu recipe; Fedora uses `libunwind-devel` and
`xz-devel` for the same libraries. You also need Rust — the published
libraries and this workspace build on stable Rust; the workspace pins
the exact stable release (see `rust-toolchain.toml`).

## Run the strace example

From a checkout of the reverie repository:

```console
$ cd reverie-examples
$ cargo run --bin strace -- ls
```

You just ran `/bin/ls` as a guest under the `strace` tool on the
default (ptrace) backend. The tool echoes every intercepted event,
`strace`-style, while the guest's own output passes through. Notice
the `--`: everything after it is the guest command, exactly as a shell
would receive it.

Copying an example is the recommended way to start a tool of your own.
The gallery, graded by complexity:

| Example | What it teaches |
|---|---|
| `noop` | The empty tool: subscribes to *nothing* (`Subscription::none()`), so it intercepts nothing. The framework-overhead baseline and the best starting skeleton. |
| `counter1` | Counting syscalls into one centralized global state. |
| `counter2` | The same count, MapReduce-style: per-thread, per-process, and global state. |
| `strace` / `strace_minimal` | Echoing events with typed-syscall pretty-printing. |
| `chunky_print` | Intercepting `write` to gate and reorder output. |
| `chaos` | Failure injection: one-byte reads and injected `EINTR`. |
| `chrome_trace` | Emitting a `chrome://tracing/` trace file. |
| `debug` | Acting as a GDB server for the guest. |

## The same tool, another backend

Example launchers accept `--backend`. The counter you will build in
the next chapter runs identically on the in-guest LiteInst backend
through the shared example preload:

```console
$ cargo build -p reverie-examples --lib --bin reverie-liteinst-examples
$ target/debug/reverie-liteinst-examples --tool counter1 -- /bin/echo hello
```

Same `Tool` implementation, different mechanism: no per-syscall ptrace
stop. That sentence — *same tool, swappable mechanism, same semantics
or a named refusal* — is the thesis of this book, and
[Backends](backends.md) and [Testing your tool](testing.md) are where
it is proved rather than asserted.

> 🚧 **Under construction — expected output transcripts.** TODO: paste
> exact, trimmed transcripts for the `strace` and `counter1` runs
> above from a clean build of this tree, so readers can verify their
> environment matches the book's. <!-- UC: gs-transcripts -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`gs-transcripts`).
>
> 🚧 **Under construction — `cargo add` path.** TODO: document
> starting from crates.io (`reverie-core` + a backend crate) in a
> fresh `cargo init` project, including which published versions this
> guide targets; the checkout path above is the one verified today.
> <!-- UC: gs-cratesio -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`gs-cratesio`).
