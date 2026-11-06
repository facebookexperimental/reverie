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

The guest's stdout is the directory listing:

```text
backend.rs
Cargo.toml
chaos_launcher.rs
chaos.rs
chrome-trace
...
```

The tool's trace goes to stderr. Its final lines have this shape
(the process ID and addresses vary from run to run):

```text
[pid 3146459] openat(-100, 0x555555582920 -> ".", OFlag(O_CLOEXEC | O_DIRECTORY | O_NDELAY), Mode(0x0)) = 3
[pid 3146459] getdents64(3, 0x555555582970, 32768) = 976
[pid 3146459] getdents64(3, 0x555555582970, 32768) = 0
[pid 3146459] write(1, 0x555555582bc0, 355) = 355
[pid 3146459] exit_group(0) = ?
Thread 3146459 exited with status Exited(0)
Process 3146459 exited with status Exited(0)
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
hello
 [counter tool] Total system calls in process tree: 79
```

The `hello` line is the guest's stdout; the counter's total goes to
stderr. The number itself is a property of the guest, host libc, and
startup path, so expect the same shape rather than the same count on
every machine.

Same `Tool` implementation, different mechanism: no per-syscall ptrace
stop. That sentence — *same tool, swappable mechanism, same semantics
or a named refusal* — is the thesis of this book, and
[Backends](backends.md) and [Testing your tool](testing.md) are where
it is proved rather than asserted.

## Starting from crates.io

The checkout above is the path this book's later chapters follow,
because they track the workspace as it changes. If you want only the
published framework and the ptrace backend, start a fresh binary
project and pin the pair this section was verified against:
`reverie-core` 0.5.0 (imported as `reverie`) and `reverie-ptrace`
0.5.0, using stable Rust 1.97.1, the workspace toolchain used for
the verification.

```console
$ cargo new my-tool
$ cd my-tool
$ cargo add reverie-core@=0.5.0 reverie-ptrace@=0.5.0
$ cargo add tokio --features macros,rt,time
```

Replace `src/main.rs` with the smallest useful launcher. It runs
`/bin/echo hello` under the built-in unit tool (`()` implements
`Tool`), so it proves the published crates, backend, and host setup
line up before you write policy of your own. The backend future is
not `Send`, so it runs on a current-thread Tokio runtime inside a
`LocalSet`:

```rust,ignore
use reverie::Backend;
use reverie::process::Command;
use reverie_ptrace::PtraceBackend;

fn main() -> Result<(), reverie::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread Tokio runtime");
    let local = tokio::task::LocalSet::new();
    let (status, ()) = local.block_on(&runtime, {
        let mut command = Command::new("/bin/echo");
        command.arg("hello");
        PtraceBackend::run::<()>(command, ())
    })?;
    println!("guest exited with {status:?}");
    Ok(())
}
```

```console
$ cargo run
hello
guest exited with Exited(0)
```

That is the whole published-crate smoke test used for this section.
For the full tool in the next chapter — and for APIs newer than
0.5.0, including the selection/admission surface — use the checkout
path above; the workspace version in this tree is ahead of the
published 0.5.0 pair.
