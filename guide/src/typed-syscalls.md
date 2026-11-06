# Typed syscalls

Raw syscall handling means six anonymous `u64`s and a manual page.
`reverie-syscalls` replaces that with a typed wrapper per syscall:
arguments with names and types, pointer values you can actually read
through the guest's memory interface, and `strace`-quality
pretty-printing for free. The `strace` example is mostly this chapter
plus a `println!`.

## What you get

* `Sysno` — the syscall number as an enum (re-exported from the
  `syscalls` crate), not an integer to look up.
* `Syscall` and the per-syscall argument structs — pattern-match the
  syscall you care about; the compiler checks you used the right
  argument meanings.
* Memory-aware accessors — a `*const c_char` argument becomes a value
  you read *from the guest* with the backend's memory implementation,
  so the same tool code works whether the guest is across a ptrace
  boundary or in-process.
* Pretty-printing — deliberately *not* `std::fmt::Display` (formatting
  needs guest memory), but `Displayable::display(&memory)`: every
  typed syscall formats itself the way `strace` would, which makes
  logging handlers one-liners and diffing two backends' traces a text
  operation.

## The discipline typed wrappers enforce

Typed access does not make guest memory trustworthy. A pointer
argument is a *claim* by the guest: it may be unmapped, racily
rewritten by another guest thread between your check and the kernel's
use, or point at memory whose meaning changes across the syscall.
Tools that enforce policy (sandboxes, determinism engines) must copy
and validate at the right moment, not merely read conveniently. The
typed layer gives you ergonomic, checked reads; the *timing* of those
reads relative to injection remains your design problem, and the
[Safety](safety.md) chapter returns to it.

## Worked example: redirect one `openat` by prefix

This tool reads the typed path, rewrites an equal-length prefix in
guest memory, and tail-injects the original syscall. Because the
rewrite is length-preserving it needs no new allocation and no
length fixup — which is exactly why it is the right first exercise:
everything interesting is in the read, the check, and the write,
and the discipline paragraph above applies verbatim (the read and
the write happen while the guest is stopped in your handler; a
second guest thread racing the buffer is still your design
problem). The two listings are one `tests/typed_openat.rs` file
(`reverie` + `reverie-ptrace` + `serde` + `tokio` dev-dependencies
against a checkout); as printed it passes
`cargo test -- --test-threads=1` (1 test).

Listing TS-1 is the tool. Configuration reaches the handler through
`guest.config()`; observations go to global state by RPC — a local
handler never touches global state directly:

<span class="filename">Listing TS-1: tests/typed_openat.rs (part 1)</span>

```rust,ignore
//! Typed-args proof: read an `openat` path from guest memory,
//! rewrite an equal-length prefix in place, tail-inject.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use reverie::process::Command;
use reverie::syscalls::{AddrMut, FromToRaw, MemoryAccess, ReadAddr, Syscall, SyscallInfo};
use reverie::{Backend, Error, GlobalTool, Guest, Pid, Tool};
use reverie_ptrace::PtraceBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PrefixPair {
    from: String,
    to: String,
}

#[derive(Debug, Default, Clone)]
pub struct RewriteGlobal {
    seen: Arc<Mutex<Vec<PathBuf>>>,
    rewritten: Arc<AtomicUsize>,
}

#[derive(PartialEq, Debug, Eq, Clone, Serialize, Deserialize)]
pub struct Observed {
    path: PathBuf,
    rewritten: bool,
}

#[reverie::global_tool]
impl GlobalTool for RewriteGlobal {
    type Request = Observed;
    type Response = ();
    type Config = PrefixPair;

    async fn init_global_state(pair: &PrefixPair) -> Self {
        assert_eq!(
            pair.from.len(),
            pair.to.len(),
            "prefix rewrite must be length-preserving"
        );
        Self::default()
    }

    async fn receive_rpc(&self, _from: Pid, msg: Observed) {
        self.seen.lock().unwrap().push(msg.path);
        if msg.rewritten {
            self.rewritten.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct PrefixRewriteTool;

#[reverie::tool]
impl Tool for PrefixRewriteTool {
    type GlobalState = RewriteGlobal;
    type ThreadState = ();

    async fn handle_syscall_event<T: Guest<Self>>(
        &self,
        guest: &mut T,
        syscall: Syscall,
    ) -> Result<i64, Error> {
        if let Syscall::Openat(openat) = syscall {
            if let Some(path_ptr) = openat.path() {
                let memory = guest.memory();
                if let Ok(path) = path_ptr.read(&memory) {
                    let pair = guest.config().clone();
                    let mut rewritten = false;
                    if path.starts_with(&pair.from) {
                        let mut memory = guest.memory();
                        let raw = openat.path().into_raw();
                        let addr =
                            AddrMut::from_ptr(raw as *const u8).expect("path pointer was Some");
                        memory
                            .write_exact(addr, pair.to.as_bytes())
                            .map_err(Error::from)?;
                        rewritten = true;
                    }
                    let _ = guest.send_rpc(Observed { path, rewritten }).await;
                }
            }
            return guest.tail_inject(Syscall::Openat(openat)).await;
        }
        guest.tail_inject(syscall).await
    }
}
```

Listing TS-2 drives it: two same-length directory prefixes with
different file contents, so the guest's own stdout proves which
file the kernel opened.

<span class="filename">Listing TS-2: tests/typed_openat.rs (part 2)</span>

```rust,ignore
fn run_cat(config: PrefixPair, file: &str) -> (Vec<u8>, RewriteGlobal) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");
    let local = tokio::task::LocalSet::new();
    let mut command = Command::new("/bin/cat");
    command.arg(file);
    let (output, global, _stats) = local
        .block_on(
            &runtime,
            PtraceBackend::run_with_output::<PrefixRewriteTool>(command, config),
        )
        .expect("ptrace backend run");
    assert_eq!(output.status.code(), Some(0));
    (output.stdout, global)
}

#[test]
fn openat_prefix_rewrite_redirects_open() {
    let base = std::env::temp_dir().join(format!("typed-openat-{}", std::process::id()));
    let aaaa = base.join("aaaa");
    let bbbb = base.join("bbbb");
    std::fs::create_dir_all(&aaaa).unwrap();
    std::fs::create_dir_all(&bbbb).unwrap();
    std::fs::write(aaaa.join("hello.txt"), "from-a\n").unwrap();
    std::fs::write(bbbb.join("hello.txt"), "from-b\n").unwrap();

    let target = aaaa.join("hello.txt");
    let config = PrefixPair {
        from: aaaa.to_string_lossy().into_owned(),
        to: bbbb.to_string_lossy().into_owned(),
    };
    let (stdout, global) = run_cat(config, &target.to_string_lossy());

    // The guest asked for aaaa/hello.txt and read bbbb's contents:
    // the rewrite happened in guest memory before the syscall ran.
    assert_eq!(stdout, b"from-b\n");
    assert_eq!(global.rewritten.load(Ordering::SeqCst), 1);
    assert!(global.seen.lock().unwrap().iter().any(|p| p == &target));
    let _ = std::fs::remove_dir_all(&base);
}
```

Run the same guest under the `strace` example for contrast: the
typed handler above is roughly the `openat` arm of that match with
the pretty-printer replaced by a policy — read, decide, optionally
rewrite, tail-inject.
>
> 🚧 **Under construction — coverage statement.** TODO: state which
> syscalls have full typed wrappers vs fall back to raw arguments, per
> architecture, generated from the crate's own tables.
> <!-- UC: typed-coverage -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`typed-coverage`).
