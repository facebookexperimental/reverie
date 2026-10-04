# reverie-preload

Shared `LD_PRELOAD` + seccomp/`SIGSYS` instrumentation runtime for Reverie's
ld-preload backends (**e9patch** and **liteinst**). It exists so the ld-preload
mechanism is written and reviewed once instead of duplicated per backend (DRY).

## What it provides

| Module | Responsibility |
| --- | --- |
| `seccomp` | Trap-everything-but-the-trusted-gate classic-BPF filter (`TSYNC`), with a testable builder. |
| `trap` | Trusted syscall gate (asm), the `SIGSYS` handler, `raw_syscall6`, dispatcher registration. |
| `dispatch` | The `SyscallDispatcher` seam + shared fail-closed `PassthroughDispatcher`. |
| `fork` | Fork-following hook (the filter is inherited atomically; only per-process state resets). |
| `signal` | Signal multiplexing / reserved-signal (`SIGSYS`) policy + alt-stack. |
| `lifecycle` | `LifecycleController` guest-half seam: `InProcessSeccomp` and `HybridPtrace` install the same SIGSYS/seccomp mechanism; launcher selection is separate. |
| `rpc` (feature `coordinator-rpc`) | Synchronous coordinator client, **wire-compatible** with the async `reverie-rpc-transport` (`RpcServer<G>`). |

## Coverage boundaries

Established by the `research-ldpreload-derisking` task and enforced here: this
runtime is for **trusted, dynamically linked, non-`AT_SECURE`, no-exec** x86-64
guests. It does **not** cover vDSO fast paths, the ~40 loader/startup syscalls
before the constructor runs, static binaries, or `execve` (all fail closed).
`fork`/`clone` children *are* fully covered — the kernel inherits the filter
atomically, so there is no post-fork install race.

## Two ways to use it

* **As a library (`rlib`):** a backend embeds the runtime, registers its own
  `SyscallDispatcher`, and calls `reverie_preload::install(...)`.
* **As a standalone `LD_PRELOAD` (`cdylib`):** set `REVERIE_PRELOAD_TOOL`
  (`passthrough` or `spoof-getpid`) and preload `libreverie_preload.so`.

```rust,ignore
use reverie_preload::dispatch::PassthroughDispatcher;
use reverie_preload::lifecycle::{InProcessSeccomp, RuntimeConfig};

// From a backend, before untrusted threads start:
unsafe {
    reverie_preload::install(
        Box::new(PassthroughDispatcher::new()),
        &InProcessSeccomp,
        &RuntimeConfig::default(),
    )?;
}
```

## Hybrid-ptrace boundary

The `LifecycleController` trait separates *policy* (`SyscallDispatcher`) from
the guest-half trap mechanism. `lifecycle::HybridPtrace` is implemented and
installs the same in-process SIGSYS handler and trusted-gate seccomp filter as
`InProcessSeccomp`; it does not create or inspect a ptrace launcher. A caller may
pair it with a unit-tool `TracerBuilder<()>`: that launcher adds no
`PTRACE_EVENT_SECCOMP` syscall action, but it still sees residual SIGSYS as a
signal-delivery stop before reinjection. Neither controller closes the
dynamic-loader window before the preload constructor or covers vDSO fast paths;
`exec` requires caller-owned rebootstrap policy. The dispatcher, seccomp filter,
trap handler, and RPC client remain shared.

## Migration note for existing backends

`reverie-liteinst` predates this crate and currently carries its own copies of
the seccomp/`SIGSYS`/gate primitives. Folding it (and `reverie-e9patch`) onto
this shared runtime is a follow-up owned by those crates' maintainers; this
crate is deliberately standalone and does **not** modify them.
