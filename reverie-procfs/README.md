# reverie-procfs

Pure Linux `/proc` content formatting and path classification helpers for
[Reverie](https://docs.rs/reverie-core), the Linux instrumentation
framework beneath [Hermit](https://hermetic-infra.org). Backends and tools
that present a `/proc` view to a guest program share these helpers —
path classification, file-content formatting, `seq_file` positioning, and
synthetic file metadata — so the bytes and metadata they produce agree.

Everything in this crate is a pure function over caller-supplied values:
it holds no process, descriptor, or scheduling state, makes no system
calls, and decides no policy. Which paths exist and what facts a file
reports remain the caller's business.

```toml
[dependencies]
reverie-procfs = "0.5"
```

See the [API documentation](https://docs.rs/reverie-procfs) for the
contracts that implementations must follow. To run programs with Hermit,
start with [`hermit-run`](https://crates.io/crates/hermit-run).
