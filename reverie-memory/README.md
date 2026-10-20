# reverie-memory

Guest-memory access primitives for [Reverie](https://docs.rs/reverie-core), the
Linux instrumentation framework beneath [Hermit](https://hermetic-infra.org).
This crate provides address types, memory access traits, and typed reads and
writes used by Reverie tools and backends. It does not launch or trace a process.

```toml
[dependencies]
reverie-memory = "0.4"
```

See the [API documentation](https://docs.rs/reverie-memory) for the contracts
that implementations must follow. To run programs with Hermit, start with
[`hermit-run`](https://crates.io/crates/hermit-run).
