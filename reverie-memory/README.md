# reverie-memory

Guest-memory access primitives for [Reverie](https://docs.rs/reverie-core), the
Linux instrumentation framework beneath [Hermit](https://hermetic-infra.org).
This crate provides address types, memory access traits, and typed reads and
writes used by Reverie tools and backends. It does not launch or trace a process.

Construct local memory access with `LocalMemory::new()` or `Default`. The type
now retains its syscall execution mechanism in a private field, so the former
empty struct literal `LocalMemory {}` must migrate to one of those constructors.
The ordinary constructors retain native kernel-copy behavior. Runtimes may use
the unsafe `with_syscall_executor` constructor to select their syscall
instruction while preserving the same kernel copies, partial results and
errors; its safety contract applies on every invoking thread. This does not
grant access to unreadable pages or enforce a remote protection key.

```toml
[dependencies]
reverie-memory = "0.4"
```

See the [API documentation](https://docs.rs/reverie-memory) for the contracts
that implementations must follow. To run programs with Hermit, start with
[`hermit-run`](https://crates.io/crates/hermit-run).
