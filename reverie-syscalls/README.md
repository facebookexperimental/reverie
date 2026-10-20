# reverie-syscalls

Typed Linux syscall arguments, results, and serialization for
[Reverie](https://docs.rs/reverie-core), the instrumentation framework beneath
[Hermit](https://hermetic-infra.org). The types let tools inspect and change
syscalls without manually decoding every register and pointer argument.

```toml
[dependencies]
reverie-syscalls = "0.4"
```

See the [API documentation](https://docs.rs/reverie-syscalls) for supported
syscalls and argument types. This library does not supply an execution backend;
use [`hermit-run`](https://crates.io/crates/hermit-run) for the Hermit CLI.
