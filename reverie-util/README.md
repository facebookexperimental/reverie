# reverie-utils

Shared command-line, logging, and utility helpers for
[Reverie](https://docs.rs/reverie-core), the Linux instrumentation framework
beneath [Hermit](https://hermetic-infra.org).

The public package is named `reverie-utils`; its Rust library is named
`reverie_util`:

```toml
[dependencies]
reverie-util = { package = "reverie-utils", version = "0.4" }
```

See the [API documentation](https://docs.rs/reverie-utils) for available
helpers. To run programs under Hermit, use the
[`hermit-run` CLI](https://crates.io/crates/hermit-run).
