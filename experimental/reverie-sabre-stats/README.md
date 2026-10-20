# reverie-sabre-stats

Shared patch-shape and slow-path statistics ABI for the optional SaBRe
integration in [Hermit](https://hermetic-infra.org). This library contains
statistics types and shared-memory access; it does not include or launch the
SaBRe rewriting engine.

This crate is selected by Hermit's opt-in `sabre` feature and is excluded from
the ordinary [`hermit-run`](https://crates.io/crates/hermit-run) installation.

```toml
[dependencies]
reverie-sabre-stats = "0.4"
```

See the [API documentation](https://docs.rs/reverie-sabre-stats) for the ABI
and collection interface, and the
[Hermit CLI](https://crates.io/crates/hermit-run) for backend selection.
