# Exec-stop mechanics moved to reverie-inguest

The pure no_std image validator remains in this crate. The opt-in host launcher,
`reverie-loader-stage1a-probe` executable, runtime fixtures and exec-stop tests
are owned by `reverie-inguest`; see [the mechanics contract](../reverie-inguest/STAGE1A.md).
The canonical `tests/fixtures/guest_cpuid.rs` and `guest_static.ld` stay here so
Hermit and Reverie share their exact source without duplicate vendoring.
