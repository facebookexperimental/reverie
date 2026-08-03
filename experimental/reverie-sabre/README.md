# reverie-sabre

`reverie-sabre` provides Reverie's experimental SaBRe adapter and the pinned
SaBRe loader needed to run it. The build-required source is vendored at the
revision recorded in `vendor/sabre/REVISION`; Cargo configures and builds the
loader only inside the package `OUT_DIR`, with no submodule or network path.

```bash
cargo build -p reverie-sabre
```

A source install requires CMake, GCC/G++, and system `libelf`, `zlib`, and zstd
development libraries. `bundled_sabre_path` returns the exact loader built for
the current package. The package license records the GPL-3.0-or-later SaBRe
source alongside Reverie's BSD-2-Clause code.
