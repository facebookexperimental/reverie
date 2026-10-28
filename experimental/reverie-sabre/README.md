# reverie-sabre

`reverie-sabre` provides Reverie's experimental SaBRe adapter and the pinned
SaBRe loader needed to run it. The build-required source is vendored at the
revision recorded in `vendor/sabre/REVISION`; Cargo configures and builds the
loader only inside the package `OUT_DIR`, with no submodule or network path.

```bash
cargo build -p reverie-sabre
```

A source install requires CMake, GCC/G++, and system zlib development files.
The required libelf implementation is pinned in this package and built as a
static archive inside Cargo `OUT_DIR`; no system libelf headers, linker alias,
or runtime library are required. `bundled_sabre_path` returns the exact loader
built for the current package. The package license records the
GPL-3.0-or-later SaBRe and LGPL-3.0-or-later libelf source alongside Reverie's
BSD-2-Clause code.
