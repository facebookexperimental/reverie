# reverie-sabre

`reverie-sabre` provides Reverie's experimental SaBRe adapter and the pinned
SaBRe loader needed to run it. The build-required source is vendored at the
revision recorded in `vendor/sabre/REVISION`; Cargo configures and builds the
loader only inside the package `OUT_DIR`, with no submodule or network path.

```bash
cargo build -p reverie-sabre
```

A source install requires CMake, GCC/G++, the `libelf.so.1` runtime library, and
system zlib and zstd development libraries. The libelf headers are pinned in
this package, and the build supplies a local linker-script alias for the runtime
SONAME, so a missing development-header package or unversioned `libelf.so`
symlink does not break the source build. `bundled_sabre_path` returns the exact
loader built for the current package. The package license records the
GPL-3.0-or-later SaBRe and LGPL-3.0-or-later libelf headers alongside Reverie's
BSD-2-Clause code.
