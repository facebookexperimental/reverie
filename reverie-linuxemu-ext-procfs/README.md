# reverie-linuxemu-ext-procfs

The LinuxEmu procfs extension: synthetic `/proc/self/maps` for
standalone [Reverie](https://docs.rs/reverie-core) compositions,
plus the pure `/proc` content helpers it renders with. Renamed
from `reverie-procfs` when the rendering moved behind the
extension seam (modularity Slice 2, S2-R4).

Compositions whose tool serves `/proc` never link this crate: a
standalone composition registers it on its extension table
(`register`, or `extension_table()` for the table carrying only
this extension), and the core then serves the claimed path from
its facts snapshot. Without a registration the core refuses it.
`/proc/self/status` is core mechanics (a readable seq
description) and is not claimed here.

Everything here renders from caller-supplied values: no process,
descriptor, or scheduling state, no system calls, no policy.

```toml
[dependencies]
reverie-linuxemu-ext-procfs = "0.5"
```

See the [API documentation](https://docs.rs/reverie-linuxemu-ext-procfs).
