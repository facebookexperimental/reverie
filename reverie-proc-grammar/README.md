# reverie-proc-grammar

Pure, grammar-backed parsers and renderers for the Linux `/proc`
per-task files — `stat`, `status`, `comm`, `fdinfo`, `io`, `sched`,
and `statm` — for [Reverie](https://docs.rs/reverie-core), the Linux
instrumentation framework beneath [Hermit](https://hermetic-infra.org).

Each format is owned by one module that cites the kernel printing
function defining it, parses the file's bytes into a full-fidelity
typed value, and renders it back byte-for-byte. Inputs are bytes,
never assumed UTF-8: a task name may contain spaces, parentheses,
newlines, and non-UTF-8 bytes. A parse that cannot account for every
byte fails with a typed error naming the field.

Everything is a pure function over caller-supplied bytes: no system
calls, no clock, no policy. Which fields a caller rewrites before
rendering — Detcore's determinism policy, a backend's presentation —
stays with the caller, expressed through the typed setters.

```toml
[dependencies]
reverie-proc-grammar = "0.5"
```

See the [API documentation](https://docs.rs/reverie-proc-grammar).
The corpus collector lives in `examples/collect-corpus.rs`; checked-in
fixtures under `tests/fixtures/` are its shape-representative output.

## Related work

Existing Rust crates in this space focus on reading: they turn live
`/proc` files into values for monitoring and inspection, and their
documented APIs (at the versions below) do not include a
`/proc`-format renderer or a stated unknown-field contract. This
crate covers the adjacent need — strict, canonical, byte-exact
parse ↔ render for callers (like Hermit) that must republish a
rewritten file and refuse, by name, any byte shape they cannot
account for. (Versions and states as of 2026-11-15.)

| Crate | Parses | Renders `/proc` bytes back | Unknown fields | Maintenance | License |
| --- | --- | --- | --- | --- | --- |
| `procfs` / `procfs-core` 0.18.0 | stat, status, statm, io, comm, maps/smaps, mountinfo, and many system files; per its support matrix fdinfo is not covered and sched is not listed | No `/proc`-format renderer in the documented API (optional serde serialization is not a byte renderer) | Tolerated: `status` is collected into a map and unclaimed labels are silently dropped; `stat` comm is lossy UTF-8 | Active (51 versions, latest 2025-08-30) | MIT OR Apache-2.0 |
| `proc-maps` 0.5.0 | `maps` only, cross-platform | No renderer in the documented API | Not a per-task-file grammar; malformed lines error | Active (latest 2026-06-29) | MIT |
| `procinfo` 0.4.2 | stat, statm, status, limits, mountinfo, loadavg, some system files | No renderer in the documented API | No documented contract | Unmaintained (latest 2017-06-25) | MIT/Apache-2.0 |
| `sysinfo` 0.40.3 | Cross-platform system/process abstraction; `/proc` parsing is internal | No renderer in the documented API | Internal, best-effort | Very active (latest 2026-11-11) | MIT |
| `fb_procfs` 0.9.0 (from Below) | `PidStat`, `PidStatus`, `PidIo`, `MountInfo` plus network/system statistics, via a live `ProcReader` | No renderer in the documented API | No documented contract | Active (latest 2025-02-25); heavier dependency set (slog, nix, openat, …) | Apache-2.0 |
| `rustix-linux-procfs` 0.1.1 | Safely *opening* procfs files/directories — a complement, not a parser | n/a | n/a | Active (latest 2025-04-21) | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT |
| **`reverie-proc-grammar`** | stat, status, statm, io, sched, fdinfo, comm — seven per-task formats | **Yes: byte-exact for every accepted input** | Refused by default (`parse_status` et al. are strict and canonical); unknown status labels only via the separately named opt-in `parse_status_preserving_unknown`, for consumers that drop them by name | This repository | BSD-2-Clause (as Reverie) |

Where a reader's tolerance is the right choice (dashboards,
one-off inspection), `procfs` and `sysinfo` remain the better
tools. Where the output bytes are republished to another program —
a deterministic runtime, a record/replay log, a test oracle —
that tolerance can let a kernel grammar change pass unnoticed,
which is the case this crate is built to make explicit instead.
