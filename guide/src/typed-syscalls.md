# Typed syscalls

Raw syscall handling means six anonymous `u64`s and a manual page.
`reverie-syscalls` replaces that with a typed wrapper per syscall:
arguments with names and types, pointer values you can actually read
through the guest's memory interface, and `strace`-quality
pretty-printing for free. The `strace` example is mostly this chapter
plus a `println!`.

## What you get

* `Sysno` — the syscall number as an enum, not an integer to look up.
* `Syscall` and the per-syscall argument structs — pattern-match the
  syscall you care about; the compiler checks you used the right
  argument meanings.
* Memory-aware accessors — a `*const c_char` argument becomes a value
  you read *from the guest* with the backend's memory implementation,
  so the same tool code works whether the guest is across a ptrace
  boundary or in-process.
* Display — every typed syscall formats itself the way `strace` would,
  which makes logging handlers one-liners and diffing two backends'
  traces a text operation.

## The discipline typed wrappers enforce

Typed access does not make guest memory trustworthy. A pointer
argument is a *claim* by the guest: it may be unmapped, racily
rewritten by another guest thread between your check and the kernel's
use, or point at memory whose meaning changes across the syscall.
Tools that enforce policy (sandboxes, determinism engines) must copy
and validate at the right moment, not merely read conveniently. The
typed layer gives you ergonomic, checked reads; the *timing* of those
reads relative to injection remains your design problem, and the
[Safety](safety.md) chapter returns to it.

> 🚧 **Under construction — typed-args listing.** TODO: a listing that
> matches `openat`, reads its path from guest memory, rewrites one
> path prefix, and tail-injects — run under `strace` for contrast.
> <!-- UC: typed-listing -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`typed-listing`).
>
> 🚧 **Under construction — coverage statement.** TODO: state which
> syscalls have full typed wrappers vs fall back to raw arguments, per
> architecture, generated from the crate's own tables.
> <!-- UC: typed-coverage -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`typed-coverage`).
