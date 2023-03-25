# A safe ptrace interface

This crate provides a safe and Rustic alternative to the infamous `ptrace` API.
There are many extremely subtle aspects of the raw ptrace API and this crate
helps avoid common pitfalls.

Note that this library is still rather low-level and does not claim to solve all
your ptrace problems. You have been warned!

## Features

 * Ergonomic interface that provides a state machine for ptrace states. This
   avoids the infamous `ESRCH` errors that can happen when you use the ptrace
   API incorrectly.
 * Provides an interface to read/write guest's memory (see "memory" feature
   flag).
 * Provides an optional and semi-experimental async interface, which can be used
   with `tokio` (see "notifier" feature).

## Usage

Add this to your `Cargo.toml` file:
```
safeptrace = "0.1"
```

## Feature Flags

### `"memory"` (off by default)

Provides access to the guest's memory. Memory can only be safely accessed when
the guest is in a stopped state, thus the `MemoryAccess` trait is only
implemented for the `Stopped` type.

### `"notifier"` (off by default)

Provides an async interface for ptrace using notifier threads. This is
semi-experimental, but testing shows that it has very good performance. It works
by spawning a separate thread for each thread being traced, waiting for ptrace
events in a loop. Thus, there will be 1 thread per guest thread.

Use with:
```
safeptrace = { version = "0.1", features = ["async"] }
```
