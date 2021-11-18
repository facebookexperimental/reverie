# Examples

Example tools built on top of Reverie.

Copying one of these examples is the recommended way to get started using
Reverie.

# chrome-trace: Generates a chrome trace file

This tool is like `strace`, but generates a trace file that can be loaded in
`chrome://tracing/`.

# counter1: Reverie Counter Tool (1)

This is a basic example of event counting. It counts the number of system
calls and reports that single integer at exit.

This version of tool uses a single, centralized piece of global state.

# counter2: Reverie Counter Tool (2)

This is a basic example of event counting. This tool counts the number of
system calls and reports that single integer at exit.

This implementation of the tool uses a *distributed* notion of state,
maintaining a per-thread, per-process, and global state. Basically, this is
an example of "MapReduce" style tracing of a process tree.

# noop: Identity Function Tool

This instrumentation tool intercepts events but does nothing with them. It is
useful for observing the overhead of interception, and as a starting point.

# chunky_print: Print-gating Tool

This example tool intercepts write events on stdout and stderr and
manipulates either when those outputs are released, or the scheduling order
that determines the order of printed output.

# pedigree: Deterministic virtual process IDs

This tool monitors the spawning of new processes and maps each new PID to a
deterministic virtual PID. The new virtual PID is reported after each
process-spawning syscall.

This tool is a work-in-progress and is not yet functioning.

`pedigree.rs` is an implementation of pedigree / virtual PID generation using local state.
`virtual_process_tree.rs` is an implementation which uses global state.

# strace: Reverie Echo Tool

This instrumentation tool simply echos intercepted events, like strace.

# chaos: Chaos Tool

This tool is meant to emulate a pathological kernel where:

 1. `read` and `recvfrom` calls return only one byte at a time. This is
    intended to catch errors in parsers that assume multiple bytes will be
    returned at a time.
 2. `EINTR` is returned instead of running the real syscall for every other
    read.
