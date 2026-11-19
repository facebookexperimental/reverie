# reverie-signal

Shared Linux x86-64 signal frame construction and `rt_sigreturn`
restore for Reverie backends.

The frame builder was lifted from LinuxEmu (the KVM backend's emulator)
so that every backend constructs and restores identical signal frames.
LinuxEmu consumes this crate and re-exports the frame types under its
existing `reverie_linuxemu::signal` paths.

## Build-system note (internal builds)

The frame tests compile two small C ABI probes at test time
(`tests/fixtures/signal_abi_*.c`, needs `cc`). Internal (Buck) targets
for this crate must declare those fixtures as resources; the Cargo DAG
already selects this package in its core test node.
