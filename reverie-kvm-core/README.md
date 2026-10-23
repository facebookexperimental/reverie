# reverie-kvm-core

The lowest layer of [Reverie](https://docs.rs/reverie-core)'s KVM backend:
the backend's error type and the fixed guest address map. reverie-kvm builds
on it and re-exports what its users need.

This is an internal building block of Reverie's KVM backend, not part of the
Reverie `Tool`, `Guest` or backend contract.
