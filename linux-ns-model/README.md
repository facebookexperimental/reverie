# linux-ns-model

A pure model of the Linux mount-namespace and mount-table semantics a
runtime needs when it interposes on Linux processes and must decide,
for a guest's `mount(2)` and `umount2(2)` calls, what Linux would do:
admit the call (and predict its exact effect, propagation included),
refuse it with Linux's `errno`, or refuse by name a request Linux
would accept but this model does not cover yet.

The crate performs no I/O and knows nothing about its consumers. Four
traits are injected by the consumer:

- `IdSource` — mount IDs, peer groups, device numbers, namespace IDs.
- `Clock` — the timestamps recorded for mount points the model creates.
- `Presentation` — the values shown where Linux would show
  host-derived ones (`statfs` capacities, the memory size behind
  filesystem defaults).
- `Performer` — identifies path operands and carries out one
  admitted host operation, then reports what the kernel did.

Admission follows a transition contract: `Model::admit` returns a
`Pending` transition that holds the model exclusively; the consumer
performs at most one host operation and hands the observed effect to
`Pending::commit`, which applies it only if it matches the model's
prediction (given the facts only the filesystem could resolve, such
as a bind mount's root). A surprise is a `Divergence` and leaves the
model unchanged.

Covered in this version: bind mounts and unmounts (including
`MNT_DETACH` and `UMOUNT_NOFOLLOW`), mount stacking, shared/slave
propagation of mount and unmount events, and rendering of
`mountinfo`, `mounts`, and `statfs`. Other mount operations are
refused by name until they are modeled.

```toml
[dependencies]
linux-ns-model = "0.5"
```

See the [API documentation](https://docs.rs/linux-ns-model) for the
contracts implementations must follow. Semantics are taken from
`mount(2)`, `umount(2)`, `mount_namespaces(7)`, `proc(5)`, and the
kernel's `Documentation/filesystems/sharedsubtree.rst`; where they
disagree with the kernel, the kernel wins, which the differential
test in `tests/kernel_differential.rs` checks.
