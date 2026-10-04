# Pipe FIONREAD

KVM supports `FIONREAD` for actual host-backed pipes and FIFOs. It resolves the
low 32 bits of the descriptor and command, checks the descriptor before the
output pointer, and requires the host object to have type `S_IFIFO`. The host
query consumes no data. Copyout writes one four-byte integer through the
permission-aware guest-memory store; an invalid destination returns `EFAULT`
without a partial write. Host errors remain errors.

When output capture is enabled, capture aliases return `ENOTTY`. Object
identity checks also reject transferred aliases whose capture metadata was
lost, preventing disclosure of supervisor output. An unrelated real pipe at
virtual descriptor 1 or 2 remains supported. If capture backing identity is
unavailable, the operation refuses. Concurrent external replacement of host
stdout or stderr is outside this lifetime model.

Other descriptor classes remain unsupported with `ENOTTY`, including regular
files, memfds, sockets and synthetic proc files. Native Linux supports some
of these cases. Pipe-only support does not repair general descriptor identity
through `SCM_RIGHTS` or provide full ioctl parity.

See `pipe_fionread` and its dispatch in
[`executor.rs`](../reverie-kvm/src/executor.rs), the
[unit controls](../reverie-kvm/src/pipe_fionread_tests.rs), and the
[native/KVM fixture](../reverie-kvm/tests/fixtures/pipe_fionread.c).
The controls retain complete-buffer checks, non-consumption, capture exclusions,
transferred aliases, request width and memory-fault behavior.
