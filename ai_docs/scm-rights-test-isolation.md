# Isolate the received-rights closure test

`received_rights_reservation_and_rewrite_failures_are_transactional` in
[`executor.rs`](../reverie-kvm/src/executor.rs) requires immediate peer EOF
after rollback or removal of an unsupported received descriptor. A concurrent
library test can spawn a host subprocess between socket creation and close.
Even `CLOEXEC` sockets remain inherited until that subprocess execs, so closing
the fixture's descriptor alone would not establish EOF.

The fixture therefore runs through an exact-test subprocess and creates its
sockets after exec. Other tests in the original library process cannot inherit
those endpoints. The subprocess has a ten-second deadline and two-second kill
grace. A failed child reports its status, stdout and stderr and fails the
parent test.

Keep the original immediate EOF assertions and transactional memory/descriptor
checks. Isolation must not become a retry, sleep or allowance for `EAGAIN`:
an extra live endpoint is still a failure. This is test ownership isolation,
not a change to production descriptor handling or a claim of general
`SCM_RIGHTS` parity.
