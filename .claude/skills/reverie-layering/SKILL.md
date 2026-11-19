---
name: reverie-layering
description: "Reverie is an independent product that must make sense without Hermit, its main consumer: keep Hermit and Detcore implementation logic out of Reverie by adding generic mechanisms, and judge independence in review from the design and dependencies. Use when designing or reviewing a Reverie API, hook, flag, build target, test or dependency."
---

# Reverie layering

Reverie is designed as an independent product: a process-instrumentation layer
that must make sense to a user who has never heard of Hermit, its main
consumer. Keep the two from being mixed up.

- Hermit and Detcore implementation logic must not leak into Reverie. When
  Hermit needs something new, add a generic Reverie mechanism (a `Tool`,
  `Guest` or backend capability, an interception or injection hook, a
  lifecycle contract) and keep Hermit's policy in Hermit.
- Ownership metadata is not implementation leakage: the `REVERIE_ONCALL`
  arrangement in `fb-only/defs.bzl`, and the oncall it names, stay exactly as
  they are.
- Reviewers judge independence from the design and the dependencies. There is
  no counted word test, allowlist, seal or numeric gate.

Boundary cases:

- A precise, controllable timer hook belongs here; a policy for how virtual
  time must behave belongs to the consumer.
- A backend capability query belongs here; a backend branch chosen for one
  consumer's scheduling policy does not.
- The example tools (strace, counter) prove the layer stands alone: every
  backend passes Reverie's generic tests with them and no consumer linked.
- A build or package edge from Reverie to a consumer is the worst leak: a
  Cargo dependency, or a Buck `load()` or dependency on a consumer's target.
- A cross-repository ABI name (a symbol a consumer defines that Reverie calls,
  or the reverse) is renamed only together with the other side, never as a
  drive-by edit.
