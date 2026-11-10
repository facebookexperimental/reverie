# Reverie Agent Guide

**Keep Hermit out of Reverie.** Reverie's main user is Hermit, but Reverie is
a standalone process-instrumentation layer that must be reusable without Hermit.
Everything in this repository must make sense to a Reverie user who has never
heard of Hermit or Detcore. That covers code, tests, documentation, comments,
names, feature flags and environment variables.

- Do not add Hermit or Detcore concepts to Reverie:
  - deterministic scheduling, virtual time, determinism policy or DETLOG;
  - Hermit command-line flags, Hermit test cells or Hermit file paths.
- When Hermit needs something new, add a generic Reverie mechanism, such as a
  `Tool`, `Guest` or backend capability or hook. Keep the Hermit-specific
  policy in the Hermit repository.
- Every backend must pass Reverie's own generic tests without Hermit,
  including the strace and counter example tools. The backends are ptrace,
  KVM, DBT, LiteInst and in-guest.
