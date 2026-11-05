# Appendix C: further reading

* This repository: `README.md` (overview + the backend contract),
  `BACKENDS.md` (the mechanism matrix with source-pinned links),
  `docs/BACKEND_SOURCES.md` (external backend ownership),
  `reverie-examples/README.md`, and the counter2 shootout under
  `benchmarks/`.
* The LiteInst guide — the building-block layer beneath the in-guest
  backend.
* API reference: [docs.rs/reverie-core](https://docs.rs/reverie-core)
  and sibling crates.
* Hermit — the largest Reverie tool — for a worked example of a
  production determinism engine written against this API:
  [Hermit: Deterministic Linux for Controlled Testing](https://developers.facebook.com/blog/post/2022/11/22/hermit-deterministic-linux-testing/).

> 🚧 **Under construction — annotated bibliography.** TODO: annotations
> for DynamoRIO, Intel Pin, QEMU TCG, gVisor systrap, e9patch, and
> lazypoline — what each is, and which Reverie mechanism it
> corresponds to — aligned with the related-work lane's survey.
> <!-- UC: reading-annotated -->
> Tracking: [reverie#1272](https://github.com/rrnewton/reverie/issues/1272) (`reading-annotated`).
