# The Reverie Guide (mdBook source)

Build locally:

```console
cargo install mdbook   # or fetch a release tarball; CI pins the version
mdbook build guide     # output in guide/book/
mdbook serve guide     # live preview
```

Conventions:

- Rust Book style: concepts first, one growing project (the syscall
  counter) across chapters, run-then-break-down in project chapters,
  reference material in appendices / docs.rs — never inline API dumps.
- Unfinished or unimplemented material gets an Under construction box:

  ```markdown
  > 🚧 **Under construction — short title.** TODO: what is missing.
  > <!-- UC: short-id -->
  ```

  The `<!-- UC: ... -->` marker is the machine-countable record. The
  count on the Introduction page must always equal
  `grep -r --count '<!-- UC:' guide/src` summed over files; CI fails
  otherwise. The project goal is to drive the count to zero.
- Terminology must match the architecture contract (tool / guest /
  backend / subscription; hooking vs trapping vs RPC; the activation
  and mechanism axes). When the contract renames something, this guide
  renames it in the same change.
- `BACKENDS.md` is the deep mechanism reference; the guide summarizes
  it and must not contradict it. If they disagree, one of them is a
  bug — file it, don't pick silently.
