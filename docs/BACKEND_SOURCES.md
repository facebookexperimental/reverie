# Backend sources

The Reverie core workspace owns the generic Tool, Guest, Backend, memory and
RPC APIs, the first-party runtimes, and the shared example Tools. It has no
DynamoRIO, SaBRe or e9patch package or backend source submodule.

## Extension ownership

| Backend | Repository | Native source owner | License notices |
| --- | --- | --- | --- |
| DynamoRIO | [hermit-dynamorio](https://github.com/rrnewton/hermit-dynamorio) | `third-party/dynamorio`, a full patched fork with recursive children; `reverie-dynamorio` owns its SDK producer | BSD-3-Clause, LGPL-2.1-only drwrap, BSD-4-Clause Valgrind headers |
| SaBRe | [hermit-3rdparty-patching](https://github.com/rrnewton/hermit-3rdparty-patching) | `experimental/reverie-sabre/vendor/{sabre,libelf}` | GPL-3.0-or-later plus documented GPL-2.0-only/BSD-3-Clause/MIT exceptions; LGPL-3.0-or-later libelf |
| e9patch | [hermit-3rdparty-patching](https://github.com/rrnewton/hermit-3rdparty-patching) | `reverie-e9patch/vendor/e9patch` | GPL-3.0-only, LGPL-3.0-or-later libdw, MIT Zydis |

The extensions retain their source notices and own their native build,
cache, install and source-custody checks. A successful core build does not
qualify an extension, its native inputs, or its runtime.

## Source and build contracts

DynamoRIO uses the complete patched fork rather than the former curated vendor
snapshot. Its maintained producer requires exact clean Git roots and all three
pinned recursive children; missing Git, dirty or incomplete checkouts and source
archives refuse. The historical vendor `REVISION` marker is provenance, not
proof of the fork's current commit or tree. The producer measures recursive
source bytes, modes and symlinks independently of the four validated Git
administration roots, and binds the Git-derived version inputs explicitly.
Its original native budget and installation checks remain in the extension.

SaBRe and e9patch retain their curated source policies in the patching
repository. The e9patch Zydis encoder exclusion, sole large-text allowance,
order-only archive prerequisites and system-library-goal assertions remain
owned by those packages. A moved source or test has no new execution credit.

The old core `third-party/{dynamorio,sabre,e9patch}` reference gitlinks and
`scripts/backend-submodule.sh` activation helper are retired. Do not substitute
those old pins for either extension's actual source contract. Use each
extension's normal checkout and Cargo producer entry points.

## Shared tests and examples

The core keeps the generic example Tools and the E2E comparator and corpus.
Extensions use the public Tool-only and neutral host APIs rather than copying
those algorithms. Their E2E entry points require explicit core comparator and
data locations and own their backend ledger rows. The core default selection
is ptrace, KVM, LiteInst and the in-guest trap runtime. Neither absent extension
inputs nor a relocated historical ledger row is a passing qualification.
