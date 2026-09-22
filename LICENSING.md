# Licensing

This page explains what the Apache-2.0 licence in this repository covers and what it does not.
[NOTICE](NOTICE) is the authoritative statement of that scope; this page says the same thing at
more length.

## What Apache-2.0 covers

Everything in this repository is licensed under the Apache License, Version 2.0:

- the `kaleidoscope` manager, the Rust crate `kaleidoscope-manager`;
- the Python client, `kscope-memory`, and the TypeScript client;
- the framework integrations, the examples and the instruction snippets;
- the conformance probes and the reference files in `reference/`;
- the agent skill in `skills/use-kaleidoscope`.

[LICENSE](LICENSE) is the licence text. [NOTICE](NOTICE) carries the copyright line,
"Copyright 2026 Kleos Research". Section 4(d) of the licence requires anyone who redistributes
this work to carry that NOTICE forward.

## What it does not cover

The Apache-2.0 licence does not apply to:

- the `kscope` memory engine, which is distributed separately;
- model weights;
- any other proprietary object code, including the executable inside a platform package such
  as `@kleos-research/kaleidoscope-darwin-arm64`.

The engine is closed source and is not part of this repository. This repository does not license
it at all: separate terms apply to it. Those terms come with the engine, in the `LICENSE.txt` file
of the npm package that installs it.

## Third-party software

- **Inside the engine.** The engine carries its third-party attributions inside the executable,
  and the same output says which attributions are not embedded yet. Print them with
  `kscope licences`.
- **In this repository.** [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) covers the
  dependencies of the code here. It is generated from the dependency manifests; see
  [CONTRIBUTING.md](CONTRIBUTING.md#third-party-notices) for how.

## How the licence metadata is kept consistent

Four manifests declare a licence: `Cargo.toml`, `python/pyproject.toml`,
`typescript/package.json` and `conformance/package.json`. A test,
`python/tests/test_licensing.py`, checks on every pull request that all four say `Apache-2.0`,
name Kleos Research as the holder, and point at licence files that exist. It exists to catch
two mistakes: a licence claimed in metadata with no file behind it, and terms stated with no one
named as holding them.
