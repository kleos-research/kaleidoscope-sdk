# Kaleidoscope for Python

`kaleidoscope-memory` is the public Python client and command package for
Kaleidoscope. The pure-Python wheel contains process/MCP helpers and console
launchers. A platform wheel contains the public manager and proprietary
`kscope` engine as object code; no engine source or compiler is required.

The first release candidate supports only the natively exercised macOS arm64
coordinate. Installation remains protected and unpublished until the legal,
signing, registry, and promotion gates are approved.

```sh
python -m pip install kaleidoscope-memory
kaleidoscope --version
kscope --version
```

```python
from kaleidoscope_memory import (
    installed_payload_paths,
    load_launch_descriptor,
    mcp_stdio_config,
)

engine = installed_payload_paths().engine
descriptor = load_launch_descriptor(engine, "default")
mcp = mcp_stdio_config(descriptor)
```

Explicit executable paths and SHA-256 pins remain available for controllers.
The wrapper implements no memory algorithm or secondary store, and models see
only the native MCP tools `search` and `remember`.

## Licence

Apache-2.0. See LICENSE for the terms and NOTICE for the copyright line that
Section 4(d) requires downstream redistributors to carry forward.

That licence covers this package's own source. It does not cover the `kscope`
memory engine or any other proprietary object-code payload delivered inside a
platform package; those are closed source, are not part of this repository, and
are not licensed by this repository at all — separate terms apply to them.
The engine carries the third-party attribution it has inside the executable, and
states in that same output which attribution is not embedded yet:

    kscope licences

Third-party attribution for this repository's own dependencies is in
THIRD_PARTY_NOTICES.md at the repository root.
