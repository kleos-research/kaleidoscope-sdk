# Kaleidoscope for Python

`kscope-memory` is the public Python client for Kaleidoscope. It contains
process and MCP helpers and console launchers, and nothing else: no memory
engine, no vault, no second memory implementation, and no installer.

The engine is a separate install. Get the `kscope` and `kaleidoscope` commands
first, then add the Python client:

```sh
npm install -g @kleos-research/kaleidoscope
kscope --version

python -m pip install kscope-memory
```

The client finds the installed commands at run time. It looks, in order, at a
path you pass it, then at `KALEIDOSCOPE_ENGINE` (`KALEIDOSCOPE_MANAGER` for the
manager), then beside the Python you are running, then on `PATH`. If it finds
nothing it says so, says everywhere it looked, and gives you the command above.

```python
from kaleidoscope_memory import (
    load_launch_descriptor,
    locate_engine,
    mcp_stdio_config,
)

engine = locate_engine().path
descriptor = load_launch_descriptor(engine, "default")
mcp = mcp_stdio_config(descriptor)
```

An explicit path always wins, for a pinned deployment:

```python
descriptor = load_launch_descriptor("/opt/kaleidoscope/bin/kscope", "default")
```

Explicit executable paths and SHA-256 pins remain available for controllers.
The wrapper implements no memory algorithm or secondary store, and models see
only the native MCP tools `search` and `remember`.

## Licence

Apache-2.0. See LICENSE for the terms and NOTICE for the copyright line that
Section 4(d) requires downstream redistributors to carry forward.

That licence covers this package's own source. It does not cover the `kscope`
memory engine, which you install separately: it is closed source, is not part
of this repository, is not shipped inside this package, and is not licensed by
this repository at all — separate terms apply to it.
The engine carries the third-party attribution it has inside the executable, and
states in that same output which attribution is not embedded yet:

    kscope licences

Third-party attribution for this repository's own dependencies is in
THIRD_PARTY_NOTICES.md at the repository root.
