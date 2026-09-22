# Kaleidoscope for Python

The Python client for [Kaleidoscope](https://memory.kleosresearch.xyz), local memory for AI
agents. It starts the `kscope` engine, keeps one session open, and gives your code or your
agent framework the two memory tools, `search` and `remember`.

The package is called `kscope-memory` and you import it as `kaleidoscope_memory`. It contains
no memory engine and does not install one: you install `kscope` separately.

**It is not on PyPI yet.** The `kscope-memory` name on PyPI is a placeholder that contains no
code. Install the client from the repository, as shown below.

## Install

You need Python 3.11 or newer, and an API key: Kaleidoscope is in early access, so email
[contact@kleosresearch.xyz](mailto:contact@kleosresearch.xyz) for one.

```bash
# The engine, and a vault for your project
npm install -g @kleos-research/kaleidoscope
kscope activate <your-key>
cd your-project
kscope init

# The Python client
git clone https://github.com/kleos-research/kaleidoscope-sdk.git
python3 -m pip install ./kaleidoscope-sdk/python
export KALEIDOSCOPE_ENGINE="$HOME/.kaleidoscope/bin/kscope"
```

`kscope init` creates a profile called `default` for your vault, and keeps a copy of the
engine at `~/.kaleidoscope/bin/kscope`. The client needs that copy: the `kscope` that npm puts
on your `PATH` is a launcher script, and the client does not accept it.

To use an agent framework, add its extra, for example `"./kaleidoscope-sdk/python[openai]"`.
The extras are `openai`, `langgraph` (for LangChain and LangGraph), `crewai` and `claude`.
Install one per environment, because they need different versions of the `mcp` package.

## Use it

```python
from kaleidoscope_memory import KaleidoscopeMemory

with KaleidoscopeMemory(profile="default") as memory:
    print(memory.search("What did we decide about retries?"))
```

In async code, use `async with` and `await memory.asearch(...)`. Inside the block,
`memory.as_openai_tools()`, `as_langchain_tools()`, `as_langgraph_tools()` and
`as_crewai_tools()` give your framework the two tools. The
[framework guide](https://github.com/kleos-research/kaleidoscope-sdk/blob/main/docs/frameworks.md)
has a full example for each.

The key comes from `api_key=`, from `KALEIDOSCOPE_API_KEY`, or from the key file that
`kscope activate` wrote, in that order. See
[API keys and the engine's environment](https://github.com/kleos-research/kaleidoscope-sdk/blob/main/docs/api-keys-and-environment.md).

## How it finds the engine

It tries these in order:

1. a path you pass, as `binary=`;
2. the `KALEIDOSCOPE_ENGINE` environment variable (it is ignored when set but empty);
3. the folder this Python installs its own commands into;
4. each folder on your `PATH`.

The first two are final: if you name a path and it is wrong, the client says so rather than
quietly running a different program. If it finds nothing, the error lists every place it
looked and the command that installs the engine.

To insist on one exact engine build, pass `expected_sha256=` with the executable's SHA-256
digest. The client then refuses any other build.

## Lower-level helpers

To wire the engine into an MCP client of your own:

```python
from kaleidoscope_memory import load_launch_descriptor, locate_engine, mcp_stdio_config

engine = locate_engine().path
descriptor = load_launch_descriptor(engine, "default")
config = mcp_stdio_config(descriptor)  # {"command": ..., "args": ["mcp", "--profile", "default"]}
```

The package also has `PersistentKaleidoscopeSession`, for a raw MCP session that stays open
for a whole run, and `Controller` and `Operator`, for calling the engine's command-line
operations directly. Operator commands are kept apart on purpose: the model only ever sees the
engine's two tools, `search` and `remember`. The client contains no memory logic and keeps no
store of its own. [COMPATIBILITY.md](https://github.com/kleos-research/kaleidoscope-sdk/blob/main/COMPATIBILITY.md)
lists the framework versions it is tested with.

Installing the package also adds `kscope` and `kaleidoscope` commands to your environment. They
find the real programs in the same way and hand over to them.

## Licence

Apache-2.0. See LICENSE for the terms and NOTICE for the copyright line, which Section 4(d) of
the licence requires anyone redistributing this package to carry forward.

The licence covers this package's own source. It does not cover the `kscope` memory engine,
which you install separately. The engine is closed source, is not part of this repository and
is not shipped in this package; this repository does not license it at all, and separate terms
apply to it. `kscope licences` prints the engine's own third-party notices, including which ones
are not embedded yet. Notices for this repository's dependencies are in `THIRD_PARTY_NOTICES.md`
at the repository root.
