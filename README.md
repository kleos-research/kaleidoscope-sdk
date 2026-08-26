# Kaleidoscope SDK

Local memory for AI agents. Your agent gets two tools — `search` and `remember` —
backed by a memory engine that runs on your own machine and keeps your data there.

This repository holds the public client surfaces: the local manager, the Python
and TypeScript clients, and integrations for the common agent frameworks.

> **Not released yet.** Nothing here installs from a registry, and the engine
> these clients drive is not publicly distributed. You can read the code and the
> [documentation](https://memory.kleosresearch.xyz/docs/); you cannot yet run it.

## What it looks like

```python
from kaleidoscope_memory import KaleidoscopeMemory

async with KaleidoscopeMemory(profile="default", api_key="ksk_alpha...") as memory:
    tools = memory.as_openai_agents_tools()
    # hand `tools` to your agent
```

One engine process per session, holding your vault. The model sees two tools and
nothing else — every other command is operator-only and never reaches it.

## Setting it up

```bash
kaleidoscope init
```

One command. It finds your vault if you already have one, writes the launch
configuration for whichever agent harness you use, adds the instructions to your
`AGENTS.md` or `CLAUDE.md`, and installs the skill where that harness looks for
it.

Everything it writes into a file of yours is marked and reversible:

```bash
kaleidoscope teardown        # removes only what it added
```

Supported harnesses: Codex, Claude Code, Cursor, OpenCode.

## The API key

Two routes, both work:

```python
# in code
memory = KaleidoscopeMemory(profile="default", api_key="ksk_alpha...")

# or in the environment, and omit the argument
#   export KALEIDOSCOPE_API_KEY=ksk_alpha...
memory = KaleidoscopeMemory(profile="default")
```

**Code beats environment; environment beats key file.** A key passed in code is
placed in the child process's environment only — `os.environ` is never mutated,
so it reaches this SDK's engine and no other subprocess your program spawns.

**There is no `.env` reader**, in either language, and none is planned. "An env
file works" means your shell or your tooling exported the variable. A `.env`
reader would put this SDK in the business of parsing files that also hold your
*other* secrets, which is exactly what the child-environment allowlist exists to
prevent.

### What this SDK will never do with your key

It carries your key to the engine and reports the engine's answer. It does not
check signatures, compute expiry, or cache a verdict. This code is Apache-2.0 and
anyone can edit it, so a validity check here would be theatre — and a second
source of truth about whether you may run. The engine decides.

## Frameworks

Working examples for each, in [`python/examples/`](python/examples/):

| framework | example |
| --- | --- |
| OpenAI Agents SDK | [`openai_agents_tools.py`](python/examples/openai_agents_tools.py) |
| LangChain | [`langchain_tools.py`](python/examples/langchain_tools.py) |
| LangGraph | [`langgraph_tools.py`](python/examples/langgraph_tools.py) |
| CrewAI | [`crewai_tools_example.py`](python/examples/crewai_tools_example.py) |
| any MCP-native host | [`native_mcp_handover.py`](python/examples/native_mcp_handover.py) |

Tool schemas come from live discovery against the engine, never from a copy kept
here. That is why `as_*_tools()` is only callable inside the context manager: the
schema does not exist until the engine has been asked for it.

### `remember` is not `mem0.add(text)`

`mem0.add("...")` takes prose and runs its own extraction. Kaleidoscope's
`remember` takes a structured write: a mode, a `content_md`, and a semantic delta
whose entities each carry a gloss. This SDK passes your fields through verbatim
and lets the engine validate them.

A `remember(text)` convenience would have to invent that structure on the model's
behalf — and one hand-written relation name in one prompt is what once produced
13,060 identical proposals in this project's history, which were then analysed as
evidence about how agents choose relations. They were evidence about one line.

What teaches a model to fill the structure in is the engine's own field
descriptions, which arrive with the schema. This is a real ergonomic gap against
mem0, and it is stated here rather than hidden behind a lossy wrapper.

## Licence

Apache-2.0 covers everything in this repository: the manager, both clients, the
integrations, examples and snippets, the reference goldens, and the skill. See
[LICENSE](LICENSE), and [NOTICE](NOTICE) for the copyright line Section 4(d)
requires redistributors to carry forward.

**It does not cover the memory engine.** The engine, the model weights, and the
other proprietary payloads are distributed separately under their own terms and
are not licensed by this repository. Third-party attribution for the code here is
in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); the engine carries its own
inside the executable.

## Layout

| path | what |
| --- | --- |
| `src/` | the local manager, in Rust |
| `python/` | `kscope-memory`, the Python client |
| `typescript/` | `@kleos-research/kaleidoscope`, the TypeScript client |
| `snippets/` | the instruction blocks `init` installs |
| `skills/` | the agent skill |
| `reference/` | goldens all three implementations are asserted against |

## Documentation

<https://memory.kleosresearch.xyz/docs/> — including an honest account of what
does and does not work today.
