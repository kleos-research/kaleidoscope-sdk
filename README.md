# Kaleidoscope SDK

Python and TypeScript clients for [Kaleidoscope](https://memory.kleosresearch.xyz), local
memory for AI agents, with ready-made tools for popular agent frameworks.

An agent that finishes a task forgets it. The next session rediscovers the same decisions,
asks questions you already answered, and repeats mistakes you already paid for. Kaleidoscope
keeps that context in a vault on your own disk. Your agent reads it with one tool, `search`,
and writes to it with another, `remember`.

The `kscope` command handles everyday use: it installs from npm and connects Claude Code,
Codex, Cursor and OpenCode for you. This repository is for the agents you build yourself. It
lets the OpenAI Agents SDK, LangChain, LangGraph, CrewAI, the Claude Agent SDK, or your own
code use the same memory.

## What is in this repository

| Part | Folder | How to get it today |
| --- | --- | --- |
| Python client, with tools for agent frameworks | `python/` | Install it from this repository. It is not on PyPI yet. |
| TypeScript client | `typescript/` | Build it from this repository. It is not on npm yet. |
| `kaleidoscope`, a manager that wires Kaleidoscope into coding agents | `src/` | Build it from this repository with Cargo. |
| The agent skill and instruction snippets | `skills/`, `snippets/` | Copy them, or install them with the manager. |

The memory engine, `kscope`, is not in this repository. It is closed source, and you install
it from npm.

## Before you start

- macOS or Linux.
- Node.js 18 or newer, to install `kscope`.
- Python 3.11 or newer, for the Python client.
- An API key. Kaleidoscope is in early access: email
  [contact@kleosresearch.xyz](mailto:contact@kleosresearch.xyz) and we will send you one.

## Quickstart

**1. Install Kaleidoscope and give your project a vault.**

```bash
npm install -g @kleos-research/kaleidoscope
kscope activate <your-key>
cd your-project
kscope init
```

`kscope init` creates the vault and a profile called `default` that points at it. It also
connects any of Claude Code, Codex, Cursor and OpenCode it finds on your machine.

**2. Install the Python client from this repository.**

```bash
git clone https://github.com/kleos-research/kaleidoscope-sdk.git
python3 -m pip install ./kaleidoscope-sdk/python
```

**3. Tell the client where the engine is.** `kscope init` keeps a copy of the engine at
`~/.kaleidoscope/bin/kscope`. The client needs that copy, not the `kscope` launcher that npm
put on your `PATH`.

```bash
export KALEIDOSCOPE_ENGINE="$HOME/.kaleidoscope/bin/kscope"
```

**4. Search your memory from Python.**

```python
from kaleidoscope_memory import KaleidoscopeMemory

with KaleidoscopeMemory(profile="default") as memory:
    print(memory.search("What did we decide about retries?"))
```

The client uses the key that `kscope activate` stored. You can also pass `api_key=` or set
`KALEIDOSCOPE_API_KEY`. A new vault is empty, so your first search finds nothing until
something has been remembered.

To see exactly what `remember` accepts, run `kscope schema remember`. It ends with a minimal
example that you can pass to `memory.remember(...)` as keyword arguments.

## Use it with an agent framework

`KaleidoscopeMemory` turns the two memory tools into your framework's own tool type. It keeps
one engine process open for the whole run.

```python
import asyncio

from agents import Agent, Runner
from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default") as memory:
        agent = Agent(
            name="Assistant",
            instructions="Search memory at the start of a task. Remember decisions once they are verified.",
            model="gpt-5-mini",
            tools=memory.as_openai_tools(),
        )
        result = await Runner.run(agent, "What did we decide about the retry policy?")
        print(result.final_output)


asyncio.run(main())
```

Install the framework together with the client by naming its extra:

```bash
python3 -m pip install "./kaleidoscope-sdk/python[openai]"
```

| Framework | Extra | Tools | Full example |
| --- | --- | --- | --- |
| OpenAI Agents SDK | `openai` | `memory.as_openai_tools()` | [openai_agents_tools.py](python/examples/openai_agents_tools.py) |
| LangChain | `langgraph` | `memory.as_langchain_tools()` | [langchain_tools.py](python/examples/langchain_tools.py) |
| LangGraph | `langgraph` | `memory.as_langgraph_tools()` | [langgraph_tools.py](python/examples/langgraph_tools.py) |
| CrewAI | `crewai` | `memory.as_crewai_tools()` | [crewai_tools_example.py](python/examples/crewai_tools_example.py) |
| Claude Agent SDK | `claude` | an MCP server entry | [claude_agent_sdk.py](python/examples/claude_agent_sdk.py) |
| Any other MCP client | none | `memory.mcp_server_config()` | [native_mcp_handover.py](python/examples/native_mcp_handover.py) |

Install one framework extra per Python environment. The extras need different versions of the
`mcp` package, so two of them cannot share an environment. [docs/frameworks.md](docs/frameworks.md)
walks through every framework.

## Other parts of this repository

- **TypeScript client.** Starts the engine and keeps one MCP session open from Node.js. See
  [typescript/README.md](typescript/README.md) to build and use it.
- **The `kaleidoscope` manager.** Connects Kaleidoscope to Claude Code, Codex, Cursor and
  OpenCode one editor at a time, previews every change, and removes its changes cleanly.
  `kscope init` covers the same setup for most people. See [docs/manager.md](docs/manager.md).
- **The agent skill.** [skills/use-kaleidoscope/SKILL.md](skills/use-kaleidoscope/SKILL.md)
  tells an agent when to search its memory and what is worth remembering.

## Documentation

- [Kaleidoscope documentation](https://memory.kleosresearch.xyz/docs/): install, concepts,
  the command line, and every supported editor and framework.
- [docs/frameworks.md](docs/frameworks.md): agent framework examples in full.
- [docs/api-keys-and-environment.md](docs/api-keys-and-environment.md): how your key reaches
  the engine, and which environment variables the clients pass on.
- [docs/manager.md](docs/manager.md): the `kaleidoscope` manager.
- [COMPATIBILITY.md](COMPATIBILITY.md): the framework and editor versions this repository is
  tested against.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). If you work here with a coding agent, point it at
[AGENTS.md](AGENTS.md).

## Licence

Everything in this repository is Apache-2.0. That licence does not cover the `kscope` engine
or model weights, which are licensed separately: see [LICENSING.md](LICENSING.md).
