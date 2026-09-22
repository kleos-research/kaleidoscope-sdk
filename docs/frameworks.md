# Using Kaleidoscope with an agent framework

`KaleidoscopeMemory`, from the Python client, hands Kaleidoscope's two memory tools, `search`
and `remember`, to your agent framework. It starts one engine process when you open it and
keeps that process for the whole run. It builds each tool from the definition the engine
publishes, so the schema your model sees is the engine's own; this client never writes one.

## Before you start

Follow the [quickstart](../README.md#quickstart) first. You need `kscope` installed and
activated, a vault with a profile called `default`, and the engine path exported:

```bash
export KALEIDOSCOPE_ENGINE="$HOME/.kaleidoscope/bin/kscope"
```

Then install the client with the extra for your framework:

| Framework | Install |
| --- | --- |
| OpenAI Agents SDK | `python3 -m pip install "./kaleidoscope-sdk/python[openai]"` |
| LangChain or LangGraph | `python3 -m pip install "./kaleidoscope-sdk/python[langgraph]"` |
| CrewAI | `python3 -m pip install "./kaleidoscope-sdk/python[crewai]"` |
| Claude Agent SDK | `python3 -m pip install "./kaleidoscope-sdk/python[claude]"` |

**Install exactly one framework extra per environment.** The extras pin the `mcp` package to
versions that exclude each other, so one virtual environment can satisfy only one of them. If
the installed `mcp` does not match what your framework needs, the `as_*_tools()` call refuses
and names both versions and the extra to install. Without that check, the framework would fail
later with a message that does not mention `mcp`.

The examples below take the key from the key file or from `KALEIDOSCOPE_API_KEY`. To pass it
in code instead, add `api_key=...` to `KaleidoscopeMemory(...)`. See
[api-keys-and-environment.md](api-keys-and-environment.md).

Runnable versions of these examples, checked by the test suite, are in
[`python/examples/`](../python/examples/).

## OpenAI Agents SDK

```python
import asyncio
from agents import Agent, Runner
from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default") as memory:
        agent = Agent(
            name="Memory-aware assistant",
            instructions=(
                "Search Kaleidoscope at the start of a nontrivial task. "
                "Remember decisions and findings once they are verified."
            ),
            model="gpt-5-mini",
            tools=memory.as_openai_tools(),
        )
        result = await Runner.run(agent, "What did we decide about the retry policy?")
        print(result.final_output)


asyncio.run(main())
```

## LangChain

```python
import asyncio
from langchain.agents import create_agent
from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default") as memory:
        agent = create_agent(
            model="openai:gpt-5-mini",
            tools=memory.as_langchain_tools(),
            system_prompt="Use Kaleidoscope as your only long-term memory.",
        )
        state = await agent.ainvoke(
            {"messages": [{"role": "user", "content": "What did we decide about retries?"}]}
        )
        print(state["messages"][-1].content)


asyncio.run(main())
```

## LangGraph

`as_langgraph_tools()` is another name for `as_langchain_tools()`.

```python
import asyncio
from langchain.chat_models import init_chat_model
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from kaleidoscope_memory import KaleidoscopeMemory


async def main() -> None:
    async with KaleidoscopeMemory(profile="default") as memory:
        tools = memory.as_langgraph_tools()
        model = init_chat_model("openai:gpt-5-mini").bind_tools(tools)

        async def call_model(state: MessagesState) -> dict:
            return {"messages": [await model.ainvoke(state["messages"])]}

        builder = StateGraph(MessagesState)
        builder.add_node("model", call_model)
        builder.add_node("tools", ToolNode(tools))
        builder.add_edge(START, "model")
        builder.add_conditional_edges("model", _needs_tools, {"tools": "tools", "end": END})
        builder.add_edge("tools", "model")
        app = builder.compile()

        # Build and run the app INSIDE the `async with` block. That block is what
        # keeps one engine process alive across turns; a client that starts a new
        # stdio process for every call would not.
        state = await app.ainvoke(
            {"messages": [{"role": "user", "content": "What did we decide about retries?"}]}
        )
        print(state["messages"][-1].content)


def _needs_tools(state: MessagesState) -> str:
    return "tools" if getattr(state["messages"][-1], "tool_calls", None) else "end"


asyncio.run(main())
```

## CrewAI

CrewAI's `kickoff()` is synchronous, so this example uses `with` rather than `async with`. The
`with` block starts one private event loop, in one thread, which owns a single engine process
for the whole crew run.

```python
from crewai import Agent, Crew, Task
from kaleidoscope_memory import KaleidoscopeMemory

with KaleidoscopeMemory(profile="default") as memory:
    agent = Agent(
        role="Memory-aware assistant",
        goal="Complete the task, using Kaleidoscope as long-term memory",
        backstory="Checks Kaleidoscope before starting and records verified decisions.",
        llm="gpt-5-mini",
        tools=memory.as_crewai_tools(),
    )
    task = Task(
        description="What did we decide about the retry policy?",
        expected_output="A concise answer citing the remembered decision.",
        agent=agent,
    )
    print(Crew(agents=[agent], tasks=[task]).kickoff())
```

## Claude Agent SDK

The Claude Agent SDK takes an MCP server entry rather than tool objects. Keep one
`ClaudeSDKClient`, and so one engine process, for the whole conversation, and allow exactly
the two Kaleidoscope tools. See
[`python/examples/claude_agent_sdk.py`](../python/examples/claude_agent_sdk.py).

## Letting the framework start the engine

If you would rather your framework start the engine itself, ask for the server configuration
instead of opening the object:

```python
from kaleidoscope_memory import KaleidoscopeMemory

memory = KaleidoscopeMemory(profile="default")
config = memory.mcp_server_config()
# -> {"command": "/abs/path/kscope", "args": ["mcp", "--profile", "default"],
#     "env": {...the twenty allowed variables, with KALEIDOSCOPE_API_KEY set...}}
```

This starts nothing. It replaces opening the object; it is not something to call inside it,
and calling it inside the `with` block refuses.

You give up two things by handing the engine over:

- **Error output is no longer bounded.** By default the MCP SDK passes the engine's error
  output straight through to the parent process. With the OpenAI Agents SDK, that means the
  model can see it.
- **Key problems arrive as the framework's error.** A missing or rejected key shows up as a
  transport error from your framework, not as this client's `EntitlementError` with its
  instructions.

The environment allowlist and the key still reach the engine.

## `remember` is not `mem0.add(text)`

`mem0.add([{"role": "user", "content": "..."}])` takes prose and extracts facts from it for you.
Kaleidoscope's `remember` takes a structured write instead: a `mode`, a `content_md` that begins
with `# `, and a `semantic_delta` describing what the memory is about, in which every entity
carries a short gloss saying what it is.

This client passes your fields to the engine unchanged, and the engine validates them. A
`remember(text)` shortcut would have to invent that structure on the model's behalf, and made-up
vocabulary written into a vault is hard to find and remove later. What teaches a model to fill
in the fields is the engine's own description of each one, which arrives with the tool schema.
Run `kscope schema remember` to read it, and to see a minimal example.

This is a real convenience gap compared with mem0, and it is stated here rather than hidden
behind a lossy wrapper.
