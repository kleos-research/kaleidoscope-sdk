from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from examples.claude_agent_sdk import run_conversation
from examples.crewai_mcp import run_crew
from kaleidoscope_memory.descriptor import load_launch_descriptor, safe_bootstrap_environment


@pytest.mark.asyncio
async def test_claude_agent_sdk_glue_reuses_one_client_and_adds_no_environment(
    fake_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KALEIDOSCOPE_TEST_SECRET", "must-not-reach-child")
    clients: list[Any] = []

    class FakeOptions:
        def __init__(self, **values: object) -> None:
            self.values = values

    class FakeClient:
        def __init__(self, *, options: FakeOptions) -> None:
            self.options = options
            self.prompts: list[str] = []
            self.enters = 0
            self.exits = 0
            clients.append(self)

        async def __aenter__(self) -> "FakeClient":
            self.enters += 1
            return self

        async def __aexit__(self, *_args: object) -> None:
            self.exits += 1

        async def query(self, prompt: str) -> None:
            self.prompts.append(prompt)

        async def receive_response(self):
            yield {"prompt": self.prompts[-1]}

    module = ModuleType("claude_agent_sdk")
    module.ClaudeAgentOptions = FakeOptions
    module.ClaudeSDKClient = FakeClient
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", module)

    descriptor = load_launch_descriptor(fake_binary, "claude")
    messages = [message async for message in run_conversation(descriptor, ["one", "two"])]
    assert messages == [{"prompt": "one"}, {"prompt": "two"}]
    assert len(clients) == 1
    client = clients[0]
    assert (client.enters, client.exits, client.prompts) == (1, 1, ["one", "two"])
    options = client.options.values
    assert options["strict_mcp_config"] is True
    assert options["allowed_tools"] == [
        "mcp__kaleidoscope__search",
        "mcp__kaleidoscope__remember",
    ]
    assert options["mcp_servers"]["kaleidoscope"]["env"] == safe_bootstrap_environment()
    assert "KALEIDOSCOPE_TEST_SECRET" not in options["mcp_servers"]["kaleidoscope"]["env"]


def test_crewai_glue_uses_one_context_and_exact_tools(
    fake_binary: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KALEIDOSCOPE_TEST_SECRET", "must-not-reach-child")
    state: dict[str, Any] = {"enters": 0, "exits": 0}

    class Tool:
        def __init__(self, name: str) -> None:
            self.name = name

    class StdioServerParameters:
        def __init__(self, **values: object) -> None:
            state["stdio"] = values

    class MCPServerAdapter:
        def __init__(self, parameters: StdioServerParameters) -> None:
            state["adapter"] = parameters

        def __enter__(self) -> list[Tool]:
            state["enters"] += 1
            return [Tool("search"), Tool("remember")]

        def __exit__(self, *_args: object) -> None:
            state["exits"] += 1

    class Agent:
        def __init__(self, **values: object) -> None:
            state["agent"] = values

    class Task:
        def __init__(self, **values: object) -> None:
            state["task"] = values

    class Crew:
        def __init__(self, **values: object) -> None:
            state["crew"] = values

        def kickoff(self) -> str:
            return "crew-result"

    crewai = ModuleType("crewai")
    crewai.Agent, crewai.Crew, crewai.Task = Agent, Crew, Task
    crewai_tools = ModuleType("crewai_tools")
    crewai_tools.MCPServerAdapter = MCPServerAdapter
    mcp = ModuleType("mcp")
    mcp.StdioServerParameters = StdioServerParameters
    monkeypatch.setitem(sys.modules, "crewai", crewai)
    monkeypatch.setitem(sys.modules, "crewai_tools", crewai_tools)
    monkeypatch.setitem(sys.modules, "mcp", mcp)

    descriptor = load_launch_descriptor(fake_binary, "crewai")
    assert run_crew(descriptor, llm=object(), task_description="fixture") == "crew-result"
    assert (state["enters"], state["exits"]) == (1, 1)
    assert state["stdio"] == {
        "command": descriptor.command,
        "args": list(descriptor.args),
        "env": safe_bootstrap_environment(),
    }
    assert {tool.name for tool in state["agent"]["tools"]} == {"search", "remember"}
