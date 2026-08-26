"""CrewAI adapter example with one context-managed stdio process per crew run.

This is the NATIVE-MCP form: the framework's own MCP client owns the child.
`crewai_tools_example.py` beside it is the tool-shaped form and is the recommended one --
`memory.as_*_tools()` builds the same two tools from live discovery and keeps
the bounded stderr and the typed entitlement error this form gives up.
Kept because it demonstrates the handover honestly, not because it is worse.
"""

from __future__ import annotations

from typing import Any

from kaleidoscope_memory.descriptor import (
    EXPECTED_TOOLS,
    LaunchDescriptor,
    safe_bootstrap_environment,
)
from kaleidoscope_memory.entitlement import entitlement_preflight


def run_crew(descriptor: LaunchDescriptor, *, llm: Any, task_description: str) -> Any:
    from crewai import Agent, Crew, Task
    from crewai_tools import MCPServerAdapter
    from mcp import StdioServerParameters

    # Third-party MCP client: the allowlist change reaches it for free, the
    # typed entitlement error does not. Preflight, then let the engine decide.
    entitlement_preflight(descriptor.command)

    parameters = StdioServerParameters(
        command=descriptor.command,
        args=list(descriptor.args),
        env=safe_bootstrap_environment(),
    )
    with MCPServerAdapter(parameters) as discovered_tools:
        tools = [tool for tool in discovered_tools if tool.name in EXPECTED_TOOLS]
        if {tool.name for tool in tools} != set(EXPECTED_TOOLS):
            raise RuntimeError("Kaleidoscope must expose exactly search and remember")
        agent = Agent(
            role="Memory-aware assistant",
            goal="Complete the task using only the public Kaleidoscope memory boundary",
            backstory="Uses Kaleidoscope as the sole durable memory owner.",
            llm=llm,
            tools=tools,
        )
        task = Task(description=task_description, expected_output="A concise result", agent=agent)
        return Crew(agents=[agent], tasks=[task]).kickoff()
