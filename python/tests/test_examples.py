"""The shipped examples: importable, lazy, and pointing at the right thing.

These are documentation that runs, so the failure mode is an example that
stopped compiling against the API it demonstrates and nobody noticed until a
user pasted it. Every assertion here is about a property a reader depends on.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).parents[1] / "examples"

#: The four tool-shaped examples, and the README section each mirrors.
TOOL_EXAMPLES = {
    "openai_agents_tools.py": "as_openai_tools",
    "langchain_tools.py": "as_langchain_tools",
    "langgraph_tools.py": "as_langgraph_tools",
    "crewai_tools_example.py": "as_crewai_tools",
}


@pytest.mark.parametrize("name", sorted(TOOL_EXAMPLES))
def test_every_tool_example_imports_without_its_framework_at_module_level(
    name: str,
) -> None:
    """Importing an example must not require the framework it demonstrates.

    All four frameworks happen to be installed here, so an import test alone
    would pass whatever the example did. The AST half is the real assertion:
    every framework import has to sit inside a function, so a user with one
    extra installed can still read and import the other three.
    """

    module = importlib.import_module(f"examples.{name[:-3]}")
    assert hasattr(module, "main")

    tree = ast.parse((EXAMPLES / name).read_text(encoding="utf-8"))
    top_level = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in getattr(node, "names", [])
    } | {
        node.module.split(".")[0]
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module
    }
    frameworks = {"agents", "crewai", "crewai_tools", "langchain", "langgraph", "langchain_core"}
    assert top_level & frameworks == set(), sorted(top_level & frameworks)


@pytest.mark.parametrize("name", sorted(TOOL_EXAMPLES))
def test_every_tool_example_uses_the_binding_it_is_named_for(name: str) -> None:
    source = (EXAMPLES / name).read_text(encoding="utf-8")
    assert f"memory.{TOOL_EXAMPLES[name]}()" in source
    assert "KaleidoscopeMemory" in source


def test_the_crewai_example_is_the_only_synchronous_one() -> None:
    """CrewAI's `kickoff()` is synchronous; the other three are not.

    Both directions, because the interesting error is an example that used the
    wrong context manager and would refuse at runtime with a message about
    modes -- correct behaviour, and a bad first experience.
    """

    crewai = (EXAMPLES / "crewai_tools_example.py").read_text(encoding="utf-8")
    assert "with KaleidoscopeMemory(" in crewai
    # The docstring EXPLAINS why it is not `async with`, so the needle has to
    # be the construct rather than the words.
    assert "async with KaleidoscopeMemory(" not in crewai

    for name in ("openai_agents_tools.py", "langchain_tools.py", "langgraph_tools.py"):
        source = (EXAMPLES / name).read_text(encoding="utf-8")
        assert "async with KaleidoscopeMemory(" in source, name


def test_the_native_mcp_examples_point_at_their_tool_shaped_replacements() -> None:
    """A reader who lands on the older form has to be told there is a newer one."""

    for old, new in (
        ("crewai_mcp.py", "crewai_tools_example.py"),
        ("langchain_mcp.py", "langchain_tools.py"),
        ("langgraph_mcp.py", "langgraph_tools.py"),
        ("openai_agents.py", "openai_agents_tools.py"),
    ):
        source = (EXAMPLES / old).read_text(encoding="utf-8")
        assert new in source, old
        assert (EXAMPLES / new).is_file(), new


def test_the_handover_example_states_what_the_caller_gives_up() -> None:
    """The two lost properties, named. Otherwise the escape hatch reads as free."""

    source = (EXAMPLES / "native_mcp_handover.py").read_text(encoding="utf-8")

    assert "mcp_server_config()" in source
    assert "stderr is not bounded" in source
    assert "EntitlementError" in source
